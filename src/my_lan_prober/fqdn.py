"""``FQDN`` — the polymorphic name of anything the computer can reach.

The word is used in its widest sense here.  A *fully qualified domain name* is
one spelling of "a thing you can address"; this module treats five more as the
same kind of value:

======================  ==================================================
:class:`FQDN` kind      example
======================  ==================================================
``ipv4``                ``192.168.1.104``
``ipv6``                ``fe80::1``
``mac``                 ``08:62:66:b4:2c:d2``
``hostname``            ``tplogin.cn``, ``localhost``
``unknown``             ``""``
======================  ==================================================

Every one of them is *reachable*, and the prober meets all of them in the same
tables: a router lease table carries IPv4 addresses and MACs, a neighbours
table carries MACs, a resolver carries addresses, and an SSH hop chain carries
names.  Giving them one type is what lets a table be merged, deduplicated and
expanded without a special case per shape.

Two properties are load-bearing:

* it is a ``str`` subclass, so every existing caller keeps working and
  ``FQDN("192.168.1.1") == "192.168.1.1"`` stays true;
* equality goes through :meth:`value`, so two spellings of one IPv6 address are
  one endpoint and two spellings of one MAC are one host.

The one genuinely new idea is :meth:`FQDN.from_mac`: a MAC has no address
arithmetic, so a host reached only by MAC is *derived* into the reserved
documentation range (RFC 5737, ``192.0.2.0/24``).  The derivation is a pure
function of the MAC, so two runs — and two fetchers — agree on it, and a
derived address can never collide with a real DHCP assignment.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from typing import ClassVar, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "FQDN",
    "KIND_IPV4",
    "KIND_IPV6",
    "KIND_MAC",
    "KIND_HOSTNAME",
    "KIND_UNKNOWN",
    "FQDN_KINDS",
    "HOP_SEPARATOR",
    "DERIVED_NETWORK",
]

KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"
KIND_MAC = "mac"
KIND_HOSTNAME = "hostname"
KIND_UNKNOWN = "unknown"

FQDN_KINDS: Tuple[str, ...] = (KIND_IPV4, KIND_IPV6, KIND_MAC, KIND_HOSTNAME, KIND_UNKNOWN)

#: Separates the hops of a multi-hop path (``bastion>jump>target``).  ``>`` is
#: deliberately not a character any of the other spellings can contain.
HOP_SEPARATOR = ">"

#: RFC 5737 documentation range — never routed, never DHCP-assigned.
DERIVED_NETWORK = "192.0.2.0/24"

#: Locally-administered bit of the first octet (IEEE 802 ``U/L``).
_LOCALLY_ADMINISTERED_BIT = 0x02

_HEX_DIGITS = set("0123456789abcdef")


def _looks_like_mac(text: str) -> bool:
    """Whether ``text`` is six hex octets with a consistent separator.

    Each test logs its own verdict at DEBUG.  Classification runs once per
    value and a table is mostly addresses, so the lines are only visible with
    ``--verbose``; when they are, they answer the question that actually gets
    asked — "why is this string being treated as a hostname?".
    """
    compact = text.replace(":", "").replace("-", "")

    # Split deliberately rather than `A or B`: the two halves fail for
    # different reasons (wrong length vs. a non-hex character), and which one
    # it was is the useful part of the message.
    if len(compact) != 12:
        log.debug("not a MAC: %r has %d hex digits, expected 12", text, len(compact))
        return False

    if not set(compact.lower()) <= _HEX_DIGITS:
        log.debug("not a MAC: %r contains a non-hex character", text)
        return False

    # Each composite test is hoisted into a named value so the decision can be
    # *logged*.  A bare `if a and b:` is its own branch as far as the coverage
    # suite is concerned, and no log call can live inside a boolean
    # expression — hoisting is the only way to say which case was hit.
    has_colon = ":" in text
    has_hyphen = "-" in text

    if has_colon and has_hyphen:
        log.debug("not a MAC: %r mixes ':' and '-' separators", text)
        return False

    if not has_colon and not has_hyphen:
        log.debug("MAC %r written without separators", text)
        return True

    separator = ":" if has_colon else "-"
    octets = text.split(separator)
    if not all(len(octet) in (1, 2) for octet in octets):
        log.debug("not a MAC: %r has an octet that is not 1-2 digits", text)
        return False

    log.debug("MAC %r accepted (%d octets, %r separator)", text, len(octets), separator)
    return True


def _normalise_mac(text: str) -> str:
    compact = text.replace(":", "").replace("-", "").lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _classify(text: str) -> str:
    if not text:
        log.debug("empty value classified as %s", KIND_UNKNOWN)
        return KIND_UNKNOWN

    if _looks_like_mac(text):
        log.debug("%r classified as %s", text, KIND_MAC)
        return KIND_MAC

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        log.debug("%r is not an address, classified as %s", text, KIND_HOSTNAME)
        return KIND_HOSTNAME

    kind = KIND_IPV4 if address.version == 4 else KIND_IPV6
    log.debug("%r classified as %s (v%d)", text, kind, address.version)
    return kind


class FQDN(str):
    """Anything reachable, under one type.

    >>> FQDN("AA-BB-CC-DD-EE-FF").value
    'aa:bb:cc:dd:ee:ff'
    >>> FQDN("2001:0db8::1") == FQDN("2001:db8::1")
    True
    >>> FQDN("bastion>jump>target").hops
    ('bastion', 'jump', 'target')
    """

    #: Cached classification, keyed by the normalised value.  ``str`` is
    #: immutable so there is no invalidation to worry about, and the same
    #: addresses recur constantly in a LAN-wide table.
    _KIND_CACHE: ClassVar[dict] = {}

    def __new__(cls, value: object = "") -> "FQDN":
        text = str(value).strip() if value is not None else ""
        kind = _classify(text)
        normalised = _normalise_mac(text) if kind == KIND_MAC else text

        if kind == KIND_MAC:
            log.debug("normalised MAC %r -> %r", text, normalised)
        elif kind == KIND_IPV6:
            # One address, one spelling: equality between an expanded and a
            # compressed IPv6 literal must not depend on how it was written.
            normalised = str(ipaddress.IPv6Address(text))
            log.debug("normalised IPv6 %r -> %r", text, normalised)

        instance = super().__new__(cls, normalised)
        instance._kind = kind
        return instance

    # -- introspection -------------------------------------------------
    @property
    def kind(self) -> str:
        """Which shape of endpoint this names."""
        return self._kind

    @property
    def value(self) -> str:
        """The normalised spelling, as a plain ``str``."""
        return str.__str__(self)

    @property
    def is_ipv4(self) -> bool:
        return self._kind == KIND_IPV4

    @property
    def is_ipv6(self) -> bool:
        return self._kind == KIND_IPV6

    @property
    def is_mac(self) -> bool:
        return self._kind == KIND_MAC

    @property
    def is_hostname(self) -> bool:
        return self._kind == KIND_HOSTNAME

    @property
    def is_locally_administered(self) -> bool:
        """Whether a MAC is private/derived (IEEE 802 locally-administered bit)."""
        if not self.is_mac:
            log.debug("%r is not a MAC; locality bit is undefined", self.value)
            return False
        first_octet = int(self.value.split(":")[0], 16)
        locally_administered = bool(first_octet & _LOCALLY_ADMINISTERED_BIT)
        log.debug(
            "MAC %s first octet 0x%02x -> locally-administered=%s",
            self.value,
            first_octet,
            locally_administered,
        )
        return locally_administered

    @property
    def version(self) -> int:
        """IP version, or ``0`` for a MAC/name/unknown endpoint."""
        if self.is_ipv4:
            log.debug("%s is IPv4", self.value)
            return 4
        if self.is_ipv6:
            log.debug("%s is IPv6", self.value)
            return 6
        log.debug("%r (%s) has no IP version", self.value, self._kind)
        return 0

    def as_address(self) -> ipaddress._BaseAddress:
        """The ``ipaddress`` object, for endpoints that have one."""
        return ipaddress.ip_address(self.value)

    # -- SSH hop chains ------------------------------------------------
    @property
    def hops(self) -> Tuple[str, ...]:
        """The hop chain, or a one-element tuple for a plain endpoint."""
        return tuple(hop.strip() for hop in self.value.split(HOP_SEPARATOR) if hop.strip())

    @property
    def is_hop_chain(self) -> bool:
        """Whether reaching this endpoint takes more than one SSH hop."""
        return len(self.hops) > 1

    @property
    def origin(self) -> str:
        """The host the walk starts from."""
        return self.hops[0] if self.hops else ""

    @property
    def destination(self) -> str:
        """The host at the far end of the walk."""
        return self.hops[-1] if self.hops else ""

    # -- the polymorphism that makes expansion possible ----------------
    @classmethod
    def from_mac(cls, mac: str, offset: int = 0) -> "FQDN":
        """Derive a stable IPv4 endpoint from a MAC address.

        A MAC has no arithmetic of its own, so an expander that wants to record
        "*this same host*, reachable another way" needs a name for it.  The
        derivation is a pure function of the MAC and the offset, and lands in
        the RFC 5737 documentation range, which no real host is assigned.
        """
        digest = hashlib.sha256(_normalise_mac(str(mac)).encode("ascii")).digest()
        last_octet = digest[0]
        return cls(
            str(
                ipaddress.ip_address(
                    int(ipaddress.ip_network(DERIVED_NETWORK)[0]) + last_octet + offset
                )
            )
        )

    def apply_offset(self, offset: int) -> "FQDN":
        """Move an IPv4 endpoint by ``offset``, wrapping inside its ``/24``.

        Wrapping rather than carrying matters: a derived address must stay
        inside its documentation range, and a probe address must stay inside
        the subnet it was found in.
        """
        if self.is_mac:
            log.debug("refusing to offset MAC %s", self.value)
            raise ValueError("a mac address has no offset arithmetic; derive an address instead")

        if self.is_hostname:
            log.debug("refusing to offset hostname %s", self.value)
            raise ValueError("a hostname has no offset arithmetic; resolve it instead")

        if self.kind == KIND_UNKNOWN:
            log.debug("offsetting an unknown endpoint yields another")
            return FQDN("")

        if offset == 0:
            log.debug("%s unchanged by a zero offset", self.value)
            return FQDN(self.value)

        if self.is_ipv6:
            address = ipaddress.IPv6Address(self.value)
            moved = (int(address) + offset) % (1 << 128)
            result = FQDN(str(ipaddress.IPv6Address(moved)))
            log.debug("offset IPv6 %s by %+d -> %s", self.value, offset, result)
            return result

        address = ipaddress.IPv4Address(self.value)
        network = ipaddress.ip_network(f"{self.value}/24", strict=False)
        base = int(network.network_address)
        # The modulo is the wrap: a host part that would overflow stays inside
        # the /24 it was found in rather than leaking into the next subnet.
        moved = base + ((int(address) - base + offset) % 256)
        result = FQDN(str(ipaddress.IPv4Address(moved)))
        if result == self.value:
            log.debug("offset IPv4 %s by %+d wrapped back onto itself", self.value, offset)
        else:
            log.debug(
                "offset IPv4 %s by %+d -> %s (wrapped in %s)",
                self.value,
                offset,
                result,
                network,
            )
        return result
