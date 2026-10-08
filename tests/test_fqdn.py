"""Tests for :mod:`my_lan_prober.fqdn`.

An ``FQDN`` is the project's polymorphic "something the computer can reach".
It is deliberately *not* "a domain name": a reachable endpoint may be an IPv4
address, an IPv6 address, a MAC address, a DNS name, or a host reached through
a chain of SSH hops.  Code that walks the LAN only ever has to name one type.

The str subclass matters: every existing caller passes plain ``str`` around,
and ``FQDN("192.168.1.1") == "192.168.1.1"`` must keep working.
"""

from __future__ import annotations

import pytest

from my_lan_prober.fqdn import (
    FQDN,
    KIND_HOSTNAME,
    KIND_IPV4,
    KIND_IPV6,
    KIND_MAC,
    KIND_UNKNOWN,
)


# ---------------------------------------------------------------------------
# It is still a string
# ---------------------------------------------------------------------------
def test_fqdn_is_a_string():
    assert isinstance(FQDN("192.168.1.1"), str)
    assert FQDN("192.168.1.1") == "192.168.1.1"


def test_fqdn_survives_being_used_as_a_dict_key():
    table = {FQDN("nas.local"): 1}

    assert table["nas.local"] == 1


# ---------------------------------------------------------------------------
# Classification — one type, every reachable thing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("192.168.1.104", KIND_IPV4),
        ("10.0.0.1", KIND_IPV4),
        ("::1", KIND_IPV6),
        ("fe80::1", KIND_IPV6),
        ("2001:db8::1", KIND_IPV6),
        ("AA:BB:CC:DD:EE:FF", KIND_MAC),
        ("aa-bb-cc-dd-ee-ff", KIND_MAC),
        ("aabbccddeeff", KIND_MAC),
        ("tplogin.cn", KIND_HOSTNAME),
        ("localhost", KIND_HOSTNAME),
        ("arch-server-main", KIND_HOSTNAME),
    ],
)
def test_fqdn_classifies_what_it_names(value, kind):
    assert FQDN(value).kind == kind


def test_fqdn_reports_an_empty_value_as_unknown():
    assert FQDN("").kind == KIND_UNKNOWN
    assert FQDN("   ").kind == KIND_UNKNOWN


@pytest.mark.parametrize(
    ("value", "attribute"),
    [
        ("192.168.1.1", "is_ipv4"),
        ("fe80::1", "is_ipv6"),
        ("aa:bb:cc:dd:ee:ff", "is_mac"),
        ("nas.local", "is_hostname"),
    ],
)
def test_fqdn_exposes_kind_predicates(value, attribute):
    assert getattr(FQDN(value), attribute) is True


def test_fqdn_predicates_are_mutually_exclusive():
    endpoint = FQDN("192.168.1.1")

    assert endpoint.is_ipv4 and not endpoint.is_ipv6
    assert not endpoint.is_mac and not endpoint.is_hostname


# ---------------------------------------------------------------------------
# MAC addresses get an identity of their own
# ---------------------------------------------------------------------------
def test_fqdn_normalises_a_mac():
    assert FQDN("AA-BB-CC-DD-EE-FF").value == "aa:bb:cc:dd:ee:ff"
    assert str(FQDN("AABBCCDDEEFF")) == "aa:bb:cc:dd:ee:ff"


def test_fqdn_keeps_ipv4_and_hostnames_verbatim():
    assert FQDN("192.168.1.104").value == "192.168.1.104"
    assert FQDN("tplogin.cn").value == "tplogin.cn"


def test_fqdn_recognises_a_locally_administered_mac():
    """The locally-administered bit is how a private/derived MAC is spotted."""
    assert FQDN("02:00:5e:00:00:01").is_locally_administered is True
    assert FQDN("a8:13:06:f9:91:3e").is_locally_administered is False


# ---------------------------------------------------------------------------
# The polymorphism that makes expansion possible
# ---------------------------------------------------------------------------
def test_mac_derived_fqdn_is_deterministic():
    """The same MAC must always derive the same sibling address.

    That determinism is what lets two runs — and two fetchers — agree on the
    identity of a host discovered a second way.
    """
    first = FQDN.from_mac("aa:bb:cc:dd:ee:ff")
    second = FQDN.from_mac("AA-BB-CC-DD-EE-FF")

    assert first == second
    assert first.is_ipv4


def test_mac_derived_fqdn_differs_per_offset():
    mac = "aa:bb:cc:dd:ee:ff"

    assert FQDN.from_mac(mac, offset=0) != FQDN.from_mac(mac, offset=1)


def test_mac_derived_fqdn_stays_inside_the_reserved_range():
    """A derived address must never collide with a real DHCP-assigned host."""
    for offset in range(8):
        address = FQDN.from_mac("a8:13:06:f9:91:3e", offset=offset)

        assert address.is_ipv4
        assert address.value.startswith("192.0.2."), address.value


def test_apply_offset_moves_an_ipv4_endpoint():
    assert FQDN("192.168.1.10").apply_offset(5) == "192.168.1.15"


def test_apply_offset_wraps_within_the_subnet_tail():
    """A host part that would overflow wraps instead of leaking into the net."""
    moved = FQDN("192.168.1.250").apply_offset(10)

    assert moved.is_ipv4
    assert moved.value.startswith("192.168.1.")


def test_apply_offset_rejects_a_mac_endpoint():
    """A MAC has no arithmetic; asking for one is a bug, not a silent no-op."""
    with pytest.raises(ValueError, match="mac"):
        FQDN("aa:bb:cc:dd:ee:ff").apply_offset(1)


def test_apply_offset_rejects_a_hostname_endpoint():
    with pytest.raises(ValueError, match="hostname"):
        FQDN("tplogin.cn").apply_offset(1)


def test_apply_offset_is_a_no_op_for_zero():
    assert FQDN("192.168.1.10").apply_offset(0) == "192.168.1.10"


def test_fqdn_resolves_ipv6_equality_across_spellings():
    """Two spellings of one address are one endpoint."""
    assert FQDN("2001:0db8:0000:0000:0000:0000:0000:0001") == FQDN("2001:db8::1")


# ---------------------------------------------------------------------------
# SSH hop chains — the multi-hop spelling of the same polymorphism
# ---------------------------------------------------------------------------
def test_multi_hop_fqdn_is_recognised_as_a_hostname_chain():
    hop = FQDN("arch-server-main>arch-n551jw")

    assert hop.is_hop_chain is True
    assert hop.hops == ("arch-server-main", "arch-n551jw")


def test_single_endpoint_is_not_a_hop_chain():
    assert FQDN("arch-server-main").is_hop_chain is False
    assert FQDN("arch-server-main").hops == ("arch-server-main",)


def test_hop_chain_exposes_its_final_destination():
    assert FQDN("bastion>jump>target").destination == "target"
    assert FQDN("bastion>jump>target").origin == "bastion"


def test_hop_chain_strips_whitespace_around_hops():
    assert FQDN(" bastion > jump ").hops == ("bastion", "jump")
