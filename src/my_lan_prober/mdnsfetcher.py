"""mDNS discovery as an ARP source.

Every other source in this package answers one of two halves of the question:
DNS and the hosts file turn a *name* into an address, and the neighbour tables
turn an *address* into a MAC.  mDNS answers both at once — it is the only
protocol on a LAN that volunteers "this address is called that" — which is
precisely what an :class:`~my_lan_prober.fqdn.FQDN` is for.

It is also the slowest source by a wide margin, because it works by asking and
then *waiting* for machines to answer.  So it is deferred (a negative priority
puts it behind every local read) and it never raises: a LAN with no mDNS
traffic is completely normal, and an empty table is the honest result.

``zeroconf`` is an optional extra.  This module imports it lazily and reports
itself unavailable without it, so selecting ``mdns`` on a machine that does not
have the extra degrades instead of failing.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable, List, Optional, Sequence

import pandas as pd

from .fetchers import REQUIRED_COLUMNS, ARPTableFetcher

log = logging.getLogger(__name__)

__all__ = ["MdnsFetcher", "parse_service_info", "SUGGESTED_SERVICE_TYPES"]

#: Service types browsed by default.
#:
#: A discovery pass only hears about service types somebody asked for, so this
#: list is what decides how much of the LAN is visible.  It covers the things
#: that actually turn up on a home or office network: files, printing, media,
#: remote login, and the catch-all device-info record.
SUGGESTED_SERVICE_TYPES: Sequence[str] = (
    "_services._dns-sd._udp.local.",  # the directory of every advertised type
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_esphomelib._tcp.local.",
    "_http._udp.local.",
)

#: How long to listen, in seconds.  Long enough for a sleepy device to answer,
#: short enough not to dominate a scan.
DEFAULT_TIMEOUT = 3.0


def _empty_table() -> pd.DataFrame:
    return pd.DataFrame(columns=[*REQUIRED_COLUMNS, "mac_address", "host", "fqdn", "source"])


def _strip_dot(value: Any) -> str:
    """mDNS names are fully qualified; the trailing dot is not part of a name."""
    text = str(value or "").strip()
    return text[:-1] if text.endswith(".") else text


def _service_label(name: str) -> str:
    """``nas._http._tcp.local.`` → ``nas``.

    The instance label is the human name of the machine, and it is worth
    keeping as an alias even though it is not the hostname: a user looking at
    the table recognises "nas" more readily than "nas.local".
    """
    label = _strip_dot(name)
    return label.split(".")[0] if label else ""


def _addresses_of(info: Any) -> List[str]:
    """Every address an mDNS answer carries, in both families.

    ``parsed_scoped_addresses`` is preferred when present because it keeps the
    IPv6 scope id, which ``fe80::`` addresses need to be usable at all.
    """
    for attribute in ("parsed_scoped_addresses", "parsed_addresses"):
        getter = getattr(info, attribute, None)
        if callable(getter):
            try:
                values = [str(value) for value in getter() if value]
            except Exception as exc:
                log.debug("mDNS %s() failed: %s", attribute, exc)
                continue
            if values:
                return values
    return []


def parse_service_info(infos: Iterable[Any]) -> pd.DataFrame:
    """Turn zeroconf answers into an address table.

    One row per *address*, because a dual-stack machine answers on both
    families and both are separately reachable.  Repeated addresses collapse:
    a host advertising three services is still one host.
    """
    rows: List[dict] = []
    seen: set = set()

    for info in infos:
        addresses = _addresses_of(info)
        if not addresses:
            continue

        hostname = _strip_dot(getattr(info, "server", None) or getattr(info, "name", None) or "")
        alias = _service_label(getattr(info, "name", "") or "")
        aliases = [alias] if alias and alias != hostname else []
        for extra in getattr(info, "aliases", None) or []:
            cleaned = _strip_dot(extra)
            if cleaned and cleaned != hostname and cleaned not in aliases:
                aliases.append(cleaned)

        for address in addresses:
            if address in seen:
                continue
            seen.add(address)
            rows.append(
                {
                    "ip": address,
                    "mac_address": None,
                    "mode": "mdns",
                    "source": "mdns",
                    "host": hostname or address,
                    "fqdn": hostname or address,
                    "aliases": ",".join(aliases),
                    "service": _strip_dot(getattr(info, "name", "") or ""),
                    "port": getattr(info, "port", None),
                }
            )

    if not rows:
        return _empty_table()
    return pd.DataFrame(rows)


class MdnsFetcher(ARPTableFetcher):
    """Discover local hosts, and the names they answer to, over mDNS.

    ``browse`` is injectable so the scanning logic is testable without
    multicast, and so a caller can substitute a discovery source of their own.
    """

    #: Discovery waits on the network; it must not delay the local reads.
    priority = -1

    def __init__(
        self,
        service_types: Optional[Sequence[str]] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        browse: Optional[Callable[[float], Iterable[Any]]] = None,
    ) -> None:
        self.service_types = list(service_types or SUGGESTED_SERVICE_TYPES)
        self.timeout = max(0.1, float(timeout))
        self._browse = browse

    def available(self) -> bool:
        """Whether ``zeroconf`` can be imported right now."""
        if self._browse is not None:
            return True
        try:
            __import__("zeroconf")
        except ImportError:
            return False
        return True

    def iptable(self) -> pd.DataFrame:
        try:
            infos = self.browse(self.timeout)
        except Exception as exc:
            log.warning("mDNS discovery failed: %s", exc)
            return _empty_table()

        frame = parse_service_info(infos)
        if frame.empty:
            log.info("mDNS discovery found nothing in %.1fs", self.timeout)
        else:
            log.info("mDNS discovery found %d address(es)", len(frame))
        return frame

    def browse(self, timeout: float) -> List[Any]:
        """Collect mDNS answers for ``timeout`` seconds.

        Imported here rather than at module scope because ``zeroconf`` is an
        extra: a module-level import would make ``my_lan_prober`` itself
        unimportable without it.
        """
        if self._browse is not None:
            return list(self._browse(timeout))
        return _zeroconf_browse(self.service_types, timeout)


def _zeroconf_browse(service_types: Sequence[str], timeout: float) -> List[Any]:  # pragma: no cover
    """Browse every service type with zeroconf, collecting the answers.

    Not unit-tested: it needs real multicast traffic.  The scanning and parsing
    logic above it is what the tests drive, through an injected ``browse``.
    """
    import time

    from zeroconf import ServiceBrowser, Zeroconf

    found: List[Any] = []

    class Listener:
        def add_service(self, zc, service_type, name):
            try:
                info = zc.get_service_info(service_type, name, timeout=int(timeout * 1000))
            except Exception as exc:
                log.debug("could not resolve %s: %s", name, exc)
                return
            if info is not None:
                found.append(info)

        def update_service(self, zc, service_type, name):
            self.add_service(zc, service_type, name)

        def remove_service(self, zc, service_type, name):
            return None

    zeroconf = Zeroconf()
    try:
        browsers = [
            ServiceBrowser(zeroconf, service_type, Listener()) for service_type in service_types
        ]
        time.sleep(timeout)
        del browsers
    finally:
        zeroconf.close()
    return found
