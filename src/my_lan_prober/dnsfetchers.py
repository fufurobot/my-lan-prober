"""Name-resolution ARP sources: the hosts file, and DNS.

``tplogin-minimal.py`` opened with a step that was never a fetcher::

    for hostname in RESOLVE_HOSTS:          # ["tplogin.cn", "localhost"]
        ip = socket.gethostbyname(hostname)
        ...probe it...

That step *is* an ARP source.  It takes a name and produces an address table,
which is exactly what ``design.md`` § 7 says a fetcher does — it was just
written inline, so nothing could compose with it, and the addresses it found
were probed but never joined to the lease table.

Three fetchers recover it:

:class:`ResolvedHostFetcher`
    the literal port of that loop: the configured names, resolved to whatever
    the system resolver says, in both address families.

:class:`DnsTableFetcher`
    the same thing through ``dnspython``, which is now a mandatory dependency.
    It queries ``A`` *and* ``AAAA`` — an A-only lookup silently loses the IPv6
    half of a dual-stack host — and it knows *why* a name failed, which
    ``socket.gethostbyname`` throws away.

:class:`HostsFileFetcher`
    the local hosts file, via ``python-hosts``.  On a stock Windows install
    this file is entirely comments, so it honestly returns an empty table
    rather than pretending a machine name is resolvable when it is not.
"""

from __future__ import annotations

import logging
import os
import socket
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence

import pandas as pd

from .fetchers import REQUIRED_COLUMNS, ARPTableFetcher
from .probes import RESOLVE_HOSTS

log = logging.getLogger(__name__)

__all__ = [
    "DnsTableFetcher",
    "HostsFileFetcher",
    "ResolvedHostFetcher",
    "parse_hosts_entries",
    "resolve_names",
    "DEFAULT_DNS_TIMEOUT",
]

#: Per-name resolver budget, in seconds.
DEFAULT_DNS_TIMEOUT = 5.0


def _empty_table() -> pd.DataFrame:
    return pd.DataFrame(columns=[*REQUIRED_COLUMNS, "mac_address", "host", "fqdn", "source"])


def _row(ip: str, *, host: str, mode: str, source: str) -> dict:
    """One resolved address, in the shape every other source produces."""
    return {
        "ip": ip,
        "mac_address": None,
        "mode": mode,
        # `host` is what the report calls the machine; `fqdn` is what was
        # resolved to reach it.  Keeping both is what lets a later expander
        # seed an SSH walk from a name rather than only from an address.
        "host": host,
        "fqdn": host,
        "source": source,
    }


def _looks_like_address(value: str) -> bool:
    """Whether a configured "name" is already an address.

    ``--resolve-host 192.168.1.1`` is a legitimate thing to ask for, and it is
    also the one case where no resolver is needed.
    """
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _dedupe(rows: Iterable[dict]) -> pd.DataFrame:
    """One row per address, first name to claim it wins."""
    seen = set()
    unique: List[dict] = []
    for row in rows:
        if row["ip"] in seen:
            continue
        seen.add(row["ip"])
        unique.append(row)
    if not unique:
        return _empty_table()
    return pd.DataFrame(unique)


# ---------------------------------------------------------------------------
# The hosts file
# ---------------------------------------------------------------------------
def parse_hosts_entries(entries: Iterable[Any]) -> pd.DataFrame:
    """Turn ``python_hosts`` entries into an address table.

    Both address families are kept: a hosts file is one of the few places a
    machine's IPv6 address is written down, and dropping it would make the
    "IPv6 is a first-class endpoint" claim false at the first source.

    Comments and blank lines carry no address and are skipped, as are entries
    with no name at all (an address alone is reachable but unnameable).
    """
    rows: List[dict] = []
    for entry in entries:
        entry_type = getattr(entry, "entry_type", None)
        if entry_type not in ("ipv4", "ipv6"):
            continue
        address = getattr(entry, "address", None)
        names = list(getattr(entry, "names", None) or [])
        if not address or not names:
            continue
        row = _row(str(address), host=str(names[0]), mode="hosts", source="hosts")
        row["aliases"] = ",".join(str(name) for name in names[1:])
        row["entry_type"] = entry_type
        rows.append(row)

    if not rows:
        frame = _empty_table()
        return frame
    return pd.DataFrame(rows)


def _module_available(name: str) -> bool:
    """Whether an optional dependency can be imported right now.

    A real ``import`` rather than ``importlib.util.find_spec``: ``find_spec``
    answers "is a file there", which is not the same question — it ignores a
    blocked import, a broken install, and a shadowing name.  The modules asked
    about here are small and already imported by the time anything calls this,
    so the import is free.
    """
    try:
        __import__(name)
    except ImportError:
        return False
    return True


class HostsFileFetcher(ARPTableFetcher):
    """Read the local hosts file as an address table.

    ``path`` is injectable so the parsing is testable without touching the
    machine's real hosts file, and so a caller can point at a container's
    ``/etc/hosts``.
    """

    def __init__(self, path: Any = None) -> None:
        self.path = Path(path) if path is not None else None

    def available(self) -> bool:
        """Available whenever ``python-hosts`` is importable.

        Deliberately not "the file exists": a missing hosts file is an empty
        table, not an unavailable source, and reporting it as unavailable would
        make the engine's diagnostics blame the wrong thing.
        """
        return _module_available("python_hosts")

    def iptable(self) -> pd.DataFrame:
        try:
            from python_hosts import Hosts
        except ImportError:  # pragma: no cover - guarded by available()
            log.warning("the hosts file source needs python-hosts: `uv add python-hosts`")
            return _empty_table()

        try:
            hosts = Hosts(path=str(self.path)) if self.path is not None else Hosts()
            return parse_hosts_entries(hosts.entries)
        except Exception as exc:
            log.warning("could not read the hosts file: %s", exc)
            return _empty_table()


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def resolve_names(
    names: Sequence[str],
    *,
    resolver: Any = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
) -> List[tuple]:
    """Resolve ``names`` to ``(name, address)`` pairs, in both families.

    Returns every address it can find and skips the ones it cannot: a name that
    does not resolve is missing *information*, not a failure of the scan, and
    raising here would abort a whole run over one stale entry.
    """
    resolved: List[tuple] = []
    dns_rdatatype = _rdatatypes()

    for name in names:
        name = str(name).strip()
        if not name:
            continue
        if _looks_like_address(name):
            resolved.append((name, name))
            continue

        if resolver is not None and dns_rdatatype is not None:
            for rdtype in dns_rdatatype:
                try:
                    answers = resolver.resolve(name, rdtype, lifetime=timeout)
                except Exception as exc:
                    log.debug("DNS %s lookup for %s failed: %s", rdtype, name, exc)
                    continue
                for answer in answers:
                    address = getattr(answer, "address", None) or str(answer)
                    resolved.append((name, str(address)))
            if any(resolved_name == name for resolved_name, _ in resolved):
                continue

        # Either there is no resolver, or it answered nothing: the system
        # resolver is the fallback, and on Windows it is the only one that
        # knows about the hosts file and the configured search suffixes.
        for address in _system_resolve(name):
            resolved.append((name, address))

    return resolved


def _rdatatypes() -> Optional[tuple]:
    """The two address families to query, or ``None`` without dnspython."""
    try:
        import dns.rdatatype
    except ImportError:  # pragma: no cover - guarded by available()
        return None
    return (dns.rdatatype.A, dns.rdatatype.AAAA)


def _system_resolve(name: str) -> List[str]:
    """Every address ``getaddrinfo`` knows for ``name``, deduplicated."""
    addresses: List[str] = []
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        log.debug("system resolution of %s failed: %s", name, exc)
        return addresses
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


class DnsTableFetcher(ARPTableFetcher):
    """Resolve names through ``dnspython``, in both address families.

    The names default to the configured ``RESOLVE_HOSTS`` (``tplogin.cn``,
    ``localhost``) so that the fetcher is the documented opening step of the
    scan rather than a new idea bolted beside it.
    """

    def __init__(
        self,
        names: Optional[Sequence[str]] = None,
        *,
        resolver: Any = None,
        timeout: float = DEFAULT_DNS_TIMEOUT,
    ) -> None:
        self.names = list(names) if names is not None else _configured_names()
        self.timeout = timeout
        self._resolver = resolver

    def resolver(self) -> Any:
        """The ``dns.resolver.Resolver`` to use, built on first use."""
        if self._resolver is None:
            import dns.resolver

            self._resolver = dns.resolver.Resolver()
        return self._resolver

    def available(self) -> bool:
        return _module_available("dns")

    def iptable(self) -> pd.DataFrame:
        active = self.resolver() if self.available() else None
        pairs = resolve_names(self.names, resolver=active, timeout=self.timeout)
        rows = [_row(address, host=name, mode="dns", source="dns") for name, address in pairs]
        if not rows:
            log.warning("DNS resolved none of: %s", ", ".join(self.names))
        return _dedupe(rows)


class ResolvedHostFetcher(ARPTableFetcher):
    """The original ``resolve and probe`` step, as a fetcher.

    Same job as :class:`DnsTableFetcher`, but it always consults the system
    resolver rather than a configured one — the behaviour ``tplogin-minimal.py``
    had, kept addressable for callers who want exactly that.
    """

    def __init__(self, names: Optional[Sequence[str]] = None, *, resolver: Any = None) -> None:
        self.names = list(names) if names is not None else _configured_names()
        self._resolver = resolver

    def available(self) -> bool:
        return True

    def iptable(self) -> pd.DataFrame:
        rows: List[dict] = []
        for name in self.names:
            name = str(name).strip()
            if not name:
                continue
            if _looks_like_address(name):
                rows.append(_row(name, host=name, mode="resolved", source="resolved"))
                continue

            addresses = self._resolve(name)
            for address in addresses:
                rows.append(_row(address, host=name, mode="resolved", source="resolved"))

            if not addresses:
                log.warning("could not resolve %s", name)

        return _dedupe(rows)

    def _resolve(self, name: str) -> List[str]:
        """Configured resolver first, then the system, then nothing."""
        addresses: List[str] = []
        if self._resolver is not None:
            for _name, address in resolve_names([name], resolver=self._resolver):
                if address not in addresses:
                    addresses.append(address)
        if not addresses:
            addresses = _system_resolve(name)
        return addresses


def _configured_names() -> List[str]:
    """The names to resolve: ``RESOLVE_HOSTS``, else the ``probes`` default."""
    raw = os.environ.get("RESOLVE_HOSTS", "").strip()
    if raw:
        return [name.strip() for name in raw.split(",") if name.strip()]
    return list(RESOLVE_HOSTS)
