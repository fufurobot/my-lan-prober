"""Tests for name-resolution ARP sources: the hosts file, and DNS.

``design.md`` § 7 treats ARP sources as "anything that can hand you an
``ip``/``mac`` table".  A hosts file and a resolver both qualify: they turn a
*name* into an address, which is exactly what the initial ``localhost`` /
``tplogin.cn`` step of ``tplogin-minimal.py`` did by hand before probing ports.

Both sources must be pure enough to test offline: the parsing and the
``python_hosts`` read are separate from any network call.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.dnsfetchers import (
    DnsTableFetcher,
    HostsFileFetcher,
    ResolvedHostFetcher,
    parse_hosts_entries,
)

# ---------------------------------------------------------------------------
# The hosts file — "the initial (localhost, ...) step as a fetcher"
# ---------------------------------------------------------------------------
HOSTS_TEXT = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# localhost name resolution is handled within DNS itself.
#\t127.0.0.1       localhost
#\t::1             localhost

127.0.0.1     localhost
::1           localhost ip6-localhost ip6-loopback
127.0.1.1     arch-server-main arch-server
192.168.1.104 arch-n551jw.localdomain arch-n551jw
"""


class FakeEntry:
    """Stand-in for ``python_hosts.HostsEntry``."""

    def __init__(self, entry_type, address, names):
        self.entry_type = entry_type
        self.address = address
        self.names = names


def test_parse_hosts_entries_keeps_ipv4_mappings():
    frame = parse_hosts_entries(
        [FakeEntry("ipv4", "192.168.1.104", ["arch-n551jw.localdomain", "arch-n551jw"])]
    )

    assert list(frame["ip"]) == ["192.168.1.104"]
    assert frame.iloc[0]["mac_address"] is None
    assert frame.iloc[0]["mode"] == "hosts"


def test_parse_hosts_entries_keeps_ipv6_mappings():
    """IPv6 is a first-class endpoint, not a parsing accident."""
    frame = parse_hosts_entries([FakeEntry("ipv6", "fe80::1", ["nas6"])])

    assert list(frame["ip"]) == ["fe80::1"]
    assert frame.iloc[0]["fqdn"] == "nas6"


def test_parse_hosts_entries_uses_the_first_name_as_the_hostname():
    frame = parse_hosts_entries(
        [FakeEntry("ipv4", "192.168.1.104", ["arch-n551jw.localdomain", "arch-n551jw"])]
    )

    assert frame.iloc[0]["host"] == "arch-n551jw.localdomain"
    assert frame.iloc[0]["aliases"] == "arch-n551jw"


def test_parse_hosts_entries_skips_comments_and_blanks():
    frame = parse_hosts_entries([FakeEntry("comment", None, None), FakeEntry("blank", None, None)])

    assert frame.empty
    assert "ip" in frame.columns


def test_parse_hosts_entries_marks_the_source_for_provenance():
    frame = parse_hosts_entries([FakeEntry("ipv4", "127.0.0.1", ["localhost"])])

    assert frame.iloc[0]["source"] == "hosts"


def test_hosts_fetcher_reads_the_real_hosts_file(monkeypatch, tmp_path):
    """The fetcher goes through ``python_hosts``, not a hand-rolled parser."""
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(HOSTS_TEXT, encoding="utf-8")

    frame = HostsFileFetcher(path=hosts_file).iptable()

    ips = set(frame["ip"])
    assert "192.168.1.104" in ips
    assert "127.0.0.1" in ips


def test_hosts_fetcher_tolerates_a_hosts_file_with_no_mappings(tmp_path):
    """A stock Windows hosts file is *all* comments — that is not a failure."""
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("# nothing here\n\n# 127.0.0.1 localhost\n", encoding="utf-8")

    frame = HostsFileFetcher(path=hosts_file).iptable()

    assert frame.empty
    assert "ip" in frame.columns


def test_hosts_fetcher_is_available_even_when_the_file_is_missing(tmp_path):
    """A missing hosts file yields no rows, not an exception."""
    frame = HostsFileFetcher(path=tmp_path / "does-not-exist").iptable()

    assert frame.empty


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
class FakeResolver:
    """Minimal ``dns.resolver.Resolver`` stand-in: name → list of addresses."""

    def __init__(self, answers):
        self._answers = answers
        self.queried = []

    def resolve(self, name, rdtype=None, lifetime=None):
        self.queried.append((name, rdtype))

        class _Answer:
            def __init__(self, values):
                self._values = values

            def __iter__(self):
                return iter(self._values)

            def __len__(self):
                return len(self._values)

        if name not in self._answers:
            import dns.resolver

            raise dns.resolver.NXDOMAIN(name)
        values = [_Record(value) for value in self._answers[name] if _wants(rdtype, value)]
        if not values:
            import dns.resolver

            raise dns.resolver.NoAnswer(name)
        return _Answer(values)


class _Record:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value

    @property
    def address(self):
        return self._value


def _wants(rdtype, value):
    import dns.rdatatype

    is_v6 = ":" in value
    if rdtype == dns.rdatatype.A:
        return not is_v6
    if rdtype == dns.rdatatype.AAAA:
        return is_v6
    return True


def test_dns_fetcher_returns_one_row_per_address():
    resolver = FakeResolver({"nas.local": ["192.168.1.50", "fe80::50"]})
    fetcher = DnsTableFetcher(names=["nas.local"], resolver=resolver)

    frame = fetcher.iptable()

    assert set(frame["ip"]) == {"192.168.1.50", "fe80::50"}
    assert set(frame["mode"]) == {"dns"}


def test_dns_fetcher_carries_the_name_that_resolved():
    resolver = FakeResolver({"nas.local": ["192.168.1.50"]})

    frame = DnsTableFetcher(names=["nas.local"], resolver=resolver).iptable()

    assert frame.iloc[0]["host"] == "nas.local"
    assert frame.iloc[0]["fqdn"] == "nas.local"
    assert frame.iloc[0]["source"] == "dns"


def test_dns_fetcher_queries_both_address_families():
    """An A-only lookup silently loses the IPv6 half of the polymorphism."""
    resolver = FakeResolver({"nas.local": ["192.168.1.50"]})

    DnsTableFetcher(names=["nas.local"], resolver=resolver).iptable()

    queried = {rdtype for _name, rdtype in resolver.queried}
    import dns.rdatatype

    assert dns.rdatatype.A in queried
    assert dns.rdatatype.AAAA in queried


def test_dns_fetcher_drops_a_name_that_does_not_resolve():
    resolver = FakeResolver({"nas.local": ["192.168.1.50"]})
    fetcher = DnsTableFetcher(names=["nas.local", "gone.local"], resolver=resolver)

    frame = fetcher.iptable()

    assert set(frame["host"]) == {"nas.local"}


def test_dns_fetcher_returns_an_empty_table_when_nothing_resolves():
    frame = DnsTableFetcher(names=["gone.local"], resolver=FakeResolver({})).iptable()

    assert frame.empty
    assert "ip" in frame.columns


def test_dns_fetcher_deduplicates_repeated_addresses():
    resolver = FakeResolver({"nas.local": ["192.168.1.50"], "nas": ["192.168.1.50"]})

    frame = DnsTableFetcher(names=["nas.local", "nas"], resolver=resolver).iptable()

    assert list(frame["ip"]) == ["192.168.1.50"]


def test_dns_fetcher_reports_itself_unavailable_without_dnspython(monkeypatch):
    """``dnspython`` is mandatory now, but the import stays guarded."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dns" or name.startswith("dns."):
            raise ImportError("no dnspython")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert DnsTableFetcher(names=["nas.local"]).available() is False


def test_dns_fetcher_is_available_with_dnspython_installed():
    assert DnsTableFetcher(names=["nas.local"]).available() is True


# ---------------------------------------------------------------------------
# The resolve-and-probe step, as a fetcher
# ---------------------------------------------------------------------------
def test_resolved_host_fetcher_expands_through_dns():
    """``localhost``/``tplogin.cn`` must come back as addresses, not names."""
    resolver = FakeResolver({"localhost": ["127.0.0.1"], "tplogin.cn": ["192.168.1.1"]})
    fetcher = ResolvedHostFetcher(names=["localhost", "tplogin.cn"], resolver=resolver)

    frame = fetcher.iptable()

    assert set(frame["ip"]) == {"127.0.0.1", "192.168.1.1"}


def test_resolved_host_fetcher_keeps_the_hostname_for_the_report():
    resolver = FakeResolver({"tplogin.cn": ["192.168.1.1"]})

    frame = ResolvedHostFetcher(names=["tplogin.cn"], resolver=resolver).iptable()

    assert frame.iloc[0]["host"] == "tplogin.cn"
    assert frame.iloc[0]["mode"] == "resolved"


def test_resolved_host_fetcher_falls_back_to_the_stdlib(monkeypatch):
    """A machine with a broken resolver config still resolves ``localhost``."""

    class Broken:
        def resolve(self, name, rdtype=None, lifetime=None):
            raise RuntimeError("resolver is down")

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda name, port, *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ],
    )

    frame = ResolvedHostFetcher(names=["localhost"], resolver=Broken()).iptable()

    assert list(frame["ip"]) == ["127.0.0.1"]


def test_resolved_host_fetcher_drops_a_name_nothing_can_resolve(monkeypatch):
    class Broken:
        def resolve(self, name, rdtype=None, lifetime=None):
            raise RuntimeError("resolver is down")

    import socket

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror())
    )

    frame = ResolvedHostFetcher(names=["gone.local"], resolver=Broken()).iptable()

    assert frame.empty


def test_the_two_resolving_sources_agree_on_a_shape():
    """Merging them later requires the same columns from both."""
    resolver = FakeResolver({"nas.local": ["192.168.1.50"]})
    dns_frame = DnsTableFetcher(names=["nas.local"], resolver=resolver).iptable()
    resolved_frame = ResolvedHostFetcher(names=["nas.local"], resolver=resolver).iptable()

    assert set(dns_frame.columns) == set(resolved_frame.columns)
    assert {"ip", "mode"} <= set(dns_frame.columns)


def test_dns_fetcher_defaults_to_the_configured_resolve_hosts(monkeypatch):
    """Out of the box it must still mean ``tplogin.cn, localhost``."""
    from my_lan_prober.probes import RESOLVE_HOSTS

    fetcher = DnsTableFetcher(resolver=FakeResolver({}))

    assert list(fetcher.names) == list(RESOLVE_HOSTS)


def test_dns_fetcher_reads_the_names_from_the_environment(monkeypatch):
    monkeypatch.setenv("RESOLVE_HOSTS", "a.local, b.local")

    assert list(DnsTableFetcher(resolver=FakeResolver({})).names) == ["a.local", "b.local"]


# ---------------------------------------------------------------------------
# A MAC-carrying result is impossible from a resolver, and must not be faked
# ---------------------------------------------------------------------------
def test_dns_sources_leave_mac_address_empty():
    """No name service knows a MAC; inventing one would corrupt the merge."""
    resolver = FakeResolver({"nas.local": ["192.168.1.50"]})

    frame = DnsTableFetcher(names=["nas.local"], resolver=resolver).iptable()

    assert pd.isna(frame.iloc[0]["mac_address"])
