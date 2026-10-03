"""Tests for :mod:`my_lan_prober.expanders`.

``design.md`` § 7 stops at "a fetcher returns a table".  An **expander** is the
other half: a fetcher that consumes the tables *other* fetchers produced and
returns a strictly bigger one, by reaching the same hosts a second way.

The polymorphism that makes this coherent lives in ``fqdn``: a MAC, an IPv4
address, an IPv6 address, a domain name and a multi-hop SSH path are all
"something the computer can reach", so a table can hold a host it learned about
by address *and* by MAC identity, and a hop chain can be walked from any of
them.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.expanders import (
    ArpTableExpander,
    SSHArpTableExpander,
    SSHHopExpander,
    TableUnion,
)
from my_lan_prober.fetchers import ARPTableFetcher

# ---------------------------------------------------------------------------
# Fixtures / stubs
# ---------------------------------------------------------------------------
ARP_FRAME = pd.DataFrame(
    [
        {"ip": "192.168.1.1", "mac_address": "48:5f:08:9b:22:c5", "mode": "arp"},
        {"ip": "192.168.1.104", "mac_address": "08:62:66:b4:2c:d2", "mode": "arp"},
    ]
)


class StubFetcher(ARPTableFetcher):
    def __init__(self, frame=None, error=None):
        self._frame = ARP_FRAME if frame is None else frame
        self._error = error
        self.calls = 0

    def iptable(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._frame.copy()


class PrefixExpander(ArpTableExpander):
    """Concrete expander for the abstract-contract tests.

    Expansion rule: every upstream row is also reachable at its address + 100,
    with the same MAC.  Deliberately trivial so the *contract* is what is
    under test, not the rule.
    """

    def expand(self, frame: pd.DataFrame) -> pd.DataFrame:
        extra = frame.copy()
        extra["ip"] = [f"10.0.0.{100 + index}" for index in range(len(extra))]
        extra["mode"] = "expanded"
        return extra


# ---------------------------------------------------------------------------
# The abstract contract
# ---------------------------------------------------------------------------
def test_arp_table_expander_is_abstract():
    with pytest.raises(TypeError):
        ArpTableExpander()  # type: ignore[abstract]


def test_arp_table_expander_is_a_fetcher():
    """An expander composes with ``>>`` exactly like any other source."""
    assert issubclass(ArpTableExpander, ARPTableFetcher)


def test_expander_requires_an_expand_rule():
    class Incomplete(ArpTableExpander):
        pass

    with pytest.raises(TypeError):
        Incomplete()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# It really returns a *bigger* table
# ---------------------------------------------------------------------------
def test_expander_returns_more_rows_than_its_upstream():
    upstream = StubFetcher()
    expander = PrefixExpander(upstream)

    frame = expander.iptable()

    assert len(frame) > len(ARP_FRAME)


def test_expander_keeps_every_upstream_row():
    """Expansion adds; it never replaces what was already known."""
    frame = PrefixExpander(StubFetcher()).iptable()

    assert {"192.168.1.1", "192.168.1.104"} <= set(frame["ip"])


def test_expander_accepts_a_list_of_upstream_fetchers():
    """The abstraction is "a list of ArpTableFetcher results", literally."""
    expander = PrefixExpander([StubFetcher(), StubFetcher()])

    assert len(expander.upstream) == 2


def test_expander_merges_every_upstream_table():
    first = StubFetcher(pd.DataFrame([{"ip": "10.1.1.1", "mode": "arp"}]))
    second = StubFetcher(pd.DataFrame([{"ip": "10.2.2.1", "mode": "arp"}]))

    frame = PrefixExpander([first, second]).iptable()

    assert {"10.1.1.1", "10.2.2.1"} <= set(frame["ip"])


def test_expander_accepts_a_bare_fetcher():
    expander = PrefixExpander(StubFetcher())

    assert len(expander.upstream) == 1


def test_expander_rejects_a_non_fetcher_upstream():
    with pytest.raises(TypeError, match="ARPTableFetcher"):
        PrefixExpander(["not a fetcher"])


def test_expander_tolerates_an_upstream_that_raises():
    """One broken upstream must not lose the others."""
    good = StubFetcher(pd.DataFrame([{"ip": "10.1.1.1", "mode": "arp"}]))
    bad = StubFetcher(error=RuntimeError("router unreachable"))

    frame = PrefixExpander([bad, good]).iptable()

    assert "10.1.1.1" in set(frame["ip"])


def test_expander_survives_every_upstream_failing():
    bad = StubFetcher(error=RuntimeError("a"))
    worse = StubFetcher(error=RuntimeError("b"))

    frame = PrefixExpander([bad, worse]).iptable()

    assert frame.empty
    assert "ip" in frame.columns


def test_expander_works_with_an_empty_upstream_table():
    empty = StubFetcher(pd.DataFrame(columns=["ip", "mac_address", "mode"]))

    frame = PrefixExpander(empty).iptable()

    assert frame.empty


# ---------------------------------------------------------------------------
# Provenance — where a row came from is part of the row
# ---------------------------------------------------------------------------
def test_every_row_records_the_source_that_produced_it():
    """Provenance survives the merge, and distinguishes derived rows."""
    frame = PrefixExpander(StubFetcher()).iptable()

    assert frame[frame["ip"] == "192.168.1.1"].iloc[0]["source"] == "StubFetcher"
    assert frame[frame["ip"] == "10.0.0.100"].iloc[0]["source"] == "PrefixExpander"


def test_upstream_rows_keep_their_own_source_label():
    upstream = StubFetcher()

    frame = PrefixExpander(upstream).iptable()

    row = frame[frame["ip"] == "192.168.1.1"].iloc[0]
    assert row["source"] == "StubFetcher"


def test_expander_records_the_depth_of_the_expansion():
    """Expanded rows carry the depth they were discovered at."""
    frame = PrefixExpander(StubFetcher()).iptable()

    assert frame[frame["ip"] == "10.0.0.100"].iloc[0]["depth"] == 1
    assert frame[frame["ip"] == "192.168.1.1"].iloc[0]["depth"] == 0


def test_expander_deduplicates_rows_it_already_had():
    """Expanding a table into itself must not double every host."""
    expander = PrefixExpander(StubFetcher())

    frame = expander.iptable()

    assert len(frame) == len(frame.drop_duplicates(subset=["ip", "mac_address"]))


# ---------------------------------------------------------------------------
# Chaining — an expander is a fetcher, so expanders compose
# ---------------------------------------------------------------------------
def test_expanders_chain_with_the_shift_operator():
    left = PrefixExpander(StubFetcher())
    right = PrefixExpander(StubFetcher())

    chain = left >> right

    assert chain.iptable() is not None


def test_expander_is_available_iff_any_upstream_is():
    class Unavailable(StubFetcher):
        def available(self):
            return False

    assert PrefixExpander(Unavailable()).available() is False
    assert PrefixExpander([Unavailable(), StubFetcher()]).available() is True


# ---------------------------------------------------------------------------
# TableUnion — the merged "all fetchers" table
# ---------------------------------------------------------------------------
def test_table_union_merges_rows_from_every_fetcher():
    first = StubFetcher(pd.DataFrame([{"ip": "10.1.1.1", "mode": "arp"}]))
    second = StubFetcher(pd.DataFrame([{"ip": "10.2.2.1", "mode": "dns"}]))

    frame = TableUnion([first, second]).iptable()

    assert set(frame["ip"]) == {"10.1.1.1", "10.2.2.1"}


def test_table_union_deduplicates_the_same_host_seen_twice():
    """Two sources seeing one host is one host, enriched — not two rows."""
    from_dns = StubFetcher(pd.DataFrame([{"ip": "192.168.1.104", "mode": "dns"}]))
    from_arp = StubFetcher(
        pd.DataFrame([{"ip": "192.168.1.104", "mac_address": "08:62:66:b4:2c:d2", "mode": "arp"}])
    )

    frame = TableUnion([from_dns, from_arp]).iptable()

    assert len(frame) == 1
    assert frame.iloc[0]["mac_address"] == "08:62:66:b4:2c:d2"


def test_table_union_keeps_a_mac_equal_host_from_collapsing_wrongly():
    """Same IP, different MAC is a real conflict: both are kept, flagged."""
    first = StubFetcher(
        pd.DataFrame([{"ip": "192.168.1.9", "mac_address": "aa:aa:aa:aa:aa:aa", "mode": "arp"}])
    )
    second = StubFetcher(
        pd.DataFrame([{"ip": "192.168.1.9", "mac_address": "bb:bb:bb:bb:bb:bb", "mode": "arp"}])
    )

    frame = TableUnion([first, second]).iptable()

    assert len(frame) == 2


def test_table_union_reports_which_sources_contributed():
    first = StubFetcher(pd.DataFrame([{"ip": "10.1.1.1", "mode": "arp"}]))
    second = StubFetcher(pd.DataFrame([{"ip": "10.2.2.1", "mode": "dns"}]))

    frame = TableUnion([first, second]).iptable()

    assert set(frame["source"]) == {"StubFetcher"}


def test_table_union_skips_an_unavailable_fetcher_without_calling_it():
    class Unavailable(StubFetcher):
        def available(self):
            return False

    missing = Unavailable(error=RuntimeError("must not be called"))
    good = StubFetcher(pd.DataFrame([{"ip": "10.1.1.1", "mode": "arp"}]))

    frame = TableUnion([missing, good]).iptable()

    assert missing.calls == 0
    assert list(frame["ip"]) == ["10.1.1.1"]


def test_table_union_raises_when_every_source_fails():
    bad = StubFetcher(error=RuntimeError("a"))
    worse = StubFetcher(error=RuntimeError("b"))

    with pytest.raises(RuntimeError):
        TableUnion([bad, worse]).iptable()


def test_table_union_accepts_an_empty_fetcher_list():
    frame = TableUnion([]).iptable()

    assert frame.empty


# ---------------------------------------------------------------------------
# SSHArpTableExpander
# ---------------------------------------------------------------------------
KNOWN_HOSTS = """\
arch-server-main ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJ4XVupfSEo1QMhcRso155bgBU0GiNWGn/mQ
arch-n551jw ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1jeFkFwfsOTULuPK0AC+FUbBWmTizIGJt
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJ
101.43.133.207 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJNOkBa4IQv7DMrFOHpJoKcCP53BqiuBvWUu
|1|FgZ8p1s= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC70AIVcOd3+M2ZwbUkSU02MWow5w3whUv
"""


def test_known_hosts_parsing_returns_every_named_host(tmp_path):
    path = tmp_path / "known_hosts"
    path.write_text(KNOWN_HOSTS, encoding="utf-8")

    expander = SSHArpTableExpander(StubFetcher(), known_hosts=path)

    assert "arch-server-main" in expander.known_hosts()
    assert "arch-n551jw" in expander.known_hosts()


def test_known_hosts_parsing_drops_hashed_entries(tmp_path):
    """A hashed host is unreadable by design; guessing is worse than skipping."""
    path = tmp_path / "known_hosts"
    path.write_text(KNOWN_HOSTS, encoding="utf-8")

    hosts = SSHArpTableExpander(StubFetcher(), known_hosts=path).known_hosts()

    assert not any(host.startswith("|1|") for host in hosts)


def test_known_hosts_parsing_expands_comma_separated_aliases(tmp_path):
    path = tmp_path / "known_hosts"
    path.write_text("bastion,10.0.0.1 ssh-ed25519 AAAA\n", encoding="utf-8")

    hosts = SSHArpTableExpander(StubFetcher(), known_hosts=path).known_hosts()

    assert hosts == ["bastion", "10.0.0.1"]


def test_known_hosts_parsing_handles_a_missing_file(tmp_path):
    expander = SSHArpTableExpander(StubFetcher(), known_hosts=tmp_path / "nope")

    assert expander.known_hosts() == []


def test_ssh_expander_probes_the_configured_hop():
    """The named hop is the door; the upstream table says who is behind it."""
    probed = []

    def fake_probe(host, command, **kwargs):
        probed.append((host, command))
        if host == "arch-server-main":
            return "192.168.2.5  0x1  0x2  02:00:5e:00:00:01  *  eth0\n"
        return ""

    frame = SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=fake_probe, enabled=True, max_depth=1
    ).iptable()

    assert "192.168.2.5" in set(frame["ip"])
    assert {host for host, _command in probed} == {"arch-server-main"}


def test_ssh_expander_probes_every_upstream_ip_through_ssh():
    """With enough depth, the hosts the upstream table found are probed too."""
    probed = []

    def fake_probe(host, command, **kwargs):
        probed.append(host)
        return ""

    SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=fake_probe, enabled=True, max_depth=2
    ).iptable()

    assert {"arch-server-main", "192.168.1.1", "192.168.1.104"} <= set(probed)


def test_ssh_expander_reports_the_hop_as_provenance():
    """The row says which machine it was seen from — the configured hop first.

    The upstream table's own hosts are probed too (that is the expansion), so
    a host several probes found accumulates every `via` that saw it.
    """

    def fake_probe(host, command, **kwargs):
        return "192.168.2.5  0x1  0x2  02:00:5e:00:00:01  *  eth0\n"

    frame = SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=fake_probe, enabled=True, max_depth=1
    ).iptable()

    row = frame[frame["ip"] == "192.168.2.5"].iloc[0]
    assert row["via"] == "arch-server-main"


def test_ssh_expander_is_unavailable_without_a_hop():
    assert SSHArpTableExpander(StubFetcher(), hop=None).available() is False


def test_ssh_expander_reads_the_hop_from_the_environment(monkeypatch):
    monkeypatch.setenv("SSH_HOP", "arch-server-main")

    expander = SSHArpTableExpander(StubFetcher(), enabled=True)
    monkeypatch.setattr(expander, "_probe", lambda host, command=None, **kwargs: "")

    assert expander.hop == "arch-server-main"
    assert expander.available() is True


def test_ssh_expander_survives_an_ssh_failure():
    """An unreachable hop degrades to the upstream table, not to nothing."""

    def broken_probe(host, command, **kwargs):
        raise OSError("connection refused")

    frame = SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=broken_probe, enabled=True
    ).iptable()

    assert {"192.168.1.1", "192.168.1.104"} <= set(frame["ip"])


def test_ssh_expander_recurses_into_hosts_it_discovers():
    """The upstream IPs are probed *and* so are the hosts those probes reveal."""
    calls = []

    def fake_probe(host, command, **kwargs):
        calls.append(host)
        if host == "arch-server-main":
            return "192.168.1.104  0x1  0x2  08:62:66:b4:2c:d2  *  eth0\n"
        if host == "192.168.1.104":
            return "192.168.3.7  0x1  0x2  00:11:22:33:44:55  *  eth0\n"
        return ""

    frame = SSHArpTableExpander(
        StubFetcher(),
        hop="arch-server-main",
        probe=fake_probe,
        enabled=True,
        max_depth=2,
    ).iptable()

    assert "192.168.3.7" in set(frame["ip"])
    assert calls.count("arch-server-main") == 1


def test_ssh_expander_stops_at_the_depth_limit():
    """A cycle between two hops must terminate, not spin forever."""

    def fake_probe(host, command, **kwargs):
        return "10.0.0.9  0x1  0x2  02:00:5e:00:00:02  *  eth0\n"

    frame = SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=fake_probe, enabled=True, max_depth=1
    ).iptable()

    assert "10.0.0.9" in set(frame["ip"])


def test_ssh_expander_is_disabled_by_default_off_the_command_line():
    """Probing hosts over SSH is invasive; it must be opt-in."""
    assert SSHArpTableExpander(StubFetcher(), hop="arch-server-main").enabled is False


def test_ssh_expander_uses_asyncssh_by_default(monkeypatch):
    """The default probe is a real ``asyncssh`` run, not a stub."""
    asyncssh = pytest.importorskip(
        "asyncssh", reason="asyncssh is an optional extra (`uv sync --extra ssh`)"
    )
    captured = {}

    class FakeConnection:
        async def run(self, command, **kwargs):
            captured["command"] = command

            class Result:
                stdout = "192.168.2.5  0x1  0x2  02:00:5e:00:00:01  *  eth0\n"

            return Result()

    class FakeConnect:
        def __init__(self, *args, **kwargs):
            captured["target"] = args[0] if args else kwargs.get("host")

        async def __aenter__(self):
            return FakeConnection()

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(asyncssh, "connect", lambda *a, **k: FakeConnect(*a, **k))

    expander = SSHArpTableExpander(StubFetcher(), hop="arch-server-main", enabled=True)
    output = expander.ssm_probe("arch-server-main")

    assert "192.168.2.5" in output


def test_ssh_expander_asks_for_the_neighbour_table():
    """The remote command must be the same one the local fetchers parse."""
    commands = []

    def fake_probe(host, command, **kwargs):
        commands.append(command)
        return ""

    SSHArpTableExpander(
        StubFetcher(), hop="arch-server-main", probe=fake_probe, enabled=True
    ).iptable()

    assert any("arp" in command or "neigh" in command for command in commands)


# ---------------------------------------------------------------------------
# SSHHopExpander — walking FQDN hop chains
# ---------------------------------------------------------------------------
def test_hop_expander_walks_each_hop():
    visited = []

    class Fetcher(StubFetcher):
        def __init__(self, name, frame):
            super().__init__(frame)
            self.name = name

    frame = SSHHopExpander(
        ["bastion", "jump", "target"],
        fetcher_for=lambda hop: (
            visited.append(hop) or Fetcher(hop, pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}]))
        ),
    ).iptable()

    assert visited == ["bastion", "jump", "target"]
    assert "10.0.0.1" in set(frame["ip"])


def test_hop_expander_notes_which_hop_each_row_came_from():
    frame = SSHHopExpander(
        ["bastion", "target"],
        fetcher_for=lambda hop: StubFetcher(
            pd.DataFrame([{"ip": f"10.0.0.{len(hop)}", "mode": "arp"}])
        ),
    ).iptable()

    assert set(frame["via"]) == {"bastion", "target"}


def test_hop_expander_records_every_hop_a_shared_host_was_seen_from():
    """Two hops reporting the same host is one host, reachable two ways.

    Collapsing them is right — it *is* one machine — but the row must still
    say that both hops can see it, which is the whole reason for walking the
    chain in the first place.
    """
    frame = SSHHopExpander(
        ["bastion", "target"],
        fetcher_for=lambda hop: StubFetcher(pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}])),
    ).iptable()

    assert len(frame) == 1
    assert set(str(frame.iloc[0]["via"]).split(",")) == {"bastion", "target"}


def test_hop_expander_survives_a_hop_that_fails():
    def fetcher_for(hop):
        if hop == "jump":
            return StubFetcher(error=RuntimeError("hop down"))
        return StubFetcher(pd.DataFrame([{"ip": f"10.0.0.{len(hop)}", "mode": "arp"}]))

    frame = SSHHopExpander(["bastion", "jump", "target"], fetcher_for=fetcher_for).iptable()

    assert set(frame["via"]) == {"bastion", "target"}
    assert len(frame) == 2
