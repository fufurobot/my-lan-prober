"""Tests for the merged-source behaviour of the engine.

The pipeline used to fetch **one** table and stop.  The user-visible change:
before a single port is probed, *every* implemented ARP source contributes its
rows, so a host known only to the hosts file, or only to DNS, or only to the
local neighbour table, is still probed.

These tests drive the real ``Engine.fetch_leases`` through the registry with
every network-touching source stubbed out.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.config import Config
from my_lan_prober.engine import Engine, build_fetcher

TPLOGIN_LEASES = pd.DataFrame(
    [
        {
            "host": "arch-n551jw",
            "mac_address": "08:62:66:b4:2c:d2",
            "ip_address": "192.168.1.104",
            "valid_time": "40:10:04",
            "mode": "dhcp",
            "ip": "192.168.1.104",
        }
    ]
)

LOCAL_ARP = pd.DataFrame([{"ip": "192.168.1.1", "mac_address": "48:5f:08:9b:22:c5", "mode": "arp"}])

DNS_ROWS = pd.DataFrame([{"ip": "127.0.0.1", "mac_address": None, "mode": "dns"}])

HOSTS_ROWS = pd.DataFrame([{"ip": "192.168.1.77", "mac_address": None, "mode": "hosts"}])


@pytest.fixture
def registry(monkeypatch):
    """A registry whose sources are all local, deterministic tables."""
    from my_lan_prober.registry import FetcherRegistry

    class Fake(Engine.__mro__[0]):  # placeholder to keep ruff quiet about shadowing
        pass

    class TableFetcher:
        def __init__(self, frame):
            self._frame = frame

        def iptable(self):
            return self._frame.copy()

        def available(self):
            return True

    built = FetcherRegistry()
    built.register("tplogin", lambda **kw: TableFetcher(TPLOGIN_LEASES))
    built.register("unix", lambda **kw: TableFetcher(LOCAL_ARP))
    built.register("windows", lambda **kw: TableFetcher(pd.DataFrame(columns=["ip", "mode"])))
    built.register("dns", lambda **kw: TableFetcher(DNS_ROWS))
    built.register("hosts", lambda **kw: TableFetcher(HOSTS_ROWS))
    built.register("resolved", lambda **kw: TableFetcher(pd.DataFrame(columns=["ip", "mode"])))
    built.register("openwrt", lambda **kw: TableFetcher(pd.DataFrame(columns=["ip", "mode"])))
    built.register("ssh", lambda **kw: TableFetcher(pd.DataFrame(columns=["ip", "mode"])))
    return built


@pytest.fixture
def config(tmp_path):
    return Config.resolve(["--output", str(tmp_path / "out.csv"), "--resolve-host", "localhost"])


class StubEngine(Engine):
    def ping(self, ip):
        return True

    def probe(self, ip, port):
        return None

    def resolve(self, hostname):
        return None


def test_engine_merges_every_selected_source(monkeypatch, config, registry):
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix,dns,hosts"

    frame = StubEngine(config).fetch_leases()

    assert {"192.168.1.104", "192.168.1.1", "127.0.0.1", "192.168.1.77"} <= set(frame["ip"])


def test_merged_table_is_bigger_than_any_single_source(monkeypatch, config, registry):
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix,dns,hosts"

    merged = StubEngine(config).fetch_leases()

    for single in (TPLOGIN_LEASES, LOCAL_ARP, DNS_ROWS, HOSTS_ROWS):
        assert len(merged) >= len(single)


def test_all_mode_uses_every_registered_source(monkeypatch, config, registry):
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "all"

    frame = StubEngine(config).fetch_leases()

    assert len(frame) == 4


def test_auto_mode_does_not_reach_an_ssh_hop_by_default(monkeypatch, config, registry):
    """``auto`` must stay non-invasive."""
    called = []

    class Noisy:
        def iptable(self):
            called.append("ssh")
            return pd.DataFrame(columns=["ip", "mode"])

        def available(self):
            return True

    registry.register("ssh", lambda **kw: Noisy())
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "auto"

    StubEngine(config).fetch_leases()

    assert called == []


def test_engine_records_which_source_each_host_came_from(monkeypatch, config, registry):
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix"

    frame = StubEngine(config).fetch_leases()

    row = frame[frame["ip"] == "192.168.1.1"].iloc[0]
    assert row["source"]


def test_engine_still_works_when_one_source_raises(monkeypatch, config, registry):
    class Broken:
        def iptable(self):
            raise RuntimeError("router unreachable")

        def available(self):
            return True

    registry.register("tplogin", lambda **kw: Broken())
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix"

    frame = StubEngine(config).fetch_leases()

    assert list(frame["ip"]) == ["192.168.1.1"]


def test_engine_raises_when_every_source_fails(monkeypatch, config, registry):
    class Broken:
        def iptable(self):
            raise RuntimeError("down")

        def available(self):
            return True

    for name in registry.names():
        registry.register(name, lambda **kw: Broken())
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "unix"

    with pytest.raises(RuntimeError):
        StubEngine(config).fetch_leases()


def test_running_the_engine_probes_hosts_found_by_secondary_sources(monkeypatch, config, registry):
    """The point of merging: a DNS-only host is still port-probed."""
    probed = []

    class RecordingEngine(StubEngine):
        def probe(self, ip, port):
            probed.append(ip)
            return None

    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "dns,hosts"
    config.ports = [22]

    RecordingEngine(config).run()

    assert "127.0.0.1" in probed
    assert "192.168.1.77" in probed


def test_merged_frame_keeps_the_lease_columns(monkeypatch, config, registry):
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix"

    frame = StubEngine(config).fetch_leases()

    for column in ("ip", "mode", "mac_address"):
        assert column in frame.columns


def test_the_same_host_from_two_sources_yields_one_row(monkeypatch, config, registry):
    """The router and the local ARP table both know 192.168.1.104."""

    class Both:
        def __init__(self, frame):
            self._frame = frame

        def iptable(self):
            return self._frame.copy()

        def available(self):
            return True

    registry.register(
        "unix",
        lambda **kw: Both(
            pd.DataFrame(
                [
                    {
                        "ip": "192.168.1.104",
                        "mac_address": "08:62:66:b4:2c:d2",
                        "mode": "arp",
                    }
                ]
            )
        ),
    )
    monkeypatch.setattr("my_lan_prober.engine.default_fetcher_registry", lambda: registry)
    config.fetcher = "tplogin,unix"

    frame = StubEngine(config).fetch_leases()

    assert len(frame[frame["ip"] == "192.168.1.104"]) == 1


# ---------------------------------------------------------------------------
# build_fetcher keeps working, now over the registry
# ---------------------------------------------------------------------------
def test_build_fetcher_accepts_a_comma_separated_selection(monkeypatch):
    fetcher = build_fetcher("unix,dns")

    assert isinstance(fetcher.iptable(), pd.DataFrame)


def test_build_fetcher_rejects_an_unknown_name():
    with pytest.raises(KeyError):
        build_fetcher("definitely-not-a-source")


def test_build_fetcher_all_is_accepted():
    assert build_fetcher("all") is not None


def test_build_fetcher_returns_a_single_source_for_a_single_name():
    from my_lan_prober.fetchers import UnixArpFetcher

    assert isinstance(build_fetcher("unix"), UnixArpFetcher)


def test_build_fetcher_returns_a_union_for_several_names():
    from my_lan_prober.expanders import TableUnion

    assert isinstance(build_fetcher("unix,dns"), TableUnion)


def test_build_fetcher_auto_is_still_the_default_chain(monkeypatch):
    """``auto`` keeps its documented meaning: non-invasive sources, merged."""
    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": False, "webkit": False}),
    )

    fetcher = build_fetcher("auto")

    assert fetcher is not None
