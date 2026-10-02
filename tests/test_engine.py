"""Tests for :mod:`my_lan_prober.engine`.

The engine is the port of ``tplogin-minimal.py``'s ``run()``: resolve hosts,
fetch the lease table, ping, probe ports, identify services, write ``ssh.sh``
helpers, and export the enriched CSV.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.config import Config
from my_lan_prober.engine import Engine, write_ssh_config

LEASE_FRAME = pd.DataFrame(
    [
        {
            "host": "arch-n551jw",
            "mac_address": "08:62:66:b4:2c:d2",
            "ip_address": "192.168.1.104",
            "valid_time": "40:10:04",
            "mode": "dhcp",
        },
        {
            "host": "gpdwin4",
            "mac_address": "b0:dc:ef:86:cb:fd",
            "ip_address": "192.168.1.105",
            "valid_time": "33:44:38",
            "mode": "dhcp",
        },
    ]
)


@pytest.fixture
def config(tmp_path):
    return Config.resolve(["--output", str(tmp_path / "leases.csv"), "--resolve-host", "localhost"])


class StubEngine(Engine):
    """Engine with every network-touching step replaced by a stub."""

    def __init__(self, config, leases=None, banners=None, alive=True):
        super().__init__(config)
        self._leases = LEASE_FRAME if leases is None else leases
        self._banners = banners or {}
        self._alive = alive

    def fetch_leases(self) -> pd.DataFrame:
        return self._leases.copy()

    def ping(self, ip: str) -> bool:
        return self._alive

    def probe(self, ip: str, port: int):
        return self._banners.get((ip, port))

    def resolve(self, hostname: str):
        return {"localhost": "127.0.0.1"}.get(hostname)


# ---------------------------------------------------------------------------
# write_ssh_config
# ---------------------------------------------------------------------------
def test_write_ssh_config_creates_an_executable_script(tmp_path):
    write_ssh_config(tmp_path, "arch-n551jw", "192.168.1.104", 22, tunnels=[(8888, 8888)])

    script = tmp_path / "arch-n551jw" / "ssh.sh"
    assert script.exists()
    body = script.read_text()
    assert body.startswith("#!/usr/bin/env bash")
    assert "192.168.1.104" in body
    assert "-p 22" in body
    assert "-L 8888:localhost:8888" in body


def test_write_ssh_config_omits_tunnels_when_there_are_none(tmp_path):
    write_ssh_config(tmp_path, "host-a", "10.0.0.5", 22)

    body = (tmp_path / "host-a" / "ssh.sh").read_text()

    assert "-L" not in body


def test_write_ssh_config_applies_the_local_port_offset(tmp_path):
    write_ssh_config(tmp_path, "h", "10.0.0.5", 22, tunnels=[(8888, 8888)], local_port_offset=1000)

    assert "-L 9888:localhost:8888" in (tmp_path / "h" / "ssh.sh").read_text()


def test_write_ssh_config_keeps_a_tunnel_alive_with_server_alive_options(tmp_path):
    write_ssh_config(tmp_path, "h", "10.0.0.5", 22, tunnels=[(80, 80)])

    body = (tmp_path / "h" / "ssh.sh").read_text()

    assert "ServerAliveInterval" in body
    assert "ExitOnForwardFailure" in body


def test_write_ssh_config_deduplicates_remote_ports(tmp_path):
    write_ssh_config(tmp_path, "h", "10.0.0.5", 22, tunnels=[(80, 80), (8080, 80)])

    body = (tmp_path / "h" / "ssh.sh").read_text()

    assert body.count("-L") == 1


# ---------------------------------------------------------------------------
# Service summarising
# ---------------------------------------------------------------------------
def test_engine_summarises_detected_services(config):
    engine = StubEngine(config, banners={("192.168.1.104", 22): "SSH-2.0-OpenSSH"})

    result = engine.run()

    row = result[result["host"] == "arch-n551jw"].iloc[0]
    assert "22:SSH" in row["detected_services"]


def test_engine_leaves_detected_services_empty_when_nothing_is_found(config):
    engine = StubEngine(config)

    result = engine.run()

    assert (
        result["detected_services"].isna().all()
        or (result["detected_services"].fillna("") == "").all()
    )


def test_engine_records_the_ping_result(config):
    engine = StubEngine(config, alive=True)

    assert engine.run()["icmp_ping"].all()


def test_engine_records_failed_pings(config):
    engine = StubEngine(config, alive=False)

    assert not engine.run()["icmp_ping"].any()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def test_engine_writes_the_enriched_csv(config):
    StubEngine(config).run()

    written = pd.read_csv(config.output)
    assert set(written["host"]) == {"arch-n551jw", "gpdwin4"}


def test_engine_writes_the_dns_csv(config):
    StubEngine(config).run()

    assert config.dns_csv.exists()


def test_engine_keeps_the_lease_columns(config):
    result = StubEngine(config).run()

    for column in ("host", "mac_address", "ip_address", "valid_time"):
        assert column in result.columns


def test_engine_creates_a_per_host_directory(config):
    StubEngine(config).run()

    assert config.data_dir.exists()


def test_engine_writes_ssh_scripts_for_ssh_hosts(config):
    engine = StubEngine(config, banners={("192.168.1.104", 22): "SSH-2.0-OpenSSH_10.5"})

    engine.run()

    script = config.data_dir / "arch-n551jw" / "ssh.sh"
    assert script.exists()
    assert "192.168.1.104" in script.read_text()


def test_engine_forwards_other_services_through_the_ssh_tunnel(config):
    engine = StubEngine(
        config,
        banners={
            ("192.168.1.104", 22): "SSH-2.0-OpenSSH_10.5",
            ("192.168.1.104", 8000): "HTTP/1.1 302 Found\r\nlocation: /hub/\r\n",
        },
    )

    engine.run()

    body = (config.data_dir / "arch-n551jw" / "ssh.sh").read_text()
    assert "-L 8000:localhost:8000" in body


def test_engine_skips_ssh_scripts_when_no_ssh_port_is_open(config):
    StubEngine(config).run()

    assert not (config.data_dir / "arch-n551jw" / "ssh.sh").exists()


def test_engine_does_not_tunnel_the_ssh_port_itself(config):
    engine = StubEngine(config, banners={("192.168.1.104", 22): "SSH-2.0-OpenSSH_10.5"})

    engine.run()

    body = (config.data_dir / "arch-n551jw" / "ssh.sh").read_text()
    assert "-L 22:localhost:22" not in body


def test_engine_returns_the_enriched_frame(config):
    result = StubEngine(config).run()

    assert isinstance(result, pd.DataFrame)
    assert len(result) == 2


def test_engine_handles_an_empty_lease_table(config):
    engine = StubEngine(
        config, leases=pd.DataFrame(columns=["host", "mac_address", "ip_address", "valid_time"])
    )

    result = engine.run()

    assert len(result) == 0


def test_engine_reports_resolved_hosts(config):
    StubEngine(config).run()

    assert "localhost" in set(pd.read_csv(config.dns_csv)["hostname"])


# ---------------------------------------------------------------------------
# Lease normalisation (DHCP scrapers vs ARP fetchers)
# ---------------------------------------------------------------------------
ARP_FRAME = pd.DataFrame(
    [
        {"ip": "192.168.1.1", "mac_address": "48:5f:08:9b:22:c5", "mode": "arp"},
        {"ip": "192.168.1.104", "mac_address": "08:62:66:b4:2c:d2", "mode": "arp"},
    ]
)


def test_normalise_leases_maps_arp_ip_to_ip_address():
    frame = Engine.normalise_leases(ARP_FRAME)

    assert "ip_address" in frame.columns
    assert list(frame["ip_address"]) == ["192.168.1.1", "192.168.1.104"]


def test_normalise_leases_falls_back_to_the_address_as_hostname():
    """ARP tables carry no hostname; the address is the only label."""
    frame = Engine.normalise_leases(ARP_FRAME)

    assert list(frame["host"]) == ["192.168.1.1", "192.168.1.104"]


def test_normalise_leases_keeps_dhcp_frames_intact():
    frame = Engine.normalise_leases(LEASE_FRAME)

    assert list(frame["host"]) == ["arch-n551jw", "gpdwin4"]
    assert list(frame["ip_address"]) == ["192.168.1.104", "192.168.1.105"]


def test_engine_runs_against_an_arp_style_lease_frame(config):
    """The engine must work when the source is ARP, not the router."""
    engine = StubEngine(config, leases=ARP_FRAME, banners={("192.168.1.104", 22): "SSH-2.0-x"})

    result = engine.run()

    assert list(result["ip_address"]) == ["192.168.1.1", "192.168.1.104"]
    assert "22:SSH" in result.iloc[1]["detected_services"]


# ---------------------------------------------------------------------------
# build_fetcher
# ---------------------------------------------------------------------------
def test_build_fetcher_passes_the_configured_browser_through(monkeypatch):
    from my_lan_prober.engine import build_fetcher

    monkeypatch.setenv("PW_BROWSER", "webkit")

    assert build_fetcher("tplogin").browser == "webkit"


def test_build_fetcher_auto_still_ends_at_the_local_arp_table(monkeypatch):
    """``auto`` must keep a local source last, whatever the browser situation."""
    from my_lan_prober.engine import build_fetcher
    from my_lan_prober.fetchers import PlaywrightFetcher, UnixArpFetcher, WindowsArpFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": False, "webkit": False}),
    )

    kinds = [type(fetcher) for fetcher in build_fetcher("auto").fetchers()]

    assert kinds[0] is PlaywrightFetcher
    assert UnixArpFetcher in kinds
    assert kinds[-1] in (UnixArpFetcher, WindowsArpFetcher)


def test_engine_falls_back_to_arp_when_no_browser_is_installed(monkeypatch, tmp_path):
    """End to end: no browser at all still produces an enriched CSV.

    ``fetch_leases`` is the default implementation here (not the stub), so
    this exercises the real ``build_fetcher`` chain.
    """
    from my_lan_prober.engine import build_fetcher
    from my_lan_prober.fetchers import PlaywrightFetcher, UnixArpFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": False, "webkit": False}),
    )
    monkeypatch.setattr(
        UnixArpFetcher,
        "iptable",
        lambda self: pd.DataFrame(
            [{"ip": "192.168.1.9", "mac_address": "aa:bb:cc:dd:ee:ff", "mode": "arp"}]
        ),
    )

    config = Config.resolve(
        ["--fetcher", "auto", "--output", str(tmp_path / "out.csv"), "--resolve-host", "localhost"]
    )
    engine = StubEngine(config)
    engine.fetch_leases = lambda: build_fetcher(config.fetcher).iptable()

    result = engine.run()

    assert list(result["ip_address"]) == ["192.168.1.9"]
    assert (tmp_path / "out.csv").exists()
