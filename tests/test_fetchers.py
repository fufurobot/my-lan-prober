"""Tests for :mod:`my_lan_prober.fetchers`.

``design.md`` § 7.  An ARP source produces a DataFrame with at least
``ip`` and ``mode``; sources chain with ``>>`` for fallback.  The parsers are
pure functions over captured command output, so they are tested against real
formats:

* Windows ``arp -a``      — ``Interface:`` headers + ``IP  MAC  Type``
* Linux ``/proc/net/arp`` — ``IP  HWtype  Flags  HWaddress  Mask  Device``
* Linux ``ip neigh show`` — ``IP dev eth0 lladdr MAC STATE``
* BSD/macOS ``arp -an``   — ``? (IP) at MAC on en0 ifscope [ethernet]``
"""

from __future__ import annotations

import subprocess

import pandas as pd
import pytest

from my_lan_prober.fetchers import (
    ARPTableFetcher,
    UnixArpFetcher,
    WindowsArpFetcher,
    parse_bsd_arp,
    parse_ip_neigh,
    parse_proc_net_arp,
    parse_windows_arp,
)

# ---------------------------------------------------------------------------
# Windows arp -a  (captured from a real Windows 11 host)
# ---------------------------------------------------------------------------
WINDOWS_ARP = """
Interface: 192.168.1.105 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           48-5f-08-9b-22-c5     dynamic
  192.168.1.100         a8-13-06-f9-91-3e     dynamic
  192.168.1.104         08-62-66-b4-2c-d2     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 10.105.62.45 --- 0x23
  Internet Address      Physical Address      Type
  10.105.62.255         ff-ff-ff-ff-ff-ff     static
  25.255.255.254        12-00-e7-38-fc-c9     static
"""


def test_parse_windows_arp_extracts_dynamic_hosts():
    frame = parse_windows_arp(WINDOWS_ARP)

    assert set(frame["ip"]) == {"192.168.1.1", "192.168.1.100", "192.168.1.104"}


def test_parse_windows_arp_normalises_mac_separators():
    frame = parse_windows_arp(WINDOWS_ARP)
    row = frame[frame["ip"] == "192.168.1.1"].iloc[0]

    assert row["mac_address"] == "48:5f:08:9b:22:c5"


def test_parse_windows_arp_skips_broadcast_and_multicast():
    """ff:ff:.. and the 224.x/239.x multicast ranges are not real hosts."""
    frame = parse_windows_arp(WINDOWS_ARP)

    assert "192.168.1.255" not in set(frame["ip"])
    assert "224.0.0.22" not in set(frame["ip"])
    assert "239.255.255.250" not in set(frame["ip"])


def test_parse_windows_arp_marks_the_mode():
    frame = parse_windows_arp(WINDOWS_ARP)

    assert set(frame["mode"]) == {"arp"}


def test_parse_windows_arp_handles_empty_output():
    frame = parse_windows_arp("")

    assert len(frame) == 0
    assert "ip" in frame.columns


def test_parse_windows_arp_accepts_bytes():
    frame = parse_windows_arp(WINDOWS_ARP.encode("utf-8"))

    assert len(frame) == 3


# ---------------------------------------------------------------------------
# Linux /proc/net/arp
# ---------------------------------------------------------------------------
PROC_NET_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.50     0x1         0x2         00:50:BF:25:68:F3     *        eth0
192.168.0.250    0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.0.77     0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
"""


def test_parse_proc_net_arp_extracts_resolved_entries():
    frame = parse_proc_net_arp(PROC_NET_ARP)

    assert set(frame["ip"]) == {"192.168.0.50", "192.168.0.77"}


def test_parse_proc_net_arp_skips_incomplete_entries():
    """Flags 0x0 means the entry was never resolved (all-zero MAC)."""
    frame = parse_proc_net_arp(PROC_NET_ARP)

    assert "192.168.0.250" not in set(frame["ip"])


def test_parse_proc_net_arp_keeps_the_interface():
    frame = parse_proc_net_arp(PROC_NET_ARP)
    row = frame[frame["ip"] == "192.168.0.77"].iloc[0]

    assert row["interface"] == "wlan0"


# ---------------------------------------------------------------------------
# Linux ip neigh show
# ---------------------------------------------------------------------------
IP_NEIGH = """192.168.22.1 dev eth0 lladdr 20:0c:30:b7:d9:ff REACHABLE
192.168.22.2 dev eth0 lladdr 02:0c:30:b7:d9:fe STALE
192.168.22.3 dev eth0  FAILED
192.168.22.4 dev eth0 lladdr 02:0c:30:b7:d9:fc DELAY
"""


def test_parse_ip_neigh_extracts_lladdr_entries():
    frame = parse_ip_neigh(IP_NEIGH)

    assert set(frame["ip"]) == {"192.168.22.1", "192.168.22.2", "192.168.22.4"}


def test_parse_ip_neigh_skips_entries_without_a_lladdr():
    frame = parse_ip_neigh(IP_NEIGH)

    assert "192.168.22.3" not in set(frame["ip"])


def test_parse_ip_neigh_keeps_the_neighbour_state():
    frame = parse_ip_neigh(IP_NEIGH)
    row = frame[frame["ip"] == "192.168.22.2"].iloc[0]

    assert row["state"] == "STALE"
    assert row["interface"] == "eth0"


# ---------------------------------------------------------------------------
# BSD / macOS arp -an
# ---------------------------------------------------------------------------
BSD_ARP = """? (192.168.1.1) at 0:1c:b3:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.2) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.4) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""


def test_parse_bsd_arp_extracts_hosts():
    frame = parse_bsd_arp(BSD_ARP)

    assert set(frame["ip"]) == {"192.168.1.1", "192.168.1.2"}


def test_parse_bsd_arp_skips_incomplete_and_broadcast():
    frame = parse_bsd_arp(BSD_ARP)

    assert "192.168.1.3" not in set(frame["ip"])
    assert "192.168.1.4" not in set(frame["ip"])


def test_parse_bsd_arp_pads_short_mac_octets():
    """BSD prints 0:1c:b3:.. without leading zeros; normalise to 00:1c:b3:.."""
    frame = parse_bsd_arp(BSD_ARP)
    row = frame[frame["ip"] == "192.168.1.1"].iloc[0]

    assert row["mac_address"] == "00:1c:b3:aa:bb:cc"


# ---------------------------------------------------------------------------
# Fetcher classes
# ---------------------------------------------------------------------------
def test_arp_table_fetcher_is_abstract():
    with pytest.raises(TypeError):
        ARPTableFetcher()  # type: ignore[abstract]


class StubFetcher(ARPTableFetcher):
    def __init__(self, frame=None, error=None):
        self._frame = frame
        self._error = error
        self.calls = 0

    def iptable(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._frame


def test_stub_fetcher_returns_its_frame():
    frame = pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}])
    fetcher = StubFetcher(frame=frame)

    assert fetcher.iptable() is frame


def test_fetcher_chain_falls_back_on_error():
    good = StubFetcher(pd.DataFrame([{"ip": "10.0.0.9", "mode": "arp"}]))
    bad = StubFetcher(error=RuntimeError("no router here"))

    chain = bad >> good
    frame = chain.iptable()

    assert list(frame["ip"]) == ["10.0.0.9"]
    assert good.calls == 1


def test_fetcher_chain_falls_back_on_empty_result():
    good = StubFetcher(pd.DataFrame([{"ip": "10.0.0.9", "mode": "arp"}]))
    empty = StubFetcher(pd.DataFrame(columns=["ip", "mode"]))

    frame = (empty >> good).iptable()

    assert list(frame["ip"]) == ["10.0.0.9"]


def test_fetcher_chain_raises_when_every_source_fails():
    chain = StubFetcher(error=RuntimeError("a")) >> StubFetcher(error=RuntimeError("b"))

    with pytest.raises(RuntimeError):
        chain.iptable()


def test_unix_fetcher_is_available_on_every_platform():
    """``UnixArpFetcher`` must degrade gracefully, never crash on import."""
    assert UnixArpFetcher is not None


def test_windows_fetcher_reports_a_clear_error_when_arp_is_missing(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("arp.exe not found")

    monkeypatch.setattr(subprocess, "run", boom)
    fetcher = WindowsArpFetcher()

    with pytest.raises(Exception):
        fetcher.iptable()


def test_windows_fetcher_uses_a_list_argv(monkeypatch):
    """Never build a shell string — that is how scanning tools get owned."""
    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = kwargs.get("shell", False)
        return subprocess.CompletedProcess(cmd, 0, stdout=WINDOWS_ARP, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    WindowsArpFetcher().iptable()

    assert isinstance(captured["cmd"], (list, tuple))
    assert captured["shell"] is False


# ---------------------------------------------------------------------------
# Lease-table HTML parsing
# ---------------------------------------------------------------------------
LEASE_HTML = """<meta charset="utf-8">
<table id="dhcpLeaseTbl" class="dataGrid"><tbody>
<tr class="dataGrid_header_tr"><td>主机</td><td>MAC地址</td><td>IP地址</td><td>有效时间</td></tr>
<tr><td title="arch-n551jw">arch-n551jw</td><td title="08-62-66-B4-2C-D2">08-62-66-B4-2C-D2</td><td title="192.168.1.104">192.168.1.104</td><td>40:10:04</td></tr>
<tr><td title="gpdwin4">gpdwin4</td><td title="B0-DC-EF-86-CB-FD">B0-DC-EF-86-CB-FD</td><td title="192.168.1.105">192.168.1.105</td><td>33:44:38</td></tr>
</tbody></table>"""


def test_parse_lease_table_works_without_a_third_party_html_parser():
    """The stdlib fallback must handle the real TP-Link markup."""
    from my_lan_prober.fetchers import _parse_lease_table

    frame = _parse_lease_table(LEASE_HTML)

    assert list(frame.columns) == ["host", "mac_address", "ip_address", "valid_time"]
    assert frame.iloc[1]["host"] == "arch-n551jw"
    assert frame.iloc[2]["ip_address"] == "192.168.1.105"


def test_playwright_parse_html_normalises_the_lease_frame(tmp_path):
    from my_lan_prober.fetchers import PlaywrightFetcher

    path = tmp_path / "leases.html"
    path.write_text(LEASE_HTML, encoding="utf-8")

    frame = PlaywrightFetcher.parse_html(path)

    assert len(frame) == 2
    assert set(frame["mode"]) == {"dhcp"}
    assert list(frame["ip"]) == ["192.168.1.104", "192.168.1.105"]
    assert frame.iloc[0]["mac_address"] == "08:62:66:b4:2c:d2"


# ---------------------------------------------------------------------------
# Browser availability: the gate that decides router-scrape vs local ARP
# ---------------------------------------------------------------------------
def test_playwright_fetcher_is_unavailable_when_no_browser_is_installed(monkeypatch):
    """``pip install playwright`` does not install a browser.

    Without one, launching is guaranteed to fail, so ``available()`` must say
    so *before* the chain decides whether to try this source at all.
    """
    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": False, "webkit": False}),
    )

    assert PlaywrightFetcher().available() is False


def test_playwright_fetcher_is_available_when_any_browser_is_installed(monkeypatch):
    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": True, "webkit": False}),
    )

    assert PlaywrightFetcher().available() is True


def test_playwright_fetcher_uses_the_first_installed_browser(monkeypatch):
    """The engine is detected, not hard-coded to chromium."""
    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": True, "webkit": True}),
    )

    assert PlaywrightFetcher().browser_engine_name() == "firefox"


def test_playwright_fetcher_prefers_an_explicit_browser_when_present(monkeypatch):
    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": True, "firefox": True, "webkit": False}),
    )

    assert PlaywrightFetcher(browser="webkit").browser_engine_name() == "chromium"
    assert PlaywrightFetcher(browser="firefox").browser_engine_name() == "firefox"


def test_playwright_fetcher_rejects_a_requested_browser_that_is_missing(monkeypatch):
    from my_lan_prober.browsers import BrowserNotInstalled

    from my_lan_prober.fetchers import PlaywrightFetcher

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": True, "firefox": False, "webkit": False}),
    )

    with pytest.raises(BrowserNotInstalled):
        PlaywrightFetcher(browser="webkit").browser_engine_name()


# ---------------------------------------------------------------------------
# Degrading to the local ARP table
# ---------------------------------------------------------------------------
class UnavailableFetcher(StubFetcher):
    """A source that cannot run here at all (e.g. no browser installed)."""

    def available(self):
        return False


def test_chain_skips_an_unavailable_source():
    """An unavailable source is not called — not merely called and failed."""
    good = StubFetcher(pd.DataFrame([{"ip": "10.0.0.9", "mode": "arp"}]))
    missing = UnavailableFetcher(error=RuntimeError("should never be called"))

    frame = (missing >> good).iptable()

    assert list(frame["ip"]) == ["10.0.0.9"]
    assert missing.calls == 0


def test_chain_raises_when_every_source_is_unavailable():
    chain = UnavailableFetcher() >> UnavailableFetcher()

    with pytest.raises(RuntimeError, match="unavailable"):
        chain.iptable()


def test_local_arp_chain_is_the_no_browser_fallback(monkeypatch):
    """No browser installed → the scan still gets a lease table.

    This is the whole point of feature 2: the router's web UI is unreachable
    without a browser, so the OS-independent local ARP table takes over
    instead of the run dying.
    """
    from my_lan_prober.fetchers import (
        PlaywrightFetcher,
        UnixArpFetcher,
        default_fetcher_chain,
    )

    monkeypatch.setattr(
        PlaywrightFetcher,
        "installed_browsers",
        classmethod(lambda cls: {"chromium": False, "firefox": False, "webkit": False}),
    )
    arp_frame = pd.DataFrame(
        [{"ip": "192.168.1.7", "mac_address": "aa:bb:cc:dd:ee:ff", "mode": "arp"}]
    )
    monkeypatch.setattr(UnixArpFetcher, "iptable", lambda self: arp_frame)

    chain = default_fetcher_chain()
    frame = chain.iptable()

    assert list(frame["ip"]) == ["192.168.1.7"]
    assert chain.fetchers()[0].available() is False
