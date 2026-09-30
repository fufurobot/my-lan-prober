"""ARP / DHCP lease sources.

``design.md`` § 7.  Every source returns a DataFrame with at least ``ip`` and
``mode``.  Sources compose with ``>>`` into a fallback chain:

    TPLoginFetcher >> UnixArpFetcher >> WindowsArpFetcher

The ``parse_*`` helpers are pure functions over captured command output, which
keeps the platform-specific formats testable without touching a live network.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Optional, Sequence

import pandas as pd

log = logging.getLogger(__name__)

__all__ = [
    "ARPTableFetcher",
    "PlaywrightFetcher",
    "TPLoginFetcher",
    "UnixArpFetcher",
    "WindowsArpFetcher",
    "OpenWRTFetcher",
    "FetcherChain",
    "parse_windows_arp",
    "parse_proc_net_arp",
    "parse_ip_neigh",
    "parse_bsd_arp",
    "normalise_mac",
]

#: Columns every fetcher guarantees.
REQUIRED_COLUMNS = ("ip", "mode")

_ALL_ZERO_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalise_mac(raw: str) -> str:
    """Return ``aa:bb:cc:dd:ee:ff`` lower-case, padding short BSD octets.

    BSD prints thin octets without leading zeros (``0:1c:b3:aa:bb:cc``), so
    each octet is padded rather than the whole string.
    """
    text = (raw or "").strip().lower()
    if not text:
        return ""
    if ":" in text:
        octets = text.split(":")
    elif "-" in text:
        octets = text.split("-")
    else:
        cleaned = re.sub(r"[^0-9a-f]", "", text)
        if len(cleaned) != 12:
            return text
        octets = [cleaned[i : i + 2] for i in range(0, 12, 2)]

    if len(octets) != 6 or any(not re.fullmatch(r"[0-9a-f]{1,2}", octet) for octet in octets):
        return text
    return ":".join(octet.rjust(2, "0") for octet in octets)


def _is_usable_host(ip: str, mac: str) -> bool:
    """Filter out broadcast/multicast addresses and unresolved entries."""
    if mac in (_ALL_ZERO_MAC, _BROADCAST_MAC):
        return False
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (address.is_multicast or address.is_unspecified)


def _to_text(raw: Any) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "ignore")
    return raw or ""


def _frame(rows: List[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])
    return pd.DataFrame(rows)


def _strip_tags(cell: str) -> str:
    return re.sub(r"<[^>]*>", "", cell).replace("&nbsp;", " ").strip()


def _parse_lease_table(html: str) -> pd.DataFrame:
    """Parse an HTML ``<table>`` into a DataFrame using only the stdlib.

    The TP-Link lease table is a flat grid, so a cell-wise scan is enough —
    and unlike ``pandas.read_html`` it needs no third-party parser.
    """
    from html.parser import HTMLParser

    class TableParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.rows: List[List[str]] = []
            self._row: Optional[List[str]] = None
            self._cell: Optional[List[str]] = None
            self._depth = 0

        def handle_starttag(self, tag: str, attrs: Any) -> None:
            if tag == "tr":
                self._row = []
            elif tag in ("td", "th") and self._row is not None:
                self._cell = []
                self._depth = 1
            elif self._cell is not None:
                self._depth += 1

        def handle_endtag(self, tag: str) -> None:
            if tag in ("td", "th") and self._cell is not None:
                self._row.append("".join(self._cell).strip())
                self._cell = None
                self._depth = 0
            elif tag == "tr" and self._row is not None:
                if self._row:
                    self.rows.append(self._row)
                self._row = None
            elif self._cell is not None:
                self._depth = max(1, self._depth - 1)

        def handle_data(self, data: str) -> None:
            if self._cell is not None:
                self._cell.append(data)

    parser = TableParser()
    parser.feed(html)
    if not parser.rows:
        return pd.DataFrame(columns=["host", "mac_address", "ip_address", "valid_time"])

    width = max(len(row) for row in parser.rows)
    normalised = [row + [""] * (width - len(row)) for row in parser.rows]
    columns = ["host", "mac_address", "ip_address", "valid_time"][:width]
    return pd.DataFrame(normalised, columns=columns)


# ---------------------------------------------------------------------------
# Platform parsers
# ---------------------------------------------------------------------------
def parse_windows_arp(output: Any) -> pd.DataFrame:
    """Parse ``arp -a`` on Windows.

    Format::

        Interface: 192.168.1.105 --- 0xb
          Internet Address      Physical Address      Type
          192.168.1.1           48-5f-08-9b-22-c5     dynamic
    """
    rows: List[dict] = []
    interface: Optional[str] = None

    for line in _to_text(output).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        header = re.match(r"^Interface:\s*(\S+)", stripped)
        if header:
            interface = header.group(1)
            continue
        if stripped.lower().startswith("internet address"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        ip, mac, entry_type = parts[0], parts[1], parts[2]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        mac = normalise_mac(mac)
        if entry_type.lower() != "dynamic" or not _is_usable_host(ip, mac):
            continue
        rows.append(
            {"ip": ip, "mac_address": mac, "mode": "arp", "interface": interface}
        )
    return _frame(rows)


def parse_proc_net_arp(output: Any) -> pd.DataFrame:
    """Parse ``/proc/net/arp``.

    Format: ``IP address  HW type  Flags  HW address  Mask  Device``.
    Flags ``0x0`` means the entry was never resolved.
    """
    rows: List[dict] = []
    for line in _to_text(output).splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].lower() == "ip":
            continue
        ip, _hwtype, flags, mac, _mask, device = parts[:6]
        if flags.lower() in ("0x0", "0x00"):
            continue
        mac = normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            continue
        rows.append(
            {"ip": ip, "mac_address": mac, "mode": "arp", "interface": device}
        )
    return _frame(rows)


def parse_ip_neigh(output: Any) -> pd.DataFrame:
    """Parse ``ip neigh show``.

    Format: ``192.168.22.1 dev eth0 lladdr 20:0c:30:b7:d9:ff REACHABLE``.
    Entries with no ``lladdr`` (``FAILED``/``INCOMPLETE``) are dropped.
    """
    rows: List[dict] = []
    for line in _to_text(output).splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        if "lladdr" not in parts:
            continue
        mac = parts[parts.index("lladdr") + 1]
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None
        state = parts[-1] if parts[-1].isupper() else None
        mac = normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            continue
        rows.append(
            {
                "ip": ip,
                "mac_address": mac,
                "mode": "arp",
                "interface": interface,
                "state": state,
            }
        )
    return _frame(rows)


def parse_bsd_arp(output: Any) -> pd.DataFrame:
    """Parse ``arp -an`` on macOS/BSD.

    Format: ``? (192.168.1.1) at 0:1c:b3:aa:bb:cc on en0 ifscope [ethernet]``.
    Short octets are padded, and ``(incomplete)`` entries are dropped.
    """
    rows: List[dict] = []
    # The MAC is hex octets; ``(incomplete)`` must not be mistaken for one.
    pattern = re.compile(
        r"^[?\w.-]*\s*\((?P<ip>[\d.]+)\)\s+at\s+"
        r"(?P<mac>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
        r"(?:\s+on\s+(?P<iface>\S+))?"
    )
    for line in _to_text(output).splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        ip = match.group("ip")
        mac = normalise_mac(match.group("mac"))
        if not _is_usable_host(ip, mac):
            continue
        rows.append(
            {
                "ip": ip,
                "mac_address": mac,
                "mode": "arp",
                "interface": match.group("iface"),
            }
        )
    return _frame(rows)


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------
class ARPTableFetcher(ABC):
    """One source of LAN address mappings."""

    @abstractmethod
    def iptable(self) -> pd.DataFrame:
        """Return a DataFrame with at least ``ip`` and ``mode``."""
        raise NotImplementedError

    def available(self) -> bool:
        """Whether this source can plausibly run here."""
        return True

    def __rshift__(self, other: "ARPTableFetcher") -> "FetcherChain":
        return FetcherChain([self, other])

    def __lshift__(self, other: "ARPTableFetcher") -> "FetcherChain":
        return FetcherChain([other, self])

    @staticmethod
    def _validate(frame: pd.DataFrame) -> pd.DataFrame:
        if frame is None:
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
        if missing:
            raise ValueError(f"fetcher result is missing columns: {missing}")
        return frame


def _run(cmd: Sequence[str], timeout: float = 10.0) -> str:
    """Run a command with a list argv (never a shell string)."""
    completed = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return completed.stdout or ""


class UnixArpFetcher(ARPTableFetcher):
    """Cross-platform local ARP table read.

    Falls back through whichever mechanism the host provides:
    ``/proc/net/arp`` → ``ip neigh`` → ``arp -an``.  This is the fallback for
    when ``tplogin.cn`` does not resolve to a TP-Link router.
    """

    #: Candidate commands, in order of preference.
    COMMANDS: Sequence[Sequence[str]] = (
        ("ip", "neigh", "show"),
        ("arp", "-an"),
        ("arp", "-a"),
    )

    def iptable(self) -> pd.DataFrame:
        frame = self._from_proc()
        if not frame.empty:
            return frame

        for command in self.COMMANDS:
            try:
                output = _run(command)
            except (OSError, subprocess.SubprocessError):
                continue
            if not output.strip():
                continue
            frame = self._parse_by_command(command, output)
            if not frame.empty:
                return frame
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])

    @staticmethod
    def _from_proc() -> pd.DataFrame:
        proc = Path("/proc/net/arp")
        try:
            if proc.exists():
                return parse_proc_net_arp(proc.read_text(encoding="utf-8", errors="ignore"))
        except OSError:  # pragma: no cover - unreadable procfs
            pass
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])

    @staticmethod
    def _parse_by_command(command: Sequence[str], output: str) -> pd.DataFrame:
        if tuple(command[:2]) == ("ip", "neigh"):
            return parse_ip_neigh(output)
        if platform.system().lower() == "windows":
            return parse_windows_arp(output)
        return parse_bsd_arp(output)


class WindowsArpFetcher(ARPTableFetcher):
    """``arp -a`` on Windows."""

    def available(self) -> bool:
        return platform.system().lower() == "windows"

    def iptable(self) -> pd.DataFrame:
        output = _run(("arp", "-a"))
        return parse_windows_arp(output)


class PlaywrightFetcher(ARPTableFetcher):
    """Base for browser-driven sources (routers with a web UI)."""

    #: Persistent browser profile directory.
    USER_DATA_DIR = Path(".playwright-user-data")
    #: HTML dump written for debugging / offline re-parsing.
    HTML_DUMP = Path("data") / "tplogin-arp.html"

    def __init__(self, password: Optional[str] = None, *, headless: bool = False) -> None:
        self.password = password
        self.headless = headless

    def run(self, context: Any, password: str) -> Any:  # pragma: no cover - abstract
        """Drive the page and return the scraped HTML."""
        raise NotImplementedError

    def get_password(self) -> str:
        """Password from the instance, the env, or an interactive prompt."""
        import os

        if self.password:
            return self.password
        env_password = os.environ.get("TPLOGIN_PASSWORD", "").strip()
        if env_password:
            return env_password

        import getpass

        password = getpass.getpass("Please enter the router admin password: ")
        if not password:
            raise ValueError("Password cannot be empty.")
        return password

    def iptable(self) -> pd.DataFrame:
        from playwright.sync_api import sync_playwright

        password = self.get_password()
        self.HTML_DUMP.parent.mkdir(parents=True, exist_ok=True)

        with sync_playwright() as playwright:
            browser = getattr(playwright, self._browser_name()).launch(headless=self.headless)
            context = browser.new_context()
            try:
                html = self.run(context, password)
            finally:
                context.close()
                browser.close()

        self.HTML_DUMP.write_text('<meta charset="utf-8">\n' + html, encoding="utf-8")
        return self.parse_html(self.HTML_DUMP)

    def _browser_name(self) -> str:
        import os

        return os.environ.get("PW_BROWSER", "chromium").strip() or "chromium"

    @staticmethod
    def parse_html(path: Any) -> pd.DataFrame:
        """Read the DHCP lease table out of the dumped HTML.

        Uses ``pandas.read_html`` when an HTML parser is installed, and falls
        back to a stdlib parser otherwise.  (``tplogin-minimal.py`` relied on
        ``read_html`` alone, which needs ``lxml`` — a dependency it never
        declared, so it raised ``ImportError`` on a clean install.)
        """
        try:
            frame = pd.read_html(path)[0]
        except (ImportError, ValueError):
            frame = _parse_lease_table(Path(path).read_text(encoding="utf-8"))

        frame = frame.iloc[1:, :].reset_index(drop=True)
        frame.columns = ["host", "mac_address", "ip_address", "valid_time"][
            : len(frame.columns)
        ]
        frame["mac_address"] = frame["mac_address"].map(normalise_mac)
        frame["mode"] = "dhcp"
        frame["ip"] = frame["ip_address"]
        return frame


class TPLoginFetcher(PlaywrightFetcher):
    """Scrape the TP-Link DHCP lease table.

    The login flow replicates the user-tested ``tplogin-minimal.py`` script.
    """

    URL = "http://tplogin.cn/"
    PASSWORD_LABEL = "密码 请输入管理员密码"
    SUBMIT_LABEL = "确 定"
    ROUTING_HEADING = "路由设置"
    DHCP_MENU_ID = "#dhcpServer_rsMenu"
    DHCP_MENU_TEXT = "DHCP服务器"
    LEASE_TABLE_ID = "#dhcpLeaseTbl"

    def run(self, context: Any, password: str) -> str:
        page = context.new_page()
        page.goto(self.URL, timeout=30_000)
        page.get_by_role("textbox", name=self.PASSWORD_LABEL).click()
        page.get_by_role("textbox", name=self.PASSWORD_LABEL).fill(password)
        page.get_by_role("button", name=self.SUBMIT_LABEL).click()
        page.get_by_role("heading", name=self.ROUTING_HEADING).click()
        page.wait_for_timeout(3000)
        page.locator(self.DHCP_MENU_ID).get_by_text(self.DHCP_MENU_TEXT).click()
        page.wait_for_timeout(1000)

        table = page.locator(self.LEASE_TABLE_ID)
        table.scroll_into_view_if_needed()
        page.wait_for_timeout(1000)
        return table.evaluate("el => el.outerHTML")


class OpenWRTFetcher(ARPTableFetcher):
    """Read the neighbour table from an OpenWRT box over SSH."""

    def __init__(
        self,
        host: Optional[str] = None,
        *,
        username: str = "root",
        port: int = 22,
        timeout: float = 10.0,
    ) -> None:
        import os

        self.host = host or os.environ.get("OPENWRT_HOST")
        self.username = username
        self.port = port
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.host)

    def iptable(self) -> pd.DataFrame:
        if not self.host:
            raise RuntimeError(
                "OpenWRTFetcher needs a host (constructor arg or OPENWRT_HOST)"
            )
        import asyncssh

        result = asyncssh.run(
            f"{self.username}@{self.host}",
            command="cat /proc/net/arp",
            port=self.port,
            connect_timeout=self.timeout,
        )
        return parse_proc_net_arp(result.stdout)


class FetcherChain(ARPTableFetcher):
    """Try each source in order; the first usable table wins."""

    def __init__(self, fetchers: Sequence[ARPTableFetcher]) -> None:
        self._fetchers: List[ARPTableFetcher] = []
        for fetcher in fetchers:
            if isinstance(fetcher, FetcherChain):
                self._fetchers.extend(fetcher._fetchers)
            else:
                self._fetchers.append(fetcher)

    def fetchers(self) -> List[ARPTableFetcher]:
        return list(self._fetchers)

    def __rshift__(self, other: ARPTableFetcher) -> "FetcherChain":
        return FetcherChain(self._fetchers + [other])

    def __lshift__(self, other: ARPTableFetcher) -> "FetcherChain":
        return FetcherChain([other] + self._fetchers)

    def iptable(self) -> pd.DataFrame:
        errors: List[str] = []
        for fetcher in self._fetchers:
            try:
                frame = self._validate(fetcher.iptable())
            except Exception as exc:  # noqa: BLE001 - fall through to the next
                errors.append(f"{type(fetcher).__name__}: {exc}")
                log.warning("ARP source %s failed: %s", type(fetcher).__name__, exc)
                continue
            if frame.empty:
                errors.append(f"{type(fetcher).__name__}: no entries")
                continue
            log.info("ARP table from %s (%d entries)", type(fetcher).__name__, len(frame))
            return frame

        raise RuntimeError("no ARP source produced a table: " + "; ".join(errors))


def default_fetcher_chain() -> FetcherChain:
    """TP-Link first, then whichever local ARP table this OS provides."""
    return FetcherChain([TPLoginFetcher(), UnixArpFetcher(), WindowsArpFetcher()])
