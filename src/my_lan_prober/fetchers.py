"""ARP / DHCP lease sources.

``design.md`` § 7.  Every source returns a DataFrame with at least ``ip`` and
``mode``.  Sources compose with ``>>`` into a fallback chain:

    TPLoginFetcher >> UnixArpFetcher >> WindowsArpFetcher

The ``parse_*`` helpers are pure functions over captured command output, which
keeps the platform-specific formats testable without touching a live network.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import platform
import re
import subprocess
import tempfile
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

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
    "default_fetcher_chain",
    "merge_tables",
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


def _validate_frame(frame: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Check a fetcher's result, from outside the class as well as inside.

    Module-level so that expanders and unions can validate an upstream table
    with the *same* rule the class applies, rather than a second, drifting
    copy of it.
    """
    return ARPTableFetcher._validate(frame)


def _empty_table() -> pd.DataFrame:
    """The canonical empty result: the required columns, no rows."""
    return pd.DataFrame(columns=list(REQUIRED_COLUMNS))


def _dedupe_key(row: pd.Series) -> tuple:
    """Identity of one host row, for merging tables from several sources.

    ``(ip, mac)`` and not ``ip`` alone: the same address appearing with two
    different MAC addresses is a real conflict (a stale lease, a spoofed
    neighbour, two interfaces on one host), and collapsing it would hide
    exactly the thing worth seeing.  Two rows that agree on both are one host
    seen twice, and merge.

    A MAC is normalised first, so two spellings of one MAC (``AA-BB-..`` and
    ``aa:bb:..``) are one identity rather than two rows.
    """
    ip = row.get("ip")
    mac = row.get("mac_address")
    if mac is None or (isinstance(mac, float) and pd.isna(mac)) or mac == "":
        mac = None
    else:
        mac = normalise_mac(str(mac))
    return (None if ip is None or pd.isna(ip) else str(ip), mac)


def merge_tables(tables: Sequence[pd.DataFrame]) -> pd.DataFrame:
    """Merge ARP tables into one, deduplicated per host.

    A row is identified by ``(ip, mac_address)``.  Sources disagree about how
    much of a host they know, and the merge has to read that disagreement
    correctly:

    * same address, same MAC (or one of them unknown) — **one host**.  The
      router's lease table (hostname + MAC + address) and the local neighbour
      table (address + MAC) describe the same machine, and collapsing them is
      what enriches the row instead of duplicating it;
    * same address, a *different* MAC — **two rows**.  That is a real conflict
      (a stale lease, a spoofed neighbour, two interfaces on one box), and
      hiding it would hide exactly the thing worth seeing.  The conflicting row
      is annotated ``conflict`` so a reader can tell it from a plain host;
    * different address, same MAC — one machine with two addresses, and the
      reason a MAC is part of the identity in the first place.

    A column another source does not know is filled in from wherever it *is*
    known, which is how one merged row ends up carrying a hostname, a MAC and
    a provenance label that no single source had all of.
    """
    frames = [table for table in tables if table is not None and len(table)]
    if not frames:
        return _empty_table()

    # Order the columns so the required ones lead and the rest stay stable.
    columns: List[str] = []
    for frame in frames:
        for column in frame.columns:
            if column not in columns:
                columns.append(column)
    for required in REQUIRED_COLUMNS:
        if required in columns:
            columns.remove(required)
    columns = [*REQUIRED_COLUMNS, *columns]

    records: List[Dict[str, Any]] = []
    by_key: Dict[tuple, Dict[str, Any]] = {}
    #: address → the row that knows the MAC for it, when exactly one does.
    by_address: Dict[str, Dict[str, Any]] = {}

    def absorb(record: Dict[str, Any], row: pd.Series) -> None:
        for column, value in row.items():
            if column in REQUIRED_COLUMNS:
                continue
            if _is_missing(record.get(column)):
                if not _is_missing(value):
                    record[column] = value
            elif column == "via" and not _is_missing(value):
                # How a host was reached accumulates: two SSH hops that both
                # see a machine are two ways to reach it, and dropping either
                # one loses the reason the walk happened.
                record["via"] = _merge_via(record[column], value)

    def note_conflict(record: Dict[str, Any]) -> None:
        record["conflict"] = True

    for frame in frames:
        for _, row in frame.iterrows():
            key = _dedupe_key(row)
            address = key[0]
            identified = key[1] is not None

            known = by_key.get(key)
            if known is not None:
                absorb(known, row)
                continue

            partner = by_address.get(address) if address is not None else None
            if partner is not None:
                if not identified:
                    # An uncovered spelling of a host that is already known:
                    # complete the existing row instead of adding a second one.
                    absorb(partner, row)
                    by_key[key] = partner
                    continue
                if not partner.get("_identified"):
                    # The address was first seen without a MAC (a resolver, a
                    # hosts file).  This row names the MAC, so it *completes*
                    # that host rather than conflicting with it.
                    partner["mac_address"] = row.get("mac_address")
                    partner["_identified"] = True
                    absorb(partner, row)
                    by_key[key] = partner
                    continue
                # The address is already pinned to a different MAC: a real
                # conflict (a stale lease, a spoofed neighbour, two interfaces
                # on one box), kept as its own row and flagged.
                record = {column: row.get(column) for column in columns}
                note_conflict(partner)
                note_conflict(record)
                records.append(record)
                by_key[key] = record
                by_address[address] = record
                continue

            record = {column: row.get(column) for column in columns}
            record["_identified"] = identified
            records.append(record)
            by_key[key] = record
            if address is not None:
                by_address[address] = record

    for record in records:
        record.pop("_identified", None)

    return pd.DataFrame(records, columns=columns) if records else _empty_table()


def _merge_via(existing: Any, incoming: Any) -> str:
    """Union two ``via`` labels into a comma-separated, order-stable list."""
    seen: List[str] = []
    for value in (existing, incoming):
        for part in str(value).split(","):
            part = part.strip()
            if part and part not in seen:
                seen.append(part)
    return ",".join(seen)


def _has_mac(row: pd.Series) -> bool:
    """Whether a row identifies its host by MAC as well as by address."""
    return not _is_missing(row.get("mac_address"))


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and pd.isna(value):
        return True
    return bool(isinstance(value, str) and not value.strip())


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
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": interface})
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
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": device})
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
    """One source of LAN address mappings.

    Beyond producing a table, a fetcher declares *when* it may run, which is
    what lets a union of them be scheduled instead of serialised:

    ``dependency()``
        the sources that must have finished first.  Returns any iterable; the
        order inside it is meaningless, because a prerequisite set has no
        order.  Entries may be classes or (for convenience) their names.
    ``priority``
        an initial hint **and a writable attribute**.  A plain attribute rather
        than a method because :class:`~my_lan_prober.expanders.TableUnion`
        rewrites it: the union derives real levels from the dependency graph
        and assigns them back, so the value after a run is the level actually
        used.  The *sign* of the initial value is what carries meaning —
        negative means "defer me past everything that is not".
    """

    #: Initial scheduling hint.  ``>= 0`` participates normally; ``< 0`` asks
    #: to be deferred behind every non-negative source.  Overridden by
    #: subclasses that want a different default; rewritten by ``TableUnion``.
    priority: int = 0

    @abstractmethod
    def iptable(self) -> pd.DataFrame:
        """Return a DataFrame with at least ``ip`` and ``mode``."""
        raise NotImplementedError

    def dependency(self) -> Iterable[Any]:
        """Sources that must finish before this one runs."""
        return ()

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
    #: Temp vars the Node driver reads, in its own priority order.
    TEMP_VARS = ("TMPDIR", "TMP", "TEMP")
    #: Project-local scratch directory, beside the package working directory.
    FALLBACK_TEMP_DIR = Path.cwd() / "playwright-temp"

    def __init__(
        self,
        password: Optional[str] = None,
        *,
        headless: bool = False,
        browser: Optional[str] = None,
    ) -> None:
        self.password = password
        self.headless = headless
        #: Explicit engine request (``--browser`` / ``PW_BROWSER``), or ``None``
        #: to auto-detect the first installed engine.
        self.browser = browser or os.environ.get("PW_BROWSER", "").strip() or None

    # -- browser engine selection --------------------------------------
    @classmethod
    def installed_browsers(cls) -> Dict[str, bool]:
        """Every Playwright engine, and whether this machine has its binary.

        ``pip install playwright`` downloads no browser, so this is the check
        that decides whether the router can be scraped at all.
        """
        from .browsers import installed_browsers

        return installed_browsers()

    def browser_engine_name(self) -> str:
        """Which engine to launch: the requested one, else the first installed.

        An explicitly requested engine that is missing raises rather than
        silently substituting another: the user asked for that engine, and
        quietly using a different one would hide a broken setup.
        """
        from .browsers import BROWSER_NAMES, BrowserNotInstalled

        # Validate first: an unknown name is a typo in a flag, and there is no
        # reason to start a browser driver (or probe the disk) to notice it.
        if self.browser and self.browser not in BROWSER_NAMES:
            raise BrowserNotInstalled(
                f"unknown browser engine {self.browser!r}; "
                f"expected one of {', '.join(BROWSER_NAMES)}"
            )

        detected = self.installed_browsers()

        if self.browser:
            if not detected.get(self.browser):
                raise BrowserNotInstalled(
                    f"the requested browser engine {self.browser!r} is not installed; "
                    f"run `playwright install {self.browser}`"
                )
            return self.browser

        for name in BROWSER_NAMES:
            if detected.get(name):
                log.info("Using Playwright browser engine: %s", name)
                return name

        raise BrowserNotInstalled(
            "no Playwright browser is installed "
            f"({', '.join(f'{name}=no' for name in BROWSER_NAMES)}); "
            "run `playwright install` to download one"
        )

    def available(self) -> bool:
        """Whether a browser exists to be launched.

        The chain consults this *before* calling :meth:`iptable`, so a machine
        without any browser falls through to the local ARP table instead of
        raising "Executable doesn't exist" mid-scan.
        """
        try:
            self.browser_engine_name()
        except Exception as exc:
            log.debug("%s is unavailable: %s", type(self).__name__, exc)
            return False
        return True

    # -- temp directory handling ---------------------------------------
    @staticmethod
    def temp_dir_is_usable(path: Any, timeout: float = 2.0) -> bool:
        """Whether a file can really be created in ``path``, quickly.

        ``os.access(..., W_OK)`` is not enough on Windows: it reports ``True``
        for directories whose writes fail with ``EPERM``.  Only an actual
        create tells the truth.

        The probe runs in a worker thread with a timeout because a wedged
        ``%LOCALAPPDATA%\\Temp`` can block the create indefinitely rather than
        failing — a hang that would otherwise stall the whole scan.
        """
        directory = Path(path)
        try:
            if not directory.is_dir():
                return False
        except OSError:
            return False

        result: Dict[str, bool] = {}

        def probe() -> None:
            handle = None
            name = None
            try:
                handle, name = tempfile.mkstemp(dir=str(directory), prefix=".probe-")
                result["ok"] = True
            except OSError:
                result["ok"] = False
            finally:
                if handle is not None:
                    with contextlib.suppress(OSError):
                        os.close(handle)
                if name is not None:
                    with contextlib.suppress(OSError):
                        os.unlink(name)

        worker = threading.Thread(target=probe, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            # Wedged: treat as unusable and move on.  The thread is a daemon
            # so a stuck filesystem call cannot keep the process alive.
            log.warning("temp directory %s did not respond within %.1fs", directory, timeout)
            return False
        return result.get("ok", False)

    @classmethod
    def resolve_driver_temp_dir(cls) -> Path:
        """First writable temp directory, in the driver's own priority order.

        The inherited values are tried verbatim first: on CPython 3.10 for
        Windows an unusable inherited directory is exactly what kills the
        launch, but when the inherited one *is* usable, second-guessing it
        would be a downgrade — the Store Python and the MSYS2 toolchain can
        both leave ``AppData\\Local\\Temp`` itself wedged while an inherited
        subdirectory of it works fine.

        The last resort is ``playwright-temp`` in the current directory, which
        the project owns and can always create.  ``tempfile.gettempdir()`` is
        deliberately *not* a candidate: when every real candidate fails it
        returns the current directory itself, so accepting it would silently
        drop browser artifacts into the project root instead of a subdirectory
        we can ignore.
        """
        candidates: List[Path] = []
        for name in cls.TEMP_VARS:
            raw = os.environ.get(name, "").strip()
            # A POSIX-style path only exists inside MSYS2; a native Windows
            # process cannot use one, so it is never a valid candidate here.
            if raw and not (os.name == "nt" and raw.startswith("/")):
                candidates.append(Path(raw))

        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        if local_appdata:
            candidates.append(Path(local_appdata) / "Temp")
        system_root = os.environ.get("SYSTEMROOT", "").strip()
        if system_root:
            candidates.append(Path(system_root) / "Temp")

        # Our own scratch directory, created on demand.
        fallback = cls.FALLBACK_TEMP_DIR
        candidates.append(fallback)

        seen = set()
        for candidate in candidates:
            key = str(candidate).lower()
            if key in seen:
                continue
            seen.add(key)
            try:
                candidate.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue
            if cls.temp_dir_is_usable(candidate):
                return candidate.resolve()

        raise RuntimeError(
            "no writable temp directory found for the Playwright driver; "
            f"tried: {', '.join(str(c) for c in candidates)}"
        )

    @classmethod
    def driver_env(cls) -> Dict[str, str]:
        """Environment for the Playwright Node driver.

        Sets every temp variable the driver consults to the same writable
        directory, so ``os.tmpdir()`` cannot land on an unusable inherited
        value.
        """
        env = dict(os.environ)
        chosen = str(cls.resolve_driver_temp_dir())
        for name in cls.TEMP_VARS:
            env[name] = chosen
        return env

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

        # Pick the engine *before* prompting for a password: there is no point
        # asking for credentials we cannot use, and the error is the useful
        # thing to surface when a machine has no browser at all.
        engine_name = self.browser_engine_name()
        password = self.get_password()
        self.HTML_DUMP.parent.mkdir(parents=True, exist_ok=True)

        # Playwright's Node driver picks its artifacts directory with
        # os.tmpdir(), which honours TMPDIR/TMP/TEMP with no fallback.  Hand
        # it an env whose temp dir is known to be writable, or the browser
        # launch dies (EPERM at mkdtemp on 3.13, WinError 5 inside asyncio's
        # pipe creation on 3.10) before it ever starts.
        with _driver_env_applied(self.driver_env()), sync_playwright() as playwright:
            browser = getattr(playwright, engine_name).launch(headless=self.headless)
            context = browser.new_context()
            try:
                html = self.run(context, password)
            finally:
                context.close()
                browser.close()

        self.HTML_DUMP.write_text('<meta charset="utf-8">\n' + html, encoding="utf-8")
        return self.parse_html(self.HTML_DUMP)

    def _browser_name(self) -> str:
        """Deprecated alias for :meth:`browser_engine_name`."""
        return self.browser_engine_name()

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
        frame.columns = ["host", "mac_address", "ip_address", "valid_time"][: len(frame.columns)]
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

    #: Logging into a router is slow and needs credentials, so it goes last.
    priority = -1

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
            raise RuntimeError("OpenWRTFetcher needs a host (constructor arg or OPENWRT_HOST)")
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
        return FetcherChain([*self._fetchers, other])

    def __lshift__(self, other: ARPTableFetcher) -> "FetcherChain":
        return FetcherChain([other, *self._fetchers])

    def iptable(self) -> pd.DataFrame:
        errors: List[str] = []
        unavailable: List[str] = []
        for fetcher in self._fetchers:
            # Ask before calling: a source that cannot possibly run here (no
            # browser installed, no SSH host configured) is skipped outright
            # rather than called and caught.  That distinction matters because
            # the *reason* is the useful part, and for Playwright the failure
            # would otherwise be a confusing "Executable doesn't exist".
            if not self._is_available(fetcher):
                unavailable.append(type(fetcher).__name__)
                log.debug("ARP source %s is not available here; skipping", type(fetcher).__name__)
                continue
            try:
                frame = self._validate(fetcher.iptable())
            except Exception as exc:
                errors.append(f"{type(fetcher).__name__}: {exc}")
                log.warning("ARP source %s failed: %s", type(fetcher).__name__, exc)
                continue
            if frame.empty:
                errors.append(f"{type(fetcher).__name__}: no entries")
                continue
            log.info("ARP table from %s (%d entries)", type(fetcher).__name__, len(frame))
            return frame

        if errors:
            raise RuntimeError("no ARP source produced a table: " + "; ".join(errors))
        raise RuntimeError(
            "every ARP source is unavailable here: "
            + ", ".join(unavailable)
            + " (no Playwright browser installed? run `playwright install`)"
        )

    @staticmethod
    def _is_available(fetcher: ARPTableFetcher) -> bool:
        """Whether ``fetcher`` can run here; a broken check is not fatal."""
        try:
            return fetcher.available()
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("availability check for %s raised: %s", type(fetcher).__name__, exc)
            return False


def default_fetcher_chain(browser: Optional[str] = None) -> FetcherChain:
    """TP-Link first, then whichever local ARP table this OS provides.

    The local sources are the answer to "Playwright has no browser": they need
    no credentials, no browser, and no extra dependency, so the scan degrades
    to a plain ARP sweep instead of failing.
    """
    return FetcherChain(
        [
            TPLoginFetcher(browser=browser),
            UnixArpFetcher(),
            WindowsArpFetcher(),
        ]
    )


@contextlib.contextmanager
def _driver_env_applied(env: Dict[str, str]):
    """Apply ``env`` to the process for the duration of the block.

    Playwright's ``sync_playwright()`` spawns its driver as a child process,
    so the temp variables must be in ``os.environ`` when the driver starts.
    They are restored afterwards so we do not leak an overridden temp dir to
    the rest of the scan (``icmp_ping`` and the port probes start
    subprocesses too).
    """
    saved = {name: os.environ.get(name) for name in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
