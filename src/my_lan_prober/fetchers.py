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
    if raw:
        text = raw.strip().lower()
    else:
        text = ""
        log.debug("normalise_mac: got no input at all; returning an empty MAC")
    if not text:
        log.debug("normalise_mac: %r is empty; leaving it unset", raw)
        return ""
    if ":" in text:
        octets = text.split(":")
        log.debug("normalise_mac: %r is colon-separated into %d octet(s)", raw, len(octets))
    elif "-" in text:
        octets = text.split("-")
        log.debug("normalise_mac: %r is dash-separated into %d octet(s)", raw, len(octets))
    else:
        cleaned = re.sub(r"[^0-9a-f]", "", text)
        if len(cleaned) != 12:
            log.debug(
                "normalise_mac: %r has no separator and %d hex digit(s), not 12; keeping as-is",
                raw,
                len(cleaned),
            )
            return text
        log.debug("normalise_mac: %r parsed as a bare 12-digit MAC", raw)
        octets = [cleaned[i : i + 2] for i in range(0, 12, 2)]

    if len(octets) != 6 or any(not re.fullmatch(r"[0-9a-f]{1,2}", octet) for octet in octets):
        log.debug(
            "normalise_mac: %r has %d octet(s) and is not six 1-2 digit hex groups; keeping as-is",
            raw,
            len(octets),
        )
        return text
    normalised = ":".join(octet.rjust(2, "0") for octet in octets)
    log.debug("normalise_mac: %r -> %s", raw, normalised)
    return normalised


def _is_usable_host(ip: str, mac: str) -> bool:
    """Filter out broadcast/multicast addresses and unresolved entries."""
    if mac in (_ALL_ZERO_MAC, _BROADCAST_MAC):
        log.debug("_is_usable_host: dropping %s: mac %s is all-zero or broadcast", ip, mac)
        return False
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        log.debug("_is_usable_host: dropping %r: not an IPv4 address (%s)", ip, exc)
        return False
    if address.is_multicast or address.is_unspecified:
        log.debug(
            "_is_usable_host: dropping %s: multicast=%s unspecified=%s",
            ip,
            address.is_multicast,
            address.is_unspecified,
        )
        return False
    return True


def _to_text(raw: Any) -> str:
    if isinstance(raw, bytes):
        log.debug("_to_text: decoding %d raw byte(s) of command output as utf-8", len(raw))
        return raw.decode("utf-8", "ignore")
    log.debug("_to_text: passing through %s output", type(raw).__name__)
    if raw:
        return raw
    else:
        log.debug("_to_text: command output was empty/None")
        return ""


def _frame(rows: List[dict]) -> pd.DataFrame:
    if not rows:
        log.debug("_frame: no rows parsed; returning the empty ip/mac_address/mode frame")
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])
    log.debug("_frame: building a frame from %d parsed row(s)", len(rows))
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
        log.debug("_dedupe_key: row for ip=%r has no usable MAC (%r)", ip, mac)
        mac = None
    else:
        mac = normalise_mac(str(mac))
        log.debug(
            "_dedupe_key: row for ip=%r normalised MAC %r -> %s", ip, row.get("mac_address"), mac
        )
    if ip is None or pd.isna(ip):
        log.debug("_dedupe_key: row has no usable ip (%r); keying on MAC alone", ip)
        return (None, mac)
    return (str(ip), mac)


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
    frames: List[pd.DataFrame] = []
    for table in tables:
        if table is None:
            log.debug("merge_tables: dropping a None input table")
        elif not len(table):
            log.debug("merge_tables: dropping an empty input table")
        else:
            frames.append(table)
    if not frames:
        log.debug(
            "merge_tables: no non-empty table among %d input(s); nothing to merge", len(tables)
        )
        return _empty_table()
    log.debug(
        "merge_tables: merging %d non-empty table(s) of %d input(s)", len(frames), len(tables)
    )

    # Order the columns so the required ones lead and the rest stay stable.
    columns: List[str] = []
    for frame in frames:
        for column in frame.columns:
            if column not in columns:
                columns.append(column)
            else:
                log.debug(
                    "merge_tables: column %r already collected; keeping first position", column
                )
    for required in REQUIRED_COLUMNS:
        if required in columns:
            columns.remove(required)
        else:
            log.debug("merge_tables: required column %r absent from every source table", required)
    columns = [*REQUIRED_COLUMNS, *columns]
    log.debug("merge_tables: merged column order is %s", columns)

    records: List[Dict[str, Any]] = []
    by_key: Dict[tuple, Dict[str, Any]] = {}
    #: address → the row that knows the MAC for it, when exactly one does.
    by_address: Dict[str, Dict[str, Any]] = {}

    def absorb(record: Dict[str, Any], row: pd.Series) -> None:
        for column, value in row.items():
            if column in REQUIRED_COLUMNS:
                log.debug("absorb: %r is a required column; never overwritten by a merge", column)
                continue
            if _is_missing(record.get(column)):
                if not _is_missing(value):
                    log.debug("absorb: filling empty %r with %r", column, value)
                    record[column] = value
                else:
                    log.debug(
                        "absorb: both existing and incoming %r are missing; leaving it", column
                    )
            elif column == "via" and not _is_missing(value):
                # How a host was reached accumulates: two SSH hops that both
                # see a machine are two ways to reach it, and dropping either
                # one loses the reason the walk happened.
                log.debug("absorb: unioning via %r with %r", record[column], value)
                record["via"] = _merge_via(record[column], value)
            else:
                log.debug(
                    "absorb: keeping existing %r=%r over incoming %r",
                    column,
                    record.get(column),
                    value,
                )

    def note_conflict(record: Dict[str, Any]) -> None:
        log.debug("note_conflict: marking row ip=%r as conflicted", record.get("ip"))
        record["conflict"] = True

    for frame in frames:
        for _, row in frame.iterrows():
            key = _dedupe_key(row)
            address = key[0]
            identified = key[1] is not None

            known = by_key.get(key)
            if known is not None:
                log.debug(
                    "merge_tables: key %r already seen; absorbing row into the existing one", key
                )
                absorb(known, row)
                continue
            log.debug("merge_tables: key %r is new (identified=%s)", key, identified)

            partner = by_address.get(address) if address is not None else None
            if partner is not None:
                if not identified:
                    # An uncovered spelling of a host that is already known:
                    # complete the existing row instead of adding a second one.
                    log.debug(
                        "merge_tables: address %s already known and this row has no MAC; "
                        "completing the existing row",
                        address,
                    )
                    absorb(partner, row)
                    by_key[key] = partner
                    continue
                if not partner.get("_identified"):
                    # The address was first seen without a MAC (a resolver, a
                    # hosts file).  This row names the MAC, so it *completes*
                    # that host rather than conflicting with it.
                    log.debug(
                        "merge_tables: address %s was known without a MAC; this row supplies %r",
                        address,
                        row.get("mac_address"),
                    )
                    partner["mac_address"] = row.get("mac_address")
                    partner["_identified"] = True
                    absorb(partner, row)
                    by_key[key] = partner
                    continue
                # The address is already pinned to a different MAC: a real
                # conflict (a stale lease, a spoofed neighbour, two interfaces
                # on one box), kept as its own row and flagged.
                log.debug(
                    "merge_tables: address %s is pinned to MAC %r but this row names %r; "
                    "keeping both and flagging the conflict",
                    address,
                    partner.get("mac_address"),
                    row.get("mac_address"),
                )
                record = {column: row.get(column) for column in columns}
                note_conflict(partner)
                note_conflict(record)
                records.append(record)
                by_key[key] = record
                by_address[address] = record
                continue
            log.debug("merge_tables: address %r has no existing row; adding a new one", address)

            record = {column: row.get(column) for column in columns}
            record["_identified"] = identified
            records.append(record)
            by_key[key] = record
            if address is not None:
                by_address[address] = record
            else:
                log.debug("merge_tables: row has no address; it cannot be indexed by address")

    for record in records:
        log.debug(
            "merge_tables: dropping the internal _identified flag from row ip=%r", record.get("ip")
        )
        record.pop("_identified", None)

    if not records:
        log.debug("merge_tables: every input row collapsed away; returning the empty table")
        return _empty_table()
    log.debug(
        "merge_tables: produced %d merged row(s) across %d column(s)", len(records), len(columns)
    )
    return pd.DataFrame(records, columns=columns)


def _merge_via(existing: Any, incoming: Any) -> str:
    """Union two ``via`` labels into a comma-separated, order-stable list."""
    seen: List[str] = []
    for value in (existing, incoming):
        for part in str(value).split(","):
            part = part.strip()
            if part and part not in seen:
                seen.append(part)
            else:
                log.debug("_merge_via: dropping duplicate/blank via part %r from %r", part, value)
    merged = ",".join(seen)
    log.debug("_merge_via: %r + %r -> %r", existing, incoming, merged)
    return merged


def _has_mac(row: pd.Series) -> bool:
    """Whether a row identifies its host by MAC as well as by address."""
    return not _is_missing(row.get("mac_address"))


def _is_missing(value: Any) -> bool:
    if value is None:
        log.debug("_is_missing: None is missing")
        return True
    if isinstance(value, float) and pd.isna(value):
        log.debug("_is_missing: NaN is missing")
        return True
    if isinstance(value, str):
        blank = not value.strip()
        log.debug("_is_missing: %r is a string; blank=%s", value, blank)
    else:
        blank = False
    if blank:
        log.debug("_is_missing: blank string %r is missing", value)
    return bool(blank)


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
                log.debug("TableParser: opening row (%d so far)", len(self.rows))
                self._row = []
            elif tag in ("td", "th") and self._row is not None:
                log.debug("TableParser: opening <%s> cell at depth 1", tag)
                self._cell = []
                self._depth = 1
            elif self._cell is not None:
                log.debug(
                    "TableParser: nested <%s> inside a cell; depth -> %d", tag, self._depth + 1
                )
                self._depth += 1
            else:
                log.debug("TableParser: ignoring <%s> outside any row or cell", tag)

        def handle_endtag(self, tag: str) -> None:
            if tag in ("td", "th") and self._cell is not None:
                log.debug(
                    "TableParser: closing <%s> cell with %d fragment(s)", tag, len(self._cell)
                )
                self._row.append("".join(self._cell).strip())
                self._cell = None
                self._depth = 0
            elif tag == "tr" and self._row is not None:
                if self._row:
                    log.debug("TableParser: closing row with %d cell(s)", len(self._row))
                    self.rows.append(self._row)
                else:
                    log.debug("TableParser: closing an empty row; dropping it")
                self._row = None
            elif self._cell is not None:
                log.debug(
                    "TableParser: closing nested <%s>; depth -> %d", tag, max(1, self._depth - 1)
                )
                self._depth = max(1, self._depth - 1)
            else:
                log.debug("TableParser: ignoring </%s> with no open cell or row", tag)

        def handle_data(self, data: str) -> None:
            if self._cell is not None:
                self._cell.append(data)
            else:
                log.debug("TableParser: discarding %d char(s) of text outside a cell", len(data))

    parser = TableParser()
    parser.feed(html)
    if not parser.rows:
        log.debug("_parse_lease_table: %d char(s) of HTML held no table rows", len(html))
        return pd.DataFrame(columns=["host", "mac_address", "ip_address", "valid_time"])
    log.debug("_parse_lease_table: parsed %d row(s) from %d char(s)", len(parser.rows), len(html))

    width = max(len(row) for row in parser.rows)
    normalised = [row + [""] * (width - len(row)) for row in parser.rows]
    columns = ["host", "mac_address", "ip_address", "valid_time"][:width]
    log.debug("_parse_lease_table: widest row has %d cell(s); labelling %s", width, columns)
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
    lines = _to_text(output).splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            log.debug("parse_windows_arp: skipping blank line")
            continue
        header = re.match(r"^Interface:\s*(\S+)", stripped)
        if header:
            interface = header.group(1)
            log.debug("parse_windows_arp: interface section is %s", interface)
            continue
        if stripped.lower().startswith("internet address"):
            log.debug("parse_windows_arp: skipping the column header line")
            continue
        parts = stripped.split()
        if len(parts) < 3:
            log.debug("parse_windows_arp: skipping %r: only %d field(s)", stripped, len(parts))
            continue
        ip, mac, entry_type = parts[0], parts[1], parts[2]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            log.debug(
                "parse_windows_arp: skipping %r: %r is not a dotted IPv4 address", stripped, ip
            )
            continue
        mac = normalise_mac(mac)
        if entry_type.lower() != "dynamic" or not _is_usable_host(ip, mac):
            log.debug(
                "parse_windows_arp: skipping %s: type %r is not dynamic or mac %s is unusable",
                ip,
                entry_type,
                mac,
            )
            continue
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": interface})
    log.debug("parse_windows_arp: kept %d row(s) from %d line(s)", len(rows), len(lines))
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
            log.debug("parse_proc_net_arp: skipping %r: %d field(s)", line, len(parts))
            continue
        ip, _hwtype, flags, mac, _mask, device = parts[:6]
        if flags.lower() in ("0x0", "0x00"):
            log.debug("skipping %s: flags %s show the entry was never resolved", ip, flags)
            continue
        mac = normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            log.debug("parse_proc_net_arp: skipping %s: mac %s is unusable", ip, mac)
            continue
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": device})
    log.debug("parse_proc_net_arp: kept %d row(s)", len(rows))
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
            log.debug("parse_ip_neigh: skipping %r: only %d field(s)", line, len(parts))
            continue
        ip = parts[0]
        if "lladdr" not in parts:
            log.debug(
                "skipping %s: state %s carries no lladdr, so the entry is unresolved",
                ip,
                parts[-1] if parts else "?",
            )
            continue
        mac = parts[parts.index("lladdr") + 1]
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None
        state = parts[-1] if parts[-1].isupper() else None
        mac = normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            log.debug("parse_ip_neigh: skipping %s: mac %s is unusable", ip, mac)
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
    log.debug("parse_ip_neigh: kept %d row(s)", len(rows))
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
            log.debug("parse_bsd_arp: skipping %r: no (ip) at mac pattern", line.strip())
            continue
        ip = match.group("ip")
        mac = normalise_mac(match.group("mac"))
        if not _is_usable_host(ip, mac):
            log.debug("parse_bsd_arp: skipping %s: mac %s is unusable", ip, mac)
            continue
        rows.append(
            {
                "ip": ip,
                "mac_address": mac,
                "mode": "arp",
                "interface": match.group("iface"),
            }
        )
    log.debug("parse_bsd_arp: kept %d row(s)", len(rows))
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
            log.debug("_validate: fetcher returned None; substituting the empty required frame")
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
        if missing:
            log.warning(
                "_validate: fetcher result of %d row(s) is missing column(s) %s (has %s)",
                len(frame),
                missing,
                list(frame.columns),
            )
            raise ValueError(f"fetcher result is missing columns: {missing}")
        log.debug("_validate: %d row(s) carry every required column", len(frame))
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
    if completed.stdout:
        output = completed.stdout
    else:
        output = ""
        log.debug("_run: %s produced no stdout to return", list(cmd))
    if not output:
        if completed.stderr:
            stderr = completed.stderr
        else:
            stderr = ""
            log.debug("_run: %s wrote nothing to stderr either", list(cmd))
        log.debug(
            "_run: %s produced no stdout (rc=%s, %d byte(s) of stderr)",
            list(cmd),
            completed.returncode,
            len(stderr),
        )
    else:
        log.debug("_run: %s produced %d char(s) of stdout", list(cmd), len(output))
    return output


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
            log.debug("UnixArpFetcher: /proc/net/arp answered with %d row(s)", len(frame))
            return frame
        log.debug("UnixArpFetcher: /proc/net/arp gave nothing; trying %s", list(self.COMMANDS))

        for command in self.COMMANDS:
            try:
                output = _run(command)
            except (OSError, subprocess.SubprocessError) as exc:
                log.debug(
                    "UnixArpFetcher: %s could not be run (%s): %s",
                    list(command),
                    type(exc).__name__,
                    exc,
                )
                continue
            if not output.strip():
                log.debug(
                    "UnixArpFetcher: %s produced no output; trying the next command", list(command)
                )
                continue
            frame = self._parse_by_command(command, output)
            if not frame.empty:
                log.debug("UnixArpFetcher: %s yielded %d row(s)", list(command), len(frame))
                return frame
            log.debug(
                "UnixArpFetcher: %s parsed to no usable rows; trying the next command",
                list(command),
            )
        log.debug("UnixArpFetcher: every local ARP mechanism came up empty")
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])

    @staticmethod
    def _from_proc() -> pd.DataFrame:
        proc = Path("/proc/net/arp")
        try:
            if proc.exists():
                log.debug("UnixArpFetcher: reading %s", proc)
                return parse_proc_net_arp(proc.read_text(encoding="utf-8", errors="ignore"))
            log.debug("UnixArpFetcher: %s does not exist on this host", proc)
        except OSError:  # pragma: no cover - unreadable procfs
            log.debug("UnixArpFetcher: %s exists but could not be read", proc)
        return pd.DataFrame(columns=["ip", "mac_address", "mode"])

    @staticmethod
    def _parse_by_command(command: Sequence[str], output: str) -> pd.DataFrame:
        if tuple(command[:2]) == ("ip", "neigh"):
            log.debug("UnixArpFetcher: parsing %s output as `ip neigh`", list(command))
            return parse_ip_neigh(output)
        system = platform.system().lower()
        if system == "windows":
            log.debug("UnixArpFetcher: parsing %s output as Windows `arp -a`", list(command))
            return parse_windows_arp(output)
        log.debug(
            "UnixArpFetcher: parsing %s output as BSD `arp -an` (platform %s)",
            list(command),
            system,
        )
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
        if browser:
            self.browser = browser
            log.debug("PlaywrightFetcher: browser engine requested explicitly as %r", browser)
        else:
            from_env = os.environ.get("PW_BROWSER", "").strip()
            if from_env:
                self.browser = from_env
                log.debug("PlaywrightFetcher: browser engine taken from PW_BROWSER=%r", from_env)
            else:
                self.browser = None
                log.debug("PlaywrightFetcher: no engine requested; will auto-detect on launch")

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
        if self.browser:
            if self.browser not in BROWSER_NAMES:
                log.warning(
                    "unknown browser engine %r requested; expected one of %s",
                    self.browser,
                    list(BROWSER_NAMES),
                )
                raise BrowserNotInstalled(
                    f"unknown browser engine {self.browser!r}; "
                    f"expected one of {', '.join(BROWSER_NAMES)}"
                )
            log.debug("browser engine %r is a known name; checking it is installed", self.browser)
        else:
            log.debug("no browser engine requested; will take the first installed one")

        detected = self.installed_browsers()
        log.debug("installed Playwright engines: %s", detected)

        if self.browser:
            if not detected.get(self.browser):
                log.warning(
                    "requested browser engine %r is not installed (detected: %s)",
                    self.browser,
                    detected,
                )
                raise BrowserNotInstalled(
                    f"the requested browser engine {self.browser!r} is not installed; "
                    f"run `playwright install {self.browser}`"
                )
            return self.browser

        for name in BROWSER_NAMES:
            if detected.get(name):
                log.info("Using Playwright browser engine: %s", name)
                return name
            log.debug("browser engine %s is not installed; trying the next candidate", name)

        log.warning("no Playwright browser is installed; checked %s", list(BROWSER_NAMES))
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
                log.debug("temp_dir_is_usable: %s is not a directory", directory)
                return False
        except OSError as exc:
            log.debug(
                "temp_dir_is_usable: %s could not be stat'ed (%s): %s",
                directory,
                type(exc).__name__,
                exc,
            )
            return False
        log.debug(
            "temp_dir_is_usable: probing %s with a real create (timeout %.1fs)", directory, timeout
        )

        result: Dict[str, bool] = {}

        def probe() -> None:
            handle = None
            name = None
            try:
                handle, name = tempfile.mkstemp(dir=str(directory), prefix=".probe-")
                result["ok"] = True
                log.debug("temp_dir_is_usable: created %s to test %s", name, directory)
            except OSError as exc:
                result["ok"] = False
                log.debug(
                    "temp_dir_is_usable: cannot create in %s (%s): %s",
                    directory,
                    type(exc).__name__,
                    exc,
                )
            finally:
                if handle is not None:
                    with contextlib.suppress(OSError):
                        log.debug("temp_dir_is_usable: closing probe handle for %s", directory)
                        os.close(handle)
                else:
                    log.debug("temp_dir_is_usable: no handle to close for %s", directory)
                if name is not None:
                    with contextlib.suppress(OSError):
                        log.debug("temp_dir_is_usable: unlinking probe file %s", name)
                        os.unlink(name)
                else:
                    log.debug("temp_dir_is_usable: no probe file to unlink in %s", directory)

        worker = threading.Thread(target=probe, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            # Wedged: treat as unusable and move on.  The thread is a daemon
            # so a stuck filesystem call cannot keep the process alive.
            log.warning("temp directory %s did not respond within %.1fs", directory, timeout)
            return False
        log.debug("temp_dir_is_usable: %s -> writable=%s", directory, result.get("ok", False))
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
            elif not raw:
                log.debug("resolve_driver_temp_dir: %s is unset; skipping it", name)
            else:
                log.debug(
                    "resolve_driver_temp_dir: skipping inherited %s=%r (POSIX path on Windows)",
                    name,
                    raw,
                )

        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        if local_appdata:
            candidates.append(Path(local_appdata) / "Temp")
        else:
            log.debug("resolve_driver_temp_dir: LOCALAPPDATA is unset; skipping it")
        system_root = os.environ.get("SYSTEMROOT", "").strip()
        if system_root:
            candidates.append(Path(system_root) / "Temp")
        else:
            log.debug("resolve_driver_temp_dir: SYSTEMROOT is unset; skipping it")

        # Our own scratch directory, created on demand.
        fallback = cls.FALLBACK_TEMP_DIR
        candidates.append(fallback)
        log.debug(
            "resolve_driver_temp_dir: %d candidate(s), in order: %s", len(candidates), candidates
        )

        seen = set()
        for candidate in candidates:
            key = str(candidate).lower()
            if key in seen:
                log.debug(
                    "resolve_driver_temp_dir: %s is a duplicate of an earlier candidate", candidate
                )
                continue
            seen.add(key)
            try:
                candidate.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                log.debug(
                    "resolve_driver_temp_dir: cannot create %s (%s): %s",
                    candidate,
                    type(exc).__name__,
                    exc,
                )
                continue
            if cls.temp_dir_is_usable(candidate):
                log.info("using %s as the Playwright driver temp directory", candidate)
                return candidate.resolve()
            log.debug(
                "resolve_driver_temp_dir: %s is not writable; trying the next candidate", candidate
            )

        log.warning("no writable temp directory among %s", candidates)
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
            log.debug("driver_env: pointing %s at %s", name, chosen)
            env[name] = chosen
        return env

    def run(self, context: Any, password: str) -> Any:  # pragma: no cover - abstract
        """Drive the page and return the scraped HTML."""
        raise NotImplementedError

    def get_password(self) -> str:
        """Password from the instance, the env, or an interactive prompt."""
        import os

        if self.password:
            log.debug("get_password: using the password supplied to the constructor")
            return self.password
        env_password = os.environ.get("TPLOGIN_PASSWORD", "").strip()
        if env_password:
            log.debug("get_password: using TPLOGIN_PASSWORD from the environment")
            return env_password
        log.debug("get_password: no password configured; prompting on the terminal")

        import getpass

        password = getpass.getpass("Please enter the router admin password: ")
        if not password:
            log.warning("get_password: the interactive prompt returned an empty password")
            raise ValueError("Password cannot be empty.")
        return password

    def iptable(self) -> pd.DataFrame:
        from playwright.sync_api import sync_playwright

        # Pick the engine *before* prompting for a password: there is no point
        # asking for credentials we cannot use, and the error is the useful
        # thing to surface when a machine has no browser at all.
        engine_name = self.browser_engine_name()
        password = self.get_password()
        log.debug("PlaywrightFetcher: launching %s (headless=%s)", engine_name, self.headless)
        self.HTML_DUMP.parent.mkdir(parents=True, exist_ok=True)

        # Playwright's Node driver picks its artifacts directory with
        # os.tmpdir(), which honours TMPDIR/TMP/TEMP with no fallback.  Hand
        # it an env whose temp dir is known to be writable, or the browser
        # launch dies (EPERM at mkdtemp on 3.13, WinError 5 inside asyncio's
        # pipe creation on 3.10) before it ever starts.
        with _driver_env_applied(self.driver_env()), sync_playwright() as playwright:
            log.debug("iptable: starting the %s browser (headless=%s)", engine_name, self.headless)
            try:
                browser = getattr(playwright, engine_name).launch(headless=self.headless)
            except Exception as exc:
                log.warning("could not launch the %s browser: %s", engine_name, exc)
                raise
            context = browser.new_context()
            try:
                html = self.run(context, password)
            finally:
                log.debug("iptable: closing the browser context and the browser")
                context.close()
                browser.close()

        log.debug("PlaywrightFetcher: scraped %d char(s); dumping to %s", len(html), self.HTML_DUMP)
        self.HTML_DUMP.write_text('<meta charset="utf-8">\n' + html, encoding="utf-8")
        return self.parse_html(self.HTML_DUMP)

    def _browser_name(self) -> str:
        """Deprecated alias for :meth:`browser_engine_name`."""
        log.debug("_browser_name is deprecated; delegating to browser_engine_name")
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
            log.debug("parse_html: pandas.read_html parsed %s into %d row(s)", path, len(frame))
        except (ImportError, ValueError) as exc:
            log.debug(
                "parse_html: read_html could not parse %s (%s); falling back to the stdlib parser",
                path,
                type(exc).__name__,
            )
            frame = _parse_lease_table(Path(path).read_text(encoding="utf-8"))

        frame = frame.iloc[1:, :].reset_index(drop=True)
        frame.columns = ["host", "mac_address", "ip_address", "valid_time"][: len(frame.columns)]
        frame["mac_address"] = frame["mac_address"].map(normalise_mac)
        frame["mode"] = "dhcp"
        frame["ip"] = frame["ip_address"]
        log.debug(
            "parse_html: %s yielded %d lease row(s), columns %s",
            path,
            len(frame),
            list(frame.columns),
        )
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

        if host:
            self.host = host
            log.debug("OpenWRTFetcher: host %r given explicitly (port %s)", host, port)
        else:
            env_host = os.environ.get("OPENWRT_HOST")
            self.host = env_host
            if env_host:
                log.debug("OpenWRTFetcher: host %r taken from OPENWRT_HOST", env_host)
            else:
                log.debug("OpenWRTFetcher: no host given and OPENWRT_HOST is unset; it cannot run")
        self.username = username
        self.port = port
        self.timeout = timeout

    def available(self) -> bool:
        log.debug("OpenWRTFetcher: available=%s (host=%r)", bool(self.host), self.host)
        return bool(self.host)

    def iptable(self) -> pd.DataFrame:
        if not self.host:
            log.warning("OpenWRTFetcher: no host configured; nothing to read over SSH")
            raise RuntimeError("OpenWRTFetcher needs a host (constructor arg or OPENWRT_HOST)")
        import asyncssh

        log.debug(
            "OpenWRTFetcher: reading /proc/net/arp from %s@%s:%s (timeout %.1fs)",
            self.username,
            self.host,
            self.port,
            self.timeout,
        )
        result = asyncssh.run(
            f"{self.username}@{self.host}",
            command="cat /proc/net/arp",
            port=self.port,
            connect_timeout=self.timeout,
        )
        return parse_proc_net_arp(result.stdout)


class FetcherChain(ARPTableFetcher):
    """Try each source in order and return the first usable table.

    The capability the engine was built around, kept because it is still a
    legitimate thing to *ask* for — one cheap source and no merging — but no
    longer what a scan does by default.

    It is deliberately **not** the engine's fetch path any more.  Two things a
    scan wants are missing from it:

    * it discards everything the other sources found, and
    * it waits, serially, for one source to answer before trying the next.

    :class:`~my_lan_prober.expanders.TableUnion` replaces both: every source
    contributes, and sources run concurrently in dependency order.  Selecting
    this class explicitly is how a caller opts back into the old serial
    behaviour.
    """

    def __init__(self, fetchers: Sequence[ARPTableFetcher]) -> None:
        self._fetchers: List[ARPTableFetcher] = []
        for fetcher in fetchers:
            if isinstance(fetcher, FetcherChain):
                log.debug(
                    "FetcherChain: flattening nested chain of %d source(s)", len(fetcher._fetchers)
                )
                self._fetchers.extend(fetcher._fetchers)
            else:
                log.debug("FetcherChain: added %s", type(fetcher).__name__)
                self._fetchers.append(fetcher)
        log.debug("FetcherChain: %d source(s) in order: %s", len(self._fetchers), self._names())

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
                log.debug(
                    "ARP source %s returned an empty table; trying the next source",
                    type(fetcher).__name__,
                )
                continue
            log.info("ARP table from %s (%d entries)", type(fetcher).__name__, len(frame))
            return frame

        if errors:
            log.warning("no ARP source produced a table: %s", errors)
            raise RuntimeError("no ARP source produced a table: " + "; ".join(errors))
        log.warning("every ARP source is unavailable here: %s", unavailable)
        raise RuntimeError(
            "every ARP source is unavailable here: "
            + ", ".join(unavailable)
            + " (no Playwright browser installed? run `playwright install`)"
        )

    def _names(self) -> List[str]:
        """The configured sources by class name, for logging."""
        return [type(fetcher).__name__ for fetcher in self._fetchers]

    @staticmethod
    def _is_available(fetcher: ARPTableFetcher) -> bool:
        """Whether ``fetcher`` can run here; a broken check is not fatal."""
        try:
            return fetcher.available()
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("availability check for %s raised: %s", type(fetcher).__name__, exc)
            return False


def default_fetcher_chain(browser: Optional[str] = None) -> FetcherChain:
    """The legacy serial selection: TP-Link, then the local ARP table.

    **Not what a scan does by default.**  The engine goes through
    :class:`~my_lan_prober.registry.FetcherRegistry` and merges every selected
    source with :class:`~my_lan_prober.expanders.TableUnion`; this helper is
    kept for a caller who explicitly wants the old behaviour — try one source,
    take the first table that answers, discard the rest.

    It is no longer described as *the* fallback, because nothing falls back any
    more: all the sources run and all their tables are merged.
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
    log.debug("_driver_env_applied: overrode %s for the duration of the block", sorted(env))
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
                log.debug("_driver_env_applied: removed %s again (it was unset)", name)
            else:
                os.environ[name] = value
                log.debug("_driver_env_applied: restored %s=%s", name, value)
