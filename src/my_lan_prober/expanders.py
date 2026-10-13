"""Expanders — fetchers that turn other fetchers' tables into bigger ones.

``design.md`` § 7 describes a fetcher as "a source of an address table".  An
**expander** is the mirror image, and the reason this module exists:

    a table answers *who did I already know about?*
    an expander answers *who else can I now reach, given that table?*

Two shapes of expansion fall out of the ``FQDN`` polymorphism:

:class:`ArpTableExpander`
    the abstract contract.  It holds a list of upstream fetchers, merges their
    tables, and adds rows.  It never removes a row, so the result is strictly a
    superset of what the upstreams produced.

:class:`SSHArpTableExpander`
    the concrete one.  It reads the SSH known-hosts file, and for every host
    the upstream table named — and every host its probes reveal in turn — it
    runs the same neighbour-table command the local fetchers parse.  This is
    how a host that is only reachable *through* another host stops being
    invisible: the remote neighbour table is a second ARP table, one hop away.

:class:`SSHHopExpander`
    walks an explicit ``bastion>jump>target`` chain, one fetcher per hop.

:class:`TableUnion`
    the degenerate expander: merge, deduplicate, add nothing.  It is what turns
    "the first non-empty source wins" into "every source contributes".

Provenance is part of the row, not a debugging afterthought: ``source`` says
which fetcher produced it, ``via`` says which SSH hop it came through, and
``depth`` says how many expansions away it was.  Merging tables from four
sources without that is how a scan report becomes unfalsifiable.
"""

from __future__ import annotations

import asyncio
import logging
from abc import abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

import pandas as pd

from .bridge import default_bridge
from .fetchers import (
    REQUIRED_COLUMNS,
    ARPTableFetcher,
    _validate_frame,
    merge_tables,
    parse_ip_neigh,
    parse_proc_net_arp,
)
from .fqdn import FQDN
from .scheduling import PriorityGraph

log = logging.getLogger(__name__)

__all__ = [
    "ArpTableExpander",
    "SSHArpTableExpander",
    "SSHHopExpander",
    "TableUnion",
    "KNOWN_HOSTS_TEMPLATE",
    "REMOTE_NEIGHBOUR_COMMANDS",
]

#: Template for the SSH known-hosts file, when no path is given.
KNOWN_HOSTS_TEMPLATE = "~/.ssh/known_hosts"

#: Neighbour-table commands tried on a remote host, in order.  Each output is
#: fed to the same parser the local fetchers use: the remote table *is* an ARP
#: table, so it must not get a second, subtly different parser.
REMOTE_NEIGHBOUR_COMMANDS: Sequence[str] = (
    "cat /proc/net/arp",
    "ip neigh show",
    "arp -an",
)

#: Default bound on how far the SSH walk recurses.  A LAN has loops (two hosts
#: that both know each other) and an unbounded walk never terminates.
DEFAULT_MAX_DEPTH = 2


def _asyncssh_available() -> bool:
    """Whether the optional ``ssh`` extra is installed.

    Checked with ``find_spec`` rather than a real import: the answer is needed
    at decision time, and importing a transport library to ask whether it is
    installed is a side effect with no upside.
    """
    import importlib.util

    try:
        found = importlib.util.find_spec("asyncssh") is not None
        log.debug("asyncssh installed: %s", found)
        return found
    except (ImportError, ValueError):  # pragma: no cover - broken environment
        log.debug("could not tell whether asyncssh is installed; assuming it is not")
        return False


def _as_fetcher_list(upstream: Any) -> List[ARPTableFetcher]:
    """Normalise ``upstream`` into a list of fetchers, rejecting anything else."""
    if isinstance(upstream, ARPTableFetcher):
        candidates: Iterable[Any] = [upstream]
        log.debug("upstream is a single fetcher %s", type(upstream).__name__)
    elif isinstance(upstream, (list, tuple)):
        candidates = upstream
        log.debug("upstream is a sequence of %d candidate(s)", len(upstream))
    else:
        candidates = [upstream]
        log.debug("upstream is a single non-fetcher candidate %r", type(upstream).__name__)

    fetchers: List[ARPTableFetcher] = []
    for candidate in candidates:
        if not isinstance(candidate, ARPTableFetcher):
            log.debug(
                "rejecting upstream entry of type %s: not an ARPTableFetcher",
                type(candidate).__name__,
            )
            raise TypeError(
                "an expander's upstream must be an ARPTableFetcher (or a list of them); "
                f"got {type(candidate).__name__}"
            )
        fetchers.append(candidate)
    log.debug("upstream resolved to %d fetcher(s)", len(fetchers))
    return fetchers


# ---------------------------------------------------------------------------
# The abstract contract
# ---------------------------------------------------------------------------
class ArpTableExpander(ARPTableFetcher):
    """A fetcher that grows the tables other fetchers produced.

    Subclasses implement :meth:`expand`, which receives the merged upstream
    table and returns *additional* rows.  The base class owns everything else:
    calling the upstreams safely, merging their tables, tagging provenance, and
    combining the result with the extra rows.

    An expander is **deferred** by default.  Without a table to expand it has
    nothing to do, so it declares a dependency on its upstreams *and* a
    negative priority: the dependency is what makes the result correct, the
    negative priority is what keeps it out of the way while the fast, local
    sources are still answering.
    """

    #: Expansion is the slow, optional half of a scan; go after the sources.
    priority = -1

    def __init__(self, upstream: Any = None) -> None:
        self.upstream: List[ARPTableFetcher] = _as_fetcher_list(upstream) if upstream else []

    def dependency(self) -> List[Any]:
        """The upstreams: expansion is meaningless before they have answered."""
        return [type(fetcher) for fetcher in self.upstream]

    # -- the contract ---------------------------------------------------
    @abstractmethod
    def expand(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Return extra rows reachable from ``frame``.

        ``frame`` is the merged, provenance-tagged upstream table.  The return
        value need only have an ``ip`` column; the base class fills in the rest.
        """
        raise NotImplementedError

    # -- upstream handling ---------------------------------------------
    def upstream_tables(self) -> List[tuple]:
        """Every upstream table that could be fetched, with the fetcher it came from.

        Called once per :meth:`iptable`, and the *only* place an upstream is
        actually invoked: a caller that needs the tables twice (to merge them
        and to inspect them) must hold on to the result rather than calling
        again, because a fetcher can have side effects — a Playwright scrape
        logs into the router, an SSH probe opens a connection.
        """
        tables: List[tuple] = []
        for fetcher in self.upstream:
            log.debug("considering upstream %s for expansion", type(fetcher).__name__)
            if not _is_available(fetcher):
                log.debug("skipping unavailable upstream %s", type(fetcher).__name__)
                continue
            try:
                tables.append((fetcher, _validate_frame(fetcher.iptable())))
            except Exception as exc:
                log.warning("upstream %s failed: %s", type(fetcher).__name__, exc)
        log.debug("collected %d upstream table(s)", len(tables))
        return tables

    def merged_upstream(self) -> pd.DataFrame:
        """The upstream tables merged into one, tagged with their source."""
        tagged = [
            _tag(table, source=type(fetcher).__name__, depth=0)
            for fetcher, table in self.upstream_tables()
        ]
        # An expander is a *source*: what its upstreams already knew arrives at
        # depth 0, whatever chain it travelled to get here.  Depth counts the
        # steps *this* expander added, not the history of the table it read.
        for table in tagged:
            if "depth" in table.columns:
                table["depth"] = 0
                log.debug("reset the upstream table's depth to 0 at the expander boundary")
            else:
                log.debug("upstream table carries no depth column; it counts as depth 0")
        if not tagged:
            log.debug("no upstream produced a table; %s expands nothing", type(self).__name__)
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        merged = merge_tables(tagged)
        log.debug(
            "merged %d upstream table(s) into %d depth-0 row(s)",
            len(tagged),
            len(merged),
        )
        return merged

    def available(self) -> bool:
        """An expander is available when at least one upstream is."""
        return any(_is_available(fetcher) for fetcher in self.upstream)

    # -- the fetcher port ----------------------------------------------
    def iptable(self) -> pd.DataFrame:
        base = self.merged_upstream()
        try:
            extra = self.expand(base)
        except Exception as exc:
            log.warning("%s could not expand its table: %s", type(self).__name__, exc)
            return base

        if extra is None or len(extra) == 0:
            log.debug(
                "%s derived no extra row(s); its upstream table stands",
                type(self).__name__,
            )
            return base

        # Rows that `expand` derived *from* the upstream table inherit its
        # provenance columns by accident (an expander that copies the frame it
        # was handed gets `source`/`depth` for free).  Those columns describe
        # where the row was *found*, and a derived row was not found there:
        # whichever expander produced it is its source, one step deeper.
        #
        # A row that already records a depth *greater* than the upstream's was
        # labelled deliberately — an SSH walk reaches several depths in one
        # call — and that label is the more informative one, so it stands.
        upstream_depth = _depth_of(base)
        extra = _reassign_provenance(
            extra,
            source=type(self).__name__,
            depth=upstream_depth + 1,
            floor=upstream_depth,
        )
        if base.empty:
            log.debug(
                "%s derived %d row(s) with no upstream table to merge them into",
                type(self).__name__,
                len(extra),
            )
            return merge_tables([extra])
        log.debug(
            "%s added %d row(s) at depth %d on top of %d upstream row(s)",
            type(self).__name__,
            len(extra),
            upstream_depth + 1,
            len(base),
        )
        return merge_tables([base, extra])

    # -- helper for subclasses -----------------------------------------
    def _rows_without_upstream_coverage(
        self, frame: pd.DataFrame, base: pd.DataFrame
    ) -> pd.DataFrame:
        """Drop rows whose address the upstream table already carries."""
        if base.empty or frame.empty:
            log.debug(
                "no upstream coverage to subtract: %d candidate row(s), %d upstream row(s)",
                len(frame),
                len(base),
            )
            return frame
        known = set(base["ip"].astype(str))
        covered = frame[~frame["ip"].astype(str).isin(known)].reset_index(drop=True)
        log.debug(
            "dropped %d of %d candidate row(s) already covered by the upstream table",
            len(frame) - len(covered),
            len(frame),
        )
        return covered


# ---------------------------------------------------------------------------
# Provenance tagging
# ---------------------------------------------------------------------------
def _depth_of(frame: pd.DataFrame) -> int:
    """The deepest provenance level present in a table.

    ``0`` for a table that carries no depth at all — a fetcher's own rows, or
    one that has not been through an expander yet.
    """
    if frame is None or frame.empty or "depth" not in frame.columns:
        log.debug("table carries no depth provenance; reporting depth 0")
        return 0
    recorded = pd.to_numeric(frame["depth"], errors="coerce")
    if recorded.isna().all():
        log.debug("every recorded depth is unusable; reporting depth 0")
        return 0
    deepest = int(recorded.max())
    log.debug("deepest provenance level in the table is %d", deepest)
    return deepest


def _reassign_provenance(
    frame: pd.DataFrame, *, source: str, depth: int, floor: int
) -> pd.DataFrame:
    """Re-label derived rows, keeping any deliberate deeper labelling.

    A row whose recorded depth is no deeper than ``floor`` — the table it was
    derived from — carries that depth only because it was copied along with the
    frame.  A row recorded *deeper* than ``floor`` was labelled on purpose by
    an expander that tracks several depths at once, and is left alone.
    """
    relabelled = frame.copy()
    relabelled["source"] = source
    if "depth" not in relabelled.columns:
        relabelled["depth"] = depth
        log.debug("labelled %d derived row(s) as %s at depth %d", len(relabelled), source, depth)
    else:
        recorded = pd.to_numeric(relabelled["depth"], errors="coerce")
        relabelled["depth"] = recorded.where(recorded > floor, depth).astype(int)
        kept = int((recorded > floor).sum())
        log.debug(
            "relabelled %d derived row(s) as %s at depth %d, keeping %d deeper label(s)",
            len(relabelled),
            source,
            depth,
            kept,
        )
    return relabelled


def _tag(
    frame: pd.DataFrame,
    *,
    source: str,
    depth: Optional[int] = None,
    via: Optional[str] = None,
) -> pd.DataFrame:
    """Give a freshly fetched table its provenance.

    Used where the depth *is* known exactly — a fetcher's own rows, one hop of
    a chain — so it assigns rather than fills.  ``missing`` depths are still
    filled in rather than clobbered, because a table may already be partly
    labelled.
    """
    tagged = frame.copy()
    if "source" not in tagged.columns or tagged["source"].isna().all():
        tagged["source"] = source
        log.debug("tagged %d row(s) with source %s", len(tagged), source)
    else:
        missing = int(tagged["source"].isna().sum())
        tagged["source"] = tagged["source"].fillna(source)
        log.debug(
            "kept the recorded source on %d row(s); filled %d blank one(s)", len(tagged), missing
        )
    if depth is not None:
        if "depth" not in tagged.columns or tagged["depth"].isna().all():
            tagged["depth"] = depth
            log.debug("tagged %d row(s) with depth %d", len(tagged), depth)
        else:
            tagged["depth"] = pd.to_numeric(tagged["depth"], errors="coerce")
            log.debug("kept the depth already recorded on %d row(s)", len(tagged))
    if via is not None:
        tagged["via"] = via
        log.debug("tagged %d row(s) as reached via %s", len(tagged), via)
    return tagged


def _is_available(fetcher: ARPTableFetcher) -> bool:
    """Whether ``fetcher`` can run here; a broken check is not fatal."""
    try:
        return fetcher.available()
    except Exception as exc:
        log.debug("availability check for %s raised: %s", type(fetcher).__name__, exc)
        return False


# ---------------------------------------------------------------------------
# TableUnion — merge everything, and schedule it properly
# ---------------------------------------------------------------------------
class TableUnion(ArpTableExpander):
    """Every source's table, merged into one — scheduled rather than serialised.

    The engine used to stop at the first source that produced a non-empty
    table, which silently discarded hosts: the router's lease table knows DHCP
    clients, the local neighbour table knows the machines this host actually
    talked to, and a resolver knows names neither of them has ever seen.

    Two things changed once the sources stopped being a fallback *chain*:

    * every source contributes, so nothing is thrown away; and
    * the sources run **concurrently**, in dependency order, because waiting
      for one of them to succeed while another could already be running is
      wasted wall-clock time.  ``max_task`` bounds how many run at once.

    The execution plan comes from :class:`~my_lan_prober.scheduling.PriorityGraph`:
    levels from the declared dependency graph, deferred sources last, run from
    the highest level down, each level concurrent.
    """

    #: A union is a container, not a source: on its own it has nothing to add,
    #: and whatever it wraps is what the caller actually wants run.
    priority = -1

    #: How many fetchers may be in flight at once, by default.
    DEFAULT_MAX_TASK = 8

    def __init__(self, upstream: Any = None, *, max_task: Optional[int] = None) -> None:
        super().__init__(upstream)
        limit = self.DEFAULT_MAX_TASK if max_task is None else int(max_task)
        if limit < 1:
            log.debug("rejecting max_task=%r: a union must allow at least one task", max_task)
            raise ValueError(f"max_task must be >= 1, got {max_task!r}")
        #: Concurrency cap for one level.  Named ``max_task`` to match the CLI.
        self.max_task = limit
        log.debug("%s will run at most %d source(s) at once", type(self).__name__, limit)

    # -- the plan -------------------------------------------------------
    def assign_priorities(self) -> dict:
        """Solve the dependency graph and write the levels onto the sources.

        Does not fetch anything: the graph is a property of the declarations,
        which is what makes it testable without a network.
        """
        graph = PriorityGraph(self.upstream)
        return graph.assign()

    def plan(self) -> list:
        """The execution phases as lists of source names, first phase first."""
        return PriorityGraph(self.upstream).plan()

    # -- expansion ------------------------------------------------------
    def expand(self, frame: pd.DataFrame) -> pd.DataFrame:
        """A union adds nothing of its own; it *is* the merge of its sources."""
        return pd.DataFrame(columns=list(REQUIRED_COLUMNS))

    # -- execution ------------------------------------------------------
    def upstream_tables(self) -> List[tuple]:
        """Fetch every source, phase by phase, concurrently inside a phase."""
        graph = PriorityGraph(self.upstream)
        graph.assign()
        phases = graph.phases()

        log.info(
            "ARP sources scheduled in %d phase(s): %s",
            len(phases),
            " | ".join(" + ".join(type(f).__name__ for f in phase) for phase in phases),
        )

        collected: List[tuple] = []
        for index, phase in enumerate(phases, start=1):
            runnable = [fetcher for fetcher in phase if _is_available(fetcher)]
            for fetcher in phase:
                if fetcher not in runnable:
                    log.debug("ARP source %s is not available here", type(fetcher).__name__)
            if not runnable:
                log.debug("phase %d has no runnable source; skipping it", index)
                continue

            log.debug("phase %d: %d source(s)", index, len(runnable))
            collected.extend(self._run_phase(runnable))
        return collected

    def _run_phase(self, fetchers: Sequence[ARPTableFetcher]) -> List[tuple]:
        """Run one phase's fetchers concurrently and collect their tables.

        The bridge owns a loop in a background thread, so the synchronous
        ``iptable()`` of each source is dispatched into a thread pool from
        inside it.  A source that raises is logged and skipped: one broken
        router must not cost the scan the other sources' findings.
        """
        if len(fetchers) == 1:
            log.debug(
                "phase of one source: running %s without a task pool", type(fetchers[0]).__name__
            )
            single = self._fetch_one(fetchers[0])
            return [single] if single is not None else []

        limiter = asyncio.Semaphore(self.max_task)

        async def guarded(fetcher: ARPTableFetcher):
            async with limiter:
                log.debug("running %s under the %d-task cap", type(fetcher).__name__, self.max_task)
                return await asyncio.to_thread(self._fetch_one, fetcher)

        async def gather():
            log.debug("gathering %d source(s) concurrently", len(fetchers))
            return await asyncio.gather(*(guarded(fetcher) for fetcher in fetchers))

        results = default_bridge().run(gather())
        tables = [table for table in results if table is not None]
        log.debug("%d of %d source(s) in the phase produced a table", len(tables), len(fetchers))
        return tables

    @staticmethod
    def _fetch_one(fetcher: ARPTableFetcher) -> Optional[tuple]:
        """Fetch one source, returning ``(fetcher, table)`` or ``None``."""
        try:
            table = _validate_frame(fetcher.iptable())
        except Exception as exc:
            log.warning("upstream %s failed: %s", type(fetcher).__name__, exc)
            return None
        return (fetcher, table)

    def iptable(self) -> pd.DataFrame:
        # Deliberately *not* going through ArpTableExpander.iptable: a union
        # that raises when every source failed must be loud, because "no ARP
        # source worked" is a different outcome from "no hosts found".
        if not self.upstream:
            # A union of nothing is nothing.  Raising here would turn "the
            # caller selected no sources" into a crash on a legitimate input.
            log.debug("union has no upstream source; returning an empty table")
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))

        tables = self.upstream_tables()
        if not tables:
            available = [fetcher for fetcher in self.upstream if _is_available(fetcher)]
            if available:
                log.debug("no table, but %d source(s) reported available", len(available))
                raise RuntimeError(
                    "no ARP source produced a table: "
                    + "; ".join(type(fetcher).__name__ for fetcher in available)
                )
            log.debug("all %d ARP source(s) are unavailable here", len(self.upstream))
            raise RuntimeError(
                "every ARP source is unavailable here: "
                + ", ".join(type(fetcher).__name__ for fetcher in self.upstream)
            )

        # Reuse the tables already fetched, never call a source again: fetching
        # is where the side effects live (a Playwright scrape logs into the
        # router, an SSH probe opens a connection).
        tagged = [
            _tag(table, source=type(fetcher).__name__, depth=_depth_of(table))
            for fetcher, table in tables
        ]
        merged = self.merge(tagged)
        log.info(
            "Merged ARP table: %d host(s) from %d source(s): %s",
            len(merged),
            len(tagged),
            ", ".join(sorted({str(name) for name in merged.get("source", [])})),
        )
        return merged

    def merge(self, tables: Sequence[pd.DataFrame]) -> pd.DataFrame:
        """Combine the phase results.  Overridable, because merging is policy."""
        return merge_tables(tables)


# ---------------------------------------------------------------------------
# SSHArpTableExpander
# ---------------------------------------------------------------------------
class SSHArpTableExpander(ArpTableExpander):
    """Reach the hosts the upstream table named, over SSH, and read *their* table.

    A LAN is not flat.  The machine running the prober sees its own neighbours;
    the router sees every DHCP lease; a server two hops away sees a whole
    subnet neither of them can reach.  Expansion is what closes that gap: for
    every host the upstream table produced — and every host those probes reveal
    in turn, up to ``max_depth`` — run the neighbour-table command over SSH and
    add the result to the table being built.

    Two deliberate limits:

    * the walk is **opt-in** (``enabled``): logging into other people's
      machines is invasive, and a scanner that does it by accident is a
      liability.  ``available()`` therefore reports ``False`` unless the caller
      switched it on *and* named a hop;
    * the walk is **bounded** (``max_depth``): real LANs contain cycles, and
      two hosts that both know each other would otherwise recurse forever.
    """

    #: Remote commands tried in order; the first non-empty output wins.
    COMMANDS: Sequence[str] = REMOTE_NEIGHBOUR_COMMANDS

    def __init__(
        self,
        upstream: Any = None,
        *,
        hop: Optional[str] = None,
        known_hosts: Any = None,
        probe: Optional[Callable[..., str]] = None,
        enabled: bool = False,
        max_depth: int = DEFAULT_MAX_DEPTH,
        username: Optional[str] = None,
        port: int = 22,
        timeout: float = 10.0,
    ) -> None:
        super().__init__(upstream)
        self._known_hosts_path = Path(known_hosts).expanduser() if known_hosts else None
        self._probe = probe
        self.enabled = enabled
        self.max_depth = max(1, int(max_depth))
        self.username = username
        self.port = port
        self.timeout = timeout
        #: The first hop, or ``None`` to fall back to ``SSH_HOP`` at call time.
        self._hop = hop
        #: Hosts whose known-hosts aliases should be seeded into the walk.
        self.seed_from_known_hosts = True

    # -- configuration --------------------------------------------------
    @property
    def hop(self) -> Optional[str]:
        """The SSH hop to log into, from the constructor or ``SSH_HOP``."""
        import os

        if self._hop:
            log.debug("using the SSH hop configured on the expander: %s", self._hop)
            return self._hop
        from_env = os.environ.get("SSH_HOP", "").strip()
        if not from_env:
            log.debug("no hop configured on the expander and SSH_HOP is unset or blank")
            return None
        log.debug("no hop configured on the expander; SSH_HOP names %s", from_env)
        return from_env

    def available(self) -> bool:
        """Only an explicitly enabled expander with a hop can run.

        ``enabled`` is checked even when a probe was injected: a caller that
        wired a probe in has already opted in, but the *default* must stay
        opt-out, and one rule for both is easier to reason about than two.
        """
        if not self.enabled:
            log.debug("SSH expansion is opt-in and not enabled here")
            return False
        if not self.hop:
            log.debug("SSH expansion has no hop to log into")
            return False
        if self._probe is None and not _asyncssh_available():
            log.warning("SSH expansion needs asyncssh: `uv sync --extra ssh`")
            return False
        any_upstream_available = any(_is_available(fetcher) for fetcher in self.upstream)
        if not any_upstream_available and not self.seed_from_known_hosts:
            log.debug("SSH expansion has no reachable upstream and no known-hosts seeding")
            return False
        log.debug(
            "SSH expansion available: upstream reachable=%s, seed_from_known_hosts=%s",
            any_upstream_available,
            self.seed_from_known_hosts,
        )
        return True

    # -- known hosts ----------------------------------------------------
    def known_hosts_path(self) -> Path:
        if self._known_hosts_path is not None:
            log.debug("using the configured known-hosts file %s", self._known_hosts_path)
            return self._known_hosts_path
        default = Path(KNOWN_HOSTS_TEMPLATE).expanduser()
        log.debug("no known-hosts file configured; falling back to %s", default)
        return default

    def known_hosts(self) -> List[str]:
        """Host names from the SSH known-hosts file, in file order.

        Hashed entries (``|1|base64|base64``) are skipped: they are hashed
        precisely so that reading them is not possible, and guessing which host
        they name would be worse than not knowing.
        """
        try:
            text = self.known_hosts_path().read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            log.debug("no readable known-hosts file at %s: %s", self.known_hosts_path(), exc)
            return []

        hosts: List[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("|"):
                log.debug("skipping blank, comment or hashed known-hosts line")
                continue
            # The host field is column 0; anything after it is key material.
            field = stripped.split()[0]
            # OpenSSH allows a leading marker such as ``@cert-authority``.
            if field.startswith("@"):
                parts = stripped.split()
                if len(parts) < 2:
                    log.debug("known-hosts marker %s names no host; skipping the line", field)
                    continue
                field = parts[1]
            for name in field.split(","):
                name = name.strip()
                if name and name not in hosts:
                    hosts.append(name)
                else:
                    log.debug("ignoring repeated or empty known-hosts alias %r", name)
        log.debug("read %d host alias(es) from the known-hosts file", len(hosts))
        return hosts

    def seed_hosts(self, base: pd.DataFrame) -> List[str]:
        """The hosts to probe first: the configured hop, then the upstream table."""
        seeds: List[str] = []
        if self.hop:
            seeds.append(self.hop)
            log.debug("seeding the walk with the configured hop %s", self.hop)
        for column in ("fqdn", "host", "ip"):
            if column in base.columns:
                for value in base[column].dropna().astype(str):
                    if value and value not in seeds:
                        seeds.append(value)
                    else:
                        log.debug(
                            "upstream column %s repeats seed host %r; skipping it", column, value
                        )
        log.debug("seeded the SSH walk with %d host(s)", len(seeds))
        return seeds

    # -- probing --------------------------------------------------------
    def ssm_probe(self, host: str) -> str:
        """Read ``host``'s neighbour table over SSH (the real, default probe)."""
        import asyncio

        import asyncssh

        if self.username:
            target = f"{self.username}@{host}"
            log.debug("probing %s as %s on port %d", host, self.username, self.port)
        else:
            target = host
            log.debug("probing %s with the default SSH user on port %d", host, self.port)

        async def run() -> str:
            async with asyncssh.connect(
                target,
                port=self.port,
                connect_timeout=self.timeout,
            ) as connection:
                log.debug("SSH connection to %s established on port %d", target, self.port)
                for command in self.COMMANDS:
                    result = await connection.run(command, check=False)
                    raw = getattr(result, "stdout", "")
                    if not raw:
                        log.debug("remote %s returned no stdout at all for %r", host, command)
                        raw = ""
                    else:
                        log.debug("remote %s returned %d byte(s) of stdout", host, len(raw))
                    if isinstance(raw, bytes):
                        log.debug(
                            "remote %s returned bytes for %r; decoding as UTF-8", host, command
                        )
                        output = raw.decode("utf-8", "ignore")
                    else:
                        output = raw
                    if output.strip():
                        log.debug(
                            "remote %s answered %r with %d byte(s)", host, command, len(output)
                        )
                        return output
                    log.debug("remote %s produced no output for %r", host, command)
                log.debug("no neighbour command produced output on %s", host)
                return ""

        return asyncio.run(run())

    def _probe_host(self, host: str) -> str:
        """Probe one host, through the injected probe or the real one."""
        if self._probe:
            probe = self._probe
            log.debug("probing %s through the injected probe", host)
        else:

            def probe(target: str, command: Optional[str] = None, **kwargs: Any) -> str:
                return self.ssm_probe(target)

            log.debug("probing %s through the default SSH probe", host)
        try:
            # The injected probe is called with the host and a representative
            # command, so a test can see *what* would be run without a network.
            log.debug("probing %s with %r", host, self.COMMANDS[0])
            output = probe(host, self.COMMANDS[0])
        except TypeError:
            log.debug(
                "probe of %s accepts no command argument; calling it with the host alone", host
            )
            output = probe(host)
        except Exception as exc:
            log.warning("SSH probe of %s failed: %s", host, exc)
            return ""
        if isinstance(output, bytes):
            log.debug("probe of %s returned bytes; decoding as UTF-8", host)
            output = output.decode("utf-8", "ignore")
        if not output:
            log.debug("probe of %s returned nothing", host)
            return ""
        log.debug("probe of %s returned %d character(s)", host, len(output))
        return output

    @staticmethod
    def parse_neighbour_output(output: str) -> pd.DataFrame:
        """Parse remote neighbour output with the fetchers' own parsers."""
        if not output.strip():
            log.debug("remote neighbour table was empty; nothing to parse")
            return pd.DataFrame(columns=["ip", "mac_address", "mode"])
        frame = parse_proc_net_arp(output)
        if frame.empty:
            log.debug("output is not a /proc/net/arp table; retrying with the ip-neigh parser")
            frame = parse_ip_neigh(output)
        log.debug("parsed %d neighbour row(s) from the remote host", len(frame))
        return frame

    # -- the expansion --------------------------------------------------
    def expand(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Walk the LAN over SSH, breadth-first, up to ``max_depth`` hops.

        ``max_depth`` bounds how many *tables* the walk collects, not how far
        it will look for them.  A hop that answers with nothing costs nothing
        and must not consume the budget: an unreachable neighbour is the normal
        case on a LAN, and letting it end the walk would make expansion depend
        on which host happened to answer first.
        """
        collected: List[pd.DataFrame] = []
        pending: List[tuple] = [(host, 1) for host in self.seed_hosts(frame)]
        visited = set()
        log.debug(
            "SSH walk starting from %d seed host(s), bounded to %d table(s)",
            len(pending),
            self.max_depth,
        )

        while pending and len(collected) < self.max_depth:
            host, depth = pending.pop(0)
            if host in visited:
                log.debug("hop %s at depth %d was already visited; skipping it", host, depth)
                continue
            visited.add(host)

            output = self._probe_host(host)
            table = self.parse_neighbour_output(output)
            if table.empty:
                log.debug("hop %s at depth %d revealed no neighbour", host, depth)
                continue

            table = _tag(table, source=type(self).__name__, depth=depth, via=host)
            collected.append(table)
            log.info("SSH expansion via %s: %d host(s)", host, len(table))
            log.debug("hop %s at depth %d revealed %d host(s)", host, depth, len(table))

            for discovered in table["ip"].dropna().astype(str):
                if discovered not in visited:
                    pending.append((discovered, depth + 1))
                else:
                    log.debug("discovered host %s is already visited; not queueing it", discovered)

        if not collected:
            log.debug(
                "SSH walk from %d seed host(s) found no neighbour table within depth %d",
                len(visited),
                self.max_depth,
            )
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        # No coverage filter here: the whole point of the walk is to reach
        # hosts the upstream table *could not* see.  A remote neighbour table
        # legitimately reports addresses the local table also knows — that is
        # agreement, not redundancy — and merge_tables() deduplicates them.
        merged = merge_tables(collected)
        log.debug(
            "SSH walk collected %d hop table(s) reaching %d host(s)",
            len(collected),
            len(merged),
        )
        return merged


# ---------------------------------------------------------------------------
# SSHHopExpander
# ---------------------------------------------------------------------------
class SSHHopExpander(ArpTableExpander):
    """Walk an explicit ``bastion>jump>target`` chain, one fetcher per hop.

    Where :class:`SSHArpTableExpander` discovers its hops from a table, this one
    is handed the FQDN hop chain itself.  Each hop gets its own fetcher (built
    by ``fetcher_for``), so a caller can decide per hop how to reach it — a
    different key, a different port, a different tool entirely.
    """

    def __init__(
        self, hops: Iterable[str], *, fetcher_for: Callable[[str], ARPTableFetcher]
    ) -> None:
        chain = (
            FQDN(">".join(str(hop) for hop in hops))
            if not isinstance(hops, (str, FQDN))
            else FQDN(hops)
        )
        self.hops: List[str] = list(chain.hops)
        self._fetcher_for = fetcher_for
        log.debug("SSH hop chain resolved to %d hop(s): %s", len(self.hops), " > ".join(self.hops))
        super().__init__([])

    def available(self) -> bool:
        if not self.hops:
            log.debug("SSH hop expander has an empty hop chain")
        return bool(self.hops)

    def expand(self, frame: pd.DataFrame) -> pd.DataFrame:
        collected: List[pd.DataFrame] = []
        for index, hop in enumerate(self.hops, start=1):
            log.debug("probing hop %d of %d: %s", index, len(self.hops), hop)
            try:
                fetcher = self._fetcher_for(hop)
                table = _validate_frame(fetcher.iptable())
            except Exception as exc:
                log.warning("SSH hop %s failed: %s", hop, exc)
                continue
            if table.empty:
                log.debug("hop %s at depth %d produced no row", hop, index)
                continue
            collected.append(_tag(table, source=type(self).__name__, depth=index, via=hop))
            log.debug("hop %s at depth %d produced %d row(s)", hop, index, len(table))

        if not collected:
            log.debug("none of the %d SSH hop(s) produced a table", len(self.hops))
            return pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        # Each hop's rows are labelled with that hop and nothing else: walking
        # bastion → jump → target describes three machines, and flattening them
        # into one `via` would throw away which one a row came from.
        merged = merge_tables(collected)
        merged["depth"] = merged["depth"].fillna(0).astype(int)
        log.debug("merged %d hop table(s) into %d row(s)", len(collected), len(merged))
        return merged


# ``Dict``/``Any`` are used in annotations above; kept imported for clarity of
# the public signature and for type-checkers reading this module.
_ = Dict
