"""Scheduling for a set of ARP sources: levels, phases, and the graph solver.

A union of fetchers is not a list to walk in order.  Each source says which
others must finish first (:meth:`~my_lan_prober.fetchers.ARPTableFetcher.dependency`)
and carries an initial hint about how urgent it is
(:attr:`~my_lan_prober.fetchers.ARPTableFetcher.priority`), and this module
turns those declarations into an execution plan.

The rules, stated once:

**levels**
    A fetcher's level is the length of the *longest* dependency path from it
    down to a root, negated.  Longest, not shortest: a fetch that depends on
    two things must wait for the slower of the two, so the deeper path decides
    when it is safe to run.

**the sign of the initial priority**
    A negative initial value means "defer me".  Such a fetcher is treated as
    depending on *every* non-negative fetcher, which is what pushes the whole
    deferred group below everything else.  Deferral is a single shared shift,
    not a per-node rewrite, so a deferred fetcher that depends on another
    deferred fetcher still runs after it.

**collapsing**
    Distinct levels are squeezed to consecutive integers so no level is empty.
    They may be negative, because the highest level runs first and the roots
    need to end up at the top.

**phases**
    Execution walks levels from the highest number to the lowest.  Every
    fetcher on one level runs concurrently, bounded by a global task limit.

Cycles are reported rather than broken: which edge to cut is a decision only
the caller can make, and guessing would silently reorder their sources.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

__all__ = [
    "PriorityGraph",
    "DependencyCycle",
    "display_name",
    "level_for",
    "resolve_dependency_names",
]


class DependencyCycle(ValueError):
    """Raised when the declared dependencies cannot be topologically ordered.

    A ``ValueError`` so existing ``except ValueError`` callers keep working,
    with the cycle spelled out because "there is a cycle" is useless without
    naming it.
    """

    def __init__(self, cycle: Sequence[str], labels: Optional[Dict[str, str]] = None) -> None:
        self.cycle = list(cycle)
        named = [labels.get(key, key) for key in self.cycle] if labels else self.cycle
        super().__init__("dependency cycle: " + " -> ".join(named))


def resolve_dependency_names(
    fetchers: Sequence[Any],
) -> Dict[str, Set[str]]:
    """Read every fetcher's declared dependencies as identity keys.

    A dependency may be declared three ways, and all three are honoured because
    a fetcher is usually written without knowing how a given run will construct
    its peers:

    * a **class** (the documented form) — matches every selected instance of
      that class;
    * an **instance** — matches exactly that source;
    * a **string** — matches an instance's ``name``, or a class name.

    Anything naming a source that was not selected is dropped rather than
    raised on: mentioning a prerequisite the run did not enable is normal, and
    a declaration is not a demand.

    The order inside ``dependency()`` is ignored entirely, which is why the
    result is a set.
    """
    # declared label -> every identity key that label refers to
    matching: Dict[str, Set[str]] = {}
    for fetcher in fetchers:
        key = _key_of(fetcher)
        for label in (key, type(fetcher).__name__, display_name(fetcher)):
            matching.setdefault(label, set()).add(key)

    resolved: Dict[str, Set[str]] = {}
    for fetcher in fetchers:
        own = _key_of(fetcher)
        deps: Set[str] = set()
        for declared in _iter_dependencies(fetcher):
            label = _declared_label(declared)
            if label is None:
                continue
            for key in matching.get(label, set()):
                if key != own:
                    # A fetcher naming itself is a no-op, not a cycle: it is
                    # the obvious thing to write when a source is its own
                    # fallback.
                    deps.add(key)
        resolved[own] = deps
    return resolved


def display_name(fetcher: Any) -> str:
    """What to call a fetcher in a log line or an error message."""
    name = getattr(fetcher, "name", None)
    if isinstance(name, str) and name:
        return name
    return type(fetcher).__name__


def _key_of(fetcher: Any) -> str:
    """A unique identity for a fetcher within one union.

    Two instances of the same class are two sources, not one: a caller may
    legitimately select ``unix`` twice with different settings, and the tests'
    stub fetchers are all the same class.  Keying on the class name alone
    silently collapsed them into a single graph node, so only one of them ever
    ran — a bug worth a comment, because it looks like a deduplication.

    The *class* name is still what a fetcher uses to declare a dependency on
    another (see :func:`resolve_dependency_names`), so the two notions are kept
    apart deliberately: identity here, matching there.
    """
    return f"{type(fetcher).__name__}#{id(fetcher)}"


def _iter_dependencies(fetcher: Any) -> Iterable[Any]:
    """Whatever ``dependency()`` returned, safely iterated.

    ``dependency()`` is a caller-supplied method on an arbitrary object, so it
    is allowed to return a single class as well as a collection — a one-element
    declaration should not require the caller to remember to wrap it.
    """
    try:
        declared = fetcher.dependency()
    except AttributeError:
        return ()
    if declared is None:
        return ()
    if isinstance(declared, (type, str)):
        return (declared,)
    try:
        return tuple(declared)
    except TypeError:
        return (declared,)


def _declared_label(declared: Any) -> Optional[str]:
    """The label a dependency declaration refers to, or ``None``.

    An *instance* is matched by its identity key, which is the only way to
    depend on one specific source rather than on every instance of its class.
    """
    if declared is None:
        return None
    if isinstance(declared, str):
        return declared
    if isinstance(declared, type):
        return declared.__name__
    if hasattr(declared, "iptable"):
        # A fetcher instance: refer to it by identity, not by class name.
        return _key_of(declared)
    return type(declared).__name__


def level_for(fetchers: Sequence[Any]) -> Dict[str, int]:
    """Assign every fetcher a scheduling level, highest runs first.

    Two invariants fix the numbers:

    1. a dependency must run strictly *before* its dependent, and execution
       walks levels from largest to smallest, so a dependency gets a strictly
       larger number than anything depending on it;
    2. a fetcher whose initial priority is negative must run after everything
       that is not, so the deferred levels sit strictly below the rest.

    Stating them this way makes the sign of the result self-explanatory: the
    roots of the graph (nothing to wait for) hold the largest numbers, and
    every step of dependency moves one level down.
    """
    fetchers = list(fetchers)
    if not fetchers:
        return {}

    keys = {_key_of(fetcher) for fetcher in fetchers}
    declared = resolve_dependency_names(fetchers)

    deferred = {key for key in keys if _priority_of(fetchers, key) < 0}
    non_deferred = keys - deferred

    edges: Dict[str, Set[str]] = {}
    for key, deps in declared.items():
        effective = set(deps)
        if key in deferred:
            # Deferral, spelled as an edge: wait for everything not deferred.
            effective |= non_deferred
        edges[key] = effective

    depth = _depths(edges, labels={_key_of(fetcher): display_name(fetcher) for fetcher in fetchers})
    collapsed = _collapse(depth)

    # (1) says a dependency needs a bigger number, and `depth` counts distance
    # from the roots, so negating it satisfies (1) outright.
    level = {key: -value for key, value in collapsed.items()}

    # (2) is then usually free, because the implicit edges already put every
    # deferred fetcher below every non-deferred one.  It stops being free when
    # a deferred fetcher also depends on another deferred fetcher: that edge
    # compresses its depth back up towards the roots.  Shift the deferred group
    # down by one shared amount, preserving the order inside it.
    if deferred and non_deferred:
        gap = min(level[key] for key in non_deferred) - max(level[key] for key in deferred)
        if gap <= 0:
            shift = gap - 1
            for key in deferred:
                level[key] += shift

    return level


def _priority_of(fetchers: Sequence[Any], key: str) -> int:
    """A fetcher's *initial* priority, before any assignment overwrites it."""
    for fetcher in fetchers:
        if _key_of(fetcher) == key:
            try:
                return int(getattr(fetcher, "priority", 0))
            except (TypeError, ValueError):
                return 0
    return 0


def _depths(edges: Dict[str, Set[str]], labels: Optional[Dict[str, str]] = None) -> Dict[str, int]:
    """Longest path from each node down to a node with no dependencies."""
    depth: Dict[str, int] = {}
    path: List[str] = []

    def visit(name: str) -> int:
        if name in depth:
            return depth[name]
        if name in path:
            raise DependencyCycle([*path[path.index(name) :], name], labels)
        path.append(name)
        try:
            deps = edges.get(name, set())
            value = 0 if not deps else 1 + max(visit(dep) for dep in sorted(deps))
        finally:
            path.pop()
        depth[name] = value
        return value

    for name in sorted(edges):
        visit(name)
    return depth


def _collapse(depth: Dict[str, int]) -> Dict[str, int]:
    """Squeeze distinct depths to consecutive integers, preserving order."""
    distinct = sorted(set(depth.values()))
    index = {value: position for position, value in enumerate(distinct)}
    return {name: index[value] for name, value in depth.items()}


class PriorityGraph:
    """The solved dependency graph: levels, and the phases to run them in.

    Kept as an object because the assignment has to be *written back* to the
    fetchers (``priority`` is a writable attribute, by design) and inspected
    afterwards, and because a plan is easier to test than a side effect.
    """

    def __init__(self, fetchers: Sequence[Any]) -> None:
        self.fetchers: List[Any] = list(fetchers)
        self.by_key: Dict[str, Any] = {_key_of(fetcher): fetcher for fetcher in self.fetchers}
        #: identity key -> scheduling level (highest runs first).
        self.levels: Dict[str, int] = level_for(self.fetchers)

    # -- assignment -----------------------------------------------------
    def assign(self) -> Dict[str, int]:
        """Write each level back onto its fetcher's ``priority`` attribute.

        The returned mapping is keyed by *display* name, because it exists to
        be read and logged; the levels themselves are keyed by identity.
        """
        for key, fetcher in self.by_key.items():
            if key not in self.levels:
                continue
            try:
                fetcher.priority = self.levels[key]
            except AttributeError:  # pragma: no cover - defensive
                log_free_warning(display_name(fetcher))
        return {
            display_name(self.by_key[key]): level
            for key, level in self.levels.items()
            if key in self.by_key
        }

    # -- the plan -------------------------------------------------------
    def phases(self) -> List[List[Any]]:
        """Fetchers grouped by level, highest level first.

        The returned order *is* the execution order: level by level, and every
        fetcher inside a level may run concurrently.
        """
        grouped: List[List[Any]] = []
        for level in sorted(set(self.levels.values()), reverse=True):
            batch = [
                self.by_key[key]
                for key in sorted(self.levels, key=lambda k: display_name(self.by_key[k]))
                if self.levels[key] == level and key in self.by_key
            ]
            if batch:
                grouped.append(batch)
        return grouped

    def plan(self) -> List[List[str]]:
        """The phases as display names, for tests and for logging a run."""
        return [[display_name(fetcher) for fetcher in phase] for phase in self.phases()]

    def phase_of(self, name: str) -> Optional[int]:
        for index, phase in enumerate(self.plan()):
            if name in phase:
                return index
        return None


def log_free_warning(name: str) -> None:  # pragma: no cover - defensive
    """A fetcher whose priority cannot be assigned is reported, not fatal."""
    import logging

    logging.getLogger(__name__).warning(
        "could not assign a scheduling level to %s; it keeps its declared priority", name
    )
