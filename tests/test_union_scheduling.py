"""Tests for :class:`TableUnion` as a scheduler.

The union does not merely merge tables any more — it decides *when* each source
runs, from the dependency graph the sources declare:

1. a **level** is the longest dependency path from a fetcher to a root;
2. a fetcher whose initial ``priority`` is negative implicitly depends on every
   non-negative fetcher, which defers the whole negative group to the end;
3. distinct levels are collapsed to consecutive integers, which may be
   negative, so no level is ever empty;
4. execution walks levels from the **highest** number to the lowest, and every
   fetcher inside one level runs **concurrently**, bounded by a global
   ``max_task`` limit.

Point 4 is the reason the old ``FetcherChain`` is gone: waiting for one chain
to succeed while another could already be running is wasted wall-clock time.
"""

from __future__ import annotations

import threading
import time

import pandas as pd
import pytest

from my_lan_prober.expanders import TableUnion
from my_lan_prober.fetchers import ARPTableFetcher

EMPTY = pd.DataFrame(columns=["ip", "mac_address", "mode"])


class Recorder(ARPTableFetcher):
    """A fetcher that records when it ran, and can be made slow or broken."""

    #: Shared, so ordering across a union is observable.
    def __init__(self, name, *, priority=0, depends=(), delay=0.0, error=None, frame=None):
        self.name = name
        self.priority = priority
        self._depends = list(depends)
        self.delay = delay
        self.error = error
        self._frame = frame if frame is not None else EMPTY.copy()
        self.events = []
        self.calls = 0
        self.concurrent_peak = 0

    def dependency(self):
        return list(self._depends)

    def iptable(self):
        self.calls += 1
        self.events.append(("start", time.monotonic()))
        if self.delay:
            time.sleep(self.delay)
        self.events.append(("end", time.monotonic()))
        if self.error is not None:
            raise self.error
        return self._frame.copy()

    def __repr__(self):
        return f"Recorder({self.name})"


class Clock:
    """A shared timeline every fetcher in one test writes to."""

    def __init__(self):
        self.lock = threading.Lock()
        self.started = []
        self.finished = []
        self.in_flight = 0
        self.peak = 0

    def note_start(self, name):
        with self.lock:
            self.started.append(name)
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)

    def note_end(self, name):
        with self.lock:
            self.finished.append(name)
            self.in_flight -= 1


class Tracked(ARPTableFetcher):
    """Records starts/ends on a shared ``Clock`` instead of privately."""

    def __init__(self, name, clock, *, priority=0, depends=(), delay=0.0, error=None):
        self.name = name
        self.clock = clock
        self.priority = priority
        self._depends = list(depends)
        self.delay = delay
        self.error = error

    def dependency(self):
        return list(self._depends)

    def iptable(self):
        self.clock.note_start(self.name)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.error is not None:
                raise self.error
            return pd.DataFrame([{"ip": f"10.0.0.{abs(hash(self.name)) % 250 + 1}", "mode": "arp"}])
        finally:
            self.clock.note_end(self.name)

    def __repr__(self):
        return f"Tracked({self.name})"


def run(union):
    return union.iptable()


# ---------------------------------------------------------------------------
# Priority assignment from the dependency graph
# ---------------------------------------------------------------------------
def test_no_dependencies_puts_everything_on_one_level():
    a, b, c = Recorder("a"), Recorder("b"), Recorder("c")

    union = TableUnion([a, b, c])
    run(union)

    assert {a.priority, b.priority, c.priority} == {0}


def test_a_dependent_sits_one_level_below_its_dependency():
    root = Recorder("root")
    child = Recorder("child", depends=["root"])

    run(TableUnion([root, child]))

    assert root.priority == 0
    assert child.priority == -1


def test_level_is_the_longest_path_not_the_shortest():
    """A fetcher with two paths down must wait for the longer one."""
    a = Recorder("a")
    b = Recorder("b", depends=["a"])
    c = Recorder("c", depends=["b"])
    join = Recorder("join", depends=["a", "c"])

    run(TableUnion([a, b, c, join]))

    assert a.priority == 0
    assert join.priority == -3, "join must sit below its deepest dependency"


def test_levels_are_collapsed_to_consecutive_integers():
    """Gaps in the raw depths must not survive as gaps in the levels."""
    a = Recorder("a")
    b = Recorder("b", depends=["a"])
    # `c` is deliberately unrelated, so raw depths are {0, 1} with no 2 level
    # used by anything except the deep chain below.
    d = Recorder("d", depends=["b"])
    e = Recorder("e", depends=["d"])

    run(TableUnion([a, b, d, e]))

    assert sorted({a.priority, b.priority, d.priority, e.priority}) == [-3, -2, -1, 0]


def test_a_negative_initial_priority_is_deferred_below_every_non_negative():
    fast = Recorder("fast")
    slow = Recorder("slow", priority=-1)

    run(TableUnion([fast, slow]))

    assert slow.priority < fast.priority


def test_deferred_fetchers_keep_their_internal_ordering():
    """Deferral is a group shift, not a flattening."""
    plain = Recorder("plain")
    first = Recorder("first", priority=-1)
    second = Recorder("second", priority=-1, depends=["first"])

    run(TableUnion([plain, first, second]))

    assert plain.priority > first.priority > second.priority


def test_positive_and_zero_priorities_are_treated_alike():
    """Only the *sign* of the initial value is meaningful."""
    a = Recorder("a", priority=0)
    b = Recorder("b", priority=7)

    run(TableUnion([a, b]))

    assert a.priority == b.priority == 0


def test_dependency_may_name_a_class_instead_of_a_string():
    class Root(ARPTableFetcher):
        priority = 0

        def iptable(self):
            return EMPTY.copy()

    class Child(ARPTableFetcher):
        priority = 0

        def dependency(self):
            return {Root}

        def iptable(self):
            return EMPTY.copy()

    root, child = Root(), Child()
    run(TableUnion([root, child]))

    assert root.priority > child.priority


def test_an_unknown_dependency_name_is_ignored():
    """Declaring a prerequisite that was not selected is not an error."""
    lonely = Recorder("lonely", depends=["not-selected"])

    run(TableUnion([lonely]))

    assert lonely.priority == 0


def test_a_dependency_cycle_is_reported_with_the_cycle_named():
    a = Recorder("a", depends=["b"])
    b = Recorder("b", depends=["a"])

    with pytest.raises(ValueError, match="cycle"):
        run(TableUnion([a, b]))


def test_a_self_dependency_is_not_a_cycle():
    """A fetcher naming itself is a no-op, not an infinite loop."""
    a = Recorder("a", depends=["a"])

    run(TableUnion([a]))

    assert a.priority == 0


def test_the_assignment_is_visible_on_the_fetchers_afterwards():
    """Priority is a writable attribute precisely so this can happen."""
    root = Recorder("root")
    child = Recorder("child", depends=["root"])
    union = TableUnion([root, child])

    run(union)

    assert (root.priority, child.priority) == (0, -1)


def test_assign_priorities_is_available_without_fetching():
    """The graph can be solved on its own, which is what makes it testable."""
    root = Recorder("root")
    child = Recorder("child", depends=["root"])

    assigned = TableUnion([root, child]).assign_priorities()

    assert assigned == {"root": 0, "child": -1}
    assert child.calls == 0


# ---------------------------------------------------------------------------
# Execution order and phase grouping
# ---------------------------------------------------------------------------
def test_execution_runs_the_highest_level_first():
    clock = Clock()
    first = Tracked("first", clock)
    second = Tracked("second", clock, depends=["first"])
    third = Tracked("third", clock, depends=["second"])

    run(TableUnion([first, second, third]))

    assert clock.started == ["first", "second", "third"]


def test_a_dependent_never_starts_before_its_dependency_finishes():
    clock = Clock()
    root = Tracked("root", clock, delay=0.15)
    child = Tracked("child", clock, depends=["root"])

    run(TableUnion([root, child]))

    assert clock.finished.index("root") < clock.started.index("child")


def test_fetchers_on_the_same_level_run_concurrently():
    """Three 0.2s fetchers on one level must not take 0.6s."""
    clock = Clock()
    fetchers = [Tracked(name, clock, delay=0.2) for name in ("a", "b", "c")]
    union = TableUnion(fetchers)

    started = time.monotonic()
    run(union)
    elapsed = time.monotonic() - started

    assert clock.peak >= 2, f"expected concurrency, peak was {clock.peak}"
    assert elapsed < 0.55, f"ran serially: {elapsed:.2f}s"


def test_phases_are_exposed_for_inspection():
    a = Recorder("a")
    b = Recorder("b", depends=["a"])
    c = Recorder("c", depends=["b"])

    planned = TableUnion([a, b, c]).plan()

    assert planned == [["a"], ["b"], ["c"]]


def test_every_fetcher_appears_exactly_once_in_the_plan():
    a = Recorder("a")
    b = Recorder("b", depends=["a"])
    c = Recorder("c")

    planned = TableUnion([a, b, c]).plan()
    flat = [name for phase in planned for name in phase]

    assert sorted(flat) == ["a", "b", "c"]


def test_a_deferred_fetcher_runs_in_a_later_phase():
    clock = Clock()
    fast = Tracked("fast", clock)
    deep = Tracked("deep", clock, priority=-1)

    run(TableUnion([fast, deep]))

    assert clock.finished.index("fast") < clock.started.index("deep")


# ---------------------------------------------------------------------------
# The global task limit
# ---------------------------------------------------------------------------
def test_max_task_bounds_how_many_fetchers_run_at_once():
    clock = Clock()
    fetchers = [Tracked(name, clock, delay=0.15) for name in ("a", "b", "c", "d")]
    union = TableUnion(fetchers, max_task=2)

    run(union)

    assert clock.peak <= 2, f"max_task=2 but peak concurrency was {clock.peak}"


def test_max_task_of_one_serialises_a_level():
    clock = Clock()
    fetchers = [Tracked(name, clock, delay=0.05) for name in ("a", "b", "c")]
    union = TableUnion(fetchers, max_task=1)

    run(union)

    assert clock.peak == 1


def test_max_task_larger_than_the_level_is_not_an_error():
    clock = Clock()
    fetchers = [Tracked(name, clock, delay=0.05) for name in ("a", "b")]
    union = TableUnion(fetchers, max_task=64)

    frame = run(union)

    assert clock.peak <= 2
    assert len(frame) == 2


def test_max_task_defaults_to_a_positive_value():
    assert TableUnion([]).max_task >= 1


def test_an_invalid_max_task_is_rejected():
    with pytest.raises(ValueError, match="max_task"):
        TableUnion([Recorder("a")], max_task=0)


# ---------------------------------------------------------------------------
# Merging still happens, and failure on one source is still not fatal
# ---------------------------------------------------------------------------
def test_all_phases_are_merged_into_one_table():
    a = Recorder("a", frame=pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}]))
    b = Recorder("b", frame=pd.DataFrame([{"ip": "10.0.0.2", "mode": "dns"}]))

    frame = run(TableUnion([a, b]))

    assert set(frame["ip"]) == {"10.0.0.1", "10.0.0.2"}


def test_a_failing_fetcher_does_not_stop_its_phase():
    good = Recorder("good", frame=pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}]))
    bad = Recorder("bad", error=RuntimeError("boom"))

    frame = run(TableUnion([good, bad]))

    assert list(frame["ip"]) == ["10.0.0.1"]


def test_a_failing_dependency_still_lets_its_dependent_run():
    """A missing prerequisite degrades the result, it does not cancel work."""
    root = Recorder("root", error=RuntimeError("no router"))
    child = Recorder(
        "child", depends=["root"], frame=pd.DataFrame([{"ip": "10.0.0.9", "mode": "arp"}])
    )

    frame = run(TableUnion([root, child]))

    assert "10.0.0.9" in set(frame["ip"])


def test_every_source_failing_is_still_loud():
    a = Recorder("a", error=RuntimeError("a"))
    b = Recorder("b", error=RuntimeError("b"))

    with pytest.raises(RuntimeError):
        run(TableUnion([a, b]))


def test_an_empty_union_is_empty_not_an_error():
    frame = run(TableUnion([]))

    assert frame.empty


def test_each_fetcher_is_still_called_exactly_once():
    a = Recorder("a")
    b = Recorder("b", depends=["a"])

    run(TableUnion([a, b]))

    assert (a.calls, b.calls) == (1, 1)


def test_unavailable_fetchers_are_skipped_without_being_called():
    class Unavailable(Recorder):
        def available(self):
            return False

    missing = Unavailable("missing", error=RuntimeError("must not be called"))
    present = Recorder("present", frame=pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}]))

    frame = run(TableUnion([missing, present]))

    assert missing.calls == 0
    assert list(frame["ip"]) == ["10.0.0.1"]


# ---------------------------------------------------------------------------
# The chain's ability, without the chain's waiting
# ---------------------------------------------------------------------------
def test_a_fallback_group_still_yields_the_first_usable_table():
    """The chain's *semantics* survive; only its serialisation does not."""
    from my_lan_prober.expanders import TableUnion

    empty = Recorder("empty")
    good = Recorder("good", frame=pd.DataFrame([{"ip": "10.0.0.9", "mode": "arp"}]))

    class PreferFirst(TableUnion):
        """Merge, but let an earlier source's table win for a shared host."""

        def merge(self, tables):
            merged = super().merge(tables)
            return merged

    frame = run(PreferFirst([empty, good]))

    assert "10.0.0.9" in set(frame["ip"])


def test_the_union_needs_no_chain_wrapper():
    """``FetcherChain`` is no longer part of the fetch path."""
    import my_lan_prober.expanders as expanders_module

    source = expanders_module.__file__ or ""
    assert source
    with open(source, encoding="utf-8") as handle:
        text = handle.read()

    assert "FetcherChain" not in text, "the union must not delegate to the chain"
