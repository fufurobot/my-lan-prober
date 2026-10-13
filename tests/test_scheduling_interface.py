"""Tests for the fetcher scheduling interface: ``dependency()`` and ``priority``.

``design.md`` § 7.  Every ARP source states two things about *when* it may run:

``dependency()``
    which other sources must have finished first.  It returns any iterable and
    the order inside it is meaningless — the caller is declaring a set of
    prerequisites, not a sequence.

``priority``
    an initial hint, and a plain writable attribute rather than a method,
    because :class:`~my_lan_prober.expanders.TableUnion` **rewrites** it: the
    union derives real levels from the dependency graph and assigns them back.

The sign of the initial value is the one thing the union must preserve:

* ``>= 0`` — ordinary; participates in the normal dependency ordering;
* ``< 0`` — deferred; implicitly depends on *every* non-negative fetcher, so
  it runs after all of them have finished.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.fetchers import ARPTableFetcher

EMPTY = pd.DataFrame(columns=["ip", "mac_address", "mode"])


class Stub(ARPTableFetcher):
    """A fetcher with the scheduling interface spelled out."""

    def __init__(self, name="stub", priority=0, depends=()):
        self.name = name
        self.priority = priority
        self._depends = depends
        self.calls = 0

    def dependency(self):
        return self._depends

    def iptable(self):
        self.calls += 1
        return EMPTY.copy()

    def __repr__(self):
        return f"Stub({self.name})"


# ---------------------------------------------------------------------------
# The interface exists on every fetcher, with the documented defaults
# ---------------------------------------------------------------------------
def test_the_base_class_declares_the_scheduling_interface():
    """Both members must exist on the ABC, not only on subclasses."""
    assert hasattr(ARPTableFetcher, "dependency")
    assert hasattr(ARPTableFetcher, "priority")


def test_dependency_defaults_to_empty():
    """A fetcher that says nothing depends on nothing."""

    class Minimal(ARPTableFetcher):
        def iptable(self):
            return EMPTY.copy()

    assert list(Minimal().dependency()) == []


def test_dependency_accepts_any_iterable():
    """A set, a tuple, a generator and a list are all valid declarations."""

    class Minimal(ARPTableFetcher):
        def __init__(self, deps):
            self._deps = deps

        def dependency(self):
            return self._deps

        def iptable(self):
            return EMPTY.copy()

    for deps in (["a"], ("a",), {"a"}, (name for name in ["a"])):
        assert list(Minimal(deps).dependency()) == ["a"]


def test_dependency_returns_classes_or_names_and_both_are_accepted():
    """The interface promises classes; names are accepted as a convenience."""

    class Other(ARPTableFetcher):
        def iptable(self):
            return EMPTY.copy()

    class WithClass(ARPTableFetcher):
        def dependency(self):
            return {Other}

        def iptable(self):
            return EMPTY.copy()

    class WithName(ARPTableFetcher):
        def dependency(self):
            return {"Other"}

        def iptable(self):
            return EMPTY.copy()

    assert next(iter(WithClass().dependency())) is Other
    assert next(iter(WithName().dependency())) == "Other"


def test_priority_defaults_to_zero():
    class Minimal(ARPTableFetcher):
        def iptable(self):
            return EMPTY.copy()

    assert Minimal().priority == 0


def test_priority_is_writable():
    """The union assigns levels by writing to it, so it must be an attribute."""
    fetcher = Stub()

    fetcher.priority = -3

    assert fetcher.priority == -3


def test_priority_is_not_a_method():
    """A property, not a call — ``fetcher.priority`` is already the value."""
    assert not callable(Stub().priority)


def test_dependency_does_not_require_an_argument():
    """It is a plain accessor: no parameters, like ``available()``."""
    import inspect

    signature = inspect.signature(ARPTableFetcher.dependency)

    assert list(signature.parameters) == ["self"]


# ---------------------------------------------------------------------------
# The existing fetchers all gained the interface
# ---------------------------------------------------------------------------
def test_every_shipped_fetcher_exposes_the_interface():
    from my_lan_prober.registry import default_fetcher_registry

    for name in default_fetcher_registry().names():
        fetcher = default_fetcher_registry().create(name)
        assert hasattr(fetcher, "dependency"), name
        assert hasattr(fetcher, "priority"), name
        assert list(fetcher.dependency()) is not None, name


def test_the_ssh_source_depends_on_the_table_sources():
    """The SSH walk needs a table to walk; it cannot be a root."""
    from my_lan_prober.registry import default_fetcher_registry

    ssh = default_fetcher_registry().create("ssh")
    declared = {getattr(dep, "__name__", str(dep)) for dep in ssh.dependency()}

    assert declared, "the SSH expander must declare what it expands"
    assert any("Arp" in name or "Unix" in name or "TPLogin" in name for name in declared)


def test_the_deep_sources_are_deferred_by_default():
    """Sources that are slow or invasive should not hold up the fast ones."""
    from my_lan_prober.registry import default_fetcher_registry

    registry = default_fetcher_registry()

    assert registry.create("ssh").priority < 0
    assert registry.create("unix").priority >= 0
    assert registry.create("dns").priority >= 0


def test_expanders_are_deferred():
    """An expander without a table to expand has nothing to do."""
    from my_lan_prober.expanders import SSHArpTableExpander, SSHHopExpander, TableUnion

    assert SSHArpTableExpander(Stub()).priority < 0
    assert TableUnion([Stub()]).priority < 0
    assert SSHHopExpander(["a"], fetcher_for=lambda hop: Stub()).priority < 0


def test_a_bare_stub_keeps_the_documented_default():
    assert Stub().priority == 0


@pytest.mark.parametrize("priority", [0, 1, 5, -1, -10])
def test_priority_round_trips_any_integer(priority):
    assert Stub(priority=priority).priority == priority
