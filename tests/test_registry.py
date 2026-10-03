"""Tests for :mod:`my_lan_prober.registry` — the ARP source registry.

The engine used to pick *one* source (``--fetcher tplogin``) and stop at the
first non-empty table.  That loses hosts: the router's lease table knows about
DHCP clients, the local ARP table knows about the machines this host actually
talked to, the hosts file knows the names the user pinned, and DNS knows the
names the world publishes.

A registry turns that from a chain of fallbacks into a *set* of sources the
engine can merge.  It is also the seam that keeps the optional dependencies
optional: a source whose library is missing is simply unavailable, not fatal.
"""

from __future__ import annotations

import pandas as pd
import pytest

from my_lan_prober.fetchers import ARPTableFetcher
from my_lan_prober.registry import FETCHER_REGISTRY, FetcherRegistry, default_fetcher_registry


# ---------------------------------------------------------------------------
# Register / look up
# ---------------------------------------------------------------------------
def test_registry_starts_empty():
    assert FetcherRegistry().names() == []


def test_registry_registers_a_factory():
    registry = FetcherRegistry()
    registry.register("mine", lambda **kwargs: ARP_FRAME_FETCHER())

    assert "mine" in registry.names()


def test_registry_create_instantiates_the_factory():
    registry = FetcherRegistry()
    registry.register("mine", lambda **kwargs: ARP_FRAME_FETCHER())

    assert isinstance(registry.create("mine"), ARPTableFetcher)


def test_registry_create_passes_keyword_arguments_through():
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return ARP_FRAME_FETCHER()

    registry = FetcherRegistry()
    registry.register("mine", factory)
    registry.create("mine", browser="webkit")

    assert captured["browser"] == "webkit"


def test_registry_rejects_an_unknown_name():
    with pytest.raises(KeyError, match="unknown ARP source"):
        FetcherRegistry().create("nope")


def test_registry_names_are_sorted_and_stable():
    registry = FetcherRegistry()
    for name in ("zeta", "alpha", "mu"):
        registry.register(name, lambda **kwargs: ARP_FRAME_FETCHER())

    assert registry.names() == ["alpha", "mu", "zeta"]


def test_registry_registering_twice_overrides():
    """A user must be able to replace a built-in source with their own."""
    registry = FetcherRegistry()

    class First(ARPTableFetcher):
        def iptable(self):
            return pd.DataFrame(columns=["ip", "mode"])

    class Second(First):
        pass

    registry.register("mine", lambda **kwargs: First())
    registry.register("mine", lambda **kwargs: Second())

    assert isinstance(registry.create("mine"), Second)


def test_registry_does_not_swallow_a_factory_that_raises():
    def bad_factory(**kwargs):
        raise RuntimeError("missing library")

    registry = FetcherRegistry()
    registry.register("bad", bad_factory)

    with pytest.raises(RuntimeError):
        registry.create("bad")


def test_registry_available_filters_out_sources_that_cannot_run():
    class Unavailable(ARPTableFetcher):
        def iptable(self):
            return pd.DataFrame(columns=["ip", "mode"])

        def available(self):
            return False

    registry = FetcherRegistry()
    registry.register("no", lambda **kwargs: Unavailable())
    registry.register("yes", lambda **kwargs: ARP_FRAME_FETCHER())

    assert [type(f).__name__ for f in registry.available()] == ["StubFrameFetcher"]


def test_registry_available_skips_a_factory_that_raises():
    registry = FetcherRegistry()
    registry.register("bad", lambda **kwargs: (_ for _ in ()).throw(ImportError("no lib")))
    registry.register("yes", lambda **kwargs: ARP_FRAME_FETCHER())

    assert len(registry.available()) == 1


# ---------------------------------------------------------------------------
# The built-in registry
# ---------------------------------------------------------------------------
def test_the_default_registry_knows_every_shipped_source():
    registry = default_fetcher_registry()

    for name in ("tplogin", "unix", "windows", "openwrt", "dns", "hosts", "resolved", "ssh"):
        assert name in registry.names(), name


def test_the_default_registry_creates_the_fetcher_it_promises():
    assert isinstance(default_fetcher_registry().create("unix"), ARPTableFetcher)


def test_the_default_registry_can_create_every_source_it_lists():
    """Every registered name must be constructible with default arguments."""
    registry = default_fetcher_registry()

    for name in registry.names():
        assert isinstance(registry.create(name), ARPTableFetcher), name


def test_openwrt_and_ssh_sources_are_unavailable_without_configuration(monkeypatch):
    """Nothing invasive runs by accident."""
    monkeypatch.delenv("OPENWRT_HOST", raising=False)
    monkeypatch.delenv("SSH_HOP", raising=False)
    registry = default_fetcher_registry()

    assert registry.create("openwrt").available() is False
    assert registry.create("ssh").available() is False


def test_the_module_level_registry_is_shared():
    assert FETCHER_REGISTRY.names() == default_fetcher_registry().names()


def test_registry_survives_a_source_with_a_missing_optional_dependency(monkeypatch):
    """The whole suite must pass with no extras installed (see ci.yml)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("playwright", "asyncssh"):
            raise ImportError(f"no {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    registry = default_fetcher_registry()
    # Constructing every source must not raise; availability is reported.
    for name in registry.names():
        registry.create(name)


# ---------------------------------------------------------------------------
# Selecting several sources at once
# ---------------------------------------------------------------------------
def test_parse_selection_accepts_a_comma_separated_list():
    registry = default_fetcher_registry()

    assert registry.parse_selection("unix,dns") == ["unix", "dns"]


def test_parse_selection_strips_whitespace():
    registry = default_fetcher_registry()

    assert registry.parse_selection(" unix , hosts ") == ["unix", "hosts"]


def test_parse_selection_of_all_returns_every_name():
    registry = default_fetcher_registry()

    assert registry.parse_selection("all") == registry.names()


def test_parse_selection_of_auto_returns_the_non_invasive_defaults():
    registry = default_fetcher_registry()

    selection = registry.parse_selection("auto")

    assert "tplogin" in selection
    assert "unix" in selection
    assert "dns" in selection
    assert "ssh" not in selection


def test_parse_selection_rejects_an_unknown_name():
    with pytest.raises(KeyError, match="unknown ARP source"):
        default_fetcher_registry().parse_selection("unix,nope")


def test_parse_selection_of_an_empty_string_is_the_default():
    registry = default_fetcher_registry()

    assert registry.parse_selection("") == registry.parse_selection("auto")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class StubFrameFetcher(ARPTableFetcher):
    def iptable(self):
        return pd.DataFrame([{"ip": "10.0.0.1", "mode": "arp"}])


def ARP_FRAME_FETCHER():
    return StubFrameFetcher()
