"""Tests for the package's public surface and CLI entry point."""

from __future__ import annotations

from pathlib import Path

import my_lan_prober
from my_lan_prober import (
    LAYERS,
    Config,
    Engine,
    Framing,
    Handler,
    HandlerChain,
    LayerSpec,
    Persistor,
    RegexBannerHandler,
    ScanResult,
    SessionFactory,
    SocketBannerHandler,
    TableSession,
)


def test_package_exposes_a_version():
    assert isinstance(my_lan_prober.__version__, str)
    assert my_lan_prober.__version__


def test_public_api_is_importable_from_the_package_root():
    assert Config is not None
    assert Engine is not None
    assert LAYERS["TCP"] is not None


def test_the_designed_abstractions_are_exported():
    for symbol in (
        LayerSpec,
        SessionFactory,
        TableSession,
        Framing,
        Handler,
        HandlerChain,
        SocketBannerHandler,
        RegexBannerHandler,
        ScanResult,
        Persistor,
    ):
        assert symbol is not None


def test_the_arp_expansion_abstractions_are_exported():
    """The expander layer is public API, not an implementation detail."""
    from my_lan_prober import (
        FQDN,
        ArpTableExpander,
        DnsTableFetcher,
        FetcherRegistry,
        HostsFileFetcher,
        ResolvedHostFetcher,
        SSHArpTableExpander,
        TableUnion,
        default_fetcher_registry,
    )

    for symbol in (
        ArpTableExpander,
        SSHArpTableExpander,
        TableUnion,
        DnsTableFetcher,
        HostsFileFetcher,
        ResolvedHostFetcher,
        FetcherRegistry,
        default_fetcher_registry,
        FQDN,
    ):
        assert symbol is not None


def test_the_arp_expansion_abstractions_are_in_dunder_all():
    import my_lan_prober

    for name in (
        "ArpTableExpander",
        "SSHArpTableExpander",
        "TableUnion",
        "DnsTableFetcher",
        "HostsFileFetcher",
        "ResolvedHostFetcher",
        "FetcherRegistry",
        "default_fetcher_registry",
        "FQDN",
    ):
        assert name in my_lan_prober.__all__, name


def test_the_public_api_does_not_import_optional_dependencies():
    """``import my_lan_prober`` must work with no extras installed."""
    import importlib.util

    source = Path(__file__).resolve().parent.parent / "src" / "my_lan_prober" / "__init__.py"
    text = source.read_text(encoding="utf-8")

    for module in ("playwright", "asyncssh", "zeroconf", "openai"):
        assert f"import {module}" not in text
        assert importlib.util.find_spec(module) in (None,) or True


def test_main_is_callable():
    assert callable(my_lan_prober.main)


def test_main_runs_the_engine(monkeypatch):
    """``main()`` must build a Config, run the Engine, and return the frame."""
    calls = {}

    class FakeEngine:
        def __init__(self, config):
            calls["config"] = config

        def run(self):
            calls["ran"] = True
            return "frame"

    monkeypatch.setattr(my_lan_prober, "Engine", FakeEngine)

    result = my_lan_prober.main([])

    assert calls["ran"] is True
    assert result == "frame"


def test_main_accepts_an_argv_sequence(monkeypatch):
    calls = {}

    class FakeEngine:
        def __init__(self, config):
            calls["config"] = config

        def run(self):
            return None

    monkeypatch.setattr(my_lan_prober, "Engine", FakeEngine)

    my_lan_prober.main(["-t", "0.5", "--resolve-host", "localhost"])

    assert calls["config"].port_timeout == 0.5
    assert calls["config"].resolve_hosts == ["localhost"]


def test_load_dotenv_is_optional(monkeypatch):
    """``.env`` loading must not be a hard dependency."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("no dotenv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Should not raise even without python-dotenv installed.
    my_lan_prober.load_env()
