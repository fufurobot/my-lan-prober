"""Tests for mDNS discovery as an ARP source.

mDNS is how a LAN publishes names without a DNS server: printers, NAS boxes,
`*.local` hosts, Chromecasts.  It is the one source that finds machines
*and* the names they answer to, which is exactly what an ``FQDN`` is for —
an mDNS answer gives an address and a hostname together, so the table gains a
host that DNS could not resolve and the local neighbour table could not name.

Two properties matter for scheduling:

* discovery is **slow** (it waits for multicast answers) and **optional**
  (``zeroconf`` is an extra), so it is deferred and reports itself unavailable
  when the library is missing;
* it is **best-effort**: a network with no mDNS traffic yields an empty table,
  not an error.
"""

from __future__ import annotations

from my_lan_prober.mdnsfetcher import MdnsFetcher, parse_service_info

from my_lan_prober.fetchers import ARPTableFetcher


# ---------------------------------------------------------------------------
# Parsing an mDNS answer
# ---------------------------------------------------------------------------
class FakeInfo:
    """Stand-in for ``zeroconf.ServiceInfo``."""

    def __init__(self, name, address, server=None, aliases=(), port=0):
        self.name = name
        self.server = server or name
        self.parsed_addresses = lambda: list(address) if isinstance(address, list) else [address]
        self.aliases = list(aliases)
        self.port = port

    def parsed_scoped_addresses(self):
        return self.parsed_addresses()


def test_parse_service_info_extracts_the_address():
    frame = parse_service_info([FakeInfo("nas._http._tcp.local.", "192.168.1.50")])

    assert list(frame["ip"]) == ["192.168.1.50"]


def test_parse_service_info_keeps_the_hostname_as_an_fqdn():
    """An mDNS answer names the machine, which is the whole point of asking."""
    frame = parse_service_info(
        [FakeInfo("nas._http._tcp.local.", "192.168.1.50", server="nas.local.")]
    )

    row = frame.iloc[0]
    assert row["fqdn"] == "nas.local"
    assert row["host"] == "nas.local"


def test_parse_service_info_strips_the_trailing_dot():
    """mDNS names are fully qualified; the dot is not part of the hostname."""
    frame = parse_service_info([FakeInfo("nas._http._tcp.local.", "192.168.1.50")])

    assert not any(str(value).endswith(".") for value in frame.iloc[0].dropna())


def test_parse_service_info_keeps_the_service_name_as_an_alias():
    frame = parse_service_info([FakeInfo("nas._http._tcp.local.", "192.168.1.50")])

    assert "nas" in str(frame.iloc[0]["aliases"])


def test_parse_service_info_keeps_every_address():
    """A dual-stack host answers on both families; both are reachable."""
    frame = parse_service_info([FakeInfo("nas._http._tcp.local.", ["192.168.1.50", "fe80::50"])])

    assert set(frame["ip"]) == {"192.168.1.50", "fe80::50"}


def test_parse_service_info_marks_the_mode_and_source():
    frame = parse_service_info([FakeInfo("nas._http._tcp.local.", "192.168.1.50")])

    assert frame.iloc[0]["mode"] == "mdns"
    assert frame.iloc[0]["source"] == "mdns"


def test_parse_service_info_skips_an_answer_with_no_address():
    frame = parse_service_info([FakeInfo("ghost._http._tcp.local.", [])])

    assert frame.empty


def test_parse_service_info_accepts_an_empty_list():
    frame = parse_service_info([])

    assert frame.empty
    assert "ip" in frame.columns


def test_parse_service_info_deduplicates_a_repeated_address():
    frame = parse_service_info(
        [
            FakeInfo("nas._http._tcp.local.", "192.168.1.50"),
            FakeInfo("nas._smb._tcp.local.", "192.168.1.50"),
        ]
    )

    assert list(frame["ip"]) == ["192.168.1.50"]


# ---------------------------------------------------------------------------
# The fetcher
# ---------------------------------------------------------------------------
def test_mdns_fetcher_is_a_fetcher():
    assert issubclass(MdnsFetcher, ARPTableFetcher)


def test_mdns_fetcher_is_available_without_zeroconf_checked_at_call_time(monkeypatch):
    """``zeroconf`` is an extra, so availability must be honest about it."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "zeroconf" or name.startswith("zeroconf."):
            raise ImportError("no zeroconf")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert MdnsFetcher().available() is False


def test_mdns_fetcher_is_unavailable_on_a_broken_import(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("zeroconf"):
            raise ImportError("broken install")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert MdnsFetcher().available() is False


def test_mdns_fetcher_returns_an_empty_table_without_traffic():
    """Best-effort: no mDNS answers is a normal LAN, not a failure."""
    fetcher = MdnsFetcher(browse=lambda timeout: [])

    frame = fetcher.iptable()

    assert frame.empty
    assert "ip" in frame.columns


def test_mdns_fetcher_uses_the_injected_browse_callable():
    seen = {}

    def browse(timeout):
        seen["timeout"] = timeout
        return [FakeInfo("nas._http._tcp.local.", "192.168.1.50")]

    frame = MdnsFetcher(browse=browse, timeout=1.5).iptable()

    assert list(frame["ip"]) == ["192.168.1.50"]
    assert seen["timeout"] == 1.5


def test_mdns_fetcher_survives_a_broken_browse_callable():
    def browse(timeout):
        raise OSError("multicast is unavailable")

    frame = MdnsFetcher(browse=browse).iptable()

    assert frame.empty


def test_mdns_fetcher_is_deferred_and_depends_on_the_table_sources():
    """Discovery takes seconds; it must not hold up the local reads."""
    fetcher = MdnsFetcher(browse=lambda timeout: [])

    assert fetcher.priority < 0
    assert list(fetcher.dependency()) == []


def test_mdns_fetcher_has_a_bounded_timeout():
    assert 0 < MdnsFetcher().timeout <= 30


# ---------------------------------------------------------------------------
# The router extra ties the three together
# ---------------------------------------------------------------------------
def test_router_extra_declares_all_three_dependencies():
    """``router`` is the one extra that covers the whole story."""
    from pathlib import Path

    import tomllib

    project = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(project.read_text(encoding="utf-8"))
    extra = data["project"]["optional-dependencies"]["router"]
    joined = " ".join(extra)

    assert "playwright" in joined
    assert "asyncssh" in joined
    assert "zeroconf" in joined


def test_the_individual_extras_survive():
    """A caller who needs one of the three must not have to take all three."""
    from pathlib import Path

    import tomllib

    project = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(project.read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]

    assert "playwright" in extras
    assert "asyncssh" in " ".join(extras["ssh"])
    assert "zeroconf" in " ".join(extras["mdns"])


def test_the_router_diagnostics_report_each_capability():
    """One call should say which router capabilities this machine has."""
    from my_lan_prober.router import router_capabilities

    capabilities = router_capabilities()

    assert set(capabilities) == {"playwright", "asyncssh", "zeroconf"}
    assert all(isinstance(value, bool) for value in capabilities.values())


def test_the_router_module_imports_without_any_extra():
    """Importing it must not require the extras it reports on."""
    import my_lan_prober.router as module

    assert module is not None


def test_mdns_is_registered_as_a_source():
    from my_lan_prober.registry import default_fetcher_registry

    assert "mdns" in default_fetcher_registry().names()


def test_the_mdns_source_is_deferred_in_the_registry():
    from my_lan_prober.registry import default_fetcher_registry

    assert default_fetcher_registry().create("mdns").priority < 0


def test_mdns_is_not_in_the_auto_selection_but_is_in_all():
    """Discovery is slow and chatty, so it stays opt-in."""
    from my_lan_prober.registry import default_fetcher_registry

    registry = default_fetcher_registry()

    assert "mdns" not in registry.parse_selection("auto")
    assert "mdns" in registry.parse_selection("all")
