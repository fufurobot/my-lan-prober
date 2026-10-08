"""my-lan-prober — probe a LAN, walk the protocol stack, enrich DHCP leases.

The public surface is re-exported here so the common entry points are one
import away::

    from my_lan_prober import Config, Engine, LAYERS, SessionFactory

The package is layered:

``framing``     how each protocol slices a byte stream into messages
``layers``      ~80 protocols described as data (``LayerSpec``)
``bridge``      one asyncio loop per process, reachable from sync code
``sessions``    transports; ``TableSession`` is driven by a ``LayerSpec``
``handlers``    parsing + dispatch, composable with ``<<`` / ``>>`` / ``+=``
``persistors``  optional storage for parsed packets
``fetchers``    DHCP/ARP sources, including TP-Link over Playwright
``fqdn``        one type for anything reachable: MAC, IPv4, IPv6, name, hop chain
``dnsfetchers`` name-resolution sources: the hosts file, and DNS
``expanders``   fetchers that grow other fetchers' tables (the SSH walk)
``registry``    every implemented source, addressable by name
``probes``      port probing and service identification
``config``      CLI > environment > default for every knob
``engine``      the end-to-end pipeline
"""

from __future__ import annotations

from typing import Optional, Sequence

from .bridge import AsyncBridge, default_bridge
from .browsers import (
    BROWSER_NAMES,
    BrowserNotInstalled,
    detect_browsers,
    first_available_browser,
    installed_browsers,
    is_browser_installed,
)
from .config import Config, ensure_temp_env, parse_cli_args
from .dnsfetchers import (
    DnsTableFetcher,
    HostsFileFetcher,
    ResolvedHostFetcher,
    parse_hosts_entries,
    resolve_names,
)
from .engine import Engine, build_fetcher, build_fetchers, write_ssh_config
from .expanders import (
    ArpTableExpander,
    SSHArpTableExpander,
    SSHHopExpander,
    TableUnion,
)
from .fetchers import (
    ARPTableFetcher,
    FetcherChain,
    OpenWRTFetcher,
    PlaywrightFetcher,
    TPLoginFetcher,
    UnixArpFetcher,
    WindowsArpFetcher,
    default_fetcher_chain,
    merge_tables,
)
from .fqdn import (
    FQDN,
    KIND_HOSTNAME,
    KIND_IPV4,
    KIND_IPV6,
    KIND_MAC,
    KIND_UNKNOWN,
)
from .framing import (
    DatagramFraming,
    DelimiterFraming,
    FixedSizeFraming,
    Framing,
    LengthPrefixFraming,
    MultiplexFraming,
    RequestResponseFraming,
    StreamFraming,
    VarintLengthFraming,
)
from .handlers import (
    AsyncHandler,
    ContextfulHandler,
    Handler,
    HandlerChain,
    HandlerDispatcher,
    RegexBannerHandler,
    ScanResult,
    SocketBannerHandler,
)
from .layers import LAYERS, LayerSpec, SessionRegistry
from .mdnsfetcher import MdnsFetcher, parse_service_info
from .persistors import (
    ArrowPlasmaPersistor,
    JSONLPersistor,
    Persistor,
    PicklePersistor,
    SQLitePersistor,
)
from .probes import COMMON_PORTS, ServiceIdentifier, icmp_ping, probe_service
from .registry import FETCHER_REGISTRY, FetcherRegistry, default_fetcher_registry
from .router import describe, missing_capabilities, router_capabilities
from .scheduling import DependencyCycle, PriorityGraph
from .sessions import (
    AsyncSession,
    AsyncSocketSession,
    Session,
    SessionFactory,
    TableSession,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "main",
    "load_env",
    "ensure_temp_env",
    # bridge
    "AsyncBridge",
    "default_bridge",
    # config / engine
    "Config",
    "Engine",
    "parse_cli_args",
    "write_ssh_config",
    # fetchers
    "ARPTableFetcher",
    "FetcherChain",
    "default_fetcher_chain",
    "merge_tables",
    "TPLoginFetcher",
    "PlaywrightFetcher",
    "UnixArpFetcher",
    "WindowsArpFetcher",
    "OpenWRTFetcher",
    # fqdn
    "FQDN",
    "KIND_IPV4",
    "KIND_IPV6",
    "KIND_MAC",
    "KIND_HOSTNAME",
    "KIND_UNKNOWN",
    # expanders
    "ArpTableExpander",
    "SSHArpTableExpander",
    "SSHHopExpander",
    "TableUnion",
    # name-resolution sources
    "DnsTableFetcher",
    "HostsFileFetcher",
    "ResolvedHostFetcher",
    "parse_hosts_entries",
    "resolve_names",
    # local discovery
    "MdnsFetcher",
    "parse_service_info",
    # scheduling
    "PriorityGraph",
    "DependencyCycle",
    # router capabilities
    "router_capabilities",
    "missing_capabilities",
    "describe",
    # registry
    "FetcherRegistry",
    "FETCHER_REGISTRY",
    "default_fetcher_registry",
    # engine helpers
    "build_fetcher",
    "build_fetchers",
    # browsers
    "BROWSER_NAMES",
    "BrowserNotInstalled",
    "detect_browsers",
    "installed_browsers",
    "is_browser_installed",
    "first_available_browser",
    # framing
    "Framing",
    "StreamFraming",
    "DatagramFraming",
    "LengthPrefixFraming",
    "VarintLengthFraming",
    "DelimiterFraming",
    "FixedSizeFraming",
    "RequestResponseFraming",
    "MultiplexFraming",
    # layers
    "LayerSpec",
    "LAYERS",
    "SessionRegistry",
    # sessions
    "Session",
    "AsyncSession",
    "TableSession",
    "AsyncSocketSession",
    "SessionFactory",
    # handlers
    "Handler",
    "HandlerDispatcher",
    "AsyncHandler",
    "ContextfulHandler",
    "SocketBannerHandler",
    "RegexBannerHandler",
    "HandlerChain",
    "ScanResult",
    # persistors
    "Persistor",
    "PicklePersistor",
    "JSONLPersistor",
    "SQLitePersistor",
    "ArrowPlasmaPersistor",
    # probes
    "COMMON_PORTS",
    "ServiceIdentifier",
    "probe_service",
    "icmp_ping",
]


def load_env() -> None:
    """Load ``.env`` if ``python-dotenv`` happens to be installed.

    Deliberately optional: the tool must run with no extra dependency, and
    every setting is also reachable through real environment variables.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def main(argv: Optional[Sequence[str]] = None):
    """CLI entry point: load ``.env``, repair the temp env, run the engine.

    ``ensure_temp_env`` runs before anything else because Playwright's Node
    driver inherits this process's environment: on CPython 3.10 for Windows an
    unusable inherited temp directory kills the browser launch inside
    ``asyncio``'s pipe creation, and no amount of Python-level care in the
    Playwright call site can repair that after the fact.
    """
    load_env()
    ensure_temp_env()
    config = Config.resolve(argv)
    return Engine(config).run()
