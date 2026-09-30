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
``probes``      port probing and service identification
``config``      CLI > environment > default for every knob
``engine``      the end-to-end pipeline
"""

from __future__ import annotations

from typing import Optional, Sequence

from .bridge import AsyncBridge, default_bridge
from .config import Config, parse_cli_args
from .engine import Engine, write_ssh_config
from .fetchers import (
    ARPTableFetcher,
    FetcherChain,
    OpenWRTFetcher,
    PlaywrightFetcher,
    TPLoginFetcher,
    UnixArpFetcher,
    WindowsArpFetcher,
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
from .persistors import (
    ArrowPlasmaPersistor,
    JSONLPersistor,
    Persistor,
    PicklePersistor,
    SQLitePersistor,
)
from .probes import COMMON_PORTS, ServiceIdentifier, icmp_ping, probe_service
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
    "TPLoginFetcher",
    "PlaywrightFetcher",
    "UnixArpFetcher",
    "WindowsArpFetcher",
    "OpenWRTFetcher",
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
    """CLI entry point: load ``.env``, resolve config, run the engine."""
    load_env()
    config = Config.resolve(argv)
    return Engine(config).run()
