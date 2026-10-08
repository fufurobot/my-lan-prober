"""The ARP source registry — every implemented fetcher, addressable by name.

The engine used to pick *one* source (``--fetcher tplogin``) and stop at the
first non-empty table.  That loses hosts, and it loses them silently:

* the router's DHCP lease table knows every client it has ever leased to;
* the local neighbour table knows the machines this host actually talked to;
* the hosts file knows the names the user pinned;
* a resolver knows the names the world publishes;
* an SSH hop knows a whole subnet that none of the others can even reach.

They are not alternatives.  A registry turns them from a list of fallbacks
into a *set* of sources the engine can ask at once and merge.

The registry is also the seam that keeps the optional dependencies optional.
``playwright``, ``asyncssh`` and ``python-hosts`` are extras; a source whose
library is missing must report itself unavailable rather than fail the run —
which is exactly what CI asserts when it installs no extras at all.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from .fetchers import (
    ARPTableFetcher,
    OpenWRTFetcher,
    TPLoginFetcher,
    UnixArpFetcher,
    WindowsArpFetcher,
)

log = logging.getLogger(__name__)

__all__ = [
    "FetcherRegistry",
    "FETCHER_REGISTRY",
    "default_fetcher_registry",
    "AUTO_SOURCES",
]

#: Sources that are safe to run without being asked for: they read local state
#: or fetch over the network, but never log into another machine.
AUTO_SOURCES = ("tplogin", "unix", "windows", "openwrt", "hosts", "dns", "resolved")

#: Factory signature: anything a source needs to be constructed with.
Factory = Callable[..., ARPTableFetcher]


class FetcherRegistry:
    """Name → factory, for every ARP source this build knows how to make."""

    def __init__(self) -> None:
        self._factories: Dict[str, Factory] = {}

    # -- registration ---------------------------------------------------
    def register(self, name: str, factory: Factory) -> None:
        """Add a source, or replace one that already has this name.

        Replacement is deliberate: a user overriding the built-in ``unix``
        source with their own is the obvious extension point, and refusing it
        would force them to invent a new name for the same concept.
        """
        self._factories[name] = factory

    def unregister(self, name: str) -> None:
        self._factories.pop(name, None)

    def names(self) -> List[str]:
        """Every registered name, sorted, so CLI help is stable."""
        return sorted(self._factories)

    def all(self) -> Dict[str, Factory]:
        return dict(self._factories)

    # -- construction ---------------------------------------------------
    def create(self, name: str, **kwargs: Any) -> ARPTableFetcher:
        """Build the named source.

        A factory that raises is *not* swallowed here: this is the explicit
        "make me this source" call, and a caller who asked for one is entitled
        to hear why it could not be made.  :meth:`available` is the tolerant
        variant used when scanning a whole selection.
        """
        try:
            factory = self._factories[name]
        except KeyError:
            raise KeyError(
                f"unknown ARP source {name!r}; known sources: {', '.join(self.names())}"
            ) from None
        return factory(**kwargs)

    def available(self, **kwargs: Any) -> List[ARPTableFetcher]:
        """Every source that can run here right now.

        A factory that raises is skipped with a warning rather than propagated:
        "playwright is not installed" must degrade the scan, not end it.
        """
        built: List[ARPTableFetcher] = []
        for name in self.names():
            try:
                fetcher = self.create(name, **kwargs)
            except Exception as exc:
                log.debug("ARP source %s could not be built: %s", name, exc)
                continue
            try:
                if not fetcher.available():
                    log.debug("ARP source %s is not available here", name)
                    continue
            except Exception as exc:
                log.debug("availability check for %s raised: %s", name, exc)
                continue
            built.append(fetcher)
        return built

    # -- selection ------------------------------------------------------
    def parse_selection(self, selection: Optional[str], **kwargs: Any) -> List[str]:
        """Turn a ``--fetcher`` value into a list of source names.

        ``all`` means every registered source; ``auto`` (and an empty value)
        means the non-invasive set — a scan must not start logging into other
        people's machines because nobody passed a flag.
        """
        raw = (selection or "").strip()
        if not raw or raw == "auto":
            return [name for name in self.names() if name in AUTO_SOURCES]
        if raw == "all":
            return self.names()

        names = [part.strip() for part in raw.split(",") if part.strip()]
        unknown = [name for name in names if name not in self._factories]
        if unknown:
            raise KeyError(
                f"unknown ARP source {', '.join(repr(name) for name in unknown)}; "
                f"known sources: {', '.join(self.names())}"
            )
        return names


# ---------------------------------------------------------------------------
# The shipped registry
# ---------------------------------------------------------------------------
def _tplogin(**kwargs: Any) -> ARPTableFetcher:
    return TPLoginFetcher(browser=kwargs.get("browser"))


def _unix(**kwargs: Any) -> ARPTableFetcher:
    return UnixArpFetcher()


def _windows(**kwargs: Any) -> ARPTableFetcher:
    return WindowsArpFetcher()


def _openwrt(**kwargs: Any) -> ARPTableFetcher:
    return OpenWRTFetcher()


def _hosts(**kwargs: Any) -> ARPTableFetcher:
    from .dnsfetchers import HostsFileFetcher

    return HostsFileFetcher()


def _dns(**kwargs: Any) -> ARPTableFetcher:
    from .dnsfetchers import DnsTableFetcher

    return DnsTableFetcher()


def _resolved(**kwargs: Any) -> ARPTableFetcher:
    from .dnsfetchers import ResolvedHostFetcher

    return ResolvedHostFetcher()


def _mdns(**kwargs: Any) -> ARPTableFetcher:
    """Local discovery: addresses *and* the names that go with them."""
    from .mdnsfetcher import MdnsFetcher

    return MdnsFetcher()


def _ssh(**kwargs: Any) -> ARPTableFetcher:
    """The SSH expander, as a source the engine can select.

    Its upstream is the tables the *other* selected sources produced, which the
    engine assembles; on its own it can still seed from the known-hosts file.
    """
    from .expanders import SSHArpTableExpander
    from .fetchers import UnixArpFetcher as _Local

    return SSHArpTableExpander(
        [_Local()],
        hop=kwargs.get("ssh_hop"),
        enabled=bool(kwargs.get("expand")),
        max_depth=int(kwargs.get("expand_depth") or 1),
        username=kwargs.get("ssh_user"),
    )


def default_fetcher_registry() -> FetcherRegistry:
    """The registry as shipped: one entry per implemented source.

    ``tplogin`` keeps its name even though the class is called
    ``TPLoginFetcher``: the CLI has always spelled it that way, and renaming a
    documented flag to match a class is a worse trade than the mismatch.
    """
    registry = FetcherRegistry()
    registry.register("tplogin", _tplogin)
    registry.register("unix", _unix)
    registry.register("windows", _windows)
    registry.register("openwrt", _openwrt)
    registry.register("hosts", _hosts)
    registry.register("dns", _dns)
    registry.register("resolved", _resolved)
    registry.register("mdns", _mdns)
    registry.register("ssh", _ssh)
    return registry


#: The process-wide registry.  Import-time construction only registers
#: factories; nothing is instantiated and no optional module is imported until
#: a caller actually asks for a source.
FETCHER_REGISTRY = default_fetcher_registry()
