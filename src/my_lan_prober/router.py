"""The ``router`` extra: one install for the whole "talk to a router" story.

Three different jobs need three different libraries, and a user who wants to
get at their router usually wants all three:

===============  =================  ==========================================
capability       library            what it buys
===============  =================  ==========================================
scrape the UI    ``playwright``     the DHCP lease table behind a web login
walk over SSH    ``asyncssh``       another host's neighbour table, and hops
discover locally ``zeroconf``       mDNS names and addresses, with no server
===============  =================  ==========================================

Installing them one at a time is three chances to get the extras wrong, so
``my-lan-prober[router]`` declares all three.  The individual extras remain for
callers who genuinely need only one — a container that scrapes and never walks
should not carry an SSH stack.

Nothing here *requires* the extras.  This module reports on them rather than
importing them at module scope, because ``my_lan_prober`` has to stay importable
in an environment where none of them are installed; CI asserts exactly that.
"""

from __future__ import annotations

from typing import Dict

__all__ = ["ROUTER_CAPABILITIES", "router_capabilities", "missing_capabilities", "describe"]


#: capability → the module that provides it.
ROUTER_CAPABILITIES: Dict[str, str] = {
    "playwright": "playwright",
    "asyncssh": "asyncssh",
    "zeroconf": "zeroconf",
}


def _importable(module: str) -> bool:
    """Whether a module can be imported right now.

    A real ``import`` rather than ``importlib.util.find_spec``: ``find_spec``
    answers "is there a file", which is not the same question — it ignores a
    blocked import, a broken install, and a shadowing name.  What the caller
    wants to know is whether the capability will actually work.
    """
    try:
        __import__(module)
    except ImportError:
        return False
    return True


def router_capabilities() -> Dict[str, bool]:
    """Which router-facing capabilities this machine has, by name."""
    return {name: _importable(module) for name, module in ROUTER_CAPABILITIES.items()}


def missing_capabilities() -> Dict[str, str]:
    """The capabilities that are absent, mapped to the extra that adds them."""
    extras = {"playwright": "playwright", "asyncssh": "ssh", "zeroconf": "mdns"}
    return {
        name: extras.get(name, "router")
        for name, present in router_capabilities().items()
        if not present
    }


def describe() -> str:
    """A one-line summary, for a log line or a diagnostic command."""
    present = router_capabilities()
    return ", ".join(
        f"{name}={'yes' if found else 'no'}" for name, found in sorted(present.items())
    )
