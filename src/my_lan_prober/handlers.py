"""Handlers — the parsing half of the stack.

``design.md`` § 3/4/5:

* ``Handler``           — ``ports``, ``description``, ``handle``, ``ahandle``,
  ``check_banner``, and the ``<<`` / ``>>`` composition operators.
* ``HandlerDispatcher`` — ``+=`` / ``-=`` for child handlers.
* ``AsyncHandler``      — ``ahandle`` is the primitive; ``handle`` blocks on it.
* ``ContextfulHandler`` — carries a live ``Session``.
* ``SocketBannerHandler`` — takes **both** a stack spec and a live session,
  glues received bytes, persists parsed packets, and upgrades the live
  session in place when a child needs a deeper stack.
* ``RegexBannerHandler`` — dispatch on a banner pattern.
* ``HandlerChain``      — first non-``None`` result wins.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from .bridge import default_bridge
from .layers import SessionRegistry
from .sessions import Session, SessionFactory

log = logging.getLogger(__name__)

__all__ = [
    "ScanResult",
    "Handler",
    "HandlerDispatcher",
    "AsyncHandler",
    "ContextfulHandler",
    "SocketBannerHandler",
    "RegexBannerHandler",
    "HandlerChain",
]


@dataclass
class ScanResult:
    """What a handler learned about one port."""

    port: Optional[int]
    service: Optional[str]
    banner: bytes = b""

    def __bool__(self) -> bool:
        return bool(self.service)


# ---------------------------------------------------------------------------
# Handler base
# ---------------------------------------------------------------------------
class Handler(ABC):
    """One step in a probe chain."""

    #: Layer stack this handler needs; drives in-place session upgrades.
    REQUIRED_STACK: Optional[List[str]] = None

    # -- metadata ------------------------------------------------------
    @abstractmethod
    def ports(self) -> Optional[Sequence[int]]:
        """Ports this handler is interested in, or ``None`` for any."""
        raise NotImplementedError

    @abstractmethod
    def description(self) -> str:
        """Human-readable label used in logs and diagnostics."""
        raise NotImplementedError

    # -- dispatch ------------------------------------------------------
    def check_banner(self, banner: bytes) -> bool:
        """Whether this handler wants to handle ``banner``."""
        return bool(banner)

    def load_full(self, payload: bytes) -> Optional[dict]:
        """Parse a payload into a row for the persistor. Default: nothing."""
        return None

    def handle_banner(self, banner: bytes, port: Optional[int] = None) -> ScanResult:
        return ScanResult(
            port=port,
            service=None,
            banner=banner or b"",
        )

    @abstractmethod
    def handle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def ahandle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        """Async entry point.  Sync handlers run via the bridge."""
        return await default_bridge().run_sync(
            self.handle, target, *args, **kwargs
        )

    # -- composition ---------------------------------------------------
    def __lshift__(self, other: "Handler") -> "HandlerChain":
        return HandlerChain([self, other])

    def __rshift__(self, other: "Handler") -> "HandlerChain":
        return HandlerChain([other, self])


class HandlerDispatcher(Handler, ABC):
    """A handler that owns child handlers."""

    @abstractmethod
    def __iadd__(self, other: Handler) -> "HandlerDispatcher":
        raise NotImplementedError

    @abstractmethod
    def __isub__(self, other: Handler) -> "HandlerDispatcher":
        raise NotImplementedError


class AsyncHandler(Handler, ABC):
    """A handler whose work is genuinely asynchronous."""

    def handle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        return default_bridge().run(self.ahandle(target, *args, **kwargs))


class ContextfulHandler(Handler, ABC):
    """A handler that carries a live :class:`Session`."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def session(self) -> Session:
        return self._session


# ---------------------------------------------------------------------------
# RegexBannerHandler
# ---------------------------------------------------------------------------
class RegexBannerHandler(Handler):
    """Identify a service by matching its banner."""

    def __init__(
        self,
        pattern: Any,
        name: str,
        *,
        stack: Optional[List[str]] = None,
    ) -> None:
        if isinstance(pattern, (bytes, str)):
            flags = re.IGNORECASE if isinstance(pattern, str) else 0
            self._pattern = re.compile(pattern, flags)
        else:
            self._pattern = pattern
        self._name = name
        self.REQUIRED_STACK = list(stack) if stack else None

    def ports(self) -> Optional[Sequence[int]]:
        return None

    def description(self) -> str:
        pattern = getattr(self._pattern, "pattern", self._pattern)
        if isinstance(pattern, bytes):
            pattern = pattern.decode("utf-8", "replace")
        return f"regex:{pattern} → {self._name}"

    def check_banner(self, banner: bytes) -> bool:
        try:
            pattern = self._pattern.pattern
            if isinstance(pattern, bytes):
                haystack: Any = banner or b""
            else:
                haystack = (banner or b"").decode("utf-8", "ignore")
            return bool(self._pattern.search(haystack))
        except Exception:
            return False

    def load_full(self, payload: bytes) -> Optional[dict]:
        return {
            "service": self._name,
            "banner": (payload or b"")[:1024].decode("utf-8", "ignore"),
        }

    def handle_banner(self, banner: bytes, port: Optional[int] = None) -> ScanResult:
        return ScanResult(port=port, service=self._name, banner=banner or b"")

    async def ahandle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        """Decline banners this handler does not match."""
        banner = kwargs.get("banner", b"")
        if not self.check_banner(banner):
            return None
        return self.handle_banner(banner, kwargs.get("port"))

    def handle(self, target: Any, *args: Any, **kwargs: Any) -> Optional[ScanResult]:
        return default_bridge().run(self.ahandle(target, *args, **kwargs))


# ---------------------------------------------------------------------------
# HandlerChain
# ---------------------------------------------------------------------------
def _flatten(handlers: Sequence[Any]) -> List[Handler]:
    flat: List[Handler] = []
    for handler in handlers:
        if isinstance(handler, HandlerChain):
            flat.extend(handler._handlers)
        else:
            flat.append(handler)
    return flat


class HandlerChain(HandlerDispatcher):
    """Run handlers in order; the first non-``None`` result wins."""

    def __init__(self, handlers: Sequence[Handler]) -> None:
        self._handlers = _flatten(list(handlers))

    def handlers(self) -> List[Handler]:
        return list(self._handlers)

    def ports(self) -> Optional[Sequence[int]]:
        seen, out = set(), []
        for handler in self._handlers:
            ports = handler.ports()
            if ports is None:
                continue
            for port in ports:
                if port not in seen:
                    seen.add(port)
                    out.append(port)
        return out or None

    def description(self) -> str:
        return " → ".join(handler.description() for handler in self._handlers)

    def __iadd__(self, other: Handler) -> "HandlerChain":
        self._handlers.append(other)
        return self

    def __isub__(self, other: Handler) -> "HandlerChain":
        self._handlers.remove(other)
        return self

    def __lshift__(self, other: Handler) -> "HandlerChain":
        return HandlerChain(self._handlers + [other])

    def __rshift__(self, other: Handler) -> "HandlerChain":
        return HandlerChain([other] + self._handlers)

    def check_banner(self, banner: bytes) -> bool:
        return any(handler.check_banner(banner) for handler in self._handlers)

    async def ahandle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        for handler in self._handlers:
            result = await handler.ahandle(target, *args, **kwargs)
            if result is not None:
                return result
        return None

    def handle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        return default_bridge().run(self.ahandle(target, *args, **kwargs))


# ---------------------------------------------------------------------------
# SocketBannerHandler
# ---------------------------------------------------------------------------
class SocketBannerHandler(ContextfulHandler, HandlerDispatcher):
    """Probe an open socket, glue what comes back, and dispatch on it."""

    def __init__(
        self,
        stack: Sequence[str],
        session: Session,
        *,
        persistor: Any = None,
        max_frame_size: Optional[int] = 1024,
        children: Optional[Sequence[Handler]] = None,
        probe: bytes = b"\r\n",
    ) -> None:
        super().__init__(session)
        self._stack = list(stack)
        self._persistor = persistor
        self._max_frame_size = max_frame_size
        self._probe = probe
        self._children: List[Handler] = []
        self._glue = bytearray()

        # The persistor and I/O hook belong to the top of the stack.
        self._session._persistor = persistor
        self._session._max_frame_size = max_frame_size
        self._session._on_io = self._on_io

        for child in children or ():
            self += child

    # -- metadata ------------------------------------------------------
    def ports(self) -> Optional[Sequence[int]]:
        return None

    def description(self) -> str:
        return "→".join(self._stack)

    def stack(self) -> List[str]:
        return list(self._stack)

    def children(self) -> List[Handler]:
        return list(self._children)

    def check_banner(self, banner: bytes) -> bool:
        return bool(banner)

    # -- dispatch ------------------------------------------------------
    def __iadd__(self, other: Handler) -> "SocketBannerHandler":
        """Attach a child, rejecting any that mishandle an empty banner."""
        try:
            other.check_banner(b"")
        except Exception:
            log.warning("rejecting handler %r: check_banner raised", other)
            return self
        self._children.append(other)
        return self

    def __isub__(self, other: Handler) -> "SocketBannerHandler":
        self._children.remove(other)
        return self

    # -- persistence hook ----------------------------------------------
    def _on_io(self, direction: str, payload: bytes) -> None:
        if direction != "recv":
            return
        self._glue.extend(payload)
        parsed = self.load_full(bytes(self._glue))
        if parsed is None:
            return
        if self._persistor is not None:
            self._persistor.store_full(parsed)

    def load_full(self, payload: bytes) -> Optional[dict]:
        return {
            "banner": payload[:1024].decode("utf-8", "ignore"),
            "length": len(payload),
        }

    def handle_banner(self, banner: bytes, port: Optional[int] = None) -> ScanResult:
        service = self._stack[-1] if self._stack else None
        return ScanResult(port=port, service=service, banner=banner)

    # -- stack rebinding ------------------------------------------------
    def _rebind_stack(self, new_stack: Sequence[str]) -> None:
        """Grow the live stack without dropping the open transport.

        ``new_stack`` extends the current stack, so only the layers past the
        current top are new.  The live root (with its open socket) is reused
        by ``SessionFactory.upgrade``.
        """
        root = self._session.root()
        # Everything already present in this handler's stack is kept as-is;
        # only the extra layers above the current top get instantiated.
        base_len = len(self._stack)
        extra = list(new_stack)[base_len:]
        if not extra:
            self._stack = list(new_stack)
            return

        self._session._persistor = None
        new_top = SessionFactory.upgrade(
            root,
            extra,
            persistor=self._persistor,
            max_frame_size=self._max_frame_size,
        )
        new_top._on_io = self._on_io
        self._stack = list(new_stack)
        self._session = new_top

    # -- execution ------------------------------------------------------
    async def ahandle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        port = kwargs.pop("port", None)
        await self._session.send_async(self._probe)

        # Drain whatever the peer volunteers, so the banner is fully glued
        # before any child gets to see it.
        while True:
            frames = await self._session.read_async()
            if frames is None:
                break

        banner = bytes(self._glue)

        for child in self._children:
            if not child.check_banner(banner):
                continue
            deeper = getattr(child, "REQUIRED_STACK", None)
            if deeper and list(deeper) != self._stack:
                self._rebind_stack(deeper)
            return await child.ahandle(
                target, *args, port=port, banner=banner, **kwargs
            )
        return self.handle_banner(banner, port)

    def handle(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        return default_bridge().run(self.ahandle(target, *args, **kwargs))
