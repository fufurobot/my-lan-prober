"""Sessions — the transport half of the stack.

``design.md`` § 2 and § 1e/1g:

* ``Session`` is transport-only: it moves bytes and forwards parsed packets
  to a persistor through the ``_on_io`` hook.
* ``AsyncSession`` adds the async API plus sync wrappers driven by
  :class:`~my_lan_prober.bridge.AsyncBridge`.
* ``TableSession`` is the single concrete class whose behaviour comes
  entirely from a :class:`~my_lan_prober.layers.LayerSpec`.
* ``AsyncSocketSession`` is the escape hatch for raw sockets.
* ``SessionFactory`` builds and upgrades stacks, reusing the live root.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from .bridge import default_bridge
from .layers import LayerSpec, SessionRegistry

__all__ = [
    "Session",
    "AsyncSession",
    "TableSession",
    "AsyncSocketSession",
    "SessionFactory",
]

#: How long a read waits for more bytes before giving up.
DEFAULT_RECV_DEBOUNCE = 0.1
DEFAULT_MAX_FRAME_SIZE = 1024


class Session(ABC):
    """Transport-only node in a protocol stack."""

    def __init__(
        self,
        *,
        base: Optional["Session"] = None,
        persistor: Any = None,
        max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        self._base = base
        self._persistor = persistor
        self._max_frame_size = max_frame_size
        self._on_io: Optional[Callable[[str, bytes], None]] = None

    # -- transport -----------------------------------------------------
    @abstractmethod
    def close(self) -> None:
        """Release transport resources."""
        raise NotImplementedError

    # -- stack navigation ---------------------------------------------
    def root(self) -> "Session":
        """The bottom-most session — the one holding the live socket."""
        session = self
        while session._base is not None:
            session = session._base
        return session

    # -- persistence ---------------------------------------------------
    def history(self) -> Any:
        """Parsed packets recorded by this session's persistor."""
        if self._persistor is None:
            return []
        return self._persistor.history()

    def _fire_io(self, direction: str, payload: bytes) -> None:
        """Notify the owner of an I/O event (``"send"`` / ``"recv"``)."""
        if self._on_io is not None:
            self._on_io(direction, payload)


class AsyncSession(Session, ABC):
    """A :class:`Session` whose I/O is asynchronous."""

    @abstractmethod
    async def send_async(self, data: bytes, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        """Write ``data`` towards the peer."""
        raise NotImplementedError

    @abstractmethod
    async def read_async(self, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        """Read the next frame(s), or ``None`` when nothing arrived."""
        raise NotImplementedError

    # -- sync wrappers -------------------------------------------------
    def send(self, data: bytes, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        return default_bridge().run(self.send_async(data, recv_debounce_seconds))

    def read(self, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        return default_bridge().run(self.read_async(recv_debounce_seconds))

    # -- helpers for concrete transports -------------------------------
    async def _send_down(self, data: bytes) -> None:
        if self._base is not None:
            await self._base.send_async(data)
        else:  # pragma: no cover - a root async session must override this
            raise NotImplementedError("root session cannot send")

    async def _read_up(self, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        if self._base is not None:
            return await self._base.read_async(recv_debounce_seconds)
        raise NotImplementedError("root session cannot read")


class TableSession(AsyncSession):
    """A session whose behaviour is entirely determined by its ``LayerSpec``."""

    def __init__(
        self,
        spec: LayerSpec,
        *,
        base: Optional[Session] = None,
        persistor: Any = None,
        max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        super().__init__(base=base, persistor=persistor, max_frame_size=max_frame_size)
        self.spec = spec
        self._inbuf = bytearray()
        self._handshake_sent = False

    async def _ensure_open(self) -> None:
        if self._handshake_sent or self.spec.handshake_out is None:
            return
        handshake = self.spec.handshake_out
        if callable(handshake):
            handshake = handshake()
        self._handshake_sent = True
        await self._send_down(handshake)
        self._fire_io("send", handshake)

    async def send_async(self, data: bytes, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        await self._ensure_open()
        wire = data
        if self.spec.transform_out is not None:
            wire = self.spec.transform_out(wire)
        wire = self.spec.framing.encode(wire)
        await self._send_down(wire)
        self._fire_io("send", wire)

    async def read_async(self, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        raw = await self._read_up(recv_debounce_seconds)
        if raw:
            self._inbuf.extend(raw)
            self._fire_io("recv", raw)
        if not self._inbuf:
            return None
        frames = self.spec.framing.frame(self._inbuf)
        if not frames:
            return None
        if self.spec.transform_in is not None:
            frames = [self.spec.transform_in(frame) for frame in frames]
        return frames

    def close(self) -> None:
        if self._base is not None:
            self._base.close()


class AsyncSocketSession(AsyncSession):
    """Escape hatch: a raw TCP socket driven by the bridge's loop."""

    def __init__(
        self,
        *,
        sock: Optional[socket.socket] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: float = 5.0,
        base: Optional[Session] = None,
        persistor: Any = None,
        max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        super().__init__(base=base, persistor=persistor, max_frame_size=max_frame_size)
        self.host = host
        self.port = port
        self._owns_socket = sock is None
        if sock is None:
            if host is None or port is None:
                raise ValueError("either sock or (host, port) is required")
            sock = socket.create_connection((host, port), timeout=timeout)
        self._sock = sock

    async def send_async(self, data: bytes, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self._sock, data)
        self._fire_io("send", data)

    async def read_async(self, recv_debounce_seconds: float = DEFAULT_RECV_DEBOUNCE):
        loop = asyncio.get_running_loop()
        try:
            raw = await asyncio.wait_for(
                loop.sock_recv(self._sock, 65536), timeout=recv_debounce_seconds
            )
        except (asyncio.TimeoutError, TimeoutError):
            return None
        except OSError:
            return None
        if not raw:
            return None
        self._fire_io("recv", raw)
        return raw

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._sock.close()
        if self._base is not None:
            self._base.close()


class SessionFactory:
    """Build a stack, or upgrade one over an already-open root."""

    @staticmethod
    def build(
        stack: List[str],
        *,
        persistor: Any = None,
        max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE,
        root_session: Optional[Session] = None,
        **root_kwargs: Any,
    ) -> AsyncSession:
        """Build ``stack``, reusing ``root_session`` as the live transport.

        ``stack[0]`` describes the transport to use when ``root_session`` is
        not supplied.  The returned session is always the *top* of the stack,
        so a single-layer build still yields a ``TableSession`` (or the
        layer's ``override_class``) sitting on the transport.
        """
        if not stack:
            raise ValueError("empty stack")

        root_spec = SessionRegistry.get(stack[0])
        if root_session is None:
            root_session = SessionFactory._instantiate_root(root_spec, root_kwargs)

        # Persistence lives at the top of the stack only, so the first layer
        # gets it only when it *is* the top (a single-layer build).
        single = len(stack) == 1
        top = SessionFactory._instantiate(
            root_spec,
            base=root_session,
            persistor=persistor if single else None,
            max_frame_size=max_frame_size if single else None,
        )
        return SessionFactory.upgrade(
            top,
            stack[1:],
            persistor=persistor,
            max_frame_size=max_frame_size,
        )

    @staticmethod
    def upgrade(
        base: Session,
        extra: List[str],
        *,
        persistor: Any = None,
        max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE,
    ) -> AsyncSession:
        """Wrap ``base`` in ``extra`` layers, persisting only at the top."""
        if not extra:
            base._persistor = persistor
            base._max_frame_size = max_frame_size
            return base  # type: ignore[return-value]

        top: Session = base
        last = len(extra) - 1
        for index, name in enumerate(extra):
            spec = SessionRegistry.get(name)
            is_top = index == last
            top = SessionFactory._instantiate(
                spec,
                base=top,
                persistor=persistor if is_top else None,
                max_frame_size=max_frame_size if is_top else None,
            )
        return top  # type: ignore[return-value]

    @staticmethod
    def _instantiate_root(spec: LayerSpec, root_kwargs: Dict[str, Any]) -> Session:
        """Build the *transport* for a root layer.

        These are the bottom of the stack, so they are plain transports: the
        layer's own framing/transform behaviour is applied by the
        ``TableSession`` that ``build`` stacks on top of them.
        """
        if spec.name in ("TCP", "UDP"):
            return AsyncSocketSession(**root_kwargs)
        if spec.override_class is not None:
            return spec.override_class(spec=spec, **root_kwargs)
        return AsyncSocketSession(**root_kwargs)

    @staticmethod
    def _instantiate(spec: LayerSpec, *, base: Session, **kwargs: Any) -> Session:
        if spec.override_class is not None:
            return spec.override_class(spec=spec, base=base, **kwargs)
        return TableSession(spec=spec, base=base, **kwargs)
