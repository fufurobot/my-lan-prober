"""Tests for :mod:`my_lan_prober.sessions`.

Covers the ``Session`` hierarchy (``design.md`` § 1e/1g/2):

* ``Session``      — transport base: ``_base``, ``_persistor``, ``_on_io``, ``root()``
* ``AsyncSession`` — ``send_async``/``read_async`` plus sync wrappers
* ``TableSession`` — behaviour driven entirely by a ``LayerSpec``
* ``AsyncSocketSession`` — escape hatch over a real socket
* ``SessionFactory`` — ``build`` / ``upgrade`` over a live root
"""

from __future__ import annotations

import socket
import threading

import pytest

from my_lan_prober.framing import DelimiterFraming
from my_lan_prober.layers import LAYERS, LayerSpec
from my_lan_prober.sessions import (
    AsyncSession,
    AsyncSocketSession,
    Session,
    SessionFactory,
    TableSession,
)


# ---------------------------------------------------------------------------
# A scripted in-memory session, so tests never touch the network
# ---------------------------------------------------------------------------
class FakeSession(AsyncSession):
    """An ``AsyncSession`` with no transport: reads come from a queue."""

    def __init__(self, chunks=None, **kwargs):
        super().__init__(**kwargs)
        self.sent = []
        self.closed = False
        self._chunks = list(chunks or [])

    async def send_async(self, data, recv_debounce_seconds=0.1):
        self.sent.append(data)
        self._fire_io("send", data)

    async def read_async(self, recv_debounce_seconds=0.1):
        if not self._chunks:
            return None
        chunk = self._chunks.pop(0)
        self._fire_io("recv", chunk)
        return chunk

    def close(self):
        self.closed = True


def layered(spec, chunks=None):
    """A ``TableSession`` over a scripted root: returns ``(top, root)``."""
    root = FakeSession(chunks=chunks)
    return TableSession(spec=spec, base=root), root


# ---------------------------------------------------------------------------
# Session / AsyncSession basics
# ---------------------------------------------------------------------------
def test_session_holds_base_persistor_and_frame_size():
    base = FakeSession()
    top = FakeSession(base=base, persistor="P", max_frame_size=99)

    assert top._base is base
    assert top._persistor == "P"
    assert top._max_frame_size == 99


def test_root_walks_to_the_bottom_of_the_stack():
    a = FakeSession()
    b = FakeSession(base=a)
    c = FakeSession(base=b)

    assert c.root() is a
    assert a.root() is a


def test_fire_io_invokes_the_hook():
    seen = []
    session = FakeSession()
    session._on_io = lambda direction, payload: seen.append((direction, payload))

    session._fire_io("recv", b"abc")

    assert seen == [("recv", b"abc")]


def test_fire_io_is_a_noop_without_a_hook():
    FakeSession()._fire_io("recv", b"abc")


def test_send_and_read_are_sync_wrappers_over_the_async_api():
    session = FakeSession(chunks=[b"hello"])

    session.send(b"ping")
    assert session.sent == [b"ping"]
    assert session.read() == b"hello"
    assert session.read() is None


def test_session_is_abstract():
    with pytest.raises(TypeError):
        Session()  # type: ignore[abstract]


def test_async_session_cannot_be_instantiated_without_the_io_methods():
    with pytest.raises(TypeError):
        AsyncSession()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Persistor plumbing
# ---------------------------------------------------------------------------
class FakePersistor:
    def __init__(self):
        self.rows = []

    def store_full(self, data):
        self.rows.append(data)
        return len(self.rows)

    def history(self):
        return self.rows


def test_history_is_empty_without_a_persistor():
    assert FakeSession().history() == []


def test_history_delegates_to_the_persistor():
    persistor = FakePersistor()
    session = FakeSession(persistor=persistor)
    persistor.store_full({"a": 1})

    assert session.history() == [{"a": 1}]


def test_close_is_safe_on_a_session_without_a_base():
    FakeSession().close()


# ---------------------------------------------------------------------------
# TableSession — behaviour driven by a LayerSpec
# ---------------------------------------------------------------------------
def test_table_session_uses_spec_framing_to_split_incoming_bytes():
    spec = LayerSpec("Lines", DelimiterFraming(b"\r\n"))
    session, _ = layered(spec, chunks=[b"220 hi\r\n250 ok\r\n"])

    assert session.read() == [b"220 hi", b"250 ok"]


def test_table_session_buffers_partial_frames_across_reads():
    spec = LayerSpec("Lines", DelimiterFraming(b"\r\n"))
    session, _ = layered(spec, chunks=[b"220 hi\r", b"\n250 ok\r\n"])

    assert session.read() is None
    assert session.read() == [b"220 hi", b"250 ok"]


def test_table_session_encode_applies_framing_on_send():
    spec = LayerSpec("Lines", DelimiterFraming(b"\r\n"))
    session, root = layered(spec)

    session.send(b"EHLO")

    assert root.sent == [b"EHLO\r\n"]


def test_table_session_applies_transform_hooks_on_both_directions():
    spec = LayerSpec(
        "Rot",
        DelimiterFraming(b"\r\n"),
        transform_out=lambda b: bytes(x + 1 for x in b),
        transform_in=lambda b: bytes(x - 1 for x in b),
    )
    session, root = layered(spec, chunks=[b"bcd\r\n"])

    session.send(b"abc")
    assert root.sent == [b"bcd\r\n"]
    assert session.read() == [b"abc"]


def test_table_session_sends_handshake_once_on_first_send():
    spec = LayerSpec("Greet", handshake_out=b"EHLO\r\n")
    session, root = layered(spec)

    session.send(b"A")
    session.send(b"B")

    assert root.sent == [b"EHLO\r\n", b"A", b"B"]


def test_table_session_supports_a_callable_handshake():
    spec = LayerSpec("Greet", handshake_out=lambda: b"PRI *\r\n")
    session, root = layered(spec)

    session.send(b"A")

    assert root.sent == [b"PRI *\r\n", b"A"]


def test_table_session_with_no_handshake_sends_only_the_payload():
    session, root = layered(LayerSpec("Plain"))

    session.send(b"A")

    assert root.sent == [b"A"]


def test_table_session_read_returns_none_when_transport_is_empty():
    session, _ = layered(LayerSpec("Plain"))

    assert session.read() is None


# ---------------------------------------------------------------------------
# SessionFactory
# ---------------------------------------------------------------------------
def test_factory_build_rejects_an_empty_stack():
    with pytest.raises(ValueError, match="empty stack"):
        SessionFactory.build([])


def test_factory_build_rejects_unknown_layers():
    with pytest.raises(KeyError, match="unknown layer"):
        SessionFactory.build(["NoSuchProto"])


def test_factory_build_creates_a_table_session_for_a_single_layer():
    session = SessionFactory.build(["TCP"], root_session=FakeSession())

    assert isinstance(session, TableSession)
    assert session.spec is LAYERS["TCP"]


def test_factory_build_stacks_layers_base_upwards():
    root = FakeSession()
    session = SessionFactory.build(["TCP", "SSH"], root_session=root)

    assert session.spec is LAYERS["SSH"]
    assert session._base.spec is LAYERS["TCP"]
    assert session._base._base is root
    assert session.root() is root


def test_factory_attaches_persistor_and_frame_size_to_the_top_only():
    persistor = FakePersistor()
    session = SessionFactory.build(
        ["TCP", "SSH"], persistor=persistor, max_frame_size=7, root_session=FakeSession()
    )

    assert session._persistor is persistor
    assert session._max_frame_size == 7
    assert session._base._persistor is None


def test_factory_upgrade_reuses_the_live_root():
    root = FakeSession()

    upgraded = SessionFactory.upgrade(root, ["TLS", "HTTP/1.1"])

    assert upgraded.spec is LAYERS["HTTP/1.1"]
    assert upgraded.root() is root
    assert upgraded._base.spec is LAYERS["TLS"]


def test_factory_upgrade_with_empty_extra_attaches_persistor_to_base():
    root = FakeSession()
    persistor = FakePersistor()

    result = SessionFactory.upgrade(root, [], persistor=persistor, max_frame_size=5)

    assert result is root
    assert root._persistor is persistor
    assert root._max_frame_size == 5


def test_factory_uses_override_class_when_a_layer_declares_one():
    class Custom(AsyncSession):
        def __init__(self, spec=None, **kwargs):
            super().__init__(**kwargs)
            self.spec = spec

        async def send_async(self, data, recv_debounce_seconds=0.1):
            pass

        async def read_async(self, recv_debounce_seconds=0.1):
            return None

        def close(self):
            pass

    spec = LayerSpec("Custom", override_class=Custom, description="t")
    from my_lan_prober.layers import SessionRegistry

    SessionRegistry.register(spec)
    try:
        session = SessionFactory.build(["Custom"], root_session=FakeSession())
        assert isinstance(session, Custom)
        assert session.spec is spec
    finally:
        SessionRegistry._specs.pop("Custom", None)


def test_factory_build_without_a_root_session_opens_a_real_socket():
    """Building on TCP with no supplied root must open a real socket."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    try:
        session = SessionFactory.build(["TCP"], host="127.0.0.1", port=port)
        assert isinstance(session, TableSession)
        assert isinstance(session.root(), AsyncSocketSession)
        session.close()
    finally:
        server.close()


# ---------------------------------------------------------------------------
# AsyncSocketSession — the escape hatch over a live socket
# ---------------------------------------------------------------------------
def test_socket_session_round_trips_bytes_over_a_real_socket():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_10.5\r\n")
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    try:
        session = AsyncSocketSession(host="127.0.0.1", port=port)
        assert session.read() == b"SSH-2.0-OpenSSH_10.5\r\n"
        session.close()
    finally:
        server.close()
        thread.join(timeout=2)


def test_socket_session_accepts_an_already_connected_socket():
    left, right = socket.socketpair()
    try:
        session = AsyncSocketSession(sock=left)
        right.sendall(b"banner")
        assert session.read() == b"banner"
        session.send(b"probe")
        assert right.recv(64) == b"probe"
        session.close()
    finally:
        right.close()


def test_socket_session_read_returns_none_on_eof():
    left, right = socket.socketpair()
    try:
        session = AsyncSocketSession(sock=left)
        right.close()
        assert session.read() is None
    finally:
        left.close()


def test_socket_session_connect_failure_raises():
    with pytest.raises(OSError):
        AsyncSocketSession(host="127.0.0.1", port=1, timeout=0.2)
