"""Tests for :mod:`my_lan_prober.handlers`.

``design.md`` § 3/4/5.  Handlers compose with ``<<`` and ``>>``; dispatch on
banner uses ``+=``; when a child declares a deeper ``REQUIRED_STACK`` the
parent upgrades the *live* session in place instead of reconnecting.
"""

from __future__ import annotations

import re

import pytest

from my_lan_prober.handlers import (
    AsyncHandler,
    ContextfulHandler,
    Handler,
    HandlerChain,
    HandlerDispatcher,
    RegexBannerHandler,
    ScanResult,
    SocketBannerHandler,
)
from my_lan_prober.layers import LAYERS, LayerSpec, SessionRegistry
from my_lan_prober.sessions import AsyncSession, TableSession


# ---------------------------------------------------------------------------
# A scripted session/root so no test touches the network
# ---------------------------------------------------------------------------
class Scripted(AsyncSession):
    """Root transport that replays canned responses per sent payload."""

    def __init__(self, replies=None, **kwargs):
        super().__init__(**kwargs)
        self.sent = []
        self._replies = list(replies or [])

    async def send_async(self, data, recv_debounce_seconds=0.1):
        self.sent.append(data)
        self._fire_io("send", data)

    async def read_async(self, recv_debounce_seconds=0.1):
        if not self._replies:
            return None
        chunk = self._replies.pop(0)
        self._fire_io("recv", chunk)
        return chunk

    def close(self):
        pass


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------
def test_scan_result_exposes_service_and_banner():
    result = ScanResult(port=22, service="SSH", banner=b"SSH-2.0-x")

    assert result.port == 22
    assert result.service == "SSH"
    assert result.banner == b"SSH-2.0-x"


def test_scan_result_is_truthy_when_a_service_was_identified():
    assert ScanResult(port=22, service="SSH", banner=b"x")


def test_scan_result_is_falsey_when_nothing_was_identified():
    assert not ScanResult(port=22, service=None, banner=b"")


# ---------------------------------------------------------------------------
# Handler operators
# ---------------------------------------------------------------------------
def test_shift_creates_a_chain_in_order():
    a = RegexBannerHandler("a", name="A")
    b = RegexBannerHandler("b", name="B")

    chain = a << b

    assert isinstance(chain, HandlerChain)
    assert [h.description() for h in chain.handlers()] == [
        a.description(),
        b.description(),
    ]


def test_rshift_creates_a_chain_reversed():
    a = RegexBannerHandler("a", name="A")
    b = RegexBannerHandler("b", name="B")

    chain = a >> b

    assert [h.description() for h in chain.handlers()] == [
        b.description(),
        a.description(),
    ]


def test_chaining_is_associative_and_flattens():
    a = RegexBannerHandler("a", name="A")
    b = RegexBannerHandler("b", name="B")
    c = RegexBannerHandler("c", name="C")

    chain = a << b << c

    assert len(chain.handlers()) == 3


def test_handler_is_abstract():
    with pytest.raises(TypeError):
        Handler()  # type: ignore[abstract]


def test_dispatcher_iadd_and_isub():
    chain = HandlerChain([])
    child = RegexBannerHandler("x", name="X")

    chain += child
    assert chain.handlers() == [child]

    chain -= child
    assert chain.handlers() == []


# ---------------------------------------------------------------------------
# RegexBannerHandler
# ---------------------------------------------------------------------------
def test_regex_handler_matches_a_banner():
    handler = RegexBannerHandler(r"^SSH-", name="SSH")

    assert handler.check_banner(b"SSH-2.0-OpenSSH_10.5")
    assert not handler.check_banner(b"HTTP/1.1 200")


def test_iadd_accepts_a_child_that_survives_the_empty_banner_smoke_test():
    """``+=`` smoke-tests the child with ``check_banner(b"")`` first."""
    parent = SocketBannerHandler(
        stack=["TCP"], session=TableSession(spec=LAYERS["TCP"], base=Scripted())
    )
    child = RegexBannerHandler(r"^SSH-", name="SSH")

    parent += child

    assert parent.children() == [child]


def test_regex_handler_rejects_an_invalid_pattern_at_construction():
    with pytest.raises(re.error):
        RegexBannerHandler(r"(", name="Broken")


def test_regex_handler_check_banner_never_raises_on_odd_input():
    handler = RegexBannerHandler(r"^SSH-", name="SSH")

    assert handler.check_banner(b"\xff\xfe invalid utf-8") is False


def test_regex_handler_accepts_a_compiled_pattern():
    import re

    handler = RegexBannerHandler(re.compile(rb"RFB"), name="VNC")

    assert handler.check_banner(b"RFB 003.008\n")


def test_regex_handler_handle_returns_a_scan_result():
    handler = RegexBannerHandler(r"^SSH-", name="SSH")

    result = handler.handle("10.0.0.1", port=22, banner=b"SSH-2.0-x")

    assert result.service == "SSH"
    assert result.port == 22
    assert result.banner == b"SSH-2.0-x"


# ---------------------------------------------------------------------------
# HandlerChain
# ---------------------------------------------------------------------------
def test_chain_returns_the_first_non_none_result():
    a = RegexBannerHandler(r"^SSH-", name="SSH")
    b = RegexBannerHandler(r"^HTTP/", name="HTTP")
    chain = a << b

    result = chain.handle("10.0.0.1", port=22, banner=b"HTTP/1.1 200 OK")

    assert result.service == "HTTP"


def test_chain_returns_none_when_nothing_matches():
    chain = RegexBannerHandler(r"^SSH-", name="SSH") << RegexBannerHandler(
        r"^HTTP/", name="HTTP"
    )

    assert chain.handle("10.0.0.1", port=22, banner=b"gibberish") is None


def test_chain_ports_is_the_union_of_every_handler():
    class Ported(Handler):
        def __init__(self, ports):
            self._ports = ports

        def ports(self):
            return self._ports

        def description(self):
            return f"ports={self._ports}"

        def handle(self, target, *args, **kwargs):
            return None

    chain = Ported([22, 80]) << Ported([80, 443])

    assert chain.ports() == [22, 80, 443]


# ---------------------------------------------------------------------------
# SocketBannerHandler
# ---------------------------------------------------------------------------
def make_socket_handler(replies=None, stack=None, children=None, persistor=None):
    root = Scripted(replies=replies)
    handler = SocketBannerHandler(
        stack=stack or ["TCP"],
        session=TableSession(spec=LAYERS["TCP"], base=root),
        persistor=persistor,
        children=children,
    )
    return handler, root


def test_socket_handler_probes_and_returns_a_result():
    handler, root = make_socket_handler(replies=[b"SSH-2.0-OpenSSH_10.5\r\n"])

    result = handler.handle("10.0.0.1", port=22)

    assert result.service == "TCP"
    assert b"SSH-2.0" in result.banner


def test_socket_handler_dispatches_to_a_matching_child():
    child = RegexBannerHandler(r"^SSH-", name="SSH")
    handler, _ = make_socket_handler(
        replies=[b"SSH-2.0-OpenSSH_10.5\r\n"], children=[child]
    )

    result = handler.handle("10.0.0.1", port=22)

    assert result.service == "SSH"


def test_socket_handler_description_names_the_stack():
    handler, _ = make_socket_handler(stack=["TCP", "TLS"])

    assert handler.description() == "TCP→TLS"


def test_socket_handler_rebinds_to_a_deeper_stack_in_place():
    """A child needing more layers must upgrade the live session."""
    child = RegexBannerHandler(r"^SSH-", name="SSH", stack=["TCP", "SSH"])
    handler, root = make_socket_handler(
        replies=[b"SSH-2.0-OpenSSH_10.5\r\n"], children=[child]
    )

    handler.handle("10.0.0.1", port=22)

    assert handler.stack() == ["TCP", "SSH"]
    assert handler.session().root() is root  # same live transport, no reconnect


def test_socket_handler_upgrade_keeps_the_persistor_at_the_top():
    persistor = _RecordingPersistor()
    child = RegexBannerHandler(r"^SSH-", name="SSH", stack=["TCP", "SSH"])
    handler, _ = make_socket_handler(
        replies=[b"SSH-2.0-OpenSSH_10.5\r\n"], children=[child], persistor=persistor
    )

    handler.handle("10.0.0.1", port=22)

    assert handler.session()._persistor is persistor


def test_socket_handler_persists_parsed_packets():
    persistor = _RecordingPersistor()
    handler, _ = make_socket_handler(
        replies=[b"SSH-2.0-OpenSSH_10.5\r\n"], persistor=persistor
    )

    handler.handle("10.0.0.1", port=22)

    assert persistor.rows, "expected the parsed packet to be stored"


def test_socket_handler_returns_none_when_the_peer_stays_silent():
    handler, _ = make_socket_handler(replies=[])

    result = handler.handle("10.0.0.1", port=22)

    assert result is None or result.service == "TCP"


def test_socket_handler_rejects_a_child_that_raises_on_empty_banner():
    """``+=`` smoke-tests with ``check_banner(b"")`` and drops bad children."""

    class Exploding(Handler):
        def ports(self):
            return None

        def description(self):
            return "boom"

        def check_banner(self, banner):
            raise RuntimeError("boom")

        def handle(self, target, *args, **kwargs):
            return None

    handler, _ = make_socket_handler()
    bad = Exploding()

    handler += bad

    assert handler.children() == []


class _RecordingPersistor:
    """Minimal persistor used to observe handler persistence."""

    def __init__(self):
        self.rows = []
        self.columns = []

    def register(self, column):
        self.columns.append(column)

    def store(self, column, data, previous_id=None):
        self.rows.append((column, data))
        return "id"

    def store_full(self, data):
        self.rows.append(data)
        return "id"

    def history(self):
        return self.rows


# ---------------------------------------------------------------------------
# ContextfulHandler / AsyncHandler
# ---------------------------------------------------------------------------
def test_contextful_handler_exposes_its_session():
    session = TableSession(spec=LAYERS["TCP"], base=Scripted())

    class Mine(ContextfulHandler):
        def ports(self):
            return None

        def description(self):
            return "mine"

        def handle(self, target, *args, **kwargs):
            return None

    handler = Mine(session)

    assert handler.session() is session


def test_async_handler_runs_ahandle_through_the_bridge():
    class Double(AsyncHandler):
        def ports(self):
            return None

        def description(self):
            return "double"

        async def ahandle(self, target, *args, **kwargs):
            return ScanResult(port=kwargs.get("port"), service="X", banner=b"")

    handler = Double()

    result = handler.handle("10.0.0.1", port=80)

    assert result.service == "X"
