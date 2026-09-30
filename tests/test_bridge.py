"""Tests for :mod:`my_lan_prober.bridge`.

``AsyncBridge`` runs exactly one asyncio loop in a background thread and lets
synchronous callers block on coroutines via
``run_coroutine_threadsafe``.  This is what keeps Playwright's sync API from
being invoked inside a running loop (``design.md`` § 8).
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from my_lan_prober.bridge import AsyncBridge


def test_run_returns_the_coroutine_result():
    bridge = AsyncBridge()

    async def coro():
        return 42

    assert bridge.run(coro()) == 42


def test_run_propagates_exceptions():
    bridge = AsyncBridge()

    async def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError, match="nope"):
        bridge.run(boom())


def test_executes_off_the_calling_thread():
    bridge = AsyncBridge()
    caller = threading.get_ident()

    async def coro():
        return threading.get_ident()

    assert bridge.run(coro()) != caller


def test_reuses_one_loop_across_calls():
    bridge = AsyncBridge()

    async def loop_id():
        return id(asyncio.get_running_loop())

    first = bridge.run(loop_id())
    second = bridge.run(loop_id())

    assert first == second


def test_loop_stays_alive_between_calls():
    """The loop must not be closed after a call, or reuse would explode."""
    bridge = AsyncBridge()

    async def coro():
        return "ok"

    for _ in range(5):
        assert bridge.run(coro()) == "ok"

    assert bridge.is_running()


def test_module_level_default_bridge_is_shared():
    from my_lan_prober.bridge import default_bridge

    assert default_bridge() is default_bridge()


def test_run_supports_timeout():
    bridge = AsyncBridge()

    async def slow():
        await asyncio.sleep(5)

    with pytest.raises(TimeoutError):
        bridge.run(slow(), timeout=0.05)


def test_shutdown_stops_the_loop():
    bridge = AsyncBridge()

    async def coro():
        return 1

    assert bridge.run(coro()) == 1
    bridge.shutdown()
    assert not bridge.is_running()
