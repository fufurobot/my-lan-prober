"""One asyncio loop per process, bridged to a synchronous API.

Playwright's sync API refuses to run inside a live event loop, while the rest
of this toolkit is async.  ``AsyncBridge`` owns a dedicated loop thread so
synchronous callers can block on coroutines with
``run_coroutine_threadsafe`` without ever nesting loops.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, Coroutine, Optional

__all__ = ["AsyncBridge", "default_bridge"]


class AsyncBridge:
    """Run coroutines on a private loop living in a background thread."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._ready = threading.Event()

    # -- lifecycle ----------------------------------------------------
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is not None and self._loop.is_running():
                return self._loop

            self._ready.clear()
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=self._run_loop,
                args=(loop,),
                name="my-lan-prober-bridge",
                daemon=True,
            )
            self._loop = loop
            self._thread = thread
            thread.start()

        # Wait outside the lock so we never deadlock with _run_loop.
        self._ready.wait(timeout=10)
        return self._loop

    def _run_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.call_soon(self._ready.set)
        try:
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:  # pragma: no cover - best effort teardown
                pass
            loop.close()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop the loop thread.  Safe to call more than once."""
        with self._lock:
            loop, thread = self._loop, self._thread
            self._loop = None
            self._thread = None
        if loop is None:
            return
        loop.call_soon_threadsafe(loop.stop)
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    def is_running(self) -> bool:
        loop = self._loop
        return bool(loop is not None and loop.is_running())

    # -- execution ----------------------------------------------------
    def run(self, coro: Coroutine[Any, Any, Any], timeout: Optional[float] = None) -> Any:
        """Block until ``coro`` finishes and return its result.

        If we are already *inside* this bridge's loop (a coroutine calling
        back into sync code), we cannot block on ourselves — run the
        coroutine on a throwaway loop in a separate thread instead.
        """
        loop = self._ensure_loop()

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is loop:
            return self._run_detached(coro, timeout)

        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError as exc:
            future.cancel()
            raise TimeoutError(f"coroutine timed out after {timeout}s") from exc

    @staticmethod
    def _run_detached(coro: Coroutine[Any, Any, Any], timeout: Optional[float]) -> Any:
        """Run ``coro`` to completion on a fresh loop in a worker thread."""
        box: dict = {}

        def target() -> None:
            try:
                box["value"] = asyncio.run(coro)
            except BaseException as exc:  # noqa: BLE001 - re-raised below
                box["error"] = exc

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        if thread.is_alive():
            raise TimeoutError(f"coroutine timed out after {timeout}s")
        if "error" in box:
            raise box["error"]
        return box.get("value")


_default: Optional[AsyncBridge] = None
_default_lock = threading.Lock()


def default_bridge() -> AsyncBridge:
    """Process-wide shared :class:`AsyncBridge`."""
    global _default
    with _default_lock:
        if _default is None:
            _default = AsyncBridge()
        return _default
