"""One asyncio loop per process, bridged to a synchronous API.

Playwright's sync API refuses to run inside a live event loop, while the rest
of this toolkit is async.  ``AsyncBridge`` owns a dedicated loop thread so
synchronous callers can block on coroutines with
``run_coroutine_threadsafe`` without ever nesting loops.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, Callable, Coroutine, Optional

log = logging.getLogger(__name__)

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
        log.debug("ensuring bridge loop from thread %s", threading.current_thread().name)
        with self._lock:
            if self._loop is not None and self._loop.is_running():
                log.debug(
                    "reusing running bridge loop %r in thread %s",
                    self._loop,
                    self._thread.name if self._thread is not None else "<no thread>",
                )
                return self._loop

            log.debug(
                "no running bridge loop (existing loop=%r); starting a new one",
                self._loop,
            )
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
            log.debug("starting bridge loop in thread %s", thread.name)

        # Wait outside the lock so we never deadlock with _run_loop.
        self._ready.wait(timeout=10)
        log.debug(
            "bridge loop %r ready=%s after waiting for thread %s",
            self._loop,
            self._ready.is_set(),
            self._thread.name if self._thread is not None else "<no thread>",
        )
        return self._loop

    def _run_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        log.debug("bridge thread %s entering its loop", threading.current_thread().name)
        asyncio.set_event_loop(loop)
        loop.call_soon(self._ready.set)
        try:
            log.debug("bridge loop %r running forever", loop)
            loop.run_forever()
            log.debug("bridge loop %r returned from run_forever", loop)
        finally:
            log.debug("tearing down bridge loop %r", loop)
            with contextlib.suppress(Exception):
                # Best-effort teardown; the loop is being discarded anyway.
                log.debug("shutting down async generators of loop %r", loop)
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            log.debug("bridge loop %r closed", loop)

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop the loop thread.  Safe to call more than once."""
        log.debug("shutdown requested for bridge (timeout=%s)", timeout)
        with self._lock:
            loop, thread = self._loop, self._thread
            self._loop = None
            self._thread = None
            log.debug("detached bridge state: loop=%r thread=%r", loop, thread)
        if loop is None:
            log.debug("shutdown is a no-op: the bridge has no loop")
            return
        loop.call_soon_threadsafe(loop.stop)
        if thread is not None and thread.is_alive():
            log.debug(
                "joining bridge thread %s for up to %ss after asking loop %r to stop",
                thread.name,
                timeout,
                loop,
            )
            thread.join(timeout=timeout)
            log.debug("bridge thread %s alive after join=%s", thread.name, thread.is_alive())

    def is_running(self) -> bool:
        loop = self._loop
        if loop is None:
            log.debug("bridge is_running=False: no loop has been created yet")
            return False
        running = loop.is_running()
        log.debug("bridge is_running=%s (loop=%r)", running, loop)
        return running

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
            log.debug(
                "no event loop is running in thread %s; using bridge loop %r",
                threading.current_thread().name,
                loop,
            )

        if running is loop:
            log.debug(
                "run() was called from inside the bridge's own loop %r; detaching "
                "to a throwaway loop instead of deadlocking",
                loop,
            )
            return self._run_detached(coro, timeout)

        log.debug(
            "submitting coroutine to bridge loop %r with timeout=%s (caller thread %s)",
            loop,
            timeout,
            threading.current_thread().name,
        )
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            result = future.result(timeout=timeout)
        except FutureTimeoutError as exc:
            log.warning(
                "bridge coroutine timed out after %ss on loop %r; cancelling it",
                timeout,
                loop,
            )
            future.cancel()
            raise TimeoutError(f"coroutine timed out after {timeout}s") from exc
        log.debug("bridge coroutine finished on loop %r", loop)
        return result

    @staticmethod
    def _run_detached(coro: Coroutine[Any, Any, Any], timeout: Optional[float]) -> Any:
        """Run ``coro`` to completion on a fresh loop in a worker thread."""
        box: dict = {}

        def target() -> None:
            log.debug("detached loop thread %s starting", threading.current_thread().name)
            try:
                box["value"] = asyncio.run(coro)
            except BaseException as exc:
                log.debug(
                    "detached run of %r raised %s: %s",
                    coro,
                    type(exc).__name__,
                    exc,
                )
                box["error"] = exc

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        log.debug("starting detached loop thread %s with timeout=%s", thread.name, timeout)
        thread.join(timeout=timeout)
        if thread.is_alive():
            log.warning(
                "detached coroutine %r still running in thread %s after %ss timeout",
                coro,
                thread.name,
                timeout,
            )
            raise TimeoutError(f"coroutine timed out after {timeout}s")
        if "error" in box:
            log.debug("re-raising detached failure from thread %s", thread.name)
            raise box["error"]
        log.debug("detached coroutine completed in thread %s", thread.name)
        return box.get("value")

    @staticmethod
    async def run_sync(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Await a *blocking* callable without stalling the bridge's loop.

        Used to run sync handlers from async code (``Handler.ahandle``).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))


_default: Optional[AsyncBridge] = None
_default_lock = threading.Lock()


def default_bridge() -> AsyncBridge:
    """Process-wide shared :class:`AsyncBridge`."""
    global _default
    with _default_lock:
        if _default is None:
            log.debug("creating the process-wide default bridge")
            _default = AsyncBridge()
        else:
            log.debug(
                "reusing the process-wide default bridge (running=%s)",
                _default.is_running(),
            )
        return _default
