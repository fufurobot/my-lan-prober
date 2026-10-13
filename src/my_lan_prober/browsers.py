"""Which Playwright browser engine can actually run on this machine.

``pip install playwright`` installs the Python driver and *no browser*.  The
binaries are a separate download::

    playwright install                    # all three engines
    playwright install firefox            # just one

Launching an engine whose binary was never downloaded fails with::

    Executable doesn't exist at .../ms-playwright/chromium-1181/chrome-win64/chrome.exe
    ╭──────────────────────────────────────────────────────╮
    │ Looks like Playwright was just installed or updated. │
    ╰──────────────────────────────────────────────────────╯

so the engine is picked by *asking Playwright*, not by assuming chromium.

``browser_type.executable_path`` is the attribute Playwright itself launches
from, so probing it is exact.  Re-deriving the path from the ``ms-playwright``
cache layout would be a guess at a private, version-stamped directory name
(``chromium-1181``, ``firefox-1490``, …) that changes with every Playwright
release.

This module is the only place that reaches for the optional ``playwright``
extra, and it imports it lazily so that a bare ``uv sync`` — which is what CI
and a fresh contributor both get — still imports the package fine.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "BROWSER_NAMES",
    "BrowserNotInstalled",
    "detect_browsers",
    "first_available_browser",
    "is_browser_installed",
    "installed_browsers",
]

#: Playwright's three engines, in the project's order of preference.
#:
#: Chromium leads because it is what the tested original used, so a machine
#: with all three installed keeps behaving exactly as before.
BROWSER_NAMES: Tuple[str, ...] = ("chromium", "firefox", "webkit")

#: What a user types to fix a missing browser.
INSTALL_HINT = "playwright install"


class BrowserNotInstalled(RuntimeError):
    """No usable Playwright browser binary was found.

    Raised instead of Playwright's own ``Error`` so the message can name the
    fix, and so callers can distinguish "no browser" (degrade to local ARP)
    from "the browser launched and then failed" (a real error).
    """


def is_browser_installed(browser_type: Any) -> bool:
    """Whether one ``BrowserType`` has a binary that exists on disk.

    ``executable_path`` is ``""`` when Playwright has no binary for that
    engine, and ``Path("").exists()`` is ``True`` — the empty path resolves to
    the current directory — so the emptiness check has to come first or every
    engine would look installed.
    """
    try:
        raw = browser_type.executable_path
    except Exception as exc:
        # A dead driver raises on attribute access; that is "not installed".
        log.debug(
            "engine %s reports no executable_path (%s: %s); treating it as not installed",
            type(browser_type).__name__,
            type(exc).__name__,
            exc,
        )
        return False
    if not raw:
        log.debug(
            "engine %s returned an empty executable_path; treating it as not installed "
            "(an empty path would otherwise resolve to the cwd and look launchable)",
            type(browser_type).__name__,
        )
        return False
    try:
        # A directory is not launchable: we exec a file.
        path = Path(str(raw))
        installed = path.is_file()
        log.debug(
            "engine %s executable_path %s is_file=%s", type(browser_type).__name__, path, installed
        )
        return installed
    except OSError as exc:  # pragma: no cover - unreadable/invalid path
        log.debug(
            "engine %s executable_path %r is unreadable (%s: %s); treating it as not installed",
            type(browser_type).__name__,
            raw,
            type(exc).__name__,
            exc,
        )
        return False


def playwright_object() -> Optional[Any]:
    """Return the started Playwright object, or ``None`` if it is unavailable.

    ``None`` means "cannot tell what is installed", which covers both expected
    states — the optional extra is missing — and the case where the driver
    process cannot be spawned at all.  The second is real: Playwright's Node
    driver is a *child process*, so a sandbox or a broken inherited temp
    directory can kill it with ``PermissionError: [WinError 5]`` from
    ``asyncio.windows_utils.pipe()`` before it says anything useful.

    Reporting "no browser detected" is the correct, safe answer in both cases:
    the caller degrades to the local ARP table rather than dying.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.debug("playwright is not installed; no browser engine is available")
        return None

    # The driver is a child process and inherits our environment; on Windows
    # an unusable temp dir kills it before it can report anything.
    context: Any
    try:
        from .fetchers import _driver_env_applied

        env = {name: os.environ[name] for name in ("TMPDIR", "TMP", "TEMP") if name in os.environ}
        log.debug("applying the driver environment %r before starting Playwright", env)
        context = _driver_env_applied(env)
    except ImportError:  # pragma: no cover - breaks a circular import
        log.debug(
            "could not import the driver environment hook (circular import); "
            "starting Playwright with the inherited environment"
        )
        context = contextlib.nullcontext()

    try:
        with context:
            log.debug("starting the Playwright driver")
            playwright = sync_playwright().start()
        log.debug("the Playwright driver started: %r", playwright)
        return playwright
    except Exception as exc:
        log.warning("could not start the Playwright driver: %s", exc)
        return None


def detect_browsers(playwright: Optional[Any] = None) -> Dict[str, bool]:
    """Map every engine name to whether its binary is present.

    Args:
        playwright: An existing Playwright object (as produced by
            ``sync_playwright().start()``).  When omitted, one is started;
            if the optional extra is not installed, every engine reports
            ``False`` rather than raising.
    """
    detected: Dict[str, bool] = dict.fromkeys(BROWSER_NAMES, False)

    if playwright is None:
        try:
            playwright = playwright_object()
        except Exception as exc:
            # "Cannot tell" must read as "not installed": the caller's correct
            # response is to degrade to the local ARP table, not to crash.
            log.warning("could not start the Playwright driver: %s", exc)
            return detected
    if playwright is None:
        log.debug("no Playwright driver available; reporting every engine as not installed")
        return detected

    for name in BROWSER_NAMES:
        engine = getattr(playwright, name, None)
        if engine is None:
            log.debug("engine %s is absent from the driver; treating it as not installed", name)
            detected[name] = False
            continue
        detected[name] = is_browser_installed(engine)
        if detected[name]:
            log.debug("playwright engine %s is installed", name)
        else:
            log.debug(
                "playwright engine %s is not installed (engine object=%r)",
                name,
                engine,
            )

    log.debug("browser detection result: %r", detected)
    return detected


def installed_browsers() -> Dict[str, bool]:
    """Every engine, and whether this machine can actually launch it."""
    return detect_browsers()


def _engine_path(playwright: Any, name: str) -> str:
    engine = getattr(playwright, name, None)
    if engine is None:
        log.debug("engine %s is absent from the driver; reporting no path", name)
        return ""
    raw = getattr(engine, "executable_path", "")
    if raw:
        log.debug("engine %s executable_path=%s", name, raw)
        return str(raw)
    log.debug("engine %s has no executable_path set; reporting no path", name)
    return ""


def first_available_browser(
    playwright: Optional[Any] = None,
    order: Optional[Sequence[str]] = None,
) -> str:
    """Name of the first installed engine, in preference order.

    Args:
        playwright: Reuse an existing Playwright object instead of starting one.
        order: Engines to try, most preferred first.  Defaults to
            :data:`BROWSER_NAMES` (chromium, firefox, webkit).

    Raises:
        BrowserNotInstalled: When no engine in ``order`` has a binary.  The
            message names the missing engines and the command that fixes it.
    """
    candidates = tuple(order) if order else BROWSER_NAMES
    log.debug("looking for an installed Playwright engine among %r", candidates)

    started = playwright is None
    if started:
        log.debug("no Playwright driver was supplied; starting one to probe the engines")
        try:
            playwright = playwright_object()
        except Exception as exc:
            log.warning("could not start the Playwright driver: %s", exc)
            raise BrowserNotInstalled(f"could not start the Playwright driver: {exc}") from exc

    if playwright is None:
        log.warning(
            "no browser engine can be used: the Playwright driver could not be started "
            "and the optional extra may be missing (hint: %s)",
            INSTALL_HINT,
        )
        raise BrowserNotInstalled(
            "playwright could not be started, so no browser engine is available; "
            f"install the optional extra and run `{INSTALL_HINT}`"
        )

    # Read the paths while the driver is alive: a stopped driver raises or
    # returns nothing on attribute access, so probing it afterwards would
    # report "<not set>" for every engine and lose the useful diagnosis.
    def _describe(name: str) -> str:
        path = _engine_path(playwright, name)
        if path:
            log.debug("engine %s probe path: %s", name, path)
            return f"{name}={path}"
        log.debug("engine %s probe path: <not set>", name)
        return f"{name}=<not set>"

    detail = ", ".join(_describe(name) for name in candidates)
    log.debug("engine executable paths before probing: %s", detail)

    try:
        for name in candidates:
            engine = getattr(playwright, name, None)
            if engine is not None and is_browser_installed(engine):
                log.info("Using Playwright browser engine: %s", name)
                return name
            log.debug("skipping engine %s: not installed", name)
    finally:
        if started:
            # We started this driver purely to read executable paths.
            log.debug("stopping the driver we started for this probe")
            _stop(playwright)

    log.warning("no Playwright browser is installed (checked %s)", detail)
    raise BrowserNotInstalled(
        f"no Playwright browser is installed (checked {detail}); "
        f"run `{INSTALL_HINT}` to download one"
    )


def _stop(playwright: Any) -> None:
    """Best-effort shutdown of a driver we started ourselves."""
    stop = getattr(playwright, "stop", None)
    if stop is None:
        log.debug("driver %r has no stop(); nothing to shut down", type(playwright).__name__)
        return
    try:
        log.debug("stopping the Playwright driver %r", type(playwright).__name__)
        stop()
    except Exception as exc:  # pragma: no cover - driver teardown is best-effort
        log.debug("could not stop the Playwright driver cleanly: %s", exc)
