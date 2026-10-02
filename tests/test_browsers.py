"""Tests for :mod:`my_lan_prober.browsers`.

Playwright ships three engines (chromium, firefox, webkit) and *none* of
their binaries are installed by ``pip install playwright`` — only the Python
package is.  The binaries arrive later, via ``playwright install``, which may
have been run for one engine, for all three, or for none.

Launching an engine whose binary is missing fails with::

    Executable doesn't exist at .../ms-playwright/chromium-1181/chrome-win64/chrome.exe
    ╭───────────────────────────────────────────────────╮
    │ Looks like Playwright was just installed or updated│
    ╰───────────────────────────────────────────────────╯

so the toolkit detects what is actually present first, and uses the first
engine that is.  Detection reads ``browser_type.executable_path`` — the same
attribute Playwright itself launches from — rather than guessing at the
``ms-playwright`` cache layout, because that layout is versioned and private.
"""

from __future__ import annotations

import pytest

from my_lan_prober.browsers import (
    BROWSER_NAMES,
    BrowserNotInstalled,
    detect_browsers,
    first_available_browser,
    is_browser_installed,
)


# ---------------------------------------------------------------------------
# A stand-in for playwright.sync_api.BrowserType / the Playwright object
# ---------------------------------------------------------------------------
class FakeBrowserType:
    """Mirrors the ``name`` / ``executable_path`` surface we rely on."""

    def __init__(self, name: str, executable_path: object) -> None:
        self.name = name
        self.executable_path = str(executable_path)


class FakePlaywright:
    def __init__(self, **engines: object) -> None:
        for name in BROWSER_NAMES:
            setattr(self, name, FakeBrowserType(name, engines.get(name, "")))


@pytest.fixture
def installed(tmp_path):
    """Build a Playwright stand-in where the given engines exist on disk."""
    created = []

    def build(*names: str) -> FakePlaywright:
        engine_paths = {}
        for name in names:
            path = tmp_path / f"{name}-binary"
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            created.append(path)
            engine_paths[name] = path
        return FakePlaywright(**engine_paths)

    return build


# ---------------------------------------------------------------------------
# The built-in engine list
# ---------------------------------------------------------------------------
def test_browser_names_are_the_three_playwright_engines():
    assert BROWSER_NAMES == ("chromium", "firefox", "webkit")


# ---------------------------------------------------------------------------
# is_browser_installed
# ---------------------------------------------------------------------------
def test_browser_is_installed_when_the_executable_exists(installed):
    playwright = installed("chromium")

    assert is_browser_installed(playwright.chromium) is True


def test_browser_is_not_installed_when_the_path_is_missing(tmp_path):
    absent = FakeBrowserType("chromium", tmp_path / "nope" / "chrome.exe")

    assert is_browser_installed(absent) is False


def test_browser_is_not_installed_when_playwright_reports_no_path():
    """A falsy ``executable_path`` means "no binary", never "the cwd"."""
    assert is_browser_installed(FakeBrowserType("chromium", "")) is False


def test_a_directory_is_not_a_launchable_browser(tmp_path):
    """``is_dir`` must not satisfy the check — we launch a *file*."""
    directory = tmp_path / "chromium-dir"
    directory.mkdir()

    assert is_browser_installed(FakeBrowserType("chromium", directory)) is False


# ---------------------------------------------------------------------------
# detect_browsers
# ---------------------------------------------------------------------------
def test_detect_browsers_reports_every_engine(installed):
    playwright = installed("chromium", "webkit")

    detected = detect_browsers(playwright)

    assert set(detected) == {"chromium", "firefox", "webkit"}
    assert detected["chromium"] is True
    assert detected["firefox"] is False
    assert detected["webkit"] is True


def test_detect_browsers_handles_nothing_installed():
    detected = detect_browsers(FakePlaywright())

    assert detected == {"chromium": False, "firefox": False, "webkit": False}


# ---------------------------------------------------------------------------
# first_available_browser
# ---------------------------------------------------------------------------
def test_first_available_returns_the_preferred_engine(installed):
    """chromium is the project default, so it wins when it is present."""
    playwright = installed("chromium", "firefox", "webkit")

    assert first_available_browser(playwright) == "chromium"


def test_first_available_falls_through_to_the_next_engine(installed):
    """The whole point: no chromium binary, but firefox is there."""
    playwright = installed("firefox", "webkit")

    assert first_available_browser(playwright) == "firefox"


def test_first_available_falls_through_to_webkit(installed):
    playwright = installed("webkit")

    assert first_available_browser(playwright) == "webkit"


def test_first_available_prefers_an_explicit_order(installed):
    playwright = installed("chromium", "webkit")

    assert first_available_browser(playwright, order=("webkit", "chromium")) == "webkit"


def test_first_available_raises_when_no_engine_is_installed():
    """A clear error beats Playwright's "Executable doesn't exist" at launch."""
    with pytest.raises(BrowserNotInstalled, match="playwright install"):
        first_available_browser(FakePlaywright())


def test_first_available_error_names_the_remedy(installed):
    with pytest.raises(BrowserNotInstalled) as excinfo:
        first_available_browser(FakePlaywright())

    message = str(excinfo.value)
    assert "chromium" in message
    assert "playwright install" in message


def test_first_available_reports_real_paths_after_stopping_its_own_driver(monkeypatch):
    """The diagnosis must survive the driver being shut down.

    ``first_available_browser`` starts a driver itself when none is passed and
    stops it again in a ``finally``.  A stopped driver raises on attribute
    access, so reading ``executable_path`` *after* the stop downgrades every
    line of the error to ``<not set>`` — losing exactly the information a user
    needs.  The paths must be captured while the driver is still alive.
    """

    class StoppedDriver:
        """Mimics Playwright: attribute access dies once stopped."""

        def __init__(self):
            self.stopped = False
            for name in BROWSER_NAMES:
                setattr(self, name, FakeBrowserType(name, f"C:/fake/{name}-binary"))

        def stop(self):
            self.stopped = True
            for name in BROWSER_NAMES:
                setattr(self, name, None)

        def __getattr__(self, item):
            if self.__dict__.get("stopped"):
                raise RuntimeError("driver has been stopped")
            raise AttributeError(item)

    driver = StoppedDriver()
    monkeypatch.setattr("my_lan_prober.browsers.playwright_object", lambda: driver)

    with pytest.raises(BrowserNotInstalled) as excinfo:
        first_available_browser()

    assert driver.stopped is True, "the driver we started must be stopped"
    message = str(excinfo.value)
    assert "chromium=C:/fake/chromium-binary" in message, (
        f"paths were lost after stopping the driver: {message}"
    )
    assert "<not set>" not in message


# ---------------------------------------------------------------------------
# The optional-dependency boundary
# ---------------------------------------------------------------------------
def test_detection_reports_nothing_when_playwright_is_absent(monkeypatch):
    """``playwright`` is an optional extra and must never be imported here."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            raise ImportError("playwright is not installed (optional extra)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert detect_browsers() == {"chromium": False, "firefox": False, "webkit": False}
    with pytest.raises(BrowserNotInstalled):
        first_available_browser()


def test_detection_survives_a_driver_that_cannot_start(monkeypatch):
    """A driver that dies on startup means "unknown", never a crash.

    Playwright's driver is a child process, and on a Windows sandbox it can
    die inside ``asyncio.windows_utils.pipe()`` with ``WinError 5`` before it
    reports anything.  That must degrade to "no browser detected" so the scan
    falls through to the local ARP table, not take the whole process down.
    """
    import my_lan_prober.browsers as browsers

    def explode():
        raise PermissionError("[WinError 5] Access is denied")

    monkeypatch.setattr(browsers, "playwright_object", explode)

    # detect_browsers must swallow it; first_available_browser must turn it
    # into the actionable error a user can actually act on.
    try:
        assert detect_browsers() == {"chromium": False, "firefox": False, "webkit": False}
    except PermissionError:  # pragma: no cover - the regression under test
        pytest.fail("detect_browsers propagated a driver-startup failure")

    with pytest.raises(BrowserNotInstalled):
        first_available_browser()


def test_is_browser_installed_tolerates_a_broken_engine_object():
    """Detection must never raise on an unexpected engine shape."""

    class Broken:
        @property
        def executable_path(self):
            raise RuntimeError("driver already exited")

    assert is_browser_installed(Broken()) is False
    assert is_browser_installed(object()) is False
