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
