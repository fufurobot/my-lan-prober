"""Smoke tests for the environment the tool actually runs in.

These exist because of a real, reproducible failure::

    playwright._impl._errors.Error: BrowserType.launch: EPERM: operation not
    permitted, mkdtemp 'C:\\Users\\fufu\\Downloads\\msys64\\tmp\\playwright-artifacts-XXXXXX'

Surfaced by running ``uv run my-lan-prober`` from a real MSYS2 clang64 shell,
after the project's interpreter was switched from a Windows Store Python 3.13
to a uv-managed Python 3.10.

Root cause
----------
Playwright launches its Node driver, and the driver picks its artifacts
directory with ``os.tmpdir()``, which honours ``TMPDIR`` → ``TMP`` → ``TEMP``
in that order.  An MSYS2 shell exports those as its own ``/tmp``
(``C:\\Users\\fufu\\Downloads\\msys64\\tmp``), a directory this user cannot
create files in despite ``os.access(..., W_OK)`` reporting ``True``.

CPython tolerates a bad candidate: ``tempfile._get_default_tempdir`` probes
each candidate by actually writing a file and silently falls through to the
next one, so ``tempfile.gettempdir()`` still returns a usable directory.  The
Node driver does no such fallback — it hands the first candidate straight to
``fs.mkdtemp()`` and the launch dies.

That asymmetry is why the traceback is confusing: Python's own temp handling
looks healthy while the subprocess fails.

The same root cause has a second, differently-shaped symptom on CPython 3.10
for Windows, where the launch dies while *creating the driver's pipes*::

    PermissionError: [WinError 5] Access is denied
      ... asyncio\\windows_utils.py: pipe() -> CreateFile()

Both are fixed the same way — the environment is repaired at process start by
``my_lan_prober.config.ensure_temp_env``, which points ``TMPDIR``/``TMP``/
``TEMP`` at ``playwright-temp`` in the current directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from my_lan_prober.fetchers import PlaywrightFetcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _playwright_driver_dir() -> Path | None:
    """Directory holding Playwright's bundled ``node.exe``, or ``None``.

    ``playwright`` is an optional extra, so a plain ``uv sync`` in CI does not
    install it.  Importing it at module scope would crash collection before
    any ``skipif`` could run — which is exactly what happened on the first CI
    run — so the import is guarded and callers treat ``None`` as "not
    installed".
    """
    try:
        import playwright
    except ImportError:
        return None
    return Path(playwright.__file__).parent / "driver"


def _node_exe() -> Path | None:
    """The driver's ``node.exe``, or ``None`` when Playwright is absent."""
    driver = _playwright_driver_dir()
    if driver is None:
        return None
    node = driver / "node.exe"
    return node if node.exists() else None


def _tmpdir_is_writable(path: Path) -> bool:
    """Whether a file can really be created in ``path``.

    Deliberately not ``os.access``: on Windows that reports ``True`` for the
    very directory whose writes fail with ``EPERM``.  Bounded by a timeout
    because a wedged directory can block the create instead of failing it.
    """
    return PlaywrightFetcher.temp_dir_is_usable(path)


# ---------------------------------------------------------------------------
# The invariant the project must uphold
# ---------------------------------------------------------------------------
def test_temp_dir_used_by_the_driver_is_writable():
    """Whatever the driver would choose must actually accept a mkdtemp.

    This is the assertion that would have caught the MSYS2 failure before it
    reached a browser launch.
    """
    chosen = Path(tempfile.gettempdir())

    assert _tmpdir_is_writable(chosen), (
        f"temp directory {chosen} is not writable; Playwright's Node driver "
        f"would fail with EPERM at BrowserType.launch"
    )


def test_environment_temp_variables_point_somewhere_writable():
    """``TMPDIR``/``TMP``/``TEMP`` are what the Node driver honours first."""
    problems = []
    for name in ("TMPDIR", "TMP", "TEMP"):
        raw = os.environ.get(name)
        if not raw:
            continue
        # A POSIX-style path only exists inside MSYS2; on a native Windows
        # process it is unusable and must not be exported to our children.
        if raw.startswith("/") and os.name == "nt":
            problems.append(f"{name}={raw!r} is an MSYS-only path")
            continue
        if not _tmpdir_is_writable(Path(raw)):
            problems.append(f"{name}={raw!r} is not writable")

    assert not problems, "unusable temp variables: " + "; ".join(problems)


def test_driver_temp_dir_resolution_matches_python():
    """The driver's ``os.tmpdir()`` must agree with Python's ``gettempdir()``.

    When they disagree, Python's temp handling works while the browser
    subprocess dies — the confusing half-broken symptom from the traceback.
    """
    node = _node_exe()
    if node is None:
        pytest.skip("playwright is not installed (optional extra)")

    result = subprocess.run(
        [str(node), "-e", "process.stdout.write(require('os').tmpdir())"],
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
    )
    assert result.returncode == 0, result.stderr

    driver_dir = Path(result.stdout.strip())
    python_dir = Path(tempfile.gettempdir())

    assert _tmpdir_is_writable(driver_dir), (
        f"node's os.tmpdir() gives {driver_dir}, which is not writable "
        f"(python would have fallen back to {python_dir})"
    )


# ---------------------------------------------------------------------------
# The repair the project performs for its own subprocesses
# ---------------------------------------------------------------------------
def test_fetcher_provides_a_writable_temp_dir_to_its_children():
    """``PlaywrightFetcher`` must hand the driver a usable temp dir."""
    env = PlaywrightFetcher.driver_env()

    chosen = Path(env["TMPDIR"])
    assert chosen.is_absolute()
    assert _tmpdir_is_writable(chosen)


def test_driver_env_sets_all_three_variables_consistently():
    """The driver reads TMPDIR, then TMP, then TEMP — all must agree."""
    env = PlaywrightFetcher.driver_env()

    assert env["TMPDIR"] == env["TMP"] == env["TEMP"]


def test_driver_env_overrides_an_unusable_inherited_value(monkeypatch):
    """The MSYS2 case: an inherited temp dir that cannot be written must lose.

    The unusable path is constructed rather than hardcoded: ``/tmp`` is a
    perfectly good temp directory on Linux (where CI runs part of the matrix),
    so asserting ``!= "/tmp"`` would be asserting a Windows-only accident.
    """
    unusable = Path("/nonexistent-temp-for-my-lan-prober")
    assert not _tmpdir_is_writable(unusable), "precondition: path must be unusable"
    monkeypatch.setenv("TMPDIR", str(unusable))
    monkeypatch.setenv("TMP", str(unusable))
    monkeypatch.setenv("TEMP", str(unusable))

    env = PlaywrightFetcher.driver_env()

    assert Path(env["TMPDIR"]) != unusable
    assert _tmpdir_is_writable(Path(env["TMPDIR"]))


def test_driver_env_keeps_a_usable_inherited_value(monkeypatch, tmp_path):
    """A good temp dir is respected rather than second-guessed."""
    good = tmp_path / "good-temp"
    good.mkdir()
    monkeypatch.setenv("TMPDIR", str(good))
    monkeypatch.setenv("TMP", str(good))
    monkeypatch.setenv("TEMP", str(good))

    env = PlaywrightFetcher.driver_env()

    assert Path(env["TMPDIR"]) == good


def test_driver_env_preserves_the_rest_of_the_environment(monkeypatch):
    monkeypatch.setenv("MY_LAN_PROBER_SENTINEL", "kept")

    env = PlaywrightFetcher.driver_env()

    assert env["MY_LAN_PROBER_SENTINEL"] == "kept"


def test_driver_env_finds_a_fallback_when_every_candidate_is_bad(monkeypatch, tmp_path):
    """Even with all candidates poisoned, a writable dir must be produced.

    The fallback must be our own scratch directory, never the project root:
    ``tempfile.gettempdir()`` returns the current directory when everything
    else fails, and accepting that would litter the workspace with browser
    artifacts.
    """
    monkeypatch.setenv("TMPDIR", "/nope")
    monkeypatch.setenv("TMP", "/nope")
    monkeypatch.setenv("TEMP", "/nope")
    monkeypatch.setenv("LOCALAPPDATA", "/nope")
    monkeypatch.setenv("SYSTEMROOT", "/nope")
    fallback = tmp_path / "playwright-temp"
    monkeypatch.setattr(PlaywrightFetcher, "FALLBACK_TEMP_DIR", fallback)

    env = PlaywrightFetcher.driver_env()

    chosen = Path(env["TMPDIR"])
    assert _tmpdir_is_writable(chosen)
    assert chosen == fallback


def test_driver_env_rejects_msys_style_paths_on_windows(monkeypatch):
    """An MSYS2 ``/tmp`` is not a path a native Windows child can use.

    ``Path('/tmp')`` is a perfectly good temp directory on Linux, where half
    the CI matrix runs, so the rejection is conditional on ``os.name``.
    """
    if os.name != "nt":
        pytest.skip("POSIX-style temp paths are valid off Windows")

    monkeypatch.setenv("TMPDIR", "/tmp")
    monkeypatch.setenv("TMP", "/tmp")
    monkeypatch.setenv("TEMP", "/tmp")

    env = PlaywrightFetcher.driver_env()

    assert Path(env["TMPDIR"]).is_absolute()
    assert not env["TMPDIR"].startswith("/")
    assert _tmpdir_is_writable(Path(env["TMPDIR"]))


# ---------------------------------------------------------------------------
# The environment repair performed at process start
# ---------------------------------------------------------------------------
def test_ensure_temp_env_points_every_variable_at_a_writable_directory(monkeypatch, tmp_path):
    """The 3.10 fix: repair the temp env before any child process starts.

    Playwright's Node driver is a child process, and on CPython 3.10 for
    Windows an unusable inherited temp directory kills the launch inside
    asyncio's pipe creation.  Only an environment variable set *before* the
    child starts can repair that, which is why this runs at the top of
    ``main()`` rather than at the Playwright call site.
    """
    from my_lan_prober.config import TEMP_ENV_VARS, ensure_temp_env

    monkeypatch.setenv("TMPDIR", "/nope")
    monkeypatch.setenv("TMP", "/nope")
    monkeypatch.setenv("TEMP", "/nope")

    chosen = ensure_temp_env(tmp_path)

    assert chosen is not None
    assert _tmpdir_is_writable(chosen)
    assert chosen == (tmp_path / "playwright-temp").resolve()
    for name in TEMP_ENV_VARS:
        assert os.environ[name] == str(chosen)


def test_ensure_temp_env_keeps_a_usable_inherited_directory(monkeypatch, tmp_path):
    from my_lan_prober.config import TEMP_ENV_VARS, ensure_temp_env

    good = tmp_path / "good-temp"
    good.mkdir()
    for name in TEMP_ENV_VARS:
        monkeypatch.setenv(name, str(good))

    chosen = ensure_temp_env(tmp_path / "unused")

    assert chosen == good.resolve()
    assert not (tmp_path / "unused" / "playwright-temp").exists()


def test_ensure_temp_env_leaves_a_broken_environment_alone(monkeypatch, tmp_path):
    """No candidate usable → report failure instead of inventing a value.

    ``ensure_temp_env`` returns ``None``; it must not set a variable to a
    directory the child cannot use, because that would hide the real problem.
    """
    from my_lan_prober.config import ensure_temp_env

    blocked = tmp_path / "blocked"
    blocked.write_text("a file, not a directory", encoding="utf-8")
    monkeypatch.setenv("TMPDIR", str(blocked / "sub"))
    monkeypatch.setenv("TMP", str(blocked / "sub"))
    monkeypatch.setenv("TEMP", str(blocked / "sub"))

    assert ensure_temp_env(blocked) is None
    assert os.environ["TMPDIR"] == str(blocked / "sub")


def test_ensure_temp_env_creates_the_workaround_directory(monkeypatch, tmp_path):
    """``playwright-temp`` is created on demand, under the given base."""
    from my_lan_prober.config import ensure_temp_env

    monkeypatch.setenv("TMPDIR", "/nope")
    monkeypatch.setenv("TMP", "/nope")
    monkeypatch.setenv("TEMP", "/nope")

    chosen = ensure_temp_env(tmp_path / "base")

    assert chosen == (tmp_path / "base" / "playwright-temp").resolve()
    assert chosen.is_dir()


def test_main_repairs_the_temp_env_before_running(monkeypatch, tmp_path):
    """``main()`` must call the repair before the engine can start Playwright."""
    import my_lan_prober

    calls = []

    def fake_ensure(base_dir=None):
        calls.append(base_dir)
        return tmp_path

    class FakeEngine:
        def __init__(self, config):
            assert calls, "ensure_temp_env must run before the engine is built"

        def run(self):
            return "ran"

    monkeypatch.setattr(my_lan_prober, "ensure_temp_env", fake_ensure)
    monkeypatch.setattr(my_lan_prober, "Engine", FakeEngine)

    assert my_lan_prober.main(["--fetcher", "unix"]) == "ran"
    assert calls == [None]


# ---------------------------------------------------------------------------
# End-to-end: the driver really can make an artifacts dir
# ---------------------------------------------------------------------------
def test_node_can_mkdtemp_an_artifacts_dir_with_the_provided_env(monkeypatch):
    """Run the driver's exact mkdtemp call under the env we hand it."""
    node = _node_exe()
    if node is None:
        pytest.skip("playwright is not installed (optional extra)")

    monkeypatch.setenv("TMPDIR", "/tmp")
    monkeypatch.setenv("TMP", "/tmp")
    monkeypatch.setenv("TEMP", "/tmp")

    env = PlaywrightFetcher.driver_env()
    script = (
        "const fs=require('fs'),p=require('path');"
        "const d=fs.mkdtempSync(p.join(require('os').tmpdir(),'playwright-artifacts-'));"
        "process.stdout.write(d);"
    )

    result = subprocess.run(
        [str(node), "-e", script],
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    created = Path(result.stdout.strip())
    try:
        assert created.is_dir()
        assert created.name.startswith("playwright-artifacts-")
    finally:
        shutil.rmtree(created, ignore_errors=True)
