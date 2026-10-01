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
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from my_lan_prober.fetchers import PlaywrightFetcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _playwright_driver_dir() -> Path:
    """Directory holding Playwright's bundled ``node.exe``."""
    import playwright

    return Path(playwright.__file__).parent / "driver"


def _node_exe() -> Path:
    return _playwright_driver_dir() / "node.exe"


def _tmpdir_is_writable(path: Path) -> bool:
    """Whether a file can really be created in ``path``.

    Deliberately not ``os.access``: on Windows that reports ``True`` for the
    very directory whose writes fail with ``EPERM``.
    """
    if not path.is_dir():
        return False
    probe = None
    try:
        fd, name = tempfile.mkstemp(dir=str(path), prefix=".writable-probe-")
        probe = name
        os.close(fd)
    except OSError:
        return False
    finally:
        if probe is not None:
            try:
                os.unlink(probe)
            except OSError:
                pass
    return True


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
    if not node.exists():
        pytest.skip("playwright driver node.exe is not installed")

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


def test_driver_env_overrides_an_unusable_inherited_value(monkeypatch, tmp_path):
    """The MSYS2 case: an inherited POSIX TMPDIR must not win."""
    monkeypatch.setenv("TMPDIR", "/tmp")
    monkeypatch.setenv("TMP", "/tmp")
    monkeypatch.setenv("TEMP", "/tmp")

    env = PlaywrightFetcher.driver_env()

    assert env["TMPDIR"] != "/tmp"
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
    """Even with all candidates poisoned, a writable dir must be produced."""
    monkeypatch.setenv("TMPDIR", "/nope")
    monkeypatch.setenv("TMP", "/nope")
    monkeypatch.setenv("TEMP", "/nope")

    env = PlaywrightFetcher.driver_env()

    assert _tmpdir_is_writable(Path(env["TMPDIR"]))


# ---------------------------------------------------------------------------
# End-to-end: the driver really can make an artifacts dir
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not _node_exe().exists(), reason="playwright driver node.exe is not installed"
)
def test_node_can_mkdtemp_an_artifacts_dir_with_the_provided_env(monkeypatch):
    """Run the driver's exact mkdtemp call under the env we hand it."""
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
        [str(_node_exe()), "-e", script],
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
