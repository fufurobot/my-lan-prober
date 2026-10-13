"""Shared pytest configuration.

Two responsibilities:

* point ``tmp_path`` at a workspace-local directory (the system temp directory
  may be read-only or absent in a sandboxed run);
* register the options the logging-coverage suite needs.

The options live here rather than in ``test_logging_coverage.py`` because
``pytest_addoption`` is only consulted on *plugins* and ``conftest.py`` — a
hook defined in a test module is never called, so ``--src`` and friends would
be unknown to pytest even though the module that documents them is right there.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

#: Workspace-local scratch root for tests that need a real filesystem.
SCRATCH_ROOT = Path(__file__).resolve().parent.parent / ".pytest-tmp"

#: Logging levels the coverage suite accepts, matching ``logging``.
LOG_LEVEL_NAMES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


@pytest.fixture
def tmp_path(request):
    """A unique, writable directory under the workspace."""
    name = request.node.name.replace("/", "_").replace("\\", "_")
    path = SCRATCH_ROOT / name
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def pytest_addoption(parser: pytest.Parser) -> None:
    """Declare the logging-coverage knobs.

    Prefixed with ``coverage-`` rather than left bare, for two reasons:

    * pytest already owns ``--log-level``, so declaring it again is an
      ``argparse`` conflict and pytest refuses to start;
    * ``--src`` and ``--granularity`` are generic enough that another plugin
      (or a future pytest) claiming them would be a silent collision.

    ``--coverage-src`` defaults to the project's ``src`` directory rather than
    to the relative string ``"src"``: a test run started from anywhere should
    scan the same tree, and a relative default silently scans nothing when the
    CWD differs.
    """
    group = parser.getgroup("logging-coverage", "exhaustive logging coverage")
    group.addoption(
        "--coverage-src",
        action="store",
        default=str(SCRATCH_ROOT.parent / "src"),
        help="Source directory to scan (default: <project>/src)",
    )
    group.addoption(
        "--coverage-granularity",
        action="store",
        default="branch",
        choices=["branch", "function", "class", "module"],
        help="How finely logging coverage is demanded (default: branch)",
    )
    group.addoption(
        "--coverage-min-level",
        action="store",
        default="DEBUG",
        choices=list(LOG_LEVEL_NAMES),
        help="Lowest logging level that counts as covered (default: DEBUG)",
    )
