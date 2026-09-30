"""Shared pytest configuration.

The default ``tmp_path`` fixture lives under the system temp directory, which
may be read-only or absent in a sandboxed run.  Point it at a workspace-local
directory instead so tests stay self-contained and writable.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

#: Workspace-local scratch root for tests that need a real filesystem.
SCRATCH_ROOT = Path(__file__).resolve().parent.parent / ".pytest-tmp"


@pytest.fixture
def tmp_path(request):
    """A unique, writable directory under the workspace."""
    name = request.node.name.replace("/", "_").replace("\\", "_")
    path = SCRATCH_ROOT / name
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path
