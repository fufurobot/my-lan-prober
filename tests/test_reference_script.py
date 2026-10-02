"""Guard rails for the standalone reference script.

``tplogin-minimal.py`` is the tested original the package was ported from.  It
is kept in the repository as a runnable, dependency-light reference, so it is
not imported by the suite — but it must not rot either.  These tests check the
properties that make it useful as a reference:

* it is syntactically valid and compiles;
* it never gains a hard ``playwright`` import it cannot run without;
* the two behaviours the package grew are present here too, so the reference
  and the package do not tell different stories.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "tplogin-minimal.py"


@pytest.fixture(scope="module")
def source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tree(source: str) -> ast.Module:
    return ast.parse(source, filename=str(SCRIPT))


def test_the_reference_script_compiles(source):
    compile(source, str(SCRIPT), "exec")


def test_the_reference_script_defines_main_pieces(tree):
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert {"run", "scrape_router_dhcp", "parse_cli_args"} <= names


# ---------------------------------------------------------------------------
# Feature 1: browser detection
# ---------------------------------------------------------------------------
def test_the_reference_script_detects_an_installed_browser(tree):
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "first_available_browser" in names, (
        "tplogin-minimal.py must pick an installed Playwright engine, not hard-code chromium"
    )


def test_the_reference_script_reads_executable_path(source):
    """The detection must ask Playwright, not guess at the cache layout."""
    assert "executable_path" in source


def test_the_reference_script_does_not_hardcode_chromium_launch(source):
    """``playwright.chromium.launch()`` is the bug this feature removes."""
    assert "playwright.chromium.launch" not in source


def test_the_reference_script_exposes_a_browser_flag(tree):
    fields = {
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    }

    assert "--browser" in fields


# ---------------------------------------------------------------------------
# Feature 2: the local ARP fallback
# ---------------------------------------------------------------------------
def test_the_reference_script_has_a_local_arp_fallback(tree):
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "local_arp_leases" in names, (
        "tplogin-minimal.py must fall back to the OS ARP table when no browser is installed"
    )


@pytest.mark.parametrize(
    "marker",
    ["/proc/net/arp", "arp -an", "neigh"],
    ids=["procfs", "bsd-and-windows-arp", "ip-neigh"],
)
def test_the_reference_fallback_covers_every_platform(source, marker):
    """One OS-independent path: procfs, then ip neigh, then arp -a/-an."""
    assert marker in source


def test_the_reference_script_imports_playwright_lazily(source):
    """A module-level playwright import makes the script unrunnable without it.

    The whole point of the ARP fallback is that the script still works when
    Playwright (or its browsers) is absent, which it cannot do if the import
    fails at module import time.
    """
    module = ast.parse(source)
    for node in module.body:
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("playwright"):
            pytest.fail(f"top-level `from {node.module} import ...` blocks the fallback")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("playwright"):
                    pytest.fail(f"top-level `import {alias.name}` blocks the fallback")
