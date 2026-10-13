"""Exhaustive check: does every branch in the source tree log?

The rest of this suite tests behaviour.  This one tests an *invariant about the
source itself*: a scanning tool that goes quiet when something interesting
happens is not debuggable in the field, because the one thing you need — "which
source did it try, and why did it fail?" — is exactly what nobody logs.

"It did not log" is not observable from a test of the running code: you cannot
call a function and assert that some *other* function was not called, because a
branch that was never taken cannot be detected that way.  So this module reads
the source instead, and enumerates the branches with :mod:`ast`.

Granularity is a choice, because "every branch must log" is a strong claim and
the right strength depends on the code:

======================  ==================================================
``--granularity``       pass condition
======================  ==================================================
``branch`` (default)    every branch body contains a logging call
``function``            at least one branch in the function logs
``class``               at least one branch in the class logs
``module``              at least one branch in the module logs
======================  ==================================================

Each unit becomes its own parametrised test case, so a failure names the file,
the line, the branch kind and a source snippet — the point is to be able to fix
it immediately, not to receive a summary count.

Usage::

    pytest tests/test_logging_coverage.py --src=src
    pytest tests/test_logging_coverage.py --granularity=function
    pytest tests/test_logging_coverage.py --log-level=WARNING
"""

from __future__ import annotations

import ast
import logging
import textwrap
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

import pytest

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

#: AST nodes that represent a decision point, and the name to report them by.
BRANCH_TYPES: Dict[type, str] = {
    ast.If: "if",
    ast.For: "for",
    ast.AsyncFor: "async for",
    ast.While: "while",
    ast.Try: "try",
    ast.ExceptHandler: "except",
    ast.With: "with",
    ast.AsyncWith: "async with",
    ast.Match: "match",
    ast.BoolOp: "bool_op",
}

#: ``logging`` level names, upper-cased, mapped to their numeric value.
LOG_LEVELS: Dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class Branch(NamedTuple):
    """One decision point, and where it lives."""

    file: Path
    function: str
    class_name: Optional[str]
    node: ast.AST
    line: int
    kind: str

    @property
    def label(self) -> str:
        return f"{self.function}:{self.kind}@{self.line}"


class Scope(NamedTuple):
    """A named unit for the coarser granularities."""

    file: Path
    name: str
    kind: str  # "function" | "class" | "module"
    lineno: int
    branches: List[Branch]


# ---------------------------------------------------------------------------
# AST collection
# ---------------------------------------------------------------------------
class _BranchCollector(ast.NodeVisitor):
    """Collect every branch in a module, tracking its enclosing scopes."""

    def __init__(self, file: Path) -> None:
        self.file = file
        self._functions: List[str] = []
        self._classes: List[str] = []
        self.branches: List[Branch] = []

    # -- scope tracking -------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._classes.append(node.name)
        self.generic_visit(node)
        self._classes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    # -- branch recording -----------------------------------------------
    def _record(self, node: ast.AST, kind: str) -> None:
        self.branches.append(
            Branch(
                file=self.file,
                function=self._functions[-1] if self._functions else "<module>",
                class_name=self._classes[-1] if self._classes else None,
                node=node,
                line=getattr(node, "lineno", 0),
                kind=kind,
            )
        )

    def generic_visit(self, node: ast.AST) -> None:
        kind = BRANCH_TYPES.get(type(node))
        if kind is not None:
            self._record(node, kind)
        super().generic_visit(node)


def collect_branches(source: str, file: Path) -> List[Branch]:
    """Every branch in ``source``, or ``[]`` if it does not parse."""
    try:
        tree = ast.parse(source, filename=str(file))
    except SyntaxError:  # pragma: no cover - a broken file is not this test's job
        return []
    collector = _BranchCollector(file)
    collector.visit(tree)
    return collector.branches


def _read(file: Path) -> Optional[str]:
    try:
        return file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):  # pragma: no cover - unreadable file
        return None


# ---------------------------------------------------------------------------
# Logging detection
# ---------------------------------------------------------------------------
def _logging_calls(node: ast.AST, *, min_level: int) -> List[str]:
    """Every logging call in ``node`` at ``min_level`` or above.

    Recognised shapes::

        logger.debug(...)      log.warning(...)     self.log.error(...)
        logging.info(...)      LOG.critical(...)    debug(...)   # imported directly

    The check is deliberately duck-typed: it cannot prove the receiver is a
    ``logging.Logger``, and trying to would mean refusing to recognise the
    common ``self.log`` delegation.  A branch that calls *any* object's
    ``.debug`` is logged, which is the property being asserted.
    """
    found: List[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Attribute):
            name = func.attr.upper()
        elif isinstance(func, ast.Name):
            name = func.id.upper()
        else:
            continue
        if name in LOG_LEVELS and LOG_LEVELS[name] >= min_level:
            found.append(name.lower())
    return found


def _branch_logs(branch: Branch, *, min_level: int) -> bool:
    # A ``try`` is logged if the try *or* any of its handlers logs: the two are
    # one decision point from the reader's perspective, and demanding a log in
    # the bare ``try`` body would push people to log the happy path twice.
    return bool(_logging_calls(branch.node, min_level=min_level))


def _snippet(file: Path, line: int, context: int = 4) -> str:
    source = _read(file)
    if source is None:  # pragma: no cover - unreadable file
        return "<unreadable>"
    lines = source.splitlines()
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    return "\n".join(f"{number + 1:5d} | {lines[number]}" for number in range(start, end))


# ---------------------------------------------------------------------------
# Scope enumeration
# ---------------------------------------------------------------------------
def enumerate_scopes(source: str, file: Path, branches: List[Branch]) -> List[Scope]:
    """Every function, class and the module itself, with their branches."""
    try:
        tree = ast.parse(source, filename=str(file))
    except SyntaxError:  # pragma: no cover
        return []

    scopes: List[Scope] = [
        Scope(file=file, name="<module>", kind="module", lineno=1, branches=list(branches))
    ]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(
                Scope(
                    file=file,
                    name=node.name,
                    kind="function",
                    lineno=node.lineno,
                    branches=[b for b in branches if b.function == node.name],
                )
            )
        elif isinstance(node, ast.ClassDef):
            scopes.append(
                Scope(
                    file=file,
                    name=node.name,
                    kind="class",
                    lineno=node.lineno,
                    branches=[b for b in branches if b.class_name == node.name],
                )
            )
    return scopes


# ---------------------------------------------------------------------------
# pytest wiring
# ---------------------------------------------------------------------------
# ``--src`` / ``--granularity`` / ``--log-level`` are declared in conftest.py,
# not here.  ``pytest_addoption`` is only consulted on plugins and conftest
# files; a hook defined in a test module is never called, so the options would
# be unknown to pytest even though the module that documents them sits right
# here.  Declaring them a second time would also make pytest reject the
# duplicate option.


def _source_files(root: str) -> List[Path]:
    path = Path(root)
    if not path.exists():  # pragma: no cover - a bad --src is the caller's error
        return []
    return sorted(p for p in path.rglob("*.py") if "__pycache__" not in p.parts)


def _cases(root: str, granularity: str, min_level: int) -> List[dict]:
    cases: List[dict] = []
    for file in _source_files(root):
        source = _read(file)
        if source is None:  # pragma: no cover
            continue
        branches = collect_branches(source, file)

        if granularity == "branch":
            for branch in branches:
                cases.append(
                    {
                        "file": file,
                        "kind": "branch",
                        "name": branch.label,
                        "branches": [branch],
                        "min_level": min_level,
                    }
                )
            continue

        if granularity == "module":
            cases.append(
                {
                    "file": file,
                    "kind": "module",
                    "name": file.stem,
                    "branches": branches,
                    "min_level": min_level,
                }
            )
            continue

        for scope in enumerate_scopes(source, file, branches):
            if scope.kind != granularity:
                continue
            cases.append(
                {
                    "file": file,
                    "kind": scope.kind,
                    "name": scope.name,
                    "branches": scope.branches,
                    "min_level": min_level,
                }
            )
    return cases


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """One case per unit, so a failure points at a place rather than a count."""
    if "log_case" not in metafunc.fixturenames:
        return

    root = metafunc.config.getoption("--coverage-src")
    granularity = metafunc.config.getoption("--coverage-granularity")
    min_level = LOG_LEVELS[metafunc.config.getoption("--coverage-min-level")]

    cases = _cases(root, granularity, min_level)
    ids = [f"{c['file'].as_posix()}::{c['kind']}::{c['name']}" for c in cases]
    metafunc.parametrize("log_case", cases, ids=ids)


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------
def test_logging_coverage(log_case: dict) -> None:
    """The unit must log; what counts as logging is set by ``--log-level``."""
    file: Path = log_case["file"]
    kind: str = log_case["kind"]
    name: str = log_case["name"]
    branches: List[Branch] = log_case["branches"]
    min_level: int = log_case["min_level"]
    level_name = logging.getLevelName(min_level)

    if not branches:
        pytest.skip(f"{file}::{kind}::{name} has no branches")

    if kind == "branch":
        branch = branches[0]
        if not _branch_logs(branch, min_level=min_level):
            pytest.fail(
                f"branch {branch.kind} at {file}:{branch.line} does not log at "
                f"{level_name} or above.\n"
                f"  in {branch.class_name + '.' if branch.class_name else ''}"
                f"{branch.function}()\n"
                f"{textwrap.indent(_snippet(file, branch.line), '    ')}"
            )
        return

    missing = [b for b in branches if not _branch_logs(b, min_level=min_level)]
    if missing:
        detail = "\n".join(
            f"    {b.kind} at line {b.line} in {b.function}()\n"
            f"{textwrap.indent(_snippet(file, b.line, context=2), '        ')}"
            for b in missing[:10]
        )
        more = f"\n  ... and {len(missing) - 10} more" if len(missing) > 10 else ""
        pytest.fail(
            f"{file}::{kind}::{name} has {len(missing)} of {len(branches)} "
            f"branch(es) with no logging call at {level_name} or above:\n{detail}{more}"
        )
