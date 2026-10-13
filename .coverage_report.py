"""Emit the branches the logging-coverage suite says are unlogged.

Writes ``.coverage-todo/<file>.txt`` with one ``line<TAB>kind<TAB>function`` row
per missing branch, sorted by line, so an editor can walk a file top to bottom.
Also prints a per-file summary.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "tests")

from test_logging_coverage import LOG_LEVELS, _cases  # noqa: E402

cases = _cases("src", "branch", LOG_LEVELS["DEBUG"])

missing = []
for case in cases:
    branch = case["branches"][0]
    from test_logging_coverage import _branch_logs

    if not _branch_logs(branch, min_level=LOG_LEVELS["DEBUG"]):
        missing.append(branch)

out = Path(".coverage-todo")
out.mkdir(exist_ok=True)
for stale in out.glob("*.txt"):
    stale.unlink()

by_file: dict = {}
for branch in missing:
    by_file.setdefault(branch.file, []).append(branch)

for file, branches in sorted(by_file.items(), key=lambda kv: -len(kv[1])):
    lines = [
        f"{b.line}\t{b.kind}\t{b.function}"
        for b in sorted(branches, key=lambda b: b.line)
    ]
    (out / f"{file.name}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"{len(missing)} unlogged branches across {len(by_file)} files")
counts = Counter(b.kind for b in missing)
print("by kind:", dict(counts.most_common()))
print()
for file, branches in sorted(by_file.items(), key=lambda kv: -len(kv[1])):
    kinds = Counter(b.kind for b in branches)
    print(f"{len(branches):4}  {file.name:22} {dict(kinds.most_common())}")
