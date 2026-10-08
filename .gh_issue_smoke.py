"""File the pre-existing CI failure as an issue (found while landing the ARP work)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("pub", Path(".gh_publish.py"))
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)

TITLE = "The smoke tests assume a non-writable path can be invented, which is false for root and on Windows runners"

BODY = """\
## What happens

Four `tests/test_smoke.py` tests fail on the GitHub runners, on **every**
recent run including commits that predate the ARP expansion work:

```
FAILED tests/test_smoke.py::test_driver_env_overrides_an_unusable_inherited_value
FAILED tests/test_smoke.py::test_driver_env_finds_a_fallback_when_every_candidate_is_bad
FAILED tests/test_smoke.py::test_ensure_temp_env_points_every_variable_at_a_writable_directory
FAILED tests/test_smoke.py::test_ensure_temp_env_creates_the_workaround_directory
FAILED tests/test_smoke.py::test_driver_env_finds_a_fallback_when_every_candidate_is_bad   (Windows)
```

They share one root cause: each test needs a path that is **not writable**, and
each one invents it by name.

| Test | Invents | Why it is still writable |
|---|---|---|
| `test_driver_env_overrides_an_unusable_inherited_value` | `/nonexistent-temp-for-my-lan-prober` | the Ubuntu runner can create directories in `/` |
| `test_driver_env_finds_a_fallback_when_every_candidate_is_bad` | `/nope` (+ `LOCALAPPDATA`, `SYSTEMROOT`) | same, and on Windows the `Path("/nope")/"Temp"` join succeeds |
| `test_ensure_temp_env_points_every_variable_at_a_writable_directory` | `/nope` | same |
| `test_ensure_temp_env_creates_the_workaround_directory` | `/nope` | same |

`test_driver_env_overrides_an_unusable_inherited_value` even asserts the
precondition first —

```python
assert not _tmpdir_is_writable(unusable), "precondition: path must be unusable"
```

— and that assertion **passes**, because `_tmpdir_is_writable` checks
`is_dir()` before it tries to create a file. A path that does not exist is
therefore "unusable" by that check while still being perfectly creatable by
`ensure_temp_env`, which does `candidate.mkdir(parents=True, exist_ok=True)`
first. The two helpers disagree about what "unusable" means, and the tests sit
exactly on the seam.

## Why it matters

CI has been red on `main` for the whole ARP expansion branch, which makes it
impossible to tell a real regression from this noise — the reason it went
unnoticed is precisely that it looks like everything else is broken too.

## Suggested fix

Make the unusable path genuinely unusable *for the process being tested*,
rather than unwritable-by-convention. The robust construction is a **file**
where a directory is expected, which `mkdir` cannot satisfy on any platform or
uid:

```python
blocker = tmp_path / "blocker"
blocker.write_text("a file, not a directory", encoding="utf-8")
unusable = blocker / "sub"          # ENOTDIR for mkdir and for mkstemp
```

`test_ensure_temp_env_leaves_a_broken_environment_alone` already uses exactly
this trick, which is why it is the one test in that group that passes.

A secondary improvement: `_tmpdir_is_writable` should distinguish "does not
exist" from "exists but rejects writes", so a caller cannot mistake the former
for the latter.

## Scope

Not caused by, and not blocking, the ARP expansion PR — filed separately so the
fix can be reviewed on its own terms.
"""


def main() -> None:
    existing = pub.existing_titles()
    if TITLE in existing:
        print(f"already filed as #{existing[TITLE]}")
        return
    status, body = pub.api("POST", f"/repos/{pub.REPO}/issues", {"title": TITLE, "body": BODY})
    if status != 201:
        print(f"FAILED {status}: {body[:400].decode('utf-8', 'ignore')}")
        raise SystemExit(1)
    data = json.loads(body)
    print(f"created #{data['number']}: {data['html_url']}")


if __name__ == "__main__":
    main()
