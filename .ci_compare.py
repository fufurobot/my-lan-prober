"""Was the Windows smoke failure introduced by this work, or pre-existing?

Checks the CI job results for the commit *before* the ARP expansion work and
for the current head, and prints the failing test names from each.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("ci", Path(".ci_logs.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

status, _head, body = ci.api("/repos/fufurobot/my-lan-prober/actions/runs?per_page=30")
runs = json.loads(body)["workflow_runs"]

for label, prefix in (("BASE", "9f4e8c8"), ("MID", "5d8a17a"), ("HEAD", "92d2a0c")):
    for run in runs:
        if not run["head_sha"].startswith(prefix):
            continue
        print(f"{label} run {run['id']} {run['head_sha'][:7]} -> {run['conclusion']}")
        _, _h, jobs_body = ci.api(f"/repos/fufurobot/my-lan-prober/actions/runs/{run['id']}/jobs")
        for job in json.loads(jobs_body)["jobs"]:
            conclusion = job.get("conclusion") or job.get("status")
            if conclusion != "success":
                print(f"   {job['name']:38} {conclusion}")
                for step in job.get("steps", []):
                    if step.get("conclusion") not in ("success", "skipped", None):
                        print(f"      step: {step['name']}")
        break
