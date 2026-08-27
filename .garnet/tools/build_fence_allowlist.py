#!/usr/bin/env python3
"""Derive a Fence allowlist from Garnet's record of the `garnet` CI job.

Reads .garnet/evidence/actions.ndjson, keeps the workload actions of the
`garnet` job (the `cargo fetch --locked` step), and emits the destinations in
Fence's allowlist syntax (openai/fence, docs/allowlist.md) with one comment
per line carrying the recorded justification and the stability count: in how
many of the recorded runs of that step the destination appeared.

Garnet records where each connection landed (the resolved edge, e.g.
`dualstack.k.sni.global.fastly.net`); Fence authorizes the hostname the
process queried. EDGE_TO_QUERIED maps the recorded edges of this workload to
the hostnames cargo actually resolves, so the emitted entries are in the form
Fence enforces. The mapping is explicit and reviewable, never guessed at
runtime.

Usage: python3 .garnet/tools/build_fence_allowlist.py [evidence.ndjson]
Writes to stdout; the checked-in .garnet/fence-allowlist.suggested.txt is this
tool's output for the current evidence export.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

STEP_SUFFIX = "Fetch locked Rust dependencies"

# Recorded edge -> hostnames the workload queried that resolve to that edge.
# `cargo fetch` resolves crates.io's index and static download hosts; both
# land on the same Fastly edge in the record.
EDGE_TO_QUERIED = {
    "dualstack.k.sni.global.fastly.net": ["index.crates.io", "static.crates.io"],
}

# Covered by Fence's default GitHub compatibility profile; emitted as a
# comment so the record's coverage stays visible without duplicating entries.
FENCE_DEFAULT_PROFILE = {"github.com", "api.github.com", "release-assets.githubusercontent.com"}

# Local DNS and Azure platform addresses are mediated by Fence's own
# structural rules, not by allowlist entries.
PLATFORM_MEDIATED = {"localhost", "168.63.129.16", "169.254.169.254"}


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "evidence" / "actions.ndjson"
    records = [json.loads(line) for line in path.open() if line.strip()]
    step_records = [
        r
        for r in records
        if r.get("job") == "garnet" and (r.get("step") or "").endswith(STEP_SUFFIX)
    ]
    all_runs = sorted({r["run_id"] for r in step_records})
    runs_by_destination = defaultdict(set)
    processes_by_destination = defaultdict(set)
    for r in step_records:
        runs_by_destination[r["destination"]].add(r["run_id"])
        if r.get("process"):
            processes_by_destination[r["destination"]].add(r["process"])

    total = len(all_runs)
    print(f'# Derived from Garnet\'s record of the `garnet` job\'s "{STEP_SUFFIX}" step')
    print(f"# across {total} recorded runs (.garnet/evidence/actions.ndjson).")
    print("# Suggestion only: the allowlist stays repo-owned and human-approved.")
    for destination in sorted(runs_by_destination):
        runs = runs_by_destination[destination]
        processes = ", ".join(sorted(processes_by_destination[destination]))
        stability = f"{len(runs)} of {total} recorded runs"
        if destination in PLATFORM_MEDIATED:
            print(f"# {destination}: mediated by Fence's own platform rules, no entry needed ({stability})")
        elif destination in FENCE_DEFAULT_PROFILE:
            print(f"# {destination}: in Fence's default GitHub profile, no entry needed ({processes}; {stability})")
        elif destination in EDGE_TO_QUERIED:
            for queried in EDGE_TO_QUERIED[destination]:
                print(f"{queried}  # {processes} landed on {destination} in {stability}")
        else:
            print(f"{destination}  # {processes}; {stability}")


if __name__ == "__main__":
    main()
