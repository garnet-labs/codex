#!/usr/bin/env python3
"""Print a CI coverage ledger for one or more repository workflow runs.

The ledger reports the state of the Garnet sensor from the job steps, the
recording evidence, and the job log. Job logs are cached in the system temp
directory so repeated runs do not fetch them again.

Usage:
    python3 .garnet/tools/coverage_ledger.py 33090277175 33089549603 \
        --evidence .garnet/evidence/actions.ndjson
"""

import argparse
import collections
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

STEP_NAME = "Garnet Runtime Review"
SELF_HOSTED = ("codex-linux-x64", "codex-windows-x64", "codex-macos-arm64")
LOG_CACHE = Path(tempfile.gettempdir()) / "garnet-coverage-ledger"


def platform_of(job):
    labels = [str(label).lower() for label in job.get("labels") or []]
    runner_group = (job.get("runner_group_name") or "").lower()
    self_hosted = any(label in SELF_HOSTED for label in labels) or (
        runner_group not in {"", "github actions"}
    )
    if any("windows" in label for label in labels):
        system = "Windows"
    elif any("macos" in label for label in labels):
        system = "macOS"
    else:
        system = "Linux"
    return f"{'self-hosted' if self_hosted else 'hosted'} {system}"


def run_of(run_id):
    out = subprocess.run(
        ["gh", "api", f"repos/garnet-labs/codex/actions/runs/{run_id}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def jobs_of(run_id):
    out = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/garnet-labs/codex/actions/runs/{run_id}/jobs?per_page=100",
            "--jq",
            ".jobs[]",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def log_of(job_id):
    LOG_CACHE.mkdir(parents=True, exist_ok=True)
    cache_path = LOG_CACHE / f"{job_id}.log"
    if not cache_path.exists():
        result = subprocess.run(
            [
                "gh",
                "api",
                f"repos/garnet-labs/codex/actions/jobs/{job_id}/logs",
            ],
            check=True,
            capture_output=True,
        )
        cache_path.write_bytes(result.stdout)

    contents = cache_path.read_bytes()
    if contents[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(contents)) as archive:
            contents = b"\n".join(
                archive.read(name) for name in sorted(archive.namelist())
            )
    return contents.decode("utf-8", errors="replace")


def evidence_actions(records, run_id, commit, job_name):
    return sum(
        1
        for record in records
        if str(record["run_id"]) == str(run_id)
        and record["commit"] == commit
        and record["job"] == job_name
    )


def words_of(value):
    return {word for word in re.split(r"[^a-z0-9]+", value.lower()) if word}


def evidence_job_for(job, available_jobs):
    name_words = words_of(job["name"])
    matches = [
        available
        for available in sorted(available_jobs)
        if words_of(available) <= name_words
    ]
    if len(matches) == 1:
        return matches[0]
    if matches:
        return max(matches, key=lambda available: len(words_of(available)))
    return None


def sensor_state(job, actions):
    steps = job.get("steps") or []
    if not steps:
        return "no runner"
    sensor_steps = [
        step
        for step in steps
        if STEP_NAME in (step.get("name") or "")
        and step.get("conclusion") != "skipped"
    ]
    if not sensor_steps:
        return "not instrumented"

    if actions:
        return "recorded"
    log = log_of(job["id"])
    if "Jibril service failed to start" in log:
        return "sensor failed"
    if "Jibril service started successfully" in log:
        return "started, nothing recorded"
    return "sensor failed"


def display_job(run, job):
    name = job["name"]
    if " / " in name:
        workflow, short_name = name.split(" / ", 1)
    else:
        workflow, short_name = run.get("name") or "unknown", name
    return workflow, short_name, name


def markdown(value):
    return str(value).replace("|", "\\|")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("runs", nargs="+")
    parser.add_argument(
        "--evidence",
        default=os.path.join(os.path.dirname(__file__), "..", "evidence", "actions.ndjson"),
    )
    args = parser.parse_args()

    with open(args.evidence) as handle:
        records = [json.loads(line) for line in handle if line.strip()]

    rows = []
    for run_id in args.runs:
        run = run_of(run_id)
        available_jobs = {
            record["job"]
            for record in records
            if str(record["run_id"]) == str(run_id)
            and record["commit"] == run["head_sha"]
        }
        for job in jobs_of(run_id):
            workflow, _, display_name = display_job(run, job)
            evidence_job = evidence_job_for(job, available_jobs)
            actions = evidence_actions(records, run_id, run["head_sha"], evidence_job)
            rows.append(
                {
                    "workflow": workflow,
                    "job": display_name,
                    "runner": platform_of(job),
                    "sensor": sensor_state(job, actions),
                    "actions": actions,
                    "result": job.get("conclusion") or "in progress",
                }
            )

    rows.sort(key=lambda row: (row["workflow"], row["job"]))
    print("| job | runner | sensor | recorded actions | job result |")
    print("| --- | --- | --- | ---: | --- |")
    for row in rows:
        actions = str(row["actions"]) if row["actions"] else "—"
        print(
            f"| {markdown(row['job'])} | {markdown(row['runner'])} | "
            f"{row['sensor']} | {actions} | {markdown(row['result'])} |"
        )

    totals = collections.Counter(row["sensor"] for row in rows)
    states = (
        "recorded",
        "sensor failed",
        "started, nothing recorded",
        "not instrumented",
        "no runner",
    )
    print(
        "Totals: "
        + ", ".join(f"{state} {totals[state]}" for state in states if totals[state])
        + "."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
