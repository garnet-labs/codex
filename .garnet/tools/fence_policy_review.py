#!/usr/bin/env python3
"""Build a fail-closed Fence policy review from Garnet runtime evidence.

The workflow uses this in two modes:

* live mode discovers the current run's Garnet profile and flow events with
  garnetctl;
* fixture mode makes the policy logic locally testable without credentials.

The script never changes the approved policy. It compares observed workload
destinations with the checked-in Fence policy and writes a Markdown decision
artifact for the pull request.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PLATFORM_DESTINATIONS = {
    "168.63.129.16",
    "169.254.169.254",
    "localhost",
}

FENCE_DEFAULT_DESTINATIONS = {
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}

# Garnet records the resolved edge while Fence authorizes the hostname queried
# by Cargo. Keep this translation explicit and reviewable.
EDGE_TO_POLICY_HOSTS = {
    "dualstack.k.sni.global.fastly.net": {
        "index.crates.io",
        "static.crates.io",
    },
}

DESTINATION_KEYS = {
    "destination",
    "destination_domain",
    "domain",
    "dst_domain",
    "dst_hostname",
    "fqdn",
    "remote_address",
    "remote_ip",
}

PROCESS_KEYS = {
    "comm",
    "executable_name",
    "process",
    "process_name",
}

STEP_KEYS = {
    "job_step",
    "step",
    "step_name",
    "workflow_step",
}


@dataclass(frozen=True)
class Observation:
    destination: str
    process: str
    step: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--garnetctl", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--job", default="policy-observe")
    parser.add_argument("--repository")
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--delay-seconds", type=int, default=6)
    return parser.parse_args()


def json_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("items", "nodes", "profiles", "events", "data", "results"):
        nested = value.get(key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return [value]


def walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.lower(), child
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def first_scalar(record: dict[str, Any], keys: set[str]) -> str:
    for key, value in walk(record):
        if key not in keys:
            continue
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            for nested_key in ("name", "hostname", "ip", "address", "value"):
                nested = value.get(nested_key)
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
    return ""


def is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def first_remote_name(record: dict[str, Any]) -> str:
    for key, value in walk(record):
        if key != "remote_names" or not isinstance(value, list):
            continue
        names = [str(item).strip() for item in value if str(item).strip()]
        for name in names:
            if not is_address(name):
                return name
        if names:
            return names[0]
    return ""


def dictionaries(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from dictionaries(child)
    elif isinstance(value, list):
        for child in value:
            yield from dictionaries(child)


def execution_context(record: dict[str, Any]) -> tuple[str, str]:
    candidates = list(dictionaries(record))
    candidates.sort(key=lambda item: bool(item.get("github_step")), reverse=True)
    for item in candidates:
        ancestry = item.get("ancestry")
        process = str(item.get("process") or "").strip()
        if not process and isinstance(ancestry, list) and ancestry:
            process = str(ancestry[-1]).strip()
        step = str(item.get("github_step") or "").strip()
        if process or step:
            return (
                process or "unknown",
                step or "Fetch locked Rust dependencies",
            )
    return (
        first_scalar(record, PROCESS_KEYS) or "unknown",
        first_scalar(record, STEP_KEYS) or "Fetch locked Rust dependencies",
    )


def observations_from_events(events: Any) -> list[Observation]:
    observations = []
    for event in json_items(events):
        destination = (
            first_remote_name(event) or first_scalar(event, DESTINATION_KEYS)
        ).lower().rstrip(".")
        if not destination:
            continue
        process, step = execution_context(event)
        observations.append(
            Observation(
                destination=destination,
                process=process,
                step=step,
            )
        )
    return observations


def read_policy(path: Path) -> set[str]:
    entries = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            entries.add(line.lower())
    return entries


def run_json(command: list[str]) -> Any:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "garnetctl failed")
    return json.loads(result.stdout)


def recursive_value(record: dict[str, Any], keys: set[str]) -> str:
    return first_scalar(record, keys)


def collect_live(args: argparse.Namespace) -> tuple[Any, str]:
    if not args.garnetctl or not args.run_id:
        raise RuntimeError("live mode requires --garnetctl and --run-id")

    profiles: list[dict[str, Any]] = []
    last_error = ""
    for attempt in range(args.attempts):
        try:
            result = run_json(
                [
                    str(args.garnetctl),
                    "list",
                    "profiles",
                    "--run-id",
                    str(args.run_id),
                    "--job",
                    args.job,
                    "--format",
                    "json",
                ]
            )
            profiles = json_items(result)
            if profiles:
                break
        except (RuntimeError, json.JSONDecodeError) as error:
            last_error = str(error)
        if attempt + 1 < args.attempts:
            time.sleep(args.delay_seconds)

    if not profiles:
        detail = f": {last_error}" if last_error else ""
        raise RuntimeError(f"no Garnet profile appeared for this run{detail}")

    profile = profiles[0]
    agent_id = recursive_value(profile, {"agent_id", "agentid"})
    profile_id = str(
        profile.get("profile_id") or profile.get("profileId") or profile.get("id") or ""
    )
    profile_url = recursive_value(
        profile, {"profile_url", "public_url", "publicurl", "url"}
    )
    if not agent_id:
        raise RuntimeError("Garnet profile did not expose an agent ID")

    events = run_json(
        [
            str(args.garnetctl),
            "list",
            "events",
            "--agent-id",
            agent_id,
            "--kinds",
            "flows",
            "--first",
            "200",
            "--format",
            "json",
        ]
    )
    if profile_id:
        profile_url = (
            f"https://app.garnet.ai/public/runs/{args.run_id}"
            f"?profile={profile_id}"
        )
    return events, profile_url


def policy_hosts(observations: list[Observation]) -> tuple[set[str], set[str]]:
    workload = set()
    excluded = set()
    for observation in observations:
        destination = observation.destination
        if destination in PLATFORM_DESTINATIONS:
            excluded.add(destination)
        elif destination in FENCE_DEFAULT_DESTINATIONS:
            excluded.add(destination)
        elif destination in EDGE_TO_POLICY_HOSTS:
            workload.update(EDGE_TO_POLICY_HOSTS[destination])
        else:
            workload.add(destination)
    return workload, excluded


def render(
    *,
    policy: set[str],
    observations: list[Observation],
    profile_url: str,
    collection_error: str,
) -> tuple[str, bool]:
    observed, excluded = policy_hosts(observations)
    additions = observed - policy
    removable = policy - observed
    complete = not collection_error and bool(observations)
    policy_matches = complete and not additions

    lines = [
        "## Evidence behind the decision",
        "",
        f"**Coverage:** {'Full for this job' if complete else 'Degraded'}",
        f"**Policy delta:** {'No change required' if policy_matches else 'Review required'}",
        "**Workload:** `cargo fetch --locked --manifest-path codex-rs/Cargo.toml`",
        "",
    ]
    if profile_url:
        lines.append(f"**Runtime receipt:** {profile_url}")
        lines.append("")
    if collection_error:
        lines.extend(
            [
            "### Evidence failure",
                "",
                f"`{collection_error}`",
                "",
                "No absence-based or policy-removal conclusion is valid.",
                "",
            ]
        )

    lines.extend(
        [
            "### Approved policy",
            "",
            "| Destination | Observed now | Decision |",
            "| --- | --- | --- |",
        ]
    )
    for destination in sorted(policy):
        status = "Yes" if destination in observed else "No"
        decision = (
            "Keep"
            if destination in observed
            else "Removal candidate only after multiple fully covered runs"
        )
        lines.append(f"| `{destination}` | {status} | {decision} |")

    lines.extend(["", "### Proposed additions", ""])
    if additions:
        for destination in sorted(additions):
            related = [
                item
                for item in observations
                if item.destination == destination
                or destination in EDGE_TO_POLICY_HOSTS.get(item.destination, set())
            ]
            process = related[0].process if related else "unknown"
            step = related[0].step if related else "unknown"
            lines.append(
                f"- `{destination}` requested by `{process}` under `{step}`. "
                "Human approval required; the workflow did not expand policy."
            )
    else:
        lines.append("- None.")

    lines.extend(["", "### Excluded platform traffic", ""])
    if excluded:
        for destination in sorted(excluded):
            lines.append(
                f"- `{destination}` is handled by Fence platform rules and is "
                "not added to repository policy."
            )
    else:
        lines.append("- None observed.")

    lines.extend(
        [
            "",
            "### Review semantics",
            "",
            "- Policy additions are never authorized automatically from PR behavior.",
            "- Non-observation is not proof of non-use.",
            "- Removal requires repeated, fully covered runs across every governed job.",
            "- Fence remains authoritative for enforcement and resident health.",
            "",
        ]
    )
    return "\n".join(lines), policy_matches


def main() -> int:
    args = parse_args()
    policy = read_policy(args.policy)
    profile_url = ""
    collection_error = ""
    events: Any = []

    try:
        if args.events:
            events = json.loads(args.events.read_text())
        else:
            events, profile_url = collect_live(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        collection_error = str(error)

    observations = observations_from_events(events)
    report, policy_matches = render(
        policy=policy,
        observations=observations,
        profile_url=profile_url,
        collection_error=collection_error,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report + "\n")
    print(report)
    return 0 if policy_matches else 2


if __name__ == "__main__":
    raise SystemExit(main())
