#!/usr/bin/env python3
"""Turn Garnet Runtime Review pull request comments into one record per action.

Input: the raw body of each `garnet-runtime-review` comment (fetched from this
repository's pull requests). Output: newline-delimited JSON, one record per
recorded action, with the execution chain behind it and the workflow step that
owns it. That shape is what a detection and response platform can index.

Usage:
    python3 .garnet/tools/build_evidence.py comments/*.md > .garnet/evidence/actions.ndjson
"""

import argparse
import html
import json
import re
import sys

TREE_CHARS = " \t│├└─"
INDENT_WIDTH = 3
NOTE_PATTERN = re.compile(
    r"\((dns resolver|cloud metadata|github infra[^)]*|rotated from [^)]+)\)"
)
JOB_PATTERN = re.compile(
    r"<details[^>]*><summary>(?:<b>(?P<delta>[^<]*)</b>\s*·\s*)?"
    r"<code>(?P<workflow>[^<]+)</code> / "
    r'<a href="(?P<run_url>[^"]+)"><code>(?P<job>[^<]+)</code>'
    r".*?</summary>(?P<inner>.*?)</details>",
    re.S,
)
PROFILE_PATTERN = re.compile(r'href="(?P<url>https://app\.garnet\.ai/public/runs/[^"]+)"')


def unmask(name):
    """Comment bodies defang hostnames so GitHub does not linkify them."""
    return name.replace("[.]", ".")


def strip_tags(line):
    return re.sub(r"<[^>]+>", "", line)


def parse_line(raw, diff_mode):
    """Return (change, depth, label, step, notes) for one rendered tree line."""
    change = "unchanged"
    line = raw
    if diff_mode:
        if raw[:1] == "+":
            change, line = "added", raw[1:]
        elif raw[:1] == "-":
            change, line = "removed", raw[1:]
        elif raw[:1] == " ":
            line = raw[1:]
    text = strip_tags(line)
    stripped = text.lstrip(TREE_CHARS)
    depth = (len(text) - len(stripped)) // INDENT_WIDTH
    label = stripped.strip()

    step = None
    step_match = re.search(r'\(step: "(.*?)"\)', label)
    if step_match is not None:
        step = step_match.group(1)
        label = re.sub(r'\s*\(step: ".*?"\)', "", label).strip()

    notes = NOTE_PATTERN.findall(label)
    for note in notes:
        label = label.replace(f"({note})", "").strip()

    return change, depth, label, step, notes


def classify(destination, chain, step, notes):
    """Bucket an action for allowlist burn-down.

    A destination owned by a recorded workflow step is workload egress: the
    repository asked for it. Everything reached by the runner's own agent
    processes with no step attribution is GitHub's runner substrate.
    """
    if "cloud metadata" in " ".join(notes):
        return "cloud-metadata"
    if "dns resolver" in " ".join(notes):
        return "dns-resolver"
    if step is not None:
        return "workload"
    if destination == "169.254.169.254":
        return "cloud-metadata"
    if destination == "168.63.129.16":
        return "azure-platform"
    substrate = {
        "provjobd",
        "systemd",
        "systemd-networkd",
        "systemd-resolve",
        "hosted-compute-agent",
        "hosted-compute-",
        "Runner.Worker",
        "sudo",
        "node",
    }
    if any(process in substrate for process in chain):
        return "runner-substrate"
    return "unattributed"


def parse_comment(body, repository):
    marker = re.search(r"<!-- garnet:summary (\{.*?\}) -->", body)
    summary = json.loads(marker.group(1)) if marker is not None else {}
    records = []

    for job_match in JOB_PATTERN.finditer(body):
        inner = job_match.group("inner")
        block = re.search(r"```diff\n(.*?)```", inner, re.S)
        diff_mode = block is not None
        if block is None:
            block = re.search(r"<pre>(.*?)</pre>", inner, re.S)
        if block is None:
            continue
        profile = PROFILE_PATTERN.search(inner)
        run_url = job_match.group("run_url")

        chain_by_depth = {}
        step_by_depth = {}
        for raw in html.unescape(block.group(1)).splitlines():
            if not raw.strip() or raw.lstrip("+- ").startswith("@@"):
                chain_by_depth, step_by_depth = {}, {}
                continue
            change, depth, label, step, notes = parse_line(raw, diff_mode)
            if not label:
                continue
            if label.startswith("○"):
                chain = [chain_by_depth[d] for d in sorted(chain_by_depth) if d < depth]
                owning_step = None
                for d in sorted(step_by_depth):
                    if d < depth:
                        owning_step = step_by_depth[d]
                destination = unmask(label.lstrip("○ ").strip())
                records.append(
                    {
                        "repository": repository,
                        "workflow": job_match.group("workflow"),
                        "job": job_match.group("job"),
                        "run_id": run_url.rstrip("/").split("/")[-1],
                        "run_url": run_url,
                        "commit": summary.get("commit"),
                        "compared_with": summary.get("previous"),
                        "comparison_scope": (
                            "snapshot" if summary.get("previous") is None else "previous-commit"
                        ),
                        "recorded_at": summary.get("recorded"),
                        "contract": summary.get("contract"),
                        "action": "outbound-connection",
                        "destination": destination,
                        "execution_chain": chain,
                        "process": chain[-1] if chain else None,
                        "step": owning_step,
                        "change": change,
                        "annotations": notes,
                        "classification": classify(destination, chain, owning_step, notes),
                        "profile_url": (
                            html.unescape(profile.group("url")) if profile is not None else None
                        ),
                    }
                )
            else:
                chain_by_depth = {d: v for d, v in chain_by_depth.items() if d < depth}
                chain_by_depth[depth] = label
                step_by_depth = {d: v for d, v in step_by_depth.items() if d < depth}
                if step is not None:
                    step_by_depth[depth] = step

    return summary, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("comments", nargs="+", help="files holding raw comment bodies")
    parser.add_argument("--repository", default="garnet-labs/codex")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if a comment's destination count does not match the records parsed from it",
    )
    args = parser.parse_args()

    all_records = []
    failures = []
    for path in args.comments:
        summary, records = parse_comment(open(path).read(), args.repository)
        distinct = len({(r["job"], r["destination"]) for r in records if r["change"] != "removed"})
        expected = summary.get("destinations")
        print(
            f"{path}: contract={summary.get('contract')} jobs={summary.get('jobs')} "
            f"destinations={expected} parsed_distinct_current={distinct} records={len(records)}",
            file=sys.stderr,
        )
        if args.check and expected is not None and distinct != expected:
            failures.append(f"{path}: comment says {expected} destinations, parsed {distinct}")
        all_records.extend(records)

    for record in all_records:
        print(json.dumps(record, sort_keys=True))

    if failures:
        for failure in failures:
            print(f"MISMATCH {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
