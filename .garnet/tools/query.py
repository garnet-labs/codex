#!/usr/bin/env python3
"""Query the recorded CI actions in `evidence/actions.ndjson`.

One record is one action: an outbound connection made by one process in one
execution chain, recorded in one CI job. `export_actions.sql` produced the file
from the Execution Profiles the Garnet platform stored for this repository; every
record carries the run, the commit, the profile it came from, and a public
profile link, so any row can be checked against its source.

    python3 .garnet/tools/query.py burndown
    python3 .garnet/tools/query.py destinations --class workload
    python3 .garnet/tools/query.py chains --destination pypi.org
    python3 .garnet/tools/query.py compare --job python-sdk-install
    python3 .garnet/tools/query.py detections
    python3 .garnet/tools/query.py allowlist
"""

import argparse
import collections
import json
import os

DEFAULT_EVIDENCE = os.path.join(
    os.path.dirname(__file__), os.pardir, "evidence", "actions.ndjson"
)

# The step name the sensor uses for a connection made outside any workflow step.
RUNNER_STEP = "99. Runner Processes"

CLASSES = (
    "workload",
    "actions-service",
    "container-runtime",
    "dns-resolver",
    "runner-substrate",
    "azure-imds",
    "azure-wireserver",
)

def bare_address_note(count):
    return (
        f"{count} further destinations were recorded as bare addresses with no name "
        "resolved in the flow; they rotate between runs, and pinning them yields "
        "churn rather than control."
    )


def is_actions_service(record):
    destination = record["destination"]
    step = record.get("step")
    chain = record.get("execution_chain") or []
    process = record.get("process")
    service_destination = (
        "store.core.windows" in destination
        or destination.startswith("glb-") and destination.endswith(".github.com")
        or destination.endswith(".actions.githubusercontent.com")
        or destination.endswith(".blob.core.windows.net")
    )
    action_process = process in {"node", "Runner.Worker"} or any(
        process_name in {"node", "Runner.Worker"} for process_name in chain
    )
    return service_destination and action_process and (
        step is None or step == RUNNER_STEP
    )


def classify(record):
    """Classify one action from what the recording itself says about it.

    `workload` is this repository's own CI work: the connection is owned by a
    named workflow step, or the process sits inside the job's own process tree.
    Everything else belongs to the runner, the cloud platform, or the container
    runtime, and no change to this repository removes it.
    """
    destination = record["destination"]
    port = record.get("remote_port") or ""
    chain = record.get("execution_chain") or []
    step = record.get("step")

    if destination == "169.254.169.254":
        return "azure-imds"
    if destination == "168.63.129.16" and not port.startswith("53 "):
        return "azure-wireserver"
    if port.startswith("53 "):
        return "dns-resolver"
    if is_actions_service(record):
        return "actions-service"
    if step is not None and step != RUNNER_STEP:
        return "workload"
    if record.get("process") == "dockerd" or "dockerd" in chain:
        return "container-runtime"
    if "Runner.Worker" in chain or "containerd-shim-runc-v2" in chain:
        return "workload"
    return "runner-substrate"


def step_name(record):
    """The workflow step that owns the action, without its ordinal."""
    step = record.get("step")
    if step is None or step == RUNNER_STEP:
        return None
    return step.split(". ", 1)[-1]


def load(path, args):
    records = []
    with open(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            record["classification"] = classify(record)
            if args.job is not None and args.job not in record["job"]:
                continue
            if args.workflow is not None and args.workflow not in (record["workflow"] or ""):
                continue
            if args.destination is not None and args.destination != record["destination"]:
                continue
            if args.commit is not None and not (record["commit"] or "").startswith(args.commit):
                continue
            if args.run is not None and args.run != record["run_id"]:
                continue
            if getattr(args, "klass", None) is not None and record["classification"] != args.klass:
                continue
            records.append(record)
    return records


def print_burndown(records):
    total = len(records)
    destinations = {r["destination"] for r in records}
    by_class = collections.Counter(r["classification"] for r in records)
    per_class_destinations = collections.defaultdict(set)
    for record in records:
        per_class_destinations[record["classification"]].add(record["destination"])

    print(f"recorded actions:  {total}")
    print(f"destinations:      {len(destinations)}")
    print(f"job profiles:      {len({r['profile_id'] for r in records})}")
    print(f"CI runs:           {len({r['run_id'] for r in records})}")
    print(f"commits:           {len({r['commit'] for r in records})}")
    print(f"jobs:              {len({r['job'] for r in records})}\n")

    print(f"{'class':18s} {'actions':>8s} {'destinations':>13s} {'share':>6s}")
    print("-" * 49)
    for classification, count in by_class.most_common():
        print(
            f"{classification:18s} {count:>8d} "
            f"{len(per_class_destinations[classification]):>13d} "
            f"{count / total * 100:>5.0f}%"
        )
    class_rows = sum(len(v) for v in per_class_destinations.values())
    shared = class_rows - len(destinations)
    print("-" * 49)
    print(f"{'total':18s} {total:>8d} {class_rows:>13d} {'100%':>6s}")
    if shared:
        print(
            f"\n{class_rows} class rows over {len(destinations)} destinations: "
            f"{shared} destinations were reached by processes in two different "
            f"classes, and are counted in both."
        )


def print_destinations(records):
    groups = collections.defaultdict(list)
    for record in records:
        groups[record["destination"]].append(record)

    def wrapped(values, width=100):
        lines = []
        current = []
        for value in values:
            candidate = ", ".join(current + [value])
            if current and len(candidate) > width:
                lines.append(", ".join(current))
                current = [value]
            else:
                current.append(value)
        if current:
            lines.append(", ".join(current))
        return lines

    for destination in sorted(groups, key=lambda d: -len(groups[d])):
        group = groups[destination]
        classes = ",".join(sorted({r["classification"] for r in group}))
        ports = sorted({(r["remote_port"] or "?") for r in group})
        processes = sorted({r["process"] for r in group if r["process"]})
        print(f"{destination}  actions: {len(group)}  class: {classes}")
        for index, line in enumerate(wrapped(ports)):
            print(f"  {'ports: ' if index == 0 else '        '}{line}")
        for index, line in enumerate(wrapped(processes)):
            print(f"  {'processes: ' if index == 0 else '            '}{line}")
        for step in sorted({s for s in (step_name(r) for r in group) if s}):
            print(f"  step: {step}")


def print_chains(records):
    seen = set()
    for record in records:
        chain = " > ".join(record["execution_chain"] or [])
        key = (record["job"], chain, record["destination"], record["step"])
        if key in seen:
            continue
        seen.add(key)
        print(f"{record['job']} · {record['commit'][:7]} · run {record['run_id']}")
        print(f"  {chain} -> {record['destination']} :{record['remote_port']}")
        if "containerd-shim-runc-v2" in (record["execution_chain"] or []):
            step = (
                "not attributable to a workflow step (process ran inside a "
                "container started by the job)"
            )
        else:
            step = step_name(record) or "outside any workflow step"
        print(f"  step: {step}")
        print(f"  profile: {record['profile_url']}")


def print_compare(records, args):
    """Diff the destination set of one job between consecutive recorded commits."""
    jobs = {r["job"] for r in records}
    if len(jobs) != 1:
        print("compare needs one job: pass --job with a name that matches exactly one")
        print("jobs in scope: " + ", ".join(sorted(jobs)))
        return
    runs = collections.defaultdict(set)
    when = {}
    for record in records:
        runs[record["run_id"]].add((record["destination"], record["process"]))
        when[record["run_id"]] = (record["recorded_at"], record["commit"])
    ordered = sorted(runs, key=lambda run: when[run][0])
    if len(ordered) < 2:
        print("only one recorded run for this job, so there is nothing to compare")
        return
    for previous, current in zip(ordered, ordered[1:]):
        print(
            f"{when[previous][1][:7]} -> {when[current][1][:7]}  "
            f"(run {previous} -> {current})"
        )
        added = runs[current] - runs[previous]
        removed = runs[previous] - runs[current]
        if not added and not removed:
            print("  no change in destinations")
        for destination, process in sorted(added):
            print(f"  + {destination:44s} {process}")
        for destination, process in sorted(removed):
            print(f"  - {destination:44s} {process}")
        print()


def print_detections(records):
    """Detection labels the platform attached to the chains that egressed."""
    labels = collections.defaultdict(lambda: [0, set(), set()])
    for record in records:
        for label in record.get("detections") or []:
            if label == "flow":
                continue
            entry = labels[label]
            entry[0] += 1
            entry[1].add(record["job"])
            entry[2].add(record["destination"])
    if not labels:
        print("no matching records in the queried scope")
        return
    print(f"{'detection':36s} {'actions':>7s} {'destinations':>12s} jobs")
    print("-" * 100)
    for label, (count, jobs, destinations) in sorted(labels.items(), key=lambda kv: -kv[1][0]):
        print(f"{label:36s} {count:>7d} {len(destinations):>12d} {','.join(sorted(jobs))[:40]}")
    print(
        "\nThese labels were recorded on this repository's own jobs; they are "
        "labels and not verdicts, and the counts are actions carrying the label "
        "rather than distinct incidents."
    )


def print_allowlist(records):
    """The destinations a CI egress allowlist has to contain for this repository."""
    for title, wanted in (
        ("internet egress performed by this repository's CI work", "workload"),
        (
            "traffic the runner's own action machinery performed, not repository workload",
            "actions-service",
        ),
        ("container images pulled by the docker daemon", "container-runtime"),
    ):
        print(f"# {title}")
        groups = collections.defaultdict(lambda: [0, set(), set(), set()])
        for record in records:
            if record["classification"] != wanted:
                continue
            entry = groups[record["destination"]]
            entry[0] += 1
            entry[1].add(record["job"])
            entry[2].add(record["process"])
            step = step_name(record)
            if step:
                entry[3].add(step)
        named = [d for d in groups if not d[0].isdigit()]
        unnamed = [d for d in groups if d[0].isdigit()]
        for destination in sorted(named, key=lambda d: -groups[d][0]):
            count, jobs, processes, steps = groups[destination]
            print(f"- {destination}   ({count} actions)")
            print(f"    jobs:      {', '.join(sorted(jobs))}")
            print(f"    processes: {', '.join(sorted(p for p in processes if p))}")
            for step in sorted(steps):
                print(f"    step:      {step}")
        if unnamed:
            print(f"- {bare_address_note(len(unnamed))}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "command",
        choices=["burndown", "destinations", "chains", "compare", "detections", "allowlist"],
    )
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--job")
    parser.add_argument("--workflow")
    parser.add_argument("--destination")
    parser.add_argument("--commit")
    parser.add_argument("--run")
    parser.add_argument("--class", dest="klass", choices=CLASSES)
    args = parser.parse_args()

    records = load(args.evidence, args)
    if not records:
        print("no matching records in the queried scope")
        return 0

    if args.command == "compare":
        print_compare(records, args)
        return 0
    {
        "burndown": print_burndown,
        "destinations": print_destinations,
        "chains": print_chains,
        "detections": print_detections,
        "allowlist": print_allowlist,
    }[args.command](records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
