# Using this data during an incident

The question an analyst asks about CI is not "was this repository scanned". It is
"a host we care about was contacted from your build infrastructure at 14:02 — what
ran, who asked for it, and what changed". This page is the path from that question
to an answer, and the field mapping that makes the records usable in a detection
and response platform.

## The pivot

Each record is one action, and it carries the full CI identity, so every hop below
is a filter on the same file rather than a lookup in a different system:

```
destination            →  which repository and job reached it
job                    →  which run, which commit, which actor
commit                 →  what that commit changed against the one before it
execution chain        →  which process performed the action, and its lineage
step                   →  the line of YAML that owns the process
profile_url            →  the recorded profile, linkable in a ticket
```

Worked example, starting from a destination and ending at a line of YAML:

```
$ python3 .garnet/tools/query.py chains --destination pypi.org
$ python3 .garnet/tools/query.py compare --job python-sdk-install
```

The first says which process reached `pypi.org` and under which step. The second
says whether it had reached it before the current commit. Together they answer
"is this new" without a human having to remember what CI used to do.

## Field mapping

Every field below is present in `evidence/actions.ndjson`. The OCSF column is a
proposal written against the Network Activity class (`class_uid` 4001); it has not
been loaded into a live platform.

| field | example | OCSF | note |
| --- | --- | --- | --- |
| `recorded_at` | `2026-08-27 12:11:04 UTC` | `time` | when the profile was recorded, not per action |
| `destination` | `pypi.org` | `dst_endpoint.hostname` | name resolved in the flow, when there was one |
| `remote_address` | `151.101.0.223` | `dst_endpoint.ip` | always present |
| `remote_port` | `443` | `dst_endpoint.port` | |
| `protocol` | `TCP` | `connection_info.protocol_name` | also `UDP`, `ICMPV6` |
| `result` | `attention` | `severity_id` | the sensor's verdict on the flow, `attention` or `pass`; it observes, it does not block |
| `process` | `uv` | `actor.process.name` | |
| `executable` | `/tmp/uv/bin/uv` | `actor.process.file.path` | |
| `pid` | `4166` | `actor.process.pid` | |
| `execution_chain` | `["Runner.Worker","bash","docker","uv"]` | `actor.process.lineage` | root first |
| `detections` | `["flow","hidden_elf_exec"]` | `finding_info.title` | `flow` alone means a plain recorded connection |
| `repository` | `garnet-labs/codex` | `metadata.product.feature.name` | |
| `workflow`, `job` | `blocking-ci`, `garnet` | `enrichments` | |
| `run_id`, `run_attempt` | `33089549603`, `1` | `metadata.correlation_uid` | the join key for everything in one run |
| `run_url` | `.../actions/runs/33089549603` | `enrichments` | |
| `actor` | `jadoonf` | `actor.user.name` | who caused the run, not who ran the process |
| `event_name` | `pull_request` | `enrichments` | |
| `ref` | `refs/pull/19/merge` | `enrichments` | |
| `commit` | `204311d…` | `enrichments` | the branch commit the pull request pointed at |
| `merge_commit` | `4210d2d…` | `enrichments` | the commit CI actually checked out |
| `runner_os`, `runner_arch` | `Linux`, `X64` | `device.os.name`, `device.hw_info.cpu_type` | |
| `agent_version` | `v2.15.0` | `metadata.version` | sensor version that recorded it |
| `step` | `4. Fetch locked Rust dependencies` | `enrichments` | the workflow step that owns the chain, prefixed with its index in the job |
| `profile_id`, `profile_url` | `…`, `https://app.garnet.ai/public/runs/…` | `metadata.uid`, `metadata.ref` | the profile a ticket can link to |
| `action` | `outbound-connection` | `class_uid` 4001 | one action class today |

Two fields carry most of the investigative weight. `step` turns a destination into
something the repository owner can change, because it names the line of YAML
responsible. `commit` with `run_id` turns a list of destinations into what a
specific change introduced.

## What an alert would look like

Nothing here is a live pipeline: these are stored recordings, queried after the
fact. If they were streamed, the shape a rule would fire on is a record whose
`step` is a repository step, whose `destination` was not present in the same job's
previous run, and whose `detections` holds a label other than `flow` — three
fields, all above.

## What this data does not carry

- **Byte counts and connection timing.** Not recorded.
- **Command-line arguments.** Redacted at the sensor from v2.15.0 onward;
  `executable` is as far as provenance goes.
- **Source endpoint.** The runner is ephemeral, so it carries no durable meaning.
- **Non-network actions.** `outbound-connection` is the only action class in this
  export. File and process actions exist in the platform's detections but are not
  in these records except as `detections` labels.
- **macOS and Windows.** The sensor is eBPF. See `coverage.md`.
