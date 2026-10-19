# Answering questions about what CI did

`evidence/actions.ndjson` holds one record per recorded action from this
repository's CI, with the execution chain behind it and the workflow step that owns
it. Query it with `tools/query.py`; do not hand-read the file.

```bash
python3 .garnet/tools/query.py burndown
python3 .garnet/tools/query.py destinations
python3 .garnet/tools/query.py chains --destination pypi.org
python3 .garnet/tools/query.py compare --job python-sdk-install
python3 .garnet/tools/query.py detections
python3 .garnet/tools/query.py allowlist
```

`--job`, `--workflow`, `--destination`, `--commit`, `--run` and `--class` filter
every command.

## Rules for answering

Say `no matching records in the queried scope` when a query returns nothing.
Absence here means the action was not recorded, not that it did not happen: do not
fill the gap by reasoning from the workflow files.

A record with no `step` was not attributed to a workflow step by the recording.
Report it that way rather than guessing which step is responsible.

Before answering "did anything reach X", check whether the job in question is
recorded at all. `coverage.md` has the ledger: the macOS and Windows jobs carry no
sensor, and the self-hosted jobs in this fork never acquire a runner.

`compare` is meaningful only as a pair. Quote both runs and both commits when
reporting what a change introduced, and say whether the pair is the head commit
against the commit before it or against the base.

Detections are labels, not verdicts. `flow` marks a plain recorded connection.
Report a label with the step and process that carry it.

## Vocabulary

An **execution chain** is one path from the runner's root process to an **action**.
Today's action class is the **outbound connection**. A **destination** is where an
outbound connection went. Chains end in actions, not in destinations.
