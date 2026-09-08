# What this repository's CI actually did

This directory holds the recorded behaviour of this repository's CI, taken at the
kernel while the jobs ran, plus the tools to query it. It exists to answer four
questions about a change with recordings instead of opinions.

Every record is one **action** — today, one outbound connection — with the
**execution chain** behind it: the path from the runner's root process to the
process that performed the action, and the workflow step that owns it.

```
Runner.Worker → bash → docker → uv → pypi.org      step: Run Python SDK checks
```

## The four questions

| question | answer |
| --- | --- |
| How much of my CI can you cover? | [`coverage.md`](coverage.md) — per job, per runner, from one real run |
| Which parts of CI still egress, and why? | [`egress.md`](egress.md) and [`egress-allowlist.proposed.yaml`](egress-allowlist.proposed.yaml) |
| What do I pivot on during an incident? | [`incident-response.md`](incident-response.md) — the pivot and the field mapping |
| What would I hunt on this data? | [`hunts.md`](hunts.md) — queries and their first false positives |

## The data

| path | what it is |
| --- | --- |
| `evidence/actions.ndjson` | one JSON record per recorded action, one line each |
| `tools/export_actions.sql` | rebuilds that file from the platform's stored profiles |
| `tools/query.py` | queries it: burn-down, destinations, chains, comparisons, detections, allowlist |
| `tools/build_allowlist.py` | regenerates the allowlist proposal |
| `tools/coverage_ledger.py` | regenerates the coverage ledger from a run's own job list |
| `tools/hunt.sql` | cross-repository form of the hunts: four read-only queries over pull-request runs |
| `AGENTS.md` | how a coding agent should answer questions from this data |

## Querying it

```bash
python3 .garnet/tools/query.py burndown                    # coverage and class totals
python3 .garnet/tools/query.py destinations                # every destination, class, job, step
python3 .garnet/tools/query.py chains --destination pypi.org
python3 .garnet/tools/query.py compare --job python-sdk-install
python3 .garnet/tools/query.py detections
python3 .garnet/tools/query.py allowlist
```

`--job`, `--workflow`, `--destination`, `--commit`, `--run` and `--class` filter
every command.

## Rebuilding it

The evidence file comes from the platform's stored profiles for this repository:

```bash
PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=180s' \
  psql "host=127.0.0.1 port=5433 user=<you> dbname=jibril sslmode=disable" \
  -v org=garnet-labs -v repo=codex \
  -At -f .garnet/tools/export_actions.sql > .garnet/evidence/actions.ndjson

python3 .garnet/tools/build_allowlist.py > .garnet/egress-allowlist.proposed.yaml
python3 .garnet/tools/coverage_ledger.py <run-id> [<run-id> …]
psql … -v days=30 -v label=<label> -f .garnet/tools/hunt.sql
```

The same records are visible without a database: each one carries a `profile_url`
to the public Execution Profile for its job.
