# Hunting over recorded CI behavior

Recorded CI behavior is a hunting surface, and pull requests on public
repositories are the part of it that anyone can contribute to. This page shows
what a hunt over that data looks like, run over real recordings, and where the
false positives are — because a hunt that nobody has burned down yet is not a
hunt, it is an alert queue.

Two surfaces answer these queries. `evidence/actions.ndjson` in this directory
covers this repository and needs nothing but `python3`. The Garnet platform holds
the same records for every repository it runs in, and `tools/hunt.sql` is the
cross-repository form of the queries below — four read-only queries, scoped to
`pull_request` runs in a window you pass in.

Every cross-repository number on this page came from running it against the read
replica on 2026-08-27 with `-v days=30`.

## Hunt 1 — a dependency install reaching a destination it never reached before

The install command did not change; the lockfile did. Ask what moved:

```
$ python3 .garnet/tools/query.py compare --job python-sdk-install
```

This is the same question a reviewer asks about a version bump, and it is the
cheapest hunt in the set, because it needs no rules and no baseline of known-bad
destinations. It only needs the previous commit's recording.

## Hunt 2 — package managers that spawn a shell

An install script running during dependency resolution is the shape of most
public supply-chain incidents. In the recordings it appears as a chain whose
process is a shell under a package manager, and the platform labels it
`interpreter_shell_spawn`:

```
$ python3 .garnet/tools/query.py detections
```

Cross-repository, the same question is query 1 of `tools/hunt.sql`. Over the 30
days to 2026-08-27, counting only `pull_request` runs, the top of that list is:

| label | actions | repositories | runs |
| --- | ---: | ---: | ---: |
| `interpreter_shell_spawn` | 19,216 | 27 | 1,642 |
| `exec_from_unusual_dir` | 11,588 | 28 | 1,758 |
| `credentials_files_access` | 6,134 | 23 | 995 |
| `global_shlib_modification` | 5,426 | 4 | 136 |
| `package_repo_config_modification` | 5,367 | 3 | 127 |

None of these is an incident on its own: `cargo`, `bun`, `uv`, `poetry` and
`cargo-binstall` all spawn shells and exec from build directories during normal
work. The value is not the label, it is the label plus the destination plus which
step owns it, which is what the next hunt uses.

One recording detail that matters when reading these counts: labels attach to the
recorded row, and one row commonly carries several. The counts are labelled
actions, not distinct incidents.

## Hunt 3 — the same chain that egressed also touched credentials

One label is noise. Two labels on the same execution chain narrow it hard. In this
repository's recordings, `credentials_files_access` sits on chains that also made
outbound connections, and it concentrates in the Rust toolchain: `cargo` under
`Fetch locked Rust dependencies` and under the `cargo-deny` action, then `rustup`
and `cargo-binstall`. A smaller set of rows sits on runner processes such as
`sudo` and `hosted-compute-agent`, outside any workflow step.

Which file was read is not in this export; that detail lives in the detection
record behind the profile link. What this export does give you is the step that
owns the chain, which is what decides whether a hit is explained or escalated:

```
$ python3 .garnet/tools/query.py detections
$ python3 .garnet/tools/query.py chains --destination github.com
```

## Hunt 4 — labels that should be rare, ranked by how rare they are

The labels that appear in the fewest repositories are where a hunt should start.
That is query 2 of `tools/hunt.sql`, same window and same `pull_request` scope:

| label | repositories | actions | where |
| --- | ---: | ---: | --- |
| `auth_logs_tamper` | 1 | 654 | `garnet-org/control-plane` |
| `webserver_shell_exec` | 1 | 15 | one LiteLLM fork |
| `webserver_exec` | 1 | 15 | one LiteLLM fork |
| `binary_self_deletion` | 1 | 14 | `garnet-org/action-testing` |
| `environ_read_from_procfs` | 1 | 3 | one LiteLLM fork |
| `crypto_miner_execution` | 1 | 2 | one LiteLLM fork |
| `dropip` | 2 | 115 | `garnet-org/action-testing`, a reference repository |
| `net_suspicious_tool_exec` | 3 | 18 | test repositories and one PostHog fork |

Query 3 drills into one label and returns the chain, the step and a profile link.
For `crypto_miner_execution` in this window it returns one run of one repository,
and the row that carries the label alone is a shell under `7. Run tests` reaching
`raw.githubusercontent.com`. That is a fetch-and-run shape worth a look, in a
fork of a project whose tests do exactly that, which is why the output of a hunt
is a question and not a verdict.

Read plainly: in this window the rare labels concentrate in repositories that exist
to trigger detections and in one contributor's forks. The hunt's first product is
that exclusion list, and its second is the small number of rows left over.

## The false positive you will find first

`code_modification_through_procfs` carries 3,316 actions across 13 repositories in
the window, and in several of them it resolves to chains with no named process
reaching GitHub's own `140.82.112.0/20` addresses — the hosted runner agent, not
the repository's work. Any hunt over this data needs the same split
`egress.md` uses: a chain owned by a workflow step is the repository's behavior,
and a chain owned by the runner is the platform's. Rank by the first and the
volume becomes workable.

## What this data does not support

There is no field in these recordings that says whether a repository is public or
private, so "hunt public repositories" is answered by filtering to the repositories
you know are public, not by a query. Nothing here is a live detection pipeline
either: these are queries over stored recordings, run after the fact.
