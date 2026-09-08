# What still egresses, and why

Every recorded action in `evidence/actions.ndjson` is one outbound connection with
the process and workflow step behind it. That is what makes a burn-down possible:
a destination can be attributed to the work this repository asked for, or to the
machine the work ran on, and the two need different decisions.

## Classes

Attribution is structural. A chain owned by a named workflow step, or descending
from the runner's worker process, is this repository's work. A chain rooted in the
runner's own daemons with no step is the platform's. Names and addresses never
decide the class.

| class | whose decision it is |
| --- | --- |
| `workload` | this repository: a named step reached it |
| `container-runtime` | this repository, indirectly: the docker daemon pulled an image a step asked for |
| `actions-service` | GitHub's: the runner's own `node` process talking to the Actions service, cache and artifact storage |
| `dns-resolver` | nobody's: name resolution on the runner |
| `runner-substrate` | GitHub's: the runner agent and its telemetry |
| `azure-imds`, `azure-wireserver` | GitHub's hosting: instance metadata and the Azure agent channel |

```
class               actions  destinations  share
-------------------------------------------------
workload                496             6    51%
dns-resolver            266             2    28%
runner-substrate        118            34    12%
container-runtime        52            39     5%
azure-wireserver         15             1     2%
azure-imds               14             1     1%
actions-service           6             3     1%
-------------------------------------------------
total                   967            86   100%
```

967 recorded actions over 74 distinct destinations, from 35 job profiles across 21
runs and 19 commits of this repository. Half the actions are this repository's own
work, and they reach six destinations. Everything else is the machine: name
resolution, the runner agent, Azure hosting, the docker daemon, and the runner's
own action machinery.

Regenerate with `python3 .garnet/tools/query.py burndown`.

## The destinations to decide on

| destination | actions | reached by | why |
| --- | ---: | --- | --- |
| `github.com` | 216 | `cargo`, `cargo-binstall`, `cargo-deny`, `curl`, `git-remote-http` | crates.io index over git, plus release downloads |
| `dualstack.k.sni.global.fastly.net` | 157 | `cargo`, `cargo-binstall`, `cargo-fmt`, `just`, `rustup` | crates.io CDN for crate downloads |
| `release-assets.githubusercontent.com` | 69 | `cargo-binstall`, `curl` | release asset downloads for CI tools |
| `api.github.com` | 46 | `cargo-binstall`, `curl` | release lookup before those downloads |
| `pypi.org` | 7 | `uv`, `python3.12` | Python dependency install for the SDK |
| `cloudfront-index.crates.io` | 1 | `cargo-binstall` | crates.io sparse index |

Six destinations. Two package ecosystems, `crates.io` and PyPI, each reached
through its index and its CDN, plus GitHub for release binaries. That is the whole
list of internet destinations this repository's recorded CI work asked for.

Everything above is reachable from a named step, so each one is a decision a
repository owner can act on: the step is in the diff, and the destination is in the
recording.

`egress-allowlist.proposed.yaml` is that list as a proposal, regenerated from the
evidence by `tools/build_allowlist.py`, with the job, process and step that reached
each destination. It has not been applied to any enforcement point.

## The destinations not to allowlist

| class | destinations | actions | what it is |
| --- | ---: | ---: | --- |
| `dns-resolver` | 2 | 266 | `localhost` and `168.63.129.16` on port 53 |
| `runner-substrate` | 34 | 118 | the runner agent, `provjobd`, the hosted-compute watchdog and orchestrator |
| `container-runtime` | 39 | 52 | `dockerd` pulling the Python job's image: `registry-1.docker.io`, `auth.docker.io`, and 36 CDN addresses with no name resolved in the flow |
| `azure-wireserver` | 1 | 15 | `168.63.129.16` on port 32526 |
| `azure-imds` | 1 | 14 | `169.254.169.254` |
| `actions-service` | 3 | 6 | the runner's `node` process reaching the Actions service and its blob storage |

The container-registry names are the exception worth deciding on: three of them
resolve (`registry-1.docker.io`, `auth.docker.io`, one Docker Hub CDN name) and a
repository can allowlist those, because the image they pull is one the workflow
asked for. The 36 bare CDN addresses behind them cannot be allowlisted usefully.

Pinning these produces churn rather than control: the addresses rotate between
runs, and none of them is reachable from a line of this repository's YAML. They are
listed in the proposal under `runner_infrastructure` so that the burn-down is
complete rather than filtered.

## Next to the `openai/fence` audit already in this repository

`.github/workflows/blob-size-policy.yml` runs `openai/fence@v0.10.0` in `mode:
audit`. On this repository's runs its report lists a suggested allowlist of bare
addresses with the port and protocol, plus the runner process it attributes them
to, and whether each would have been blocked. That is the enforcement point's own
view: an address, and a decision about it.

The recording is the other half of the same question: which workflow step asked for
it, which process performed it, and which destination name it used. `pypi.org`
reached by `uv` under the Python install job is a rule a repository owner can
approve; `52.85.151.128` reached by `dockerd` is not, and the two are
indistinguishable from an address list alone.

One honest limit on the join: in the run recorded here the sensor failed to start
in the Blob size policy job itself (see [`coverage.md`](coverage.md)), so this is a
comparison of what each side reports about this CI, not two views of one job.

## The derived allowlist, enforced

`fence-allowlist.suggested.txt` is the burn-down turned into Fence's own syntax:
the destinations the `garnet` job's "Fetch locked Rust dependencies" step reached
in 10 of 10 recorded runs, each with the process that reached it and the
stability count as a comment. `tools/build_fence_allowlist.py` regenerates it
from the evidence.

The `fence-enforced` job in `blocking-ci.yml` runs the same dependency fetch with
`openai/fence` in `mode: block` and exactly that allowlist. On run
[33098634205](https://github.com/garnet-labs/codex/actions/runs/33098634205/job/98610081093)
it fetched all 1,211 crates green: Fence's own report shows `index.crates.io` and
`static.crates.io` allowed, nothing blocked, and an empty `suggested_allowlist` —
the record predicted the workload's egress exactly.

Running both agents inside one job did not hold up: with the sensor recording,
Fence's post-job check found its resident health evidence stale
([run 33098634205, `garnet` job](https://github.com/garnet-labs/codex/actions/runs/33098634205/job/98610081514)),
and in the job where Fence's check passed the sensor had failed to start. So the
join is two lanes of one workflow run — the sensor records the workload in the
`garnet` job, Fence enforces the derived allowlist on the identical workload in
`fence-enforced` — not one co-instrumented job.

## Reading the totals

A destination reached by processes in more than one class counts in each of them,
so the per-class destination counts sum to more than the distinct total. The action
counts do not overlap: every action has exactly one class.
