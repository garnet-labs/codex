# What eight dependency updates actually did

This fork's open Dependabot pull requests are a real cohort: eight routine
dependency updates, each re-run on the instrumented CI on 2026-08-27 so Garnet
could record what the updated code executed. Every recorded update produced a
head-bound Runtime Review comment on its own PR. Two branches were refreshed
by merging `main` into the already-recorded bump commit, so their comments
compare the merged head against its immediate parent — two recorded runs of
the same updated dependency, before and after the refresh.

| PR | update | recorded head | comparison | what the record shows |
| --- | --- | --- | --- | --- |
| [#18](https://github.com/garnet-labs/codex/pull/18) | datamodel-code-generator 0.31.2 → 0.64.0 | `82bcc05` | vs `c0f5089` | 1 job changed +4 −4 destinations, 3 unchanged — every add/remove is runner-infrastructure IP churn; the workload's execution chains and destinations are unchanged |
| [#9](https://github.com/garnet-labs/codex/pull/9) | tar 0.4.44 → 0.4.46 | `6807425` | vs `cf24349` | 1 job changed +4 −4 destinations, 3 unchanged — same shape: runner IP churn only, workload unchanged |
| [#8](https://github.com/garnet-labs/codex/pull/8) | openssl 0.10.75 → 0.10.80 | `de2baab` | none recorded | snapshot: 4 jobs, 29 destinations, all expected workload and runner destinations |
| [#5](https://github.com/garnet-labs/codex/pull/5) | rustls-webpki 0.103.10 → 0.103.13 | `d55ee02` | none recorded | snapshot: 4 jobs, 22 destinations, all expected |
| [#3](https://github.com/garnet-labs/codex/pull/3) | actix-http 3.11.2 → 3.12.1 | `59e800f` | none recorded | snapshot: 4 jobs, 24 destinations, all expected |
| [#2](https://github.com/garnet-labs/codex/pull/2) | rand 0.9.2 → 0.9.3 | — | — | not refreshable: the branch's `Cargo.lock` conflicts with main, so no instrumented run exists |
| [#7](https://github.com/garnet-labs/codex/pull/7) | rmcp 0.15.0 → 1.4.0 | — | — | not refreshable: `Cargo.lock` conflict |
| [#10](https://github.com/garnet-labs/codex/pull/10) | opentelemetry_sdk 0.31.0 → 0.32.1 | — | — | not refreshable: `^0.31` cannot resolve against the available 0.32.1 |

"Snapshot" means the head commit is recorded but its previous commit is not, so
the comment shows what ran without a diff. "Not refreshable" means no recorded
run exists for the branch, so its runtime behavior is undeterminable — not
clean.

## The base rate

Across the five recorded updates — 20 job recordings, and two before/after
comparisons — no update introduced a new workload destination or a new
execution chain in the workload. Everything that moved between commits
was GitHub's own runner infrastructure rotating addresses, and the comments
attribute that churn to the runner background, not to the changed dependency.

That is the number a reviewer needs before trusting the signal: on this
repository's routine dependency traffic the record is quiet, so the day a
bumped crate's build script opens a connection to somewhere new, the diff that
names it is the only changed thing on the page.
