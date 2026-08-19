# Garnet Runtime Evidence — PR #15 (openssl 0.10.75 → 0.10.80)

This file is a head-SHA-bound runtime receipt for this PR's instrumented CI
job. It is generated from kernel-level recording (Garnet / Jibril eBPF sensor)
of the actual workflow execution — not from static analysis of the diff.

## Recorded run

| Field | Value |
| --- | --- |
| Workflow / job | `blocking-ci` / `cargo-deny` |
| Run | <https://github.com/garnet-labs/codex/actions/runs/32201470892> |
| Execution Profile (receipt) | <https://app.garnet.ai/public/runs/32201470892?profile=01a0176e-9925-7d0a-a940-debfc6e4c20c> |
| Recorded commit | `c13fe5ab3d57a2309481c217898948b416325d78` (this PR's openssl bump) |
| Baseline commit | `6167b0f1701975690e6b05e566f4bc31221271bd` (pre-bump scaffolding commit on this branch) |
| Recorded at | 2026-08-19 00:31:59 UTC |
| Scope | 31 execution chains · 11 network destinations · kinds: network |
| Job conclusion | `Run cargo-deny` step failed on both baseline and bump runs (pre-existing advisory/policy state; not introduced by this bump). Recording covers the full execution regardless. |

## Execution diff (baseline vs this PR)

```diff
@@ 6167b0f (previous) vs c13fe5a (current) @@
  systemd
  ├─ dockerd
+ │  ├─ ○ 100.49.151.0
- │  ├─ ○ 23.21.246.185
+ │  ├─ ○ 23.21.28.55
- │  ├─ ○ 3.167.56.67
+ │  ├─ ○ 3.169.173.32
+ │  ├─ ○ 3.169.173.6
- │  └─ ○ 54.144.20.148
  ├─ hosted-compute-
- │  ├─ ○ 140.82.112.24
- │  ├─ ○ 140.82.113.23
  │  └─ ○ localhost (dns resolver)
  ├─ containerd-shim-runc-v2
  │  └─ containerd-shim-runc-v2
  │     └─ cargo-deny
  │        └─ cargo (step: "Run cargo-deny")
  │           └─ ○ 168.63.129.16
  ├─ containerd-shim
  │  └─ entrypoint.sh
  │     └─ cargo-deny (step: "Run cargo-deny")
  │        ├─ cargo
  │        │  └─ ○ dualstack.k.sni.global.fastly[.]net
  │        └─ ○ github[.]com
  └─ systemd-network
     └─ ○ ip6-allrouters

  Runner.Worker
  └─ bash
     └─ bash
        ├─ cargo-binstall (step: "Check for a clean worktree")
        │  └─ ○ api.github[.]com
        └─ bash
           └─ curl (step: "Check for a clean worktree")
              └─ ○ release-assets.githubusercontent[.]com
```

Legend: names on the path = processes · `○` = observed action ·
`+` only in the current record · `-` only in the previous record.

## Attribution

**Build/test-tooling chains** (`cargo-deny` → `cargo`, `cargo-binstall`,
`curl` in check-clean-worktree):

- Destinations observed: `github.com`, `api.github.com`,
  `release-assets.githubusercontent.com`, `dualstack.k.sni.global.fastly.net`
  (crates.io CDN), `168.63.129.16` (Azure host wireserver).
- Delta vs baseline: **none**. No new process chains and no new outbound
  destinations are rooted in cargo, cargo-deny, build scripts, or the updated
  `openssl`/`openssl-sys` crates.

**Runner-platform chains** (`dockerd`, `hosted-compute-*`,
`systemd-network`):

- All of the +4/−5 destination churn in this comparison happens here
  (CDN IP rotation under `dockerd`; GitHub control-plane addresses
  `140.82.112.24` / `140.82.113.23` present only in the baseline record).
- Classification: GitHub-hosted runner platform behavior — not attributable
  to this PR.

## Machine-readable summary

```json
{
  "contract": "6.10.0",
  "recorded_commit": "c13fe5ab3d57a2309481c217898948b416325d78",
  "baseline_commit": "6167b0f1701975690e6b05e566f4bc31221271bd",
  "jobs_recorded": 1,
  "chains": 31,
  "destinations_total": 11,
  "destinations_added": 4,
  "destinations_removed": 5,
  "build_tooling_destination_delta": 0,
  "build_tooling_process_delta": 0,
  "platform_attributed_churn": 9,
  "verdict": "no build-attributable runtime delta"
}
```

## Staleness rule

This evidence is bound to recorded commit `c13fe5a`. Commits on this branch
after that SHA touch only `AGENTS.md` and `.garnet/**` (review metadata), so
the recorded run remains representative of the code change under review.
Garnet re-records on every push; the latest live comparison is in the
`garnet-runtime-review` PR comment bound to the current head SHA.
