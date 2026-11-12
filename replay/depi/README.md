# Depi Codex Backdoor — Replay Through Garnet

> Prompt injection on the Codex issue labeler → CoreCLR debug-pipe sandbox escape →
> runtime-token theft via logs → cache poisoning → execution inside rust-ci →
> fake release → release-deletion booby trap → OIDC token capture
>
> Reconstructed from [Depi's disclosure](https://depi.security/blog/20261111-backdooring-codex/)
> (Worty & Madder, Nov 11 2026). Replayed on this fork, instrumented with
> Garnet Runtime Review (garnet-org/action v2.5.2), following the clinejection-poc
> replay pattern.

Everything runs inside `garnet-labs/codex`. Upstream `openai/codex` is never
referenced by any replay step. The memory read targets this replay's own
Runner.Worker; the "exfiltration" is this fork's own logs; the fake release is
created on this fork; there is no npm publish (this fork has no OIDC trust
policy, which is where the chain demonstrably ends).

## Stage map

| Stage | What happens | Where |
|---|---|---|
| 1 | Attacker opens the malicious issue; the injected prompt makes the issue-labeler agent run the payload; payload dumps Runner.Worker memory and prints token slices to the log; job sleeps | `garnet-depi-replay.yml` job `victim` |
| 2 | Attacker harvests the token from the victim's in-flight log (same run), computes rust-ci's cache key, plants the poisoned zstd tar through the Actions cache service with the stolen token, pushes the stage-3 trigger commit | `garnet-depi-replay.yml` job `attacker` |
| 3 | The trigger commit makes blocking-ci run the real rust-ci `argument_comment_lint` job: the poisoned cache restores, `test_depi.py` runs under Garnet during `python3 -m unittest discover` | real `.github/workflows/rust-ci.yml` |
| 4 | `test_depi.py` creates the fake release; after the harness PR merges, deleting the release fires `garnet-depi-booby-trap.yml` (id-token: write), which captures the OIDC JWT | real release event |

Run order: one push to `replay/depi/.trigger` (or one dispatch after merge) —
stages 1 and 2 run in parallel and stage 3 is triggered automatically. The
only manual steps left: merge the PR, then delete the fake `bot-*` release.

## Payload map

- `payload/diag.py` — the CoreCLR debug-pipe memory reader (session handshake,
  GET_DCB, ELF scan, link_map, libc GNU-hash `__environ` lookup, env dump,
  64-char log slices). The base64 blob in the issue body is this file,
  gzip+base64.
- `attacker/harvest_token.py` — polls the victim job's in-flight log (same
  run) and reassembles the token from the slices.
- `attacker/hashfiles.py` — `hashFiles()` replication for the cache key
  `argument-comment-lint-Linux-6.1.0-6.1.0-<hash>` (per-file sha256 raw
  digests into a running sha256, verified byte-identical against the key
  this fork's rust-ci printed on main).
- `attacker/cache_version.py` — the cache-lookup `version` string the
  victim's actions/cache@v5.0.4 computes (paths + `zstd-without-long` +
  salt, sha256).
- `attacker/test_depi.py` — the poisoned-cache payload: fires at import
  time under unittest discovery; fake release + booby-trap workflow
  planting attempt.

## Accuracy vs the real exploit

| Element | Source | Status |
|---|---|---|
| Entry workflow `issue-labeler.yml`, `allow-users: "*"`, issue title/body in prompt | this fork's pre-fix copy | exact |
| codex-action pin `5c3f4cc…` (v1.7) | this fork's pre-fix copy | exact |
| Injected issue body (prompt-closing prefix, diagnostic command, sleep instruction, expected-results text) | article | exact |
| Payload command shape (`base64 -d \| gunzip > /tmp/diag.py && python3 …`) | article | exact |
| CoreCLR debug transport v2.0 (48-byte header, types 0/1/4/6/9/10), DCB bootstrap, ELF/link_map/libc walk, GNU-hash `__environ`, env dump, token patterns | article | exact reconstruction |
| Base64 blob contents | redacted in article | reconstructed to identical behavior |
| Exfil channel: workflow logs, slices that survive masking | article | exact |
| Sleep keeping the runtime token valid | article (5000s) | shortened (default 420s) |
| Cache poison target key and sink job (rust-ci `argument_comment_lint`, dylint cache + `unittest discover`) | this fork's pre-fix copy | exact — key replication verified byte-identical against the key this fork's rust-ci printed on main (run 42969052505) |
| Cache-service protocol (reserve key+version, blob upload with `Content-Range`, commit with size) | actions/cache@v5.0.4 bundled toolkit | exact — endpoints, `zstd-without-long` lookup version and salt from the bundle; the poisoned tar is zstd with absolute member paths, matching the toolkit's `tar -xf -P -C` extraction |
| Poisoned file path `…/tools/argument-comment-lint/test_depi.py` | article | exact |
| Fake release script (git-trees workflow planting, `bot-` tag, publish PATCH) | article | exact attempt |
| Workflow planting via git trees with the job token | article | blocked by GitHub (job token) — pre-planted via this PR instead |
| npm publish with the OIDC token | article | not attempted — no trust policy on this fork; chain ends at JWT capture |
| Agent decision (prompt injection → shell) | article | simulated — fork has no `CODEX_OPENAI_API_KEY`; payload replayed exactly |
| Runtime token source inside the victim job | article (Runner.Worker memory) | exact — and load-bearing: the current runner image (20261101.360) exposes neither `ACTIONS_RUNTIME_TOKEN` nor `ACTIONS_CACHE_URL` in step env (verified by the stage-1 calibration probe), so the memory read is the only source; stage 2's own-token fallback does not exist and was removed |
| `gh` inside the poisoned rust-ci step | article (final script runs `gh api`) | the job token is likewise absent from step env, so `test_depi.py` performs its own debug-pipe memory read for `GITHUB_TOKEN` before running the release script |
| `github.repository == 'openai/codex'` gate on the labeler | this fork's copy | replaced by the stage-1 replay job |
| Cache poisoning choreography (two dispatched stage workflows, manual run-order timing) | — | replay-only; collapsed into one workflow with parallel victim/attacker jobs and an automatic stage-3 trigger commit |

## Garnet questions this replay answers

1. Does the Execution Profile record the debug-pipe `open()`/`read()` traffic
   (stage 1 has no egress at all — the token leaves through the logs)?
2. Does the `runner → python3 → unittest → gh api` chain inside rust-ci show up
   in the PR comment / Step Summary (stage 3)?
3. What do the detection labels (`show_detections: true`) fire on at each stage?

Findings live in `docs/garnet-detection-analysis.md` once the stages have run.
