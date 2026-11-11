#!/usr/bin/env python3
"""
hashfiles.py — replication of GitHub Actions' hashFiles() expression.

The cache key rust-ci uses is
  argument-comment-lint-Linux-<CARGO_DYLINT_VERSION>-<DYLINT_LINK_VERSION>-hashFiles(a, b, c, d)
with CARGO_DYLINT_VERSION=DYLINT_LINK_VERSION=6.1.0 in the job env.
The attacker computes the same key from a plain checkout, no secrets
needed — that is what makes the poisoned entry match.

Algorithm (actions/runner expression SDK): for each pattern in order, glob
its files (sorted), and for each file update a single running sha256 with
the hex digest of the file's contents; the final digest is the result.
"""

import glob
import hashlib
import sys


def hash_files(patterns):
    h = hashlib.sha256()
    for pattern in patterns:
        paths = sorted(glob.glob(pattern))
        for path in paths:
            with open(path, "rb") as f:
                h.update(hashlib.sha256(f.read()).hexdigest().encode())
    return h.hexdigest()


if __name__ == "__main__":
    print(hash_files(sys.argv[1:]))
