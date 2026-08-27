#!/usr/bin/env python3
"""Check relative Markdown links and file-like inline references."""

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
INLINE_REFERENCE = re.compile(r"`([^`\n]+)`")
FILE_SUFFIXES = (
    ".md",
    ".ndjson",
    ".py",
    ".sql",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".lock",
)


def relative_target(value):
    target = value.strip().strip("<>")
    if not target or target.startswith("#"):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    return unquote(parsed.path)


def looks_like_file(value):
    if value.startswith(("./", "../", ".garnet/", "evidence/", "tools/")):
        return True
    return value.endswith(FILE_SUFFIXES)


def check_file(source, target):
    base = REPOSITORY if target.startswith(".github/") else source.parent
    path = (base / target).resolve()
    if path.exists():
        return None
    return f"{source.relative_to(ROOT)}: {target} -> {path.relative_to(ROOT.parent)}"


def main():
    broken = []
    for source in sorted(ROOT.rglob("*.md")):
        text = source.read_text()
        for match in MARKDOWN_LINK.finditer(text):
            target = relative_target(match.group(1))
            if target is not None:
                problem = check_file(source, target)
                if problem:
                    broken.append(problem)
        for match in INLINE_REFERENCE.finditer(text):
            target = relative_target(match.group(1))
            if target is not None and looks_like_file(target):
                problem = check_file(source, target)
                if problem:
                    broken.append(problem)

    if broken:
        for problem in sorted(set(broken)):
            print(f"broken: {problem}")
        return 1
    print(f"checked {len(list(ROOT.rglob('*.md')))} markdown files: no broken references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
