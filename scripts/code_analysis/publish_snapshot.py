#!/usr/bin/env python3
"""Atomically promote a generated dashboard under a bounded publication root."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


REQUIRED_FILES = {"index.html", "current-snapshot.json", "raw-observations.json"}


def publish(source: Path, root: Path) -> None:
    source = source.resolve(strict=True)
    root = root.resolve()
    if source == root or root in source.parents:
        raise ValueError("source must be outside the publication root")
    missing = sorted(name for name in REQUIRED_FILES if not (source / name).is_file())
    if missing:
        raise ValueError("dashboard is incomplete: " + ", ".join(missing))
    snapshot = json.loads((source / "current-snapshot.json").read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != "snapshot-v1" or snapshot.get("publishable") is not True:
        raise ValueError("refusing to publish an invalid snapshot")
    root.mkdir(parents=True, exist_ok=True)
    staging = root / ".staging"
    current = root / "current"
    previous = root / "previous"
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(source, staging)
    if previous.exists():
        shutil.rmtree(previous)
    if current.exists():
        current.rename(previous)
    staging.rename(current)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--publication-root", type=Path, required=True)
    args = parser.parse_args()
    publish(args.source, args.publication_root)


if __name__ == "__main__":
    main()
