#!/usr/bin/env python3
"""Atomically promote a generated dashboard under a bounded publication root."""
from __future__ import annotations

import argparse
import json
import shutil
import uuid
from pathlib import Path


REQUIRED_FILES = {"index.html", "current-snapshot.json", "raw-observations.json"}


def validate_source(source: Path, expected_repository: str | None = None,
                    expected_commit: str | None = None) -> dict:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("dashboard source must be a real directory")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"dashboard must not contain symlinks: {path.relative_to(source)}")
    source = source.resolve(strict=True)
    missing = sorted(name for name in REQUIRED_FILES if not (source / name).is_file())
    if missing:
        raise ValueError("dashboard is incomplete: " + ", ".join(missing))
    snapshot = json.loads((source / "current-snapshot.json").read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != "snapshot-v1" or snapshot.get("publishable") is not True:
        raise ValueError("refusing to publish an invalid snapshot")
    if expected_repository and snapshot.get("repository_identity") != expected_repository:
        raise ValueError("snapshot repository does not match the selected workflow run")
    if expected_commit and snapshot.get("commit_sha") != expected_commit:
        raise ValueError("snapshot commit does not match the selected workflow run")
    observations = json.loads((source / "raw-observations.json").read_text(encoding="utf-8"))
    displayed_findings = (len(snapshot.get("canonical_findings", [])) +
                          len(snapshot.get("ai_advisories", [])))
    if displayed_findings != snapshot.get("finding_count"):
        raise ValueError("snapshot finding count does not reconcile")
    if len(observations) != snapshot.get("observation_count"):
        raise ValueError("snapshot observation count does not reconcile")
    return snapshot


def publish(source: Path, root: Path, expected_repository: str | None = None,
            expected_commit: str | None = None) -> None:
    source = source.resolve(strict=True)
    root = root.resolve()
    if source == root or root in source.parents:
        raise ValueError("source must be outside the publication root")
    validate_source(source, expected_repository, expected_commit)
    root.mkdir(parents=True, exist_ok=True)
    transaction = uuid.uuid4().hex
    staging = root / f".staging-{transaction}"
    rollback = root / f".rollback-{transaction}"
    current = root / "current"
    previous = root / "previous"
    shutil.copytree(source, staging)
    moved_current = False
    try:
        if current.exists():
            current.rename(rollback)
            moved_current = True
        staging.rename(current)
    except BaseException:
        if moved_current and rollback.exists() and not current.exists():
            rollback.rename(current)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if previous.exists():
        shutil.rmtree(previous)
    if rollback.exists():
        rollback.rename(previous)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--publication-root", type=Path, required=True)
    parser.add_argument("--expected-repository")
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    publish(args.source, args.publication_root, args.expected_repository, args.expected_commit)


if __name__ == "__main__":
    main()
