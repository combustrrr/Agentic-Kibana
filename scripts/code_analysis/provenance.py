#!/usr/bin/env python3
"""Create deterministic exact-commit artifact provenance."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def build(root: Path, commit: str, workflow_run_ids: list[str]) -> dict:
    hashes = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        hashes.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    if not hashes:
        raise ValueError("no scanner artifacts were retained")
    return {"schema_version": "snapshot-provenance-v1", "commit_sha": commit,
            "workflow_run_ids": workflow_run_ids, "artifact_hashes": hashes}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow-run-id", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(build(args.artifacts, args.commit, args.workflow_run_id),
                                           indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
