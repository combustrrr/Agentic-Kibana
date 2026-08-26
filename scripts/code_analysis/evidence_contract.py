#!/usr/bin/env python3
"""Attest retained scanner evidence to one repository, commit, and workflow set."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(manifest: dict, artifacts: Path, repository: str, commit: str,
          workflow_run_ids: list[str]) -> dict:
    channels = []
    for configured in manifest["required_static_channels"]:
        files = sorted({path for pattern in configured["artifact_patterns"]
                        for path in artifacts.rglob(pattern) if path.is_file()})
        channels.append({
            "channel": configured["channel"],
            "scanner_family": configured["scanner_family"],
            "status": "EVIDENCE_RETAINED" if files else "MISSING",
            "artifacts": [{"path": path.relative_to(artifacts).as_posix(),
                           "sha256": file_hash(path)} for path in files],
        })
    return {
        "schema_version": "scanner-evidence-contract-v1",
        "repository_identity": repository,
        "commit_sha": commit,
        "workflow_run_ids": workflow_run_ids,
        "channels": channels,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow-run-id", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = build(manifest, args.artifacts, args.repository, args.commit,
                   args.workflow_run_id)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
