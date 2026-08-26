#!/usr/bin/env python3
"""Validate required channels against an exact-commit evidence contract."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def build(manifest: dict, artifacts: Path, findings: list[dict] | None = None,
          contract: dict | None = None, repository: str | None = None,
          commit: str | None = None) -> dict:
    counts = Counter(str(row.get("source_tool") or "Unknown")
                     for row in (findings or []))
    if contract is not None:
        if contract.get("schema_version") != "scanner-evidence-contract-v1":
            raise ValueError("scanner evidence contract is missing or unsupported")
        if repository and contract.get("repository_identity") != repository:
            raise ValueError("scanner evidence repository does not match")
        if commit and contract.get("commit_sha") != commit:
            raise ValueError("scanner evidence commit does not match")

    contracted = {row.get("channel"): row
                  for row in (contract or {}).get("channels", [])}
    channels = []
    for configured in manifest["required_static_channels"]:
        files = sorted({
            path.relative_to(artifacts).as_posix()
            for pattern in configured["artifact_patterns"]
            for path in artifacts.rglob(pattern)
            if path.is_file()
        })
        attestation = contracted.get(configured["channel"], {})
        expected = {row.get("path"): row.get("sha256")
                    for row in attestation.get("artifacts", [])}
        hashes_valid = bool(files) and set(files) == set(expected)
        if hashes_valid:
            for relative in files:
                actual = hashlib.sha256((artifacts / relative).read_bytes()).hexdigest()
                if actual != expected[relative]:
                    hashes_valid = False
                    break
        completed = (attestation.get("status") == "EVIDENCE_RETAINED" and
                     hashes_valid)
        channels.append({
            **configured,
            "status": "COMPLETED" if completed else "INVALID_EVIDENCE",
            "artifact_files": files,
            "finding_count": counts.get(str(configured["scanner_family"]), 0),
        })
    return {"schema_version": "1", "channels": channels,
            "analysis_change_flags": []}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--evidence-contract", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    findings = (json.loads(args.findings.read_text(encoding="utf-8"))
                if args.findings else [])
    contract = json.loads(args.evidence_contract.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = build(manifest, args.artifacts, findings, contract,
                   args.repository, args.commit)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    invalid = [row["channel"] for row in result["channels"]
               if row["status"] != "COMPLETED"]
    if invalid:
        raise SystemExit("required scanner channels invalid: " + ", ".join(invalid))


if __name__ == "__main__":
    main()
