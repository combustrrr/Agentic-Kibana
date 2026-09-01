#!/usr/bin/env python3
"""Create a validated, current full-codebase findings snapshot."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from monitoring import build_snapshot, canonicalize, load_json, write_json
except ModuleNotFoundError:  # package import in repository tests
    from scripts.code_analysis.monitoring import build_snapshot, canonicalize, load_json, write_json


def build_additional_channels(catalog: dict, artifacts: Path | None,
                              snapshot: dict) -> list[dict]:
    """Describe only additional lanes backed by current snapshot evidence."""
    status_by_family: dict[str, dict] = {}
    if artifacts and artifacts.is_dir():
        for status_file in sorted(artifacts.rglob("*-status.json")):
            try:
                status = load_json(status_file)
            except (OSError, ValueError):
                continue
            family = str(status.get("scanner_family") or "")
            if family:
                status_by_family[family] = status
    observations = snapshot.get("observations", [])
    observation_counts = Counter(str(row.get("scanner_family")) for row in observations)
    findings = [*snapshot.get("canonical_findings", []), *snapshot.get("ai_advisories", [])]
    rows = []
    for configured in catalog.get("tools", []):
        state = str(configured.get("state") or "")
        if state == "ACTIVE_REQUIRED":
            continue
        tool = str(configured.get("tool") or "Unknown")
        evidence_families = [tool, *map(str, configured.get("evidence_families") or [])]
        native = next((status_by_family.get(family, {}) for family in evidence_families
                       if status_by_family.get(family)), {})
        observed = sum(observation_counts.get(family, 0) for family in evidence_families)
        if not native and not observed:
            continue
        if native:
            status = str(native.get("status") or "UNKNOWN")
        else:
            status = "COMPLETED_OPTIONAL"
        rows.append({
            "tool": tool,
            "channel": str(configured.get("channel") or ""),
            "surface": str(configured.get("surface") or ""),
            "state": state,
            "status": status,
            "reason": str(native.get("reason") or configured.get("activation") or configured.get("note") or ""),
            "finding_count": sum(
                any(family in row.get("supporting_scanner_families", [])
                    for family in evidence_families) for row in findings
            ),
            "observation_count": observed,
            "evidence_source": "AI_ADVISORY" if tool == "CodeRabbit" else "DETERMINISTIC",
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-findings", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow-run-id", action="append", required=True)
    parser.add_argument("--channel-manifest", type=Path, required=True)
    parser.add_argument("--channel-status", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--tool-catalog", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run = {
        "commit_sha": args.commit,
        "branch": args.branch,
        "workflow_run_id": args.workflow_run_id[0],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    current = canonicalize(load_json(args.raw_findings), args.repository, run,
                           load_json(args.channel_manifest))
    provenance = load_json(args.provenance)
    provenance["workflow_run_ids"] = args.workflow_run_id
    snapshot = build_snapshot(current, load_json(args.channel_status), provenance)
    if args.tool_catalog:
        snapshot["additional_channels"] = build_additional_channels(
            load_json(args.tool_catalog), args.artifacts, snapshot
        )
    else:
        snapshot["additional_channels"] = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, snapshot)


if __name__ == "__main__":
    main()
