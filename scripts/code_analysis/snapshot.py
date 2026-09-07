#!/usr/bin/env python3
"""Create a validated, current full-codebase findings snapshot."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from monitoring import build_snapshot, canonicalize, load_json, write_json
except ModuleNotFoundError:  # package import in repository tests
    from scripts.code_analysis.monitoring import build_snapshot, canonicalize, load_json, write_json


CLASSES = {"code", "security", "dependencies", "infrastructure", "reliability"}
COMPLETE_STATUSES = {"COMPLETED", "CONFIGURED_COMPLETE", "COMPLETED_OPTIONAL", "POLICY_FINDINGS"}


def build_analysis_channels(catalog: dict, artifacts: Path | None,
                            snapshot: dict) -> list[dict]:
    """Assemble one catalog-ordered inventory; absent evidence is never a clean zero."""
    configured_channels = catalog.get("tools", [])
    identities = [row.get("channel") for row in configured_channels]
    if not identities or any(not value for value in identities) or len(set(identities)) != len(identities):
        raise ValueError("analysis catalog requires unique nonempty channel identities")
    if any(row.get("class") not in CLASSES for row in configured_channels):
        raise ValueError("analysis catalog contains an unknown channel class")
    gate_rows = snapshot.get("channel_status", [])
    gate_by_id = {row.get("channel"): row for row in gate_rows if row.get("channel")}
    gate_by_family = {row.get("scanner_family"): row for row in gate_rows}
    configured_families = {row["tool"] for row in configured_channels}
    if any(row.get("channel") not in identities and row.get("scanner_family") not in configured_families for row in gate_rows):
        raise ValueError("publication channel is missing from the analysis catalog")
    native_by_family = {}
    if artifacts and artifacts.is_dir():
        for status_file in sorted(artifacts.rglob("*-status.json")):
            try:
                native = load_json(status_file)
            except (OSError, ValueError):
                continue
            if isinstance(native, dict) and native.get("scanner_family"):
                native_by_family[str(native["scanner_family"])] = (
                    native, status_file.relative_to(artifacts).as_posix())
    observations_by_family = {}
    for observation in snapshot.get("observations", []):
        observations_by_family.setdefault(observation.get("scanner_family"), []).append(observation)
    findings_by_family = {}
    for index, finding in enumerate([*snapshot.get("canonical_findings", []), *snapshot.get("ai_advisories", [])]):
        for family in finding.get("supporting_scanner_families", []):
            findings_by_family.setdefault(family, set()).add(index)
    rows = []
    for configured in configured_channels:
        name = configured["tool"]
        families = list(dict.fromkeys([name, *configured.get("evidence_families", [])]))
        gate = gate_by_id.get(configured["channel"]) or gate_by_family.get(name)
        native, status_artifact = next((native_by_family[family] for family in families
                                       if family in native_by_family), ({}, None))
        observations = [row for family in families for row in observations_by_family.get(family, [])]
        finding_ids = set().union(*(findings_by_family.get(family, set()) for family in families))
        status = str(gate["status"] if gate else native.get("status") or
                     ("COMPLETED_OPTIONAL" if observations else "NOT_AVAILABLE"))
        reason = str((gate or {}).get("reason") or native.get("reason") or "")
        if not gate and not native and not observations:
            reason = "No retained evidence for this exact snapshot"
        rows.append({
            "channel": configured["channel"], "name": name,
            "class": configured["class"], "surface": configured.get("surface", ""),
            "status": status,
            "findings": len(finding_ids) if finding_ids or status in COMPLETE_STATUSES else None,
            "observation_count": len(observations),
            "observation_ids": [row["observation_id"] for row in observations],
            "reason": reason,
            "workflow": configured.get("workflow") or (gate or {}).get("workflow"),
            "artifact_files": list(gate.get("artifact_files", [])) if gate else None,
            "status_artifact": status_artifact,
            "evidence_source": configured.get("evidence_source", "DETERMINISTIC"),
            "test_exit_code": native.get("test_exit_code"),
            "coverage_exit_code": native.get("coverage_exit_code"),
        })
    return rows


def build_analysis_snapshot(snapshot: dict, catalog: dict, artifacts: Path | None = None) -> dict:
    """Version the published contract: one observation inventory plus a separate gate."""
    channels = build_analysis_channels(catalog, artifacts, snapshot)
    gate_ids = [next(row["channel"] for row in channels
                     if row["channel"] == gate.get("channel") or row["name"] == gate.get("scanner_family"))
                for gate in snapshot.get("channel_status", [])]
    result = {key: value for key, value in snapshot.items()
              if key not in {"channel_status", "additional_channels"}}
    result.update({
        "schema_version": "snapshot-v2",
        "snapshot_id": str(snapshot["snapshot_id"]).replace("snapshot-v1:", "snapshot-v2:", 1),
        "analysis_channels": channels,
        "analysis_channel_count": len(channels),
        "publication_gate": {"policy": "static-evidence-v1", "channel_ids": gate_ids,
                             "satisfied": snapshot.get("publishable") is True},
    })
    return result


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
    parser.add_argument("--tool-catalog", type=Path, default=Path(__file__).resolve().parents[2] / "config/code-analysis/proposal-tool-catalog.json")
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
    snapshot = build_analysis_snapshot(snapshot, load_json(args.tool_catalog), args.artifacts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, snapshot)


if __name__ == "__main__":
    main()
