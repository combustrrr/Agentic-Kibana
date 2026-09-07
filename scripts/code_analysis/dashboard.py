#!/usr/bin/env python3
"""Generate the bounded, read-only current findings dashboard."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_snapshot(snapshot: dict, *, allow_partial: bool = False) -> None:
    if snapshot.get("schema_version") != "snapshot-v2" or (not allow_partial and snapshot.get("publishable") is not True):
        raise ValueError("dashboard requires a publishable snapshot-v2 document")
    if "channel_status" in snapshot or "additional_channels" in snapshot:
        raise ValueError("snapshot-v2 cannot contain split channel inventories")
    channels = snapshot.get("analysis_channels")
    if not isinstance(channels, list) or not channels:
        raise ValueError("snapshot requires all analysis channels")
    if snapshot.get("analysis_channel_count") != len(channels):
        raise ValueError("analysis channel count does not reconcile")
    identities = [row.get("channel") for row in channels]
    if any(not value for value in identities) or len(identities) != len(set(identities)):
        raise ValueError("analysis channel identities must be unique")
    for row in channels:
        count = row.get("findings")
        if row.get("class") not in {"code", "security", "dependencies", "infrastructure", "reliability"}:
            raise ValueError("unknown analysis channel class")
        if not row.get("name") or not row.get("status"):
            raise ValueError("analysis channel metadata is incomplete")
        if count is not None and (type(count) is not int or count < 0):
            raise ValueError("invalid channel finding count")
    gate = snapshot.get("publication_gate", {})
    if gate.get("policy") != "static-evidence-v1":
        raise ValueError("unsupported publication policy")
    if not gate.get("channel_ids") or (not allow_partial and gate.get("satisfied") is not True):
        raise ValueError("publication gate is not satisfied")
    by_id = {row["channel"]: row for row in channels}
    if any(identity not in by_id for identity in gate["channel_ids"]):
        raise ValueError("publication gate references unknown channels")
    if (not allow_partial or gate.get("satisfied") is True) and any(
            by_id[identity]["status"] != "COMPLETED" for identity in gate["channel_ids"]):
        raise ValueError("publication gate evidence is incomplete")
    findings = snapshot.get("canonical_findings", [])
    advisories = snapshot.get("ai_advisories", [])
    observations = snapshot.get("observations", [])
    observations_by_id = {row["observation_id"]: row for row in observations}
    channel_observation_ids = []
    for channel in channels:
        ids = channel.get("observation_ids")
        if not isinstance(ids, list) or channel.get("observation_count") != len(ids):
            raise ValueError("channel observation count does not reconcile")
        if any(identity not in observations_by_id for identity in ids):
            raise ValueError("channel references unavailable observation evidence")
        channel_observation_ids.extend(ids)
    if len(channel_observation_ids) != len(set(channel_observation_ids)):
        raise ValueError("an observation cannot belong to multiple analysis channels")
    if set(channel_observation_ids) != set(observations_by_id):
        raise ValueError("analysis channels do not account for every observation")
    if snapshot.get("finding_count") != len(findings) + len(advisories):
        raise ValueError("snapshot finding count does not reconcile")
    if snapshot.get("observation_count") != len(observations):
        raise ValueError("snapshot observation count does not reconcile")


def github_summary(snapshot: dict) -> str:
    validate_snapshot(snapshot)
    severities = Counter(row.get("severity", "UNKNOWN") for row in snapshot["canonical_findings"])
    all_channels = snapshot["analysis_channels"]
    covered_statuses = {"COMPLETED", "CONFIGURED_COMPLETE", "COMPLETED_OPTIONAL"}
    covered = sum(row.get("status") in covered_statuses for row in all_channels)
    lines = ["## Issue Wall — Web of Scanners", "",
             f"- **Snapshot commit:** `{snapshot['commit_sha']}`",
             f"- **Analysis coverage:** {covered}/{len(all_channels)} channels",
             f"- **Canonical findings:** {snapshot['finding_count']:,}",
             f"- **Raw observations:** {snapshot['observation_count']:,}",
             f"- **AI advisories:** {snapshot['ai_advisory_count']:,}",
             f"- **Channels incomplete or unavailable:** {len(all_channels) - covered}",
             "- **Mode:** read-only; no Issues, patches, comments, history, or remediation",
             "- **Offline launch:** download and extract the artifact, then open `dashboard/index.html`", "",
             "| Severity | Findings |", "|---|---:|",
             *[f"| {key} | {value:,} |" for key, value in sorted(severities.items())]]
    return "\n".join(lines) + "\n"


def artifact_readme(snapshot: dict) -> str:
    """Return the offline-first launch guide shipped beside Issue Wall."""
    validate_snapshot(snapshot)
    return "\n".join([
        "# Start here — Issue Wall",
        "",
        "This is the read-only developer portal for the Web of Scanners.",
        "",
        "1. Extract the complete GitHub Actions artifact.",
        "2. Open `dashboard/index.html` in a modern browser.",
        "3. Start with Snapshot health and Risk posture, then explore Issue discovery.",
        "4. Use Issue Wall, filters, CSV export, and the Evidence Graph to investigate.",
        "5. Inspect Channel Observatory, Workflow Provenance, and Snapshot Proof.",
        "",
        "## Two-minute review walkthrough",
        "",
        "1. Confirm the repository, branch and commit; expand Snapshot details for the full SHA.",
        "2. Review Observation Health across all analysis channels and the Critical/High Issue Wall.",
        "3. Open the first Actionable Issue and follow its immutable source link.",
        "4. Expand supporting scanner evidence and Snapshot integrity/source proof.",
        "5. Toggle all priorities only if Low/informational notes are requested.",
        "",
        f"- Repository: `{snapshot['repository_identity']}`",
        f"- Branch: `{snapshot['branch']}`",
        f"- Exact commit: `{snapshot['commit_sha']}`",
        f"- Canonical findings: {snapshot['finding_count']:,}",
        f"- Raw observations: {snapshot['observation_count']:,}",
        f"- Snapshot ID: `{snapshot['snapshot_id']}`",
        "",
        "Keep the files together. Issue Wall is self-contained and does not require a local server.",
        "The JSON downloads are evidence records, not instructions to execute scanner output.",
        "",
    ])


def generate(snapshot: dict, output: Path) -> None:
    """Render the current UI from the separately reviewable static template."""
    validate_snapshot(snapshot)
    payload = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    template = Path(__file__).with_name("dashboard_template.html").read_text(encoding="utf-8")
    output.write_text(template.replace("__PAYLOAD__", payload), encoding="utf-8")


def write_dashboard(snapshot: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generate(snapshot, output_dir / "index.html")
    (output_dir / "current-snapshot.json").write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "raw-observations.json").write_text(json.dumps(snapshot["observations"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "github-summary.md").write_text(github_summary(snapshot), encoding="utf-8")
    (output_dir / "START_HERE.md").write_text(artifact_readme(snapshot), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    write_dashboard(load(args.snapshot), args.output_dir)


if __name__ == "__main__":
    main()
