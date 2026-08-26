#!/usr/bin/env python3
"""Build canonical monitoring evidence and compare it with accepted history."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "2"
IDENTITY_VERSION = "sid-v1"
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
TRIAGE_STATES = {"UNREVIEWED", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DEFERRED"}

def check_key(repository: str, commit: str, name: str = "Code Analysis Dashboard",
              namespace: str = "agentic-soc-static-monitoring-v1") -> str:
    return "\0".join((repository, commit, name, namespace))


class EvidenceError(ValueError):
    """Raised when evidence cannot support a trustworthy comparison."""


def canonical_text(value: Any) -> str:
    return unicodedata.normalize("NFC", str(value if value not in (None, "") else "<NONE>"))


def canonical_path(value: Any) -> str:
    path = canonical_text(value).replace("\\", "/").removeprefix("./")
    return re.sub(r"/+", "/", path)


def normalized_anchor(finding: dict[str, Any]) -> str:
    snippet = re.sub(r"\s+", " ", str(finding.get("code_snippet") or "").strip())
    start_col = int(finding.get("start_col") or 0)
    column = f"\0column:{start_col}" if start_col else ""
    if snippet:
        # Location disambiguates repeated identical statements; drift matching compares
        # the retained statement and can still classify a unique line shift as MOVED.
        return canonical_text(
            f"line:{int(finding.get('start_line') or 0)}\0snippet:{snippet}{column}")
    # Legacy artifacts do not always retain snippets. Location is an explicit weak fallback.
    return f"line:{int(finding.get('start_line') or 0)}{column}"


def correlation_anchor(finding: dict[str, Any]) -> str:
    """Return a conservative within-run anchor for cross-tool correlation.

    Missing evidence must create extra canonical rows rather than hide distinct
    issues. Native IDs are therefore the final fallback, not file+line alone.
    """
    snippet = re.sub(r"\s+", " ", str(finding.get("code_snippet") or "").strip())
    start_col = int(finding.get("start_col") or 0)
    end_col = int(finding.get("end_col") or 0)
    if snippet:
        column = f":column:{start_col}:{end_col or start_col}" if start_col else ""
        return canonical_text(f"snippet:{snippet}{column}")
    if start_col:
        return f"column:{start_col}:{end_col or start_col}"
    symbol = str(finding.get("enclosing_symbol") or "").strip()
    if symbol:
        return canonical_text(f"symbol:{symbol}")
    family = scanner_family(str(finding.get("source_tool") or "Unknown"))
    native = finding.get("native_result_id") or finding.get("id")
    if native:
        return canonical_text(f"native:{family}:{native}")
    rule = str(finding.get("rule_id") or "unknown")
    message = re.sub(r"\s+", " ", str(finding.get("message") or "").strip())
    return canonical_text(f"fallback:{family}:{rule}:{message}")


def stable_id(repository: str, finding: dict[str, Any]) -> str:
    fields = (
        IDENTITY_VERSION,
        repository,
        canonical_path(finding.get("file")),
        finding.get("rule_concept") or finding.get("rule_id"),
        finding.get("enclosing_symbol") or "<NONE>",
        normalized_anchor(finding),
        correlation_anchor(finding),
    )
    digest = hashlib.sha256("\0".join(canonical_text(item) for item in fields).encode("utf-8")).hexdigest()
    return f"{IDENTITY_VERSION}:{digest}"


def compatibility_fingerprint(finding: dict[str, Any]) -> str:
    key = "\0".join((canonical_path(finding.get("file")),
                     str(int(finding.get("start_line") or 0)),
                     canonical_text(finding.get("rule_concept") or finding.get("rule_id")),
                     correlation_anchor(finding)))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def scanner_family(tool: str) -> str:
    aliases = {"Trivy-SCA": "Trivy", "Coverage.py": "Coverage.py"}
    return aliases.get(tool, tool or "Unknown")


def observation_id(stable: str, run: dict[str, Any], observation: dict[str, Any]) -> str:
    fields = (
        stable,
        run.get("commit_sha"),
        observation.get("scanner_family"),
        observation.get("channel"),
        run.get("workflow_run_id"),
        observation.get("native_result_id") or "<NONE>",
    )
    return "obs-v1:" + hashlib.sha256("\0".join(canonical_text(item) for item in fields).encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON evidence {path}: {exc}") from exc


def validate_channel_manifest(manifest: dict[str, Any]) -> None:
    channels = manifest.get("required_static_channels")
    if manifest.get("schema_version") != "1" or not isinstance(channels, list) or not channels:
        raise EvidenceError("required-channel manifest is missing or unsupported")
    ids = [row.get("channel") for row in channels]
    if any(not item for item in ids) or len(ids) != len(set(ids)):
        raise EvidenceError("required-channel manifest contains missing or duplicate channel IDs")


def canonicalize(raw_findings: list[dict[str, Any]], repository: str, run: dict[str, Any],
                 channel_manifest: dict[str, Any]) -> dict[str, Any]:
    validate_channel_manifest(channel_manifest)
    channel_by_family: dict[str, str] = {}
    for row in channel_manifest["required_static_channels"]:
        channel_by_family.setdefault(str(row["scanner_family"]), str(row["channel"]))

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in raw_findings:
        groups[compatibility_fingerprint(raw)].append(raw)

    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for fingerprint in sorted(groups):
        members = sorted(groups[fingerprint], key=lambda row: (
            -SEVERITY_RANK.get(str(row.get("severity")), 0), str(row.get("source_tool")), str(row.get("rule_id"))))
        primary = members[0]
        sid = stable_id(repository, primary)
        member_observations: list[dict[str, Any]] = []
        for member in members:
            family = scanner_family(str(member.get("source_tool") or "Unknown"))
            observation = {
                "scanner_family": family,
                "channel": channel_by_family.get(family, family.lower().replace(" ", "-")),
                "rule": str(member.get("rule_id") or "unknown"),
                "native_result_id": str(member.get("native_result_id") or member.get("id") or "<NONE>"),
                "analysis_category": str(member.get("analysis_category") or "<NONE>"),
                "file": canonical_path(member.get("file")),
                "start_line": int(member.get("start_line") or 0),
                "end_line": int(member.get("end_line") or member.get("start_line") or 0),
                "start_col": int(member.get("start_col") or 0),
                "end_col": int(member.get("end_col") or 0),
                "tool_version": str(member.get("tool_version") or "<NONE>"),
                "ruleset_version": str(member.get("ruleset_version") or "<NONE>"),
                "raw_artifact": str(member.get("raw_artifact") or "<NONE>"),
                "message": str(member.get("message") or member.get("description") or ""),
                "severity": str(member.get("severity") or "MEDIUM"),
            }
            observation["observation_id"] = observation_id(sid, run, observation)
            member_observations.append(observation)
            observations.append(observation)
        families = sorted({row["scanner_family"] for row in member_observations})
        channels = sorted({row["channel"] for row in member_observations})
        findings.append({
            "stable_id": sid,
            "compatibility_fingerprint": fingerprint,
            "concept": str(primary.get("rule_concept") or primary.get("rule_id") or "unknown"),
            "category": str(primary.get("category") or "QUALITY"),
            "severity": str(primary.get("severity") or "MEDIUM"),
            "file": canonical_path(primary.get("file")),
            "start_line": int(primary.get("start_line") or 0),
            "end_line": int(primary.get("end_line") or primary.get("start_line") or 0),
            "start_col": int(primary.get("start_col") or 0),
            "end_col": int(primary.get("end_col") or 0),
            "component": canonical_path(primary.get("file")).split("/", 1)[0],
            "enclosing_symbol": str(primary.get("enclosing_symbol") or "<NONE>"),
            "region_anchor": normalized_anchor(primary),
            "message": str(primary.get("message") or primary.get("description") or ""),
            "supporting_scanner_families": families,
            "supporting_channels": channels,
            "observation_count": len(member_observations),
            "scanner_family_count": len(families),
            "observation_ids": [row["observation_id"] for row in member_observations],
            "first_seen": str(primary.get("first_seen") or run.get("generated_at") or "<NONE>"),
            "evidence_source": "DETERMINISTIC",
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "identity_version": IDENTITY_VERSION,
        "repository_identity": repository,
        "run": run,
        "findings": findings,
        "observations": observations,
    }


def build_snapshot(current: dict[str, Any], channel_status: dict[str, Any],
                   provenance: dict[str, Any]) -> dict[str, Any]:
    """Build the one current, publishable findings snapshot.

    This deliberately has no baseline, lifecycle, or triage semantics.  A snapshot is
    publishable only when its exact-commit provenance and required scanner evidence
    reconcile with the canonical evidence document.
    """
    repository = str(current.get("repository_identity") or "")
    if validate_evidence(current, repository) != "VALID":
        raise EvidenceError("canonical evidence is invalid")
    channels = channel_status.get("channels")
    if not isinstance(channels, list) or not channels:
        raise EvidenceError("channel status is missing")
    incomplete = [str(row.get("channel")) for row in channels if row.get("status") != "COMPLETED"]
    if incomplete:
        raise EvidenceError("required scanner channels incomplete: " + ", ".join(incomplete))
    run = current.get("run") or {}
    commit = str(run.get("commit_sha") or "")
    if not commit or str(provenance.get("commit_sha") or "") != commit:
        raise EvidenceError("snapshot provenance commit does not match canonical evidence")
    workflow_runs = provenance.get("workflow_run_ids")
    artifact_hashes = provenance.get("artifact_hashes")
    if not isinstance(workflow_runs, list) or not workflow_runs:
        raise EvidenceError("snapshot provenance has no workflow runs")
    if not isinstance(artifact_hashes, list) or not artifact_hashes:
        raise EvidenceError("snapshot provenance has no artifact hashes")
    if any(not row.get("path") or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or ""))
           for row in artifact_hashes):
        raise EvidenceError("snapshot provenance contains an invalid artifact hash")
    findings = current["findings"]
    observations = current["observations"]
    referenced = [item for row in findings for item in row.get("observation_ids", [])]
    observed_ids = [row.get("observation_id") for row in observations]
    if len(referenced) != len(observations) or sorted(referenced) != sorted(observed_ids):
        raise EvidenceError("canonical finding and observation counts do not reconcile")
    deterministic = [row for row in findings if row.get("evidence_source") != "AI_ADVISORY"]
    advisories = [row for row in findings if row.get("evidence_source") == "AI_ADVISORY"]
    generated_at = str(run.get("generated_at") or datetime.now(timezone.utc).isoformat())
    snapshot_key = "\0".join((repository, commit, str(run.get("branch") or ""), generated_at,
                               *sorted(str(row["sha256"]) for row in artifact_hashes)))
    return {
        "schema_version": "snapshot-v1",
        "snapshot_id": "snapshot-v1:" + hashlib.sha256(snapshot_key.encode("utf-8")).hexdigest(),
        "repository_identity": repository,
        "commit_sha": commit,
        "branch": str(run.get("branch") or ""),
        "generated_at": generated_at,
        "workflow_run_ids": [str(value) for value in workflow_runs],
        "scanner_versions": sorted({f"{row['scanner_family']}:{row['tool_version']}" for row in observations}),
        "channel_status": channels,
        "artifact_hashes": artifact_hashes,
        "finding_count": len(findings),
        "observation_count": len(observations),
        "deterministic_finding_count": len(deterministic),
        "ai_advisory_count": len(advisories),
        "canonical_findings": deterministic,
        "ai_advisories": advisories,
        "observations": observations,
        "publishable": True,
    }


def validate_evidence(document: dict[str, Any], expected_repository: str) -> str:
    if not document:
        return "UNAVAILABLE"
    if document.get("schema_version") != SCHEMA_VERSION or document.get("repository_identity") != expected_repository:
        return "INVALID"
    findings = document.get("findings")
    if not isinstance(findings, list):
        return "INVALID"
    ids = [row.get("stable_id") for row in findings]
    return "VALID" if all(ids) and len(ids) == len(set(ids)) else "INVALID"


def effective_triage(registry: dict[str, Any], now: datetime | None = None) -> dict[str, dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    result: dict[str, dict[str, Any]] = {}
    for migration in registry.get("identity_migrations", []):
        required = ("from_stable_id", "to_stable_id", "reviewed_by", "reviewed_at", "rationale")
        if any(not migration.get(field) for field in required):
            raise EvidenceError("identity migration requires an explicit reviewed record")
    for row in registry.get("decisions", []):
        if row.get("status") not in TRIAGE_STATES or not row.get("stable_id"):
            raise EvidenceError("invalid triage decision")
        effective = row["status"]
        if row.get("expires_at"):
            expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
            if expires <= now:
                effective = "UNREVIEWED"
        result[str(row["stable_id"])] = {**row, "effective_status": effective}
    return result


def _similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    return SequenceMatcher(None, str(left.get("region_anchor")), str(right.get("region_anchor"))).ratio()


def _strong_matches(baseline: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, tuple[str, float]]:
    candidates: list[tuple[float, int, str, str]] = []
    for old in baseline:
        for new in current:
            if (old.get("file"), old.get("concept"), old.get("enclosing_symbol")) != (
                    new.get("file"), new.get("concept"), new.get("enclosing_symbol")):
                continue
            distance = abs(int(old.get("start_line") or 0) - int(new.get("start_line") or 0))
            score = _similarity(old, new)
            if score >= 0.90 and distance <= 50:
                candidates.append((score, distance, str(old["stable_id"]), str(new["stable_id"])))
    by_old: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
    by_new: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
    for score, distance, old_id, new_id in candidates:
        by_old[old_id].append((score, distance, new_id))
        by_new[new_id].append((score, distance, old_id))
    matches: dict[str, tuple[str, float]] = {}
    used_new: set[str] = set()
    for old_id in sorted(by_old):
        ranked = sorted(by_old[old_id], key=lambda row: (-row[0], row[1], row[2]))
        best = ranked[0]
        margin = best[0] - ranked[1][0] if len(ranked) > 1 else 1.0
        reverse = sorted(by_new[best[2]], key=lambda row: (-row[0], row[1], row[2]))[0]
        if margin >= 0.15 and reverse[2] == old_id and best[2] not in used_new:
            matches[old_id] = (best[2], best[0])
            used_new.add(best[2])
    return matches


def compare(current: dict[str, Any], baseline: dict[str, Any] | None,
            previous: dict[str, Any] | None, channel_status: dict[str, Any],
            triage_registry: dict[str, Any]) -> dict[str, Any]:
    repository = str(current.get("repository_identity"))
    validity = {
        "baseline_validity": validate_evidence(baseline or {}, repository),
        "current_run_validity": validate_evidence(current, repository),
        "previous_run_validity": validate_evidence(previous or {}, repository),
    }
    if validity["baseline_validity"] != "VALID" or validity["current_run_validity"] != "VALID":
        raise EvidenceError(f"untrustworthy comparison: {validity}")
    baseline_findings = baseline["findings"] if baseline else []
    current_findings = current["findings"]
    old_by_id = {row["stable_id"]: row for row in baseline_findings}
    new_by_id = {row["stable_id"]: row for row in current_findings}
    exact = set(old_by_id) & set(new_by_id)
    unmatched_old = [old_by_id[key] for key in sorted(set(old_by_id) - exact)]
    unmatched_new = [new_by_id[key] for key in sorted(set(new_by_id) - exact)]
    moved = _strong_matches(unmatched_old, unmatched_new)
    moved_new = {value[0] for value in moved.values()}
    statuses = {str(row["scanner_family"]): str(row["status"]) for row in channel_status.get("channels", [])}
    triage = effective_triage(triage_registry)
    rows: list[dict[str, Any]] = []
    for sid in sorted(exact):
        rows.append({**new_by_id[sid], "lifecycle": "EXISTING", "reason_code": "EXACT_IDENTITY"})
    for old_id, (new_id, score) in sorted(moved.items()):
        old, new = old_by_id[old_id], new_by_id[new_id]
        rows.append({**new, "lifecycle": "MOVED", "reason_code": "STRONG_DRIFT_MATCH",
                     "previous_stable_id": old_id, "region_similarity": round(score, 4),
                     "line_shift": int(new["start_line"]) - int(old["start_line"])})
    for old in unmatched_old:
        if old["stable_id"] in moved:
            continue
        failed = [family for family in old.get("supporting_scanner_families", []) if statuses.get(family) != "COMPLETED"]
        lifecycle = "INDETERMINATE" if failed else "NOT_OBSERVED"
        reason = "OWNING_CHANNEL_MISSING" if any(family not in statuses for family in failed) else "OWNING_CHANNEL_FAILED"
        rows.append({**old, "lifecycle": lifecycle,
                     "reason_code": reason if failed else "NOT_DETECTED_BY_COMPLETED_OWNERS",
                     "missing_or_failed_families": failed})
    for new in unmatched_new:
        if new["stable_id"] not in moved_new:
            plausible = any((old.get("file"), old.get("concept"), old.get("enclosing_symbol")) ==
                            (new.get("file"), new.get("concept"), new.get("enclosing_symbol")) for old in unmatched_old)
            rows.append({**new, "lifecycle": "NEW", "reason_code": "AMBIGUOUS_DRIFT" if plausible else "NO_BASELINE_MATCH"})
    previous_states: dict[str, str] = {}
    if previous and validity["previous_run_validity"] == "VALID":
        previous_by_id = {row["stable_id"]: row for row in previous["findings"]}
        previous_exact = set(previous_by_id) & set(new_by_id)
        previous_states.update({sid: "EXISTING" for sid in previous_exact})
        previous_old = [previous_by_id[sid] for sid in sorted(set(previous_by_id) - previous_exact)]
        previous_new = [new_by_id[sid] for sid in sorted(set(new_by_id) - previous_exact)]
        for _, (new_id, _) in _strong_matches(previous_old, previous_new).items():
            previous_states[new_id] = "MOVED"
        for sid in new_by_id:
            previous_states.setdefault(sid, "NEW")
    for row in rows:
        decision = triage.get(row["stable_id"])
        row["triage"] = decision["effective_status"] if decision else "UNREVIEWED"
        row["previous_run_state"] = previous_states.get(row["stable_id"], "UNAVAILABLE")
        row["analysis_change_flags"] = channel_status.get("analysis_change_flags", [])
    counts = Counter(row["lifecycle"] for row in rows)
    accounted = sum(counts[state] for state in ("EXISTING", "MOVED", "NOT_OBSERVED", "INDETERMINATE"))
    if accounted != len(baseline_findings):
        raise EvidenceError(f"conservation failure: baseline={len(baseline_findings)} accounted={accounted}")
    return {"schema_version": SCHEMA_VERSION, **validity, "baseline_id": baseline.get("baseline_id"),
            "current_run": current.get("run"), "previous_run": previous.get("run") if previous else "UNAVAILABLE",
            "channel_status": channel_status, "findings": rows, "counts": dict(counts)}


def defectdojo_fixture(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"adapter_version": "defectdojo-fixture-v1", "close_old_findings": False,
            "do_not_reactivate": True, "findings": [{"internal_stable_id": row["stable_id"],
            "unique_id_from_tool": "agentic-soc:" + hashlib.sha256(row["stable_id"].encode()).hexdigest(),
            "title": row["concept"], "severity": row["severity"], "file_path": row["file"],
            "line": row["start_line"]} for row in findings]}


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-findings", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--channel-manifest", type=Path, required=True)
    parser.add_argument("--channel-status", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--triage", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run = {"commit_sha": args.commit, "branch": args.branch, "workflow_run_id": args.workflow_run_id,
           "generated_at": datetime.now(timezone.utc).isoformat()}
    current = canonicalize(load_json(args.raw_findings), args.repository, run, load_json(args.channel_manifest))
    baseline = load_json(args.baseline)
    previous = load_json(args.previous) if args.previous and args.previous.exists() else None
    comparison = compare(current, baseline, previous, load_json(args.channel_status), load_json(args.triage))
    write_json(args.output_dir / "canonical-findings.json", current)
    write_json(args.output_dir / "comparison.json", comparison)
    write_json(args.output_dir / "defectdojo-export.json", defectdojo_fixture(current["findings"]))


if __name__ == "__main__":
    main()
