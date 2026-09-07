"""Current-only hosted report contracts. No network or source execution."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from scripts.code_analysis.dashboard import validate_snapshot
from scripts.code_analysis.snapshot import COMPLETE_STATUSES

SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def target(repository: str, branch: str, sha: str, *, pr: int | None = None,
           source_repository: str | None = None, base_sha: str | None = None,
           base_branch: str | None = None) -> dict:
    source_repository = source_repository or repository
    if not REPOSITORY.fullmatch(repository) or not REPOSITORY.fullmatch(source_repository):
        raise ValueError("invalid source repository")
    if not SHA.fullmatch(sha) or (base_sha is not None and not SHA.fullmatch(base_sha)):
        raise ValueError("invalid source SHA")
    if not branch or (pr is not None and (type(pr) is not int or pr <= 0)):
        raise ValueError("invalid target")
    return {"id": digest([repository, "pr" if pr else "branch", pr or branch])[:24],
            "repository": repository, "source_repository": source_repository,
            "kind": "pr" if pr else "branch", "branch": branch, "pr": pr,
            "head_sha": sha, "base_sha": base_sha, "base_branch": base_branch,
            "label": f"PR #{pr}: {branch}" if pr else branch}


def analysis_key(row: dict, tooling_sha: str, config: dict) -> str:
    # PR review evidence is contextual; do not reuse it across different PRs/bases.
    return digest([row["source_repository"], row["head_sha"], tooling_sha, config,
                   [row["repository"], row["pr"], row["base_sha"]] if row.get("pr") else None])


def reconcile(previous: dict, discovered: list[dict], checked_at: str) -> dict:
    """Call only after every discovery page succeeds; never interpret failure as empty."""
    old = {row["id"]: row for row in previous.get("targets", [])}
    rows = []
    for current in discovered:
        former = old.get(current["id"], {})
        row = {**former, **current, "checked_at": checked_at}
        if former.get("head_sha") != current["head_sha"] or former.get("base_sha") != current.get("base_sha"):
            row["status"] = "stale" if row.get("report") else "queued"
            row.pop("analysis_key", None)
            row.pop("scan_run_id", None)
        rows.append(row)
    return {**previous, "schema_version": "dashboard-index-v1", "checked_at": checked_at,
            "targets": rows}


def accept(row: dict, report: dict) -> bool:
    identity = report["target"]
    return (row["id"] == identity["id"] and row["head_sha"] == report["analyzed_sha"]
            and row.get("base_sha") == identity.get("base_sha")
            and row["source_repository"] == identity["source_repository"])


def safe_file(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and "\\" not in name and ":" not in name


def build(snapshot: dict, identity: dict, output: Path, *, producer_repository: str,
          source: Path | None = None, tooling_sha: str | None = None) -> dict:
    validate_snapshot(snapshot, allow_partial=True)
    if snapshot["commit_sha"] != identity["head_sha"] or snapshot["repository_identity"].lower() != identity["source_repository"].lower():
        raise ValueError("snapshot source does not match target")
    if not REPOSITORY.fullmatch(producer_repository):
        raise ValueError("invalid producer repository")
    observations = {row["observation_id"]: row for row in snapshot["observations"]}
    if len(observations) != len(snapshot["observations"]):
        raise ValueError("duplicate observation identity")
    channels = snapshot["analysis_channels"]
    incomplete = [row["channel"] for row in channels if row["status"] not in COMPLETE_STATUSES
                  and not (row["status"] in {"NOT_APPLICABLE", "DEFERRED"} and row.get("reason"))]
    runs = []
    for run in snapshot["workflow_run_ids"]:
        if not str(run).isdigit():
            raise ValueError("invalid producer run")
        runs.append({"id": str(run), "url": f"https://github.com/{producer_repository}/actions/runs/{run}"})
    report = {"schema_version": "hosted-report-v1", "target": identity,
              "analyzed_sha": snapshot["commit_sha"], "generated_at": snapshot["generated_at"],
              "tooling_sha": tooling_sha, "producer_runs": runs,
              "status": "partial" if incomplete else "current", "incomplete_channels": incomplete,
              "publication_gate": snapshot["publication_gate"], "channels": channels,
              "finding_count": snapshot["finding_count"], "observation_count": snapshot["observation_count"]}
    index, details = [], []
    findings = [*snapshot["canonical_findings"], *snapshot.get("ai_advisories", [])]
    def secret_observation(o):
        return o.get('scanner_family') == 'Gitleaks' or o.get('channel') == 'gitleaks' or o.get('rule_concept') == 'hardcoded-secret'
    secret_files = {o.get("file") for o in observations.values() if secret_observation(o)}
    seen = set()
    source_cache = {}
    for finding in findings:
        fid = finding["stable_id"]
        if fid in seen:
            raise ValueError("duplicate canonical identity")
        seen.add(fid)
        origins = []
        for oid in finding["observation_ids"]:
            if oid not in observations:
                raise ValueError("finding references missing observation")
            o = observations[oid]
            origins.append({k: o.get(k) for k in ("scanner_family", "rule", "file", "start_line", "raw_artifact", "observation_id")})
        secret = any(secret_observation(observations[oid]) for oid in finding['observation_ids'])
        name = finding.get("file", "")
        line = finding.get("start_line", 0)
        row = {"id": fid, "severity": finding["severity"], "file": name, "line": line,
               "message": "Potential secret detected; value withheld from public report." if secret else finding.get("message", ""),
               "scanners": finding.get("supporting_scanner_families", []),
               "rules": sorted({str(o["rule"]) for o in origins}), "page": len(details) // 100}
        detail = {**row, "origins": origins, "source": None, "source_start": None, "source_url": None}
        if safe_file(name):
            detail["source_url"] = f"https://github.com/{identity['source_repository']}/blob/{identity['head_sha']}/{quote(name, safe='/')}" + (f"#L{line}" if line else "")
            if source and name not in secret_files:
                path = source / name
                if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(source.resolve()) and path.stat().st_size < 1_000_000:
                    if name not in source_cache:
                        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                        key = digest(lines)
                        write(output / "source" / f"{key}.json", lines)
                        source_cache[name] = key
                    detail.update(source=f"source/{source_cache[name]}.json", source_start=1)
        index.append(row)
        details.append(detail)
    for start in range(0, len(details), 100):
        write(output / "details" / f"{start // 100}.json", details[start:start + 100])
    report["severities"] = dict(Counter(r["severity"] for r in index))
    write(output / "findings.json", index)
    write(output / "report.json", report)
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--producer-repository", required=True)
    p.add_argument("--source", type=Path)
    args = p.parse_args()
    build(load(args.snapshot), load(args.target), args.output,
          producer_repository=args.producer_repository, source=args.source)


if __name__ == "__main__":
    main()
