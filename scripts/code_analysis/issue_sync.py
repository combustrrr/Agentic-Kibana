#!/usr/bin/env python3
"""Plan or explicitly apply advisory GitHub Issues for normalized findings.

Dry-run is the default. This tool never closes issues and never changes branches,
checks, pull requests, or branch protection.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

MARKER = "<!-- code-analysis-fingerprint:{fingerprint} -->"
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def load_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}")
    return data


def existing_fingerprints(issues: list[dict]) -> set[str]:
    found: set[str] = set()
    prefix = MARKER.split("{")[0]
    for issue in issues:
        body = str(issue.get("body") or "")
        start = body.find(prefix)
        if start >= 0:
            value = body[start + len(prefix):].split(" -->", 1)[0].strip()
            if value:
                found.add(value)
        for label in issue.get("labels", []):
            name = label.get("name", "") if isinstance(label, dict) else str(label)
            if name.startswith("fp:"):
                found.add(name.removeprefix("fp:"))
    return found


def issue_for(finding: dict) -> dict:
    fingerprint = str(finding["id"])
    severity = str(finding.get("severity", "MEDIUM")).upper()
    tool = str(finding.get("source_tool") or "unknown")
    path = str(finding.get("file") or "unknown")
    line = int(finding.get("start_line") or 0)
    concept = str(finding.get("rule_concept") or finding.get("rule_id") or "finding")
    message = str(finding.get("message") or finding.get("rule_name") or concept)
    evidence = [tool, *[str(item).split(":", 1)[0] for item in finding.get("evidence", [])]]
    evidence = sorted(set(filter(None, evidence)))
    title = f"[{severity}] {concept} in {path}:{line}"[:256]
    body = "\n".join([
        MARKER.format(fingerprint=fingerprint), "## Advisory code-analysis finding", "",
        f"- **Location:** `{path}:{line}`", f"- **Concept:** `{concept}`",
        f"- **Severity:** `{severity}`", f"- **Detected by:** {', '.join(evidence)}",
        f"- **Primary rule:** `{finding.get('rule_id', '')}`", "", "### Finding", message, "",
        "This issue is advisory. It does not block merging and is not automatically closed after a missing scan.",
    ])
    labels = ["code-analysis", "advisory", f"severity:{severity.lower()}", f"fp:{fingerprint}"]
    if len(evidence) > 1:
        labels.append("corroborated")
    return {"fingerprint": fingerprint, "title": title, "body": body, "labels": labels}


def build_plan(findings: list[dict], issues: list[dict], severities: set[str], limit: int) -> dict:
    known = existing_fingerprints(issues)
    eligible = [f for f in findings if str(f.get("severity", "")).upper() in severities]
    eligible.sort(key=lambda f: (-SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0),
                                 str(f.get("file", "")), int(f.get("start_line") or 0), str(f.get("id", ""))))
    pending = [f for f in eligible if str(f.get("id")) not in known]
    creates = [issue_for(f) for f in pending[:limit]]
    return {"mode": "advisory", "close_issues": False, "eligible": len(eligible),
            "already_tracked": len(eligible) - len(pending), "create": creates,
            "deferred_by_limit": max(0, len(pending) - len(creates))}


def apply_plan(plan: dict, repository: str) -> None:
    for item in plan["create"]:
        for label in item["labels"]:
            subprocess.run(["gh", "label", "create", label, "--repo", repository,
                            "--color", "D4C5F9", "--force"], check=True)
        command = ["gh", "issue", "create", "--repo", repository, "--title", item["title"],
                   "--body", item["body"]]
        for label in item["labels"]:
            command.extend(["--label", label])
        subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--existing-issues", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--severity", action="append", default=[])
    parser.add_argument("--max-new", type=int, default=25)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args()
    severities = {value.upper() for value in (args.severity or ["CRITICAL", "HIGH"])}
    plan = build_plan(load_json(args.findings), load_json(args.existing_issues), severities, max(0, args.max_new))
    args.output.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in plan.items() if key != "create"}, indent=2))
    if args.apply:
        if not args.repository:
            raise SystemExit("--repository or GITHUB_REPOSITORY is required with --apply")
        apply_plan(plan, args.repository)
    else:
        print("Dry run only; no GitHub Issues were changed.")


if __name__ == "__main__":
    main()
