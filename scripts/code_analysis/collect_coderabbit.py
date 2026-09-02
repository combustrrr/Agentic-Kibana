#!/usr/bin/env python3
"""Collect exact-head CodeRabbit PR review evidence as optional AI advisories."""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
BOT_LOGINS = {"coderabbitai[bot]", "coderabbitai"}


def request_json(url: str, token: str) -> Any:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "agentic-soc-coderabbit-advisory-collector/1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def paged(url: str, token: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page in range(1, 11):
        separator = "&" if "?" in url else "?"
        batch = request_json(f"{url}{separator}per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise ValueError("GitHub API returned a non-list collection")
        rows.extend(batch)
        if len(batch) < 100:
            break
    return rows


def severity(body: str) -> str:
    text = body.lower()
    if re.search(r"\b(critical|blocker)\b", text):
        return "CRITICAL"
    if re.search(r"\b(high|major)\b", text):
        return "HIGH"
    if re.search(r"\b(medium|moderate)\b", text):
        return "MEDIUM"
    if re.search(r"\b(low|minor|nitpick)\b", text):
        return "LOW"
    return "INFO"


def collect(repository: str, branch: str, commit: str, token: str) -> tuple[dict, dict]:
    commit = commit.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full SHA")
    pulls = request_json(f"{API}/repos/{repository}/commits/{commit}/pulls", token)
    relevant = [row for row in pulls if row.get("state") == "open" and
                row.get("head", {}).get("sha", "").lower() == commit and
                row.get("head", {}).get("ref") == branch and
                row.get("head", {}).get("repo", {}).get("full_name") == repository]
    advisories: list[dict[str, Any]] = []
    review_seen = False
    completion_signals: list[str] = []
    pr_numbers: list[int] = []
    for pull in relevant:
        number = int(pull["number"])
        pr_numbers.append(number)
        reviews = paged(f"{API}/repos/{repository}/pulls/{number}/reviews", token)
        review_seen = review_seen or any(
            str(row.get("user", {}).get("login", "")).lower() in BOT_LOGINS and
            str(row.get("commit_id") or "").lower() == commit
            for row in reviews
        )
        if review_seen:
            completion_signals.append("exact-head-review")
        comments = paged(f"{API}/repos/{repository}/pulls/{number}/comments", token)
        for row in comments:
            login = str(row.get("user", {}).get("login", "")).lower()
            if login not in BOT_LOGINS or row.get("in_reply_to_id") is not None:
                continue
            if str(row.get("commit_id") or "").lower() != commit:
                continue
            path = str(row.get("path") or "")
            line = int(row.get("line") or row.get("original_line") or 0)
            body = str(row.get("body") or "").strip()[:8000]
            if not path or not body:
                continue
            advisories.append({
                "id": f"coderabbit-review-comment-{row['id']}",
                "native_result_id": str(row["id"]),
                "native_url": str(row.get("html_url") or ""),
                "pr_number": str(number),
                "file": path,
                "start_line": line,
                "end_line": line,
                "rule_id": "coderabbit-pr-advisory",
                "rule_concept": "ai-pr-review-advisory",
                "severity": severity(body),
                "category": "AI_REVIEW",
                "message": body,
                "commit": commit,
                "branch": branch,
                "analysis_category": f"github-pr-review:{number}",
                "evidence_source": "AI_ADVISORY",
            })
    if relevant and not review_seen:
        combined = request_json(f"{API}/repos/{repository}/commits/{commit}/status", token)
        statuses = combined.get("statuses", []) if isinstance(combined, dict) else []
        if any(str(row.get("context") or "").strip().lower() == "coderabbit" and
               str(row.get("state") or "").strip().lower() == "success" and
               str(row.get("description") or "").strip().lower().startswith("review completed")
               for row in statuses):
            review_seen = True
            completion_signals.append("exact-head-success-status")
    status = "COMPLETED_OPTIONAL" if review_seen else "NOT_APPLICABLE"
    reason = ("No open same-repository PR exists for this branch head" if not relevant else
              "CodeRabbit review evidence collected for the exact PR head" if review_seen else
              "An open PR exists, but CodeRabbit has not submitted an exact-head review")
    evidence = {"schema_version": "1", "repository": repository, "branch": branch,
                "commit_sha": commit, "pull_requests": pr_numbers,
                "completion_signals": sorted(set(completion_signals)),
                "advisories": advisories}
    status_doc = {"schema_version": "1", "scanner_family": "CodeRabbit", "status": status,
                  "reason": reason, "finding_count": len(advisories),
                  "observation_count": len(advisories), "commit_sha": commit}
    return evidence, status_doc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN", "").strip()
    if not token:
        raise SystemExit("GH_TOKEN is required")
    evidence, status = collect(args.repository, args.branch, args.commit, token)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "coderabbit-advisories.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.output_dir / "coderabbit-status.json").write_text(
        json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
