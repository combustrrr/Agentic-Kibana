"""Export bounded native SonarQube Cloud issues for one completed branch analysis."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def _request(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _task_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if not values.get("serverUrl") or not values.get("ceTaskUrl"):
        raise ValueError("Sonar report-task.txt lacks serverUrl or ceTaskUrl")
    return values


def export(path: Path, output: Path, project: str, branch: str, commit: str,
           token: str, pull_request: str = "", maximum: int = 20_000,
           poll_seconds: int = 180) -> dict[str, Any]:
    task_info = _task_file(path)
    if task_info.get("projectKey") and task_info["projectKey"] != project:
        raise ValueError("Sonar report project does not match requested project")
    deadline = time.monotonic() + poll_seconds
    task: dict[str, Any] = {}
    while time.monotonic() < deadline:
        task = _request(task_info["ceTaskUrl"], token).get("task", {})
        if task.get("status") in {"SUCCESS", "FAILED", "CANCELED"}:
            break
        time.sleep(3)
    if task.get("status") != "SUCCESS":
        status = task.get("status", "TIMEOUT")
        raise RuntimeError(f"Sonar compute task did not succeed: {status}")

    server = task_info["serverUrl"].rstrip("/")
    issues: list[dict[str, Any]] = []
    page = 1
    while True:
        parameters = {"componentKeys": project, "p": page, "ps": 500,
                      "additionalFields": "_all"}
        parameters["pullRequest" if pull_request else "branch"] = pull_request or branch
        query = urllib.parse.urlencode(parameters)
        document = _request(f"{server}/api/issues/search?{query}", token)
        rows = document.get("issues", [])
        if not isinstance(rows, list):
            raise TypeError("Sonar issues response has no issue list")
        issues.extend(row for row in rows if not row.get("external")
                      and not str(row.get("rule", "")).startswith("external_"))
        if len(issues) > maximum:
            raise ValueError(f"Sonar native issue export exceeds bound of {maximum}")
        total = int(document.get("paging", {}).get("total", len(rows)))
        if total > maximum:
            raise ValueError(f"Sonar issue result exceeds bound of {maximum}")
        if page * 500 >= total:
            break
        page += 1

    result = {"schema_version": "1", "scanner_family": "SonarQube Cloud",
              "project_key": project, "branch": branch, "commit": commit,
              "pull_request": pull_request,
              "analysis_id": str(task.get("analysisId") or ""),
              "native_issue_count": len(issues), "issues": issues}
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-task", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--pull-request", default="")
    args = parser.parse_args()
    token = os.environ.get("SONAR_TOKEN", "")
    if not token:
        raise SystemExit("SONAR_TOKEN is required")
    export(args.report_task, args.output, args.project, args.branch, args.commit, token,
           pull_request=args.pull_request)


if __name__ == "__main__":
    main()
