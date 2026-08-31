"""Emit secret-free Sonar token validity and branch-access diagnostics."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _status(url: str, token: str) -> tuple[int, bool | None]:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"} if token else {}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.load(response)
            valid = document.get("valid") if isinstance(document, dict) else None
            return response.status, valid if isinstance(valid, bool) else None
    except urllib.error.HTTPError as error:
        return error.code, False if "authentication/validate" in url else None


def probe(output: Path) -> dict[str, object]:
    server = "https://sonarcloud.io"
    project = "combustrrr_Agentic-Kibana"
    branch = os.environ.get("SCAN_BRANCH", "")
    issue_query = urllib.parse.urlencode(
        {"componentKeys": project, "branch": branch, "p": 1, "ps": 1}
    )
    result: dict[str, object] = {
        "schema_version": "1",
        "project": project,
        "branch": branch,
        "credentials": {},
    }
    credentials = result["credentials"]
    assert isinstance(credentials, dict)
    for role, variable in (
        ("analysis", "SONAR_TOKEN"),
        ("issue_api", "SONAR_API_TOKEN"),
    ):
        token = os.environ.get(variable, "")
        if not token:
            credentials[role] = {"configured": False}
            continue
        auth_status, valid = _status(f"{server}/api/authentication/validate", token)
        issue_status, _ = _status(f"{server}/api/issues/search?{issue_query}", token)
        credentials[role] = {
            "configured": True,
            "authentication_http_status": auth_status,
            "authenticated": valid,
            "branch_issues_http_status": issue_status,
        }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    probe(Path("sonar-access-probe.json"))
