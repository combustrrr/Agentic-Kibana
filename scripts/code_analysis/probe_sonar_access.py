"""Emit secret-free Sonar token validity and branch-access diagnostics."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _request(url: str, token: str) -> tuple[int, object | None]:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"} if token else {}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


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
        auth_status, auth_document = _request(
            f"{server}/api/authentication/validate", token
        )
        authenticated = (
            auth_document.get("valid") if isinstance(auth_document, dict) else False
        )
        user_status, user_document = _request(f"{server}/api/users/current", token)
        login = user_document.get("login") if isinstance(user_document, dict) else None
        permission_query = urllib.parse.urlencode(
            {"projectKey": project, "permission": "user", "ps": 500}
        )
        permission_status, permission_document = _request(
            f"{server}/api/permissions/users?{permission_query}", token
        )
        browse_granted = None
        if login and isinstance(permission_document, dict):
            users = permission_document.get("users", [])
            browse_granted = any(
                row.get("login") == login and "user" in row.get("permissions", [])
                for row in users
                if isinstance(row, dict)
            )
        issue_status, _ = _request(f"{server}/api/issues/search?{issue_query}", token)
        credentials[role] = {
            "configured": True,
            "authentication_http_status": auth_status,
            "authenticated": authenticated,
            "current_user_http_status": user_status,
            "current_user_login": login,
            "permission_list_http_status": permission_status,
            "browse_granted_to_current_user": browse_granted,
            "branch_issues_http_status": issue_status,
        }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    probe(Path("sonar-access-probe.json"))
