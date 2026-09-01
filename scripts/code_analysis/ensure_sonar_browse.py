"""Idempotently grant Sonar Browse to the user represented by SONAR_API_TOKEN."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _request(url: str, token: str, data: bytes | None = None) -> tuple[int, object | None]:
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, None


def ensure(output: Path) -> dict[str, object]:
    token = os.environ.get("SONAR_API_TOKEN", "")
    if not token:
        raise SystemExit("SONAR_API_TOKEN is required")
    server = "https://sonarcloud.io"
    user_status, user = _request(f"{server}/api/users/current", token)
    login = user.get("login") if isinstance(user, dict) else None
    if user_status != 200 or not login:
        raise SystemExit("SONAR_API_TOKEN has no current Sonar user")
    form = urllib.parse.urlencode(
        {
            "login": login,
            "organization": "combustrrr",
            "permission": "user",
            "projectKey": "combustrrr_Agentic-Kibana",
        }
    ).encode("ascii")
    grant_status, _ = _request(f"{server}/api/permissions/add_user", token, form)
    branch = os.environ.get("SCAN_BRANCH", "")
    issue_query = urllib.parse.urlencode(
        {
            "componentKeys": "combustrrr_Agentic-Kibana",
            "branch": branch,
            "p": 1,
            "ps": 1,
        }
    )
    issue_status, _ = _request(f"{server}/api/issues/search?{issue_query}", token)
    result: dict[str, object] = {
        "schema_version": "1",
        "project": "combustrrr_Agentic-Kibana",
        "current_user_login": login,
        "grant_http_status": grant_status,
        "browse_granted": grant_status in {200, 204},
        "branch": branch,
        "branch_issues_http_status_after_grant": issue_status,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["browse_granted"]:
        raise SystemExit(f"Sonar Browse grant failed with HTTP {grant_status}")
    return result


if __name__ == "__main__":
    ensure(Path("sonar-browse-grant.json"))
