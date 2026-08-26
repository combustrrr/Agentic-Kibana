#!/usr/bin/env python3
"""Pull the latest validated Actions dashboard and publish it on a QA host.

The worker is outbound-only. It is not a GitHub Actions runner and never executes
repository workflow code on the QA VM.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

try:
    from publish_snapshot import publish
except ModuleNotFoundError:  # package import in repository tests
    from scripts.code_analysis.publish_snapshot import publish


API = "https://api.github.com"


def request_json(url: str, token: str) -> dict:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "agentic-soc-findings-pull-worker/1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def download(url: str, token: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "User-Agent": "agentic-soc-findings-pull-worker/1",
    })
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            target = (destination / member.filename).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe artifact path: {member.filename}")
        bundle.extractall(destination)


def select_artifact(repository: str, branch: str, token: str) -> tuple[dict, dict]:
    query = urllib.parse.urlencode({"branch": branch, "status": "success", "per_page": 20})
    runs = request_json(f"{API}/repos/{repository}/actions/workflows/05-issue-aggregation.yml/runs?{query}", token)
    for run in runs.get("workflow_runs", []):
        artifacts = request_json(f"{API}/repos/{repository}/actions/runs/{run['id']}/artifacts", token)
        candidates = [row for row in artifacts.get("artifacts", [])
                      if row.get("name", "").startswith("current-findings-dashboard-") and not row.get("expired")]
        if candidates:
            return run, sorted(candidates, key=lambda row: row["id"], reverse=True)[0]
    raise RuntimeError("no non-expired validated dashboard artifact found")


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_token() -> str:
    token = os.environ.get("GH_TOKEN", "").strip()
    token_file = os.environ.get("GH_TOKEN_FILE", "").strip()
    if token:
        return token
    if token_file:
        return Path(token_file).read_text(encoding="utf-8").strip()
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", default="feature/static-code-analysis")
    parser.add_argument("--publication-root", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    args = parser.parse_args()
    token = read_token()
    if not token:
        raise SystemExit(
            "GH_TOKEN or GH_TOKEN_FILE is required "
            "(Actions read-only fine-grained token or GitHub App token)"
        )
    run, artifact = select_artifact(args.repository, args.branch, token)
    if args.state_file.is_file():
        state = json.loads(args.state_file.read_text(encoding="utf-8"))
        if state.get("artifact_id") == artifact["id"]:
            print(f"dashboard already current: artifact {artifact['id']}")
            return
    with tempfile.TemporaryDirectory(prefix="findings-pull-") as directory:
        root = Path(directory)
        archive = root / "artifact.zip"
        extracted = root / "extracted"
        extracted.mkdir()
        download(artifact["archive_download_url"], token, archive)
        safe_extract(archive, extracted)
        dashboard = extracted / "dashboard"
        publish(dashboard, args.publication_root)
    write_state(args.state_file, {"schema_version": "1", "repository": args.repository,
                                  "branch": args.branch, "run_id": run["id"],
                                  "commit_sha": run["head_sha"], "artifact_id": artifact["id"],
                                  "artifact_name": artifact["name"]})
    print(f"published {artifact['name']} for {run['head_sha']}")


if __name__ == "__main__":
    main()
