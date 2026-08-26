#!/usr/bin/env python3
"""Pull the latest validated Actions dashboard and publish it on a QA host.

The worker is outbound-only. It is not a GitHub Actions runner and never executes
repository workflow code on the QA VM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000


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
        declared = int(response.headers.get("Content-Length", "0") or 0)
        if declared > MAX_ARCHIVE_BYTES:
            raise ValueError("dashboard artifact exceeds the download limit")
        received = 0
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > MAX_ARCHIVE_BYTES:
                raise ValueError("dashboard artifact exceeds the download limit")
            output.write(chunk)


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("dashboard artifact contains too many files")
        if sum(member.file_size for member in members) > MAX_EXTRACTED_BYTES:
            raise ValueError("dashboard artifact exceeds the extraction limit")
        for member in members:
            unix_mode = member.external_attr >> 16
            if unix_mode and (unix_mode & 0o170000) == 0o120000:
                raise ValueError(f"dashboard artifact contains a symlink: {member.filename}")
            normalized = member.filename.replace("\\", "/")
            target = (destination / normalized).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe artifact path: {member.filename}")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)


def artifact_branch_key(branch: str) -> str:
    """Match the portable branch key emitted by the aggregation workflow."""
    slug = (re.sub(r"[^A-Za-z0-9._-]+", "-", branch).strip("-") or "unknown")[:80]
    digest = hashlib.sha256(branch.encode("utf-8")).hexdigest()[:12]
    return f"{slug}-{digest}"


def branch_head_sha(repository: str, branch: str, token: str) -> str:
    encoded = urllib.parse.quote(branch, safe="")
    payload = request_json(f"{API}/repos/{repository}/branches/{encoded}", token)
    commit = str(payload.get("commit", {}).get("sha", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError(f"branch {branch!r} has no valid GitHub head SHA")
    return commit


def artifact_commit(name: str, branch: str) -> str:
    """Extract the full analyzed commit from a source-scoped artifact name."""
    prefix = f"current-findings-dashboard-{artifact_branch_key(branch)}-"
    match = re.fullmatch(re.escape(prefix) + r"([0-9a-fA-F]{40})-\d+", name)
    if not match:
        raise ValueError(f"dashboard artifact has an invalid identity: {name}")
    return match.group(1).lower()


def select_artifact(repository: str, branch: str, token: str) -> tuple[dict, dict, str]:
    # workflow_run jobs themselves are attached to the default branch. Filtering the
    # API by the analyzed branch would therefore hide valid feature/Testing snapshots.
    query = urllib.parse.urlencode({"status": "success", "per_page": 30})
    prefix = f"current-findings-dashboard-{artifact_branch_key(branch)}-"
    expected_commit = branch_head_sha(repository, branch, token)
    runs = request_json(f"{API}/repos/{repository}/actions/workflows/05-issue-aggregation.yml/runs?{query}", token)
    for run in runs.get("workflow_runs", []):
        artifacts = request_json(f"{API}/repos/{repository}/actions/runs/{run['id']}/artifacts", token)
        candidates = [row for row in artifacts.get("artifacts", [])
                      if row.get("name", "").startswith(prefix) and not row.get("expired")]
        for artifact in sorted(candidates, key=lambda row: row["id"], reverse=True):
            analyzed_commit = artifact_commit(artifact["name"], branch)
            if analyzed_commit == expected_commit:
                return run, artifact, analyzed_commit
    raise RuntimeError(
        f"no non-expired validated dashboard artifact found for latest {branch} commit "
        f"{expected_commit}"
    )


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
    run, artifact, analyzed_commit = select_artifact(args.repository, args.branch, token)
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
        publish(dashboard, args.publication_root, args.repository, analyzed_commit, args.branch)
    write_state(args.state_file, {"schema_version": "1", "repository": args.repository,
                                  "branch": args.branch, "run_id": run["id"],
                                  "commit_sha": analyzed_commit, "artifact_id": artifact["id"],
                                  "artifact_name": artifact["name"]})
    print(f"published {artifact['name']} for {analyzed_commit}")


if __name__ == "__main__":
    main()
