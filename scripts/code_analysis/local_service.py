#!/usr/bin/env python3
"""Run the separate developer-facing Web of Scanners control plane locally.

The product never imports this module. Scanner execution remains in the repository's
trusted GitHub Actions workflows; this launcher dispatches an exact commit, retrieves
only a validated Issue Wall artifact, and serves it on loopback.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import time
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlparse


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_DATA = ROOT / "tmp" / "web-of-scanners-local"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def run(command: list[str], *, capture: bool = False, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command, cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
    )
    return result.stdout.strip() if capture else ""


def repository_from_remote(remote: str) -> str:
    value = remote.strip().removesuffix(".git")
    if value.startswith("git@github.com:"):
        value = value.split(":", 1)[1]
    elif value.startswith("ssh://git@github.com/"):
        value = urlparse(value).path.lstrip("/")
    elif value.startswith(("https://github.com/", "http://github.com/")):
        value = urlparse(value).path.lstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("origin must identify a GitHub owner/repository")
    return value


def detect_repository() -> str:
    return repository_from_remote(run(["git", "remote", "get-url", "origin"], capture=True))


def git_identity(branch: str | None = None) -> tuple[str, str]:
    selected = branch or run(["git", "branch", "--show-current"], capture=True)
    if not selected:
        raise ValueError("detached HEAD requires --branch")
    sha = run(["git", "rev-parse", "HEAD"], capture=True).lower()
    if not SHA_RE.fullmatch(sha):
        raise ValueError("git did not return a full commit SHA")
    return selected, sha


def remote_branch_identity(repository: str, branch: str) -> tuple[str, str]:
    if not branch.strip() or any(character in branch for character in "\r\n\0"):
        raise ValueError("branch must be a non-empty single-line name")
    sha = run([
        "gh", "api", f"repos/{repository}/branches/{quote(branch, safe='')}",
        "--jq", ".commit.sha",
    ], capture=True).lower()
    if not SHA_RE.fullmatch(sha):
        raise ValueError("GitHub did not return a full branch-head SHA")
    return branch, sha


def list_branches(repository: str) -> None:
    output = run([
        "gh", "api", "--paginate", f"repos/{repository}/branches?per_page=100",
        "--jq", ".[].name",
    ], capture=True)
    print(output or "No branches returned")


def gh_token() -> str:
    token = os.environ.get("GH_TOKEN", "").strip()
    if token:
        return token
    try:
        return run(["gh", "auth", "token"], capture=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise RuntimeError("authenticate GitHub CLI first with: gh auth login") from error


def dispatch(repository: str, branch: str, sha: str, workflow_ref: str) -> None:
    if not SHA_RE.fullmatch(sha):
        raise ValueError("scan commit must be a full lowercase SHA")
    # The remote existence check prevents a confusing dispatch for an unpushed commit.
    run(["gh", "api", f"repos/{repository}/commits/{sha}", "--silent"])
    run([
        "gh", "workflow", "run", "08-full-code-analysis.yml",
        "--repo", repository, "--ref", workflow_ref,
        "-f", f"scan_branch={branch}", "-f", f"expected_sha={sha}",
    ])
    print(f"Web of Scanners dispatched for {branch} at {sha}")
    print(f"Track it at https://github.com/{repository}/actions/workflows/08-full-code-analysis.yml")


def refresh(repository: str, branch: str, data_root: Path, *, force: bool = False) -> None:
    environment = os.environ.copy()
    environment["GH_TOKEN"] = gh_token()
    command = [
        sys.executable, str(HERE / "pull_worker.py"),
        "--repository", repository, "--branch", branch,
        "--publication-root", str(data_root / "published"),
        "--state-file", str(data_root / "pull-state.json"),
    ]
    if force:
        command.append("--force")
    run(command, env=environment)


def wait_for_commit(repository: str, branch: str, sha: str, data_root: Path,
                    timeout_seconds: int, poll_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            refresh(repository, branch, data_root)
        except (RuntimeError, subprocess.CalledProcessError, ValueError) as error:
            print(f"Issue Wall not ready yet: {error}")
        state_file = data_root / "pull-state.json"
        if state_file.is_file():
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if state.get("commit_sha") == sha:
                return
        time.sleep(poll_seconds)
    raise TimeoutError(f"timed out waiting for Issue Wall at {sha}")


class IssueWallHandler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def list_directory(self, path: str):  # type: ignore[no-untyped-def]
        self.send_error(404)
        return None


def serve(data_root: Path, host: str, port: int, *, open_browser: bool = False) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Issue Wall may bind only to loopback")
    current = data_root / "published" / "current"
    if not (current / "index.html").is_file():
        raise FileNotFoundError("no local Issue Wall; run refresh or start --scan first")
    handler = functools.partial(IssueWallHandler, directory=str(current))
    url = f"http://{host}:{port}/"
    with ThreadingHTTPServer((host, port), handler) as server:
        print(f"Issue Wall is available at {url}")
        print("Press Ctrl+C to stop. This service is separate from Agentic SOC.")
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nIssue Wall stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "scan", "refresh", "serve", "status", "branches"))
    parser.add_argument("--repository", help="GitHub owner/repository; defaults to origin")
    parser.add_argument("--branch", help="branch to scan/serve; defaults to current branch")
    parser.add_argument("--workflow-ref", default="feature/static-code-analysis",
                        help="trusted branch containing the workflow definition")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--scan", action="store_true", help="dispatch a scan before start")
    parser.add_argument("--no-wait", action="store_true", help="do not wait for a new artifact")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--open", action="store_true", dest="open_browser")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    repository = args.repository or detect_repository()
    if args.command == "branches":
        list_branches(repository)
        return
    branch, sha = (remote_branch_identity(repository, args.branch)
                   if args.branch else git_identity())
    data_root = args.data_root.resolve()

    if args.command == "status":
        state_file = data_root / "pull-state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.is_file() else {}
        print(json.dumps({"repository": repository, "branch": branch, "local_commit": sha,
                          "served": state, "url": f"http://{args.host}:{args.port}/"}, indent=2))
        return
    if args.command == "scan" or (args.command == "start" and args.scan):
        dispatch(repository, branch, sha, args.workflow_ref)
        if args.command == "scan":
            return
    if args.command == "refresh":
        refresh(repository, branch, data_root, force=args.force)
        return
    if args.command == "start":
        if args.scan and not args.no_wait:
            wait_for_commit(repository, branch, sha, data_root, args.timeout, args.poll_seconds)
        elif not args.scan:
            refresh(repository, branch, data_root, force=args.force)
    serve(data_root, args.host, args.port, open_browser=args.open_browser)


if __name__ == "__main__":
    main()
