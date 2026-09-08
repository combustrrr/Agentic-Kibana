"""Register this launcher's GitHub App without printing its client secret."""
from __future__ import annotations

import argparse
import html
import json
import secrets
import subprocess
import threading
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-origin", required=True)
    parser.add_argument("--dashboard-url", required=True)
    args = parser.parse_args()
    worker = urllib.parse.urlsplit(args.worker_origin)
    dashboard = urllib.parse.urlsplit(args.dashboard_url)
    if worker.scheme != "https" or worker.path not in {"", "/"} or worker.query or worker.fragment:
        raise SystemExit("Worker origin must be an HTTPS origin")
    if dashboard.scheme != "https" or not dashboard.netloc:
        raise SystemExit("Dashboard URL must use HTTPS")

    state = secrets.token_urlsafe(32)
    result: dict[str, str] = {}
    ready = threading.Event()
    manifest = {
        "name": "Kavach Code Analysis Launcher - combustrrr",
        "url": args.dashboard_url,
        "redirect_url": "http://127.0.0.1:8979/created",
        "callback_urls": [args.worker_origin.rstrip("/") + "/auth/callback"],
        "setup_url": args.dashboard_url,
        "public": False,
        "request_oauth_on_install": False,
        "hook_attributes": {"url": args.worker_origin.rstrip("/") + "/webhook", "active": False},
        "default_events": [],
        "default_permissions": {
            "actions": "write",
            "contents": "read",
            "metadata": "read",
            "pull_requests": "read",
        },
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/":
                body = f"""<!doctype html><meta charset=utf-8><title>Create analysis GitHub App</title>
<h1>Create the analysis launcher GitHub App</h1><p>GitHub will show the requested repository permissions before creation.</p>
<form method=post action=https://github.com/settings/apps/new>
<input type=hidden name=state value="{html.escape(state)}"><textarea hidden name=manifest>{html.escape(json.dumps(manifest))}</textarea>
<button type=submit>Create GitHub App on GitHub</button></form>"""
                self.send_response(200)
            elif parsed.path == "/created":
                query = urllib.parse.parse_qs(parsed.query)
                if query.get("state") != [state] or len(query.get("code", [])) != 1:
                    self.send_response(401)
                    body = "GitHub App creation state did not match. Close this page."
                else:
                    result["code"] = query["code"][0]
                    self.send_response(200)
                    body = "GitHub App created. You can close this page and return to Codex."
                    ready.set()
            else:
                self.send_response(404)
                body = "Not found"
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 8979), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webbrowser.open("http://127.0.0.1:8979/")
    if not ready.wait(600):
        server.shutdown()
        raise SystemExit("Timed out waiting for GitHub App creation")
    server.shutdown()

    request = urllib.request.Request(
        f"https://api.github.com/app-manifests/{result['code']}/conversions",
        method="POST",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "code-analysis-launcher"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        app = json.load(response)
    client_id = app["client_id"]
    subprocess.run(
        ["npx.cmd", "--yes", "wrangler@4.129.1", "secret", "put", "GITHUB_CLIENT_SECRET"],
        input=app["client_secret"] + "\n",
        text=True,
        check=True,
    )
    config_path = Path(__file__).with_name("wrangler.jsonc")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["vars"]["GITHUB_CLIENT_ID"] = client_id
    config["preview_urls"] = False
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"GitHub App created: {app['html_url']}")
    print(f"GitHub App client ID configured: {client_id}")
    print(f"Install URL: https://github.com/apps/{app['slug']}/installations/new")
    webbrowser.open(f"https://github.com/apps/{app['slug']}/installations/new")


if __name__ == "__main__":
    main()
