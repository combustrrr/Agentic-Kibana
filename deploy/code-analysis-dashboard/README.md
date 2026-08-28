# Issue Wall deployment

**Issue Wall** is the developer portal for the coordinated **Web of Scanners**.

This profile serves the validated custom dashboard; it does not run or modify the
Agentic SOC application.

1. Install the repository at `/opt/agentic-soc-findings/repo` for the dedicated
   `agentic-findings` service account.
2. Create `/var/lib/agentic-soc-findings` and
   `/opt/agentic-soc-findings/repo/var/code-analysis`, owned by that account.
3. Write the Actions-read-only token to
   `/etc/agentic-soc-findings/github-token`, owned by root and mode `0600`.
   The service exposes it through systemd's protected credentials directory; the
   token never appears in the repository, unit environment, or process arguments.
4. Copy the `.service` and `.timer` units to `/etc/systemd/system/`, run
   `systemctl daemon-reload`, and enable the timer.
5. Start `docker compose up -d` from this directory. The server binds only to
   `127.0.0.1:8787`.
6. Put the company HTTPS/VPN/OIDC reverse proxy in front of the loopback endpoint.

The published page includes a read-only severity issue wall and links to the fork's
GitHub Actions pages for full scanning, dashboard rebuilds, run activity, and continuous
monitoring. GitHub performs authentication, authorization, branch selection, dispatch,
and audit. Never place an Actions-write token in the static page, nginx configuration,
publication directory, or pull-worker credential.

The container exposes `GET /healthz` on the loopback listener and Compose verifies it
every 30 seconds. HTML and snapshot responses use `Cache-Control: no-store`, so atomic
refreshes are visible immediately. The container runs as an unprivileged user with all
Linux capabilities dropped. CPU, memory, PID count, log size, and shutdown time are
bounded; non-read methods and dotfile paths are denied.

The worker makes outbound HTTPS requests only. It downloads a successful dashboard
artifact, validates safe extraction and snapshot contents, and atomically swaps the
`current` directory. A failed pull or validation leaves the previous dashboard served.

Do not install this public fork as a persistent self-hosted GitHub Actions runner.
