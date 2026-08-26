# Current-findings dashboard deployment

This profile serves the validated custom dashboard; it does not run or modify the
Agentic SOC application.

1. Install the repository at `/opt/agentic-soc-findings/repo` for the dedicated
   `agentic-findings` service account.
2. Create `/var/lib/agentic-soc-findings` and
   `/opt/agentic-soc-findings/repo/var/code-analysis`, owned by that account.
3. Install `worker.env.example` as `/etc/agentic-soc-findings/worker.env`, mode `0600`.
   Write the Actions-read-only token to the referenced root-owned credential file,
   also mode `0600`; do not place it in the repository or process arguments.
4. Copy the `.service` and `.timer` units to `/etc/systemd/system/`, run
   `systemctl daemon-reload`, and enable the timer.
5. Start `docker compose up -d` from this directory. The server binds only to
   `127.0.0.1:8787`.
6. Put the company HTTPS/VPN/OIDC reverse proxy in front of the loopback endpoint.

The worker makes outbound HTTPS requests only. It downloads a successful dashboard
artifact, validates safe extraction and snapshot contents, and atomically swaps the
`current` directory. A failed pull or validation leaves the previous dashboard served.

Do not install this public fork as a persistent self-hosted GitHub Actions runner.
