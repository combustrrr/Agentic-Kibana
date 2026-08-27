# QA VM deployment contract

The mandatory security and release gates are maintained in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

The QA VM is an outbound-only findings host. It is **not** an Agentic SOC runtime
dependency and, because the fork is public, it must not be registered as a persistent
self-hosted GitHub Actions runner.

## Supported flows

### GitHub-hosted collection (default)

```text
GitHub-hosted scanner workflows
  -> immutable exact-commit artifacts
  -> shared pipeline.py normalization/publication build
  -> current-findings-dashboard artifact
  -> outbound-only pull_worker.py
  -> atomic local publication
  -> loopback nginx container
  -> company VPN/OIDC reverse proxy
```

The VM token requires Actions **read** access only. Prefer a repository-scoped GitHub
App installation token; a fine-grained machine-user token is the fallback. Never use a
classic personal access token.

Example interactive command (the supplied systemd unit uses `LoadCredential`
instead, so the token is not exposed in its environment):

```bash
GH_TOKEN_FILE=/etc/agentic-soc-findings/github-token
export GH_TOKEN="$(cat "$GH_TOKEN_FILE")"
python3 scripts/code_analysis/pull_worker.py \
  --repository combustrrr/Agentic-Kibana \
  --branch feature/static-code-analysis \
  --publication-root /srv/agentic-soc-findings \
  --state-file /var/lib/agentic-soc-findings/pull-state.json
```

Run it from a locked-down `systemd` oneshot service on a timer. The service account
needs write access only to `/opt/agentic-soc-findings/repo/var/code-analysis` and
`/var/lib/agentic-soc-findings`; bind the dashboard container to `127.0.0.1` and put
company VPN/OIDC authentication in front of it.

## Supervisor activation checklist

Before starting Compose, create the publication and state directories explicitly and
assign them to the dedicated account; do not let Docker create a root-owned bind source.
Install the checked-in service and timer units under `/etc/systemd/system`, then use
`systemctl daemon-reload`, enable/start `agentic-findings-pull.timer`, and inspect the
first oneshot with `systemctl status agentic-findings-pull.service` plus `journalctl -u
agentic-findings-pull.service`. The timer schedules from unit inactivity, so both a
successful refresh and a failed refresh receive another bounded attempt.

Start the dashboard container only after `docker compose config` succeeds. Its
`/healthz` endpoint returns `503` until a validated `current/index.html` exists and
returns `200` afterward. A failed refresh never replaces that current directory, so
the container remains ready and continues serving the last-known-good snapshot across
worker or host restarts. Corrupt optional pull-state JSON is ignored and rebuilt after
the next validated publication. The worker searches a bounded paginated workflow
history, preventing busy unrelated branches from starving the configured branch.

### Manual artifact recovery

GitHub Actions artifacts are the immutable handoff format: each dashboard artifact name
contains the source-scoped branch key, full analyzed SHA, and aggregation run ID; its
payload retains normalized findings, raw observations, channel status, provenance, and
SHA-256 evidence hashes. The GitHub Check is the discovery pointer, while the artifact
is the portable build record. This follows the conventional CI separation of building
once, validating, and promoting without re-running source code on the serving host.

An operator can explicitly reconstruct the current dashboard from a known artifact ID:

```bash
python3 scripts/code_analysis/pull_worker.py \
  --repository combustrrr/Agentic-Kibana \
  --branch feature/static-code-analysis \
  --artifact-id 123456789 \
  --force \
  --publication-root /srv/agentic-soc-findings \
  --state-file /var/lib/agentic-soc-findings/pull-state.json
```

Manual selection is not a bypass. The worker requires a non-expired artifact from a
successful `05-issue-aggregation.yml` run, verifies its branch-scoped identity, and
requires its analyzed SHA to equal the branch's current GitHub head. It then repeats ZIP
size, file-count, traversal, symlink, snapshot, repository, branch, and commit checks
before atomic publication. `--force` only rebuilds the serving copy of an already valid
artifact; it does not relax any validation.

### Local scanner collection (controlled use)

Local scanners may write the same filenames defined in
`required-channels.json` into one exact-commit artifact directory. Feed that directory
to the same command used by Actions:

```bash
python3 scripts/code_analysis/pipeline.py \
  --artifacts /var/lib/agentic-soc-findings/scans/$COMMIT/raw \
  --output /var/lib/agentic-soc-findings/scans/$COMMIT/result \
  --repository combustrrr/Agentic-Kibana \
  --commit "$COMMIT" \
  --branch feature/static-code-analysis \
  --workflow-run-id "local:$COMMIT" \
  --manifest config/code-analysis/required-channels.json \
  --publication-root /srv/agentic-soc-findings
```

The command fails closed when a required channel is missing, an artifact is corrupt,
normalization fails, or counts do not reconcile. It builds in staging and only exposes
the new `current` directory after validation. The former `current` directory is retained
only as `previous` rollback protection.

Do not scan during Agentic SOC application startup. Use a timer, a controlled manual
run, or an approved post-commit workflow. The dashboard continues serving the last
validated snapshot while collection runs.

## Initial sizing

The requested Ubuntu LTS VM with 8 vCPU, 16 GiB RAM, and 200 GiB SSD is appropriate
for the dashboard, pull worker, local scanner evaluation, and one evaluation findings
service. Do not co-locate production SonarQube, DefectDojo, their databases, and
untrusted scan execution on this single initial host without measuring and separating
resource/security boundaries.
