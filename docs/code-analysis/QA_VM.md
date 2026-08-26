# QA VM deployment contract

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

Example timer command:

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
needs write access only to `/srv/agentic-soc-findings` and
`/var/lib/agentic-soc-findings`; bind the dashboard container to `127.0.0.1` and put
company VPN/OIDC authentication in front of it.

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
