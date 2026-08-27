# External code-analysis service production readiness

## Service boundary

The service is an external engineering control plane. It analyzes the fork, downloads
immutable GitHub Actions evidence outbound, and serves a read-only current-findings
dashboard. It is not imported by, deployed with, or required by the Agentic SOC
application. It has no authority to patch code, create Issues or comments, alter refs,
change branch protection, deploy the application, contact upstream, or contact
DefectDojo.

## Security-first mission

The primary purpose of this service is to expose security weaknesses in the complete
SOC codebase. Semantic SAST, project-specific SAST, Python security, secrets,
dependency/SCA, container, and IaC evidence therefore receive first-class dashboard
visibility. Type, lint, complexity, dead-code, and coverage channels remain required
because they expose unsafe assumptions and untested or fragile security-sensitive
paths, but they do not replace security analysis.

AI review is used as a complementary threat-discovery mechanism for authorization,
trust-boundary, agent-tool, prompt-injection, and cross-file logic concerns that a
fixed rule may miss. AI output remains `AI_ADVISORY`: it is shown separately, retains
its source evidence, and requires human confirmation. It never counts as deterministic
corroboration and never gains patch, commit, blocking-check, or remediation authority.

## Automated and manual operation

- Every push/eligible PR on a branch carrying the approved definitions starts the four
  required scanner workflows, whose outputs map to 16 required structured channels.
- The dispatcher accepts only successful same-repository runs, uses the analyzed
  `head_sha`, verifies every required artifact/hash, reconciles normalized counts, and
  publishes only a complete snapshot.
- CodeRabbit reviews all PR targets in the cloud. Exact-head original bot comments use
  the separate `AI_ADVISORY` lane and never corroborate deterministic evidence.
- A valid snapshot with findings produces a neutral Check; a valid empty snapshot
  succeeds; invalid or incomplete analysis fails.
- Manual analysis verifies that the selected branch remains at the resolved SHA before
  each dispatch and after the set. Publication independently requires all four runs for
  one exact SHA, so branch movement cannot publish mixed evidence.

## Supply-chain and workflow controls

- GitHub Actions use full commit SHAs and directly installed scanner versions are
  pinned.
- Write permissions are job-scoped and limited to SARIF upload, dashboard Checks, or
  workflow dispatch. Analysis has no repository-content or collaboration write access.
- `audit_workflows.py` enforces immutable Actions, job timeouts, safe shell input,
  read-only analysis permissions, and private/pinned optional portal profiles.
- Native CI and documentation validation cover the fork default `claude/main` without
  removing the original `main` and `Testing` contracts.

## QA VM profile

The supported host is Ubuntu LTS, initially 8 vCPU, 16 GiB RAM, and 200 GiB SSD. The
outbound-only pull worker uses an Actions-read-only credential supplied through systemd,
validates archive size/path/symlink limits, and atomically retains the last valid
dashboard. The nginx container binds to `127.0.0.1:8787`, runs unprivileged and
read-only, drops all capabilities, bounds CPU/memory/PIDs/logs, denies non-read methods,
and requires the company VPN/OIDC HTTPS proxy before developer access. Readiness is
content-aware (`503` before the first validated publication); refresh retries are based
on systemd unit inactivity, corrupt optimization state cannot strand the worker, and a
bounded paginated Actions search prevents other branches from hiding the selected
branch's latest exact-head artifact.

## Deployment gates

1. Run `python scripts/code_analysis/audit_workflows.py` and all analysis-service tests.
2. Validate Compose files using the QA VM's `docker compose config`.
3. Authorize CodeRabbit and prove an exact-head review reaches `AI_ADVISORY`.
4. Use a read-only GitHub credential stored at mode `0600`.
5. Verify loopback health and company access control.
6. Run a manual scan and reconcile 16 channels, run links, hashes, and finding counts.
7. Restart the worker/container and prove the last valid snapshot remains available.

DefectDojo and CodeScene remain deferred. Their profiles require explicit secrets and
immutable image-digest variables and bind only to localhost. They are not part of the
supported dashboard service.
