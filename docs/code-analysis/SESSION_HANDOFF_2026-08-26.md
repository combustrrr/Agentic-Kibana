# Code Analysis Fresh-Chat Handoff — 2026-08-26

> **Read this first in the next chat.** This is a concise operational handoff, not a
> replacement for [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) or the
> authoritative [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md).

## 1. Actual objective

Build an external, read-only multi-scanner service that answers:

> What issues do the configured scanners currently detect across this branch's complete
> codebase, and how can developers inspect them in one clean view?

The active product is:

```text
selected branch head
  -> complementary scanner web
  -> retained raw evidence
  -> normalize and conservatively deduplicate
  -> every canonical current finding
  -> one searchable hosted dashboard
```

The goal is detection and visualization, **not** reducing findings to zero. History,
lifecycle, DefectDojo, triage analytics, remediation, patches, autofix, GitHub Issue
creation, blocking checks, and trend analytics are deferred.

## 2. Repository and safety boundary

- Working fork: `combustrrr/Agentic-Kibana` (`origin`).
- Original company repository: `ARYDESTROYER/Agentic-Kibana` (`upstream`), read-only.
- Development branch: `feature/static-code-analysis`.
- Fork default/dispatcher branch: `claude/main`.
- Current accepted implementation commit: `14874b1` on both fork branches.
- Fork `Testing` matched upstream `Testing` at `0972ac0` when verified on 2026-08-26.
- Fork analysis/default and upstream `main` were divergent; do not describe them as
  upstream-synchronized and do not mutate upstream.
- No active analysis workflow creates Issues/comments, patches, commits, branches,
  deployments, DefectDojo requests, application changes, or production changes.

The default and analysis branches are mirrored only so GitHub uses the approved workflow
definitions. That internal mirroring is separate from upstream synchronization.

## 3. Implemented scanner web

Four required workflows produce 16 structured channels:

| Workflow | Required channels |
|---|---|
| `01-code-quality.yml` | Ruff, Pyright, ESLint, TypeScript, Bandit |
| `02-security-sast.yml` | CodeQL, Semgrep |
| `03-dependency-security.yml` | OSV-Scanner, Gitleaks, Trivy, Checkov, Hadolint |
| `04-code-health.yml` | Vulture, Radon, Xenon, Coverage.py |

Additional lanes:

- Snyk SCA + Code is token-gated, scan-only, and optional; `SNYK_TOKEN` is configured.
- CodeRabbit is configured as cloud PR review and separate `AI_ADVISORY`; a real App
  review on the fork still needs proof.
- Dependency Review is PR-only.
- Schemathesis/API fuzzing is isolated and manual, not part of the required static gate.
- SonarQube and CodeScene remain evaluation candidates, not implemented canonical sources.
- DefectDojo is deferred and must not drive the current architecture.

AI output never counts as deterministic corroboration and cannot block, patch, suppress,
or remediate.

## 4. Dashboard product

The custom static dashboard is the developer visualization, separate from Agentic SOC.
It provides:

- all deterministic canonical findings;
- a dedicated Security Focus scope;
- a separately labelled AI Advisory scope;
- exact snapshot commit, branch, generation time, and channel completeness;
- canonical and raw-observation counts;
- severity/category/component/directory/concept/scanner distributions;
- search and compound filtering;
- 50/100/250-row bounded pagination (never mounts the full backlog);
- finding drill-down with every scanner/channel/rule/native ID/message/location;
- workflow-run links, scanner versions, artifact references, and SHA-256 proof; and
- complete snapshot and raw-evidence downloads.

The same generated site is served locally or on the future QA VM using
`deploy/code-analysis-dashboard/`. The hardened container binds `127.0.0.1:8787`, is
read-only, and is intended to sit behind company VPN/OIDC. Recommended VM starting size:
Ubuntu LTS, 8 vCPU, 16 GiB RAM, 200 GiB SSD, outbound HTTPS to GitHub.

## 5. Automated and manual behavior

- Pushes and PRs run the four required workflows automatically only when the relevant
  pushed/base branch contains those workflow definitions. The analysis/default branches
  do; the clean upstream-mirrored `Testing` branch currently does not.
- Where PR automation is active, it scans the exact PR head rather than GitHub's
  synthetic merge commit.
- `Full Code Analysis (Manual)` is the one-click operator workflow.
- Operator chooses the workflow definition from `claude/main` and enters any fork branch,
  for example `Testing`.
- The orchestrator resolves and locks that branch's current 40-character SHA.
- Approved workflow definitions run from `claude/main`; scanner source checkouts remain
  pinned to the selected branch SHA.
- Analysis-only dependencies/config/rules/normalizers are sparsely checked out into
  `.analysis-tooling`, so a clean upstream branch need not contain the service code.
- Each manual scanner run has a deterministic `<workflow> · <branch> · <SHA>` title.
- The orchestrator waits for all four exact-title runs, then starts one dashboard build.
- The dashboard publishes only after all required channels and evidence reconcile.

This split is intentional: the workflow/tooling commit identifies the trusted analysis
implementation; the input SHA identifies the codebase being analyzed.

## 6. Important verified evidence

- Historical accepted snapshot run `32578162932`: 8,535 canonical findings.
- Improved real dashboard run `32940124398` published the refined current-findings UI.
- Platform acceptance around run `32938363593` proved 16/16 required channels and a
  10/10 canary run (`32938363577`).
- Snyk run `32965286130` verified authenticated Open Source and Code scanning evidence.
- Local 10,000-finding benchmark completed in 9.65 seconds at 147.48 MiB peak Python
  allocation, producing 13,000 observations and a 13.55 MB bounded dashboard.
- Latest local validation after commit `14874b1`: affected workflow YAML parsed,
  executable service policy passed, 37/37 service tests passed, 79-page documentation
  consistency passed, and `git diff --check` passed.

Do not claim the latest manual cross-branch pipeline is accepted until the next cloud
rerun completes successfully.

## 7. Recent failures and fixes

### Manual run `Analyze branch · Testing #1`

Failed immediately with `fatal: not a git repository`. Root cause: checkout-free
orchestrator used `gh` without explicit repository context.

Fixes:

- `3241d0b`: set trusted `GH_REPO` for all GitHub CLI operations.
- `c5b2eb3`: execute scanner workflow definitions from fork default rather than requiring
  the selected source branch to contain those workflow files.

### Manual run `Analyze branch · Testing #2`

Dispatched workflows, then failed. Ruff could not find
`scripts/code_analysis/audit_workflows.py`; Bandit consequently produced no JSON/SARIF.
GitHub displayed downstream missing-artifact errors. CodeQL configuration also reported
failed runs. Root cause: the clean upstream `Testing` checkout does not contain analysis
service scripts/configuration. A second orchestration defect searched manual runs by the
scanned SHA even though GitHub records `workflow_dispatch` runs against the definition
ref.

Fix `14874b1`:

- separate target source checkout from trusted sparse `.analysis-tooling` checkout;
- point Ruff/Bandit/Semgrep/CodeQL/health jobs at the appropriate trusted configs/tools;
- add deterministic branch/SHA run titles to workflows 01–04; and
- locate manual scanner artifacts by exact run title instead of incorrect dispatch SHA.

Node 20 and CodeQL Action v3 messages shown in run #2 were deprecation warnings, not the
root cause. No insecure compatibility override was enabled. Updating pinned Actions to
supported major versions remains follow-up work and requires verifying immutable SHAs.

## 8. Exact next steps

1. In GitHub Actions, open **Full Code Analysis (Manual)**.
2. Choose **Use workflow from: `claude/main`**.
3. Enter **`Testing`** as `scan_branch`.
4. Run it and verify all four exact-title scanner workflows succeed.
5. Verify the orchestrator starts one `Dashboard · Testing · <Testing SHA>` run.
6. Verify the dashboard run publishes a complete artifact with 16/16 required channels,
   reconciled counts/hashes, Snyk status, and a visible Check/artifact link.
7. If it fails, capture the first failing step and its bounded diagnostic. Fix the root
   cause; do not weaken publishability or mark missing evidence successful.
8. Only after the cloud run passes, update `IMPLEMENTATION_STATUS.md`,
   `PENDING_WORK.md`, `EXECUTION_PLAN.md`, and `Journal.md` with the accepted run IDs.

After cloud acceptance, the next external gates are CodeRabbit App proof and QA-VM
deployment/restart/failed-refresh acceptance. A separate design decision is still needed
for automatic analysis of branches that intentionally do not contain service workflows;
do not use `pull_request_target` or broaden write authority casually. Until then, use the
manual exact-branch orchestrator for `Testing` and similar clean mirror branches.

## 9. Useful commands for the next agent

```powershell
git status --short --branch
git fetch --prune origin
git fetch --prune upstream
python scripts/code_analysis/audit_workflows.py
python -m unittest scripts.code_analysis.test_service
python scripts/check_docs.py
git diff --check
```

Do not assume `actionlint` is installed locally. It was unavailable in the final shell;
use it when available, but report its absence honestly.
