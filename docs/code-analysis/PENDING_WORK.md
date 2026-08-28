# Code Analysis — Pending Work

> **Prioritization date:** 2026-08-28
> **Primary objective:** improve issue detection and the unified current-findings view  
> **Not an active objective:** fixing findings or reducing the count to zero

Only work that advances trustworthy detection, evidence ingestion, visualization, or
approved hosting belongs in the near-term backlog.

## P0 — Finish current platform delivery

### P0.1 Repair and re-prove outbound dashboard publication

**Current state:** the enterprise dashboard itself is accepted. Exact-Testing
orchestrator run `33102796200` and aggregation run `33103518514` succeeded for SHA
`0972ac0ab405161fc22255e622eae0bb52713d03`; artifact `9659488883` validates at 16/16
required channels with 37,372 canonical findings and 38,268 observations. GitHub CLI
download works. The Python pull worker receives HTTP 401 when `urllib` follows GitHub's
authenticated artifact redirect on this Windows host.

**Exit criteria:**

- reproduce the redirect behavior with a unit test that never contacts GitHub;
- follow redirects without forwarding GitHub authorization to the signed storage host;
- retain archive size, path, symlink, exact-branch/SHA, successful-run, and atomic
  last-known-good protections;
- validate manual `--artifact-id` recovery on Windows and the supported Ubuntu QA host.

### P0.2 Reconcile optional security-control truth

The first complete expansion run produced evidence, but four supervisor statuses need
resolution before the optional-control board is fully trustworthy:

- **GitHub secret protection:** API evidence is `UNAVAILABLE` for secret scanning,
  push protection, and alerts. Confirm repository settings and token visibility; never
  broaden retained data beyond state/count/alert number.
- **Snyk:** Code analysis succeeded, but Open Source SCA is `CONFIGURED_PARTIAL` because
  three Python manifests reported `Missing required packages`; npm projects completed.
  Build isolated dependency environments or use supported lock/export inputs, then
  measure overlap and unique findings.
- **Shipping Image Trivy / OpenSSF Scorecard:** jobs and artifacts succeeded, but their
  dashboard catalog rows remain `PENDING_REVIEW`. Add truthful family/status mapping or
  native status documents and regression fixtures.
- **SBOM policy:** 568 packages yielded 1,265 license observations and 396 denied-license
  observations (298 canonical findings). Review duplicate CycloneDX/SPDX evidence,
  validate package/license attribution, define approved exceptions, and keep policy
  findings visible until an owner decision.

### P0.3 Activate and verify CodeRabbit cloud PR review

**Current state:** privacy/code-sharing approval received and the repository owner reports
the GitHub App installed. Automatic cloud review and incremental review after every PR
push now explicitly cover every base branch, without request-changes authority. GitHub
Checks wait for the scanner window, and exact-head inline review-comment ingestion plus
checkout-free dashboard refresh are implemented. A real fork PR review remains unverified.

**Exit criteria:**

- confirm the installed CodeRabbit GitHub App is authorized for this fork only;
- open or update an eligible fork PR and verify automatic incremental review after a push;
- verify dashboard adapter output is `AI_ADVISORY`, retains native evidence, rejects
  stale comments, and never contributes deterministic corroboration;
- determine whether it adds non-redundant findings;
- confirm the app has no upstream-company repository access and cannot apply patches.

### P0.4 Deploy the dashboard to the company QA VM

**Dependency:** company-provided Ubuntu LTS VM.

**Exit criteria:**

- 8 vCPU / 16 GiB RAM / 200 GiB SSD or measured equivalent;
- outbound GitHub HTTPS and no inbound GitHub webhook requirement;
- repository-scoped read credential loaded from a protected file/systemd credential;
- pull worker verifies and atomically publishes an exact-commit artifact;
- container binds `127.0.0.1` and runs read-only with dropped capabilities;
- company VPN/OIDC protects developer access;
- restart test proves the current snapshot remains available;
- failed refresh test proves the prior snapshot remains served.

### P0.5 Reconcile fork pull requests after the default-branch upgrade

- Twelve open Dependabot PRs remain. Their displayed checks predate the accepted
  `acc4aa5` default-branch workflow contract and several show superseded CI failures.
- Rebase/regenerate each candidate, review breaking major-version upgrades separately,
  and close only demonstrably superseded duplicates.
- Do not bulk merge dependency changes; require current CI, scanner, release-image, and
  compatibility evidence per PR.
- GitHub Issues are disabled on the fork, so the dashboard remains the findings backlog
  unless a separate issue-synchronization objective is approved.

## P1 — Improve detection breadth and evidence quality

### P1.1 Measure Snyk's unique contribution

- Use exact-Testing artifact `9659304881` from run `33102828962` as the current baseline.
- Repair the three unresolved Python dependency manifests; Snyk Code succeeded and npm
  SCA completed, but the overall SCA surface is truthfully `CONFIGURED_PARTIAL`.
- Reconcile Snyk observations/canonical findings in the custom dashboard.
- Measure overlap with OSV, CodeQL, Semgrep, and other existing families.
- Keep Snyk optional unless unique value and acceptable reliability are demonstrated.

### P1.2 Evaluate SonarQube

- Use the QA VM only after core hosting is stable.
- Configure read-only analysis and authenticated machine-readable issue export.
- Ingest into the normalizer rather than making SonarQube a competing canonical UI.
- Retain only if it adds useful issues not already represented.

### P1.3 Evaluate CodeScene

- Confirm OSS eligibility/license and a stable export API/file.
- Prioritize behavioral hotspots/health signals that static scanners do not provide.
- Do not scrape the visual UI or count non-exportable scores as canonical findings.

### P1.4 Expand project-specific detection

- Continue reviewing `AGENTS.md`, auth/RBAC, agent tools, LLM boundaries, Elasticsearch
  query construction, state reset, connectors, and middleware for narrowly testable rules.
- Add every new claimed concept to the canary contract with retained tool/rule/location
  evidence and false-positive fixtures.
- Prefer meaningful new surfaces over redundant scanner count.

### P1.5 Verify GitHub-native secret posture

- Run the implemented read-only posture job and confirm secret-scanning and
  push-protection state on the fork; an owner must enable disabled settings.
- Keep Gitleaks as retained cross-platform evidence.
- Do not expose detected secret values in dashboard artifacts.

## P2 — Optional dynamic and contextual discovery

### P2.1 Schemathesis operational evaluation

- Boot the bounded test backend in an isolated environment.
- Run the manual/weekly workflow and verify `DYNAMIC` dashboard visibility.
- Measure duration/flakiness before considering per-commit dynamic execution. The
  latest-head supervisor intentionally covers required static scanners only.

### P2.2 Atheris execution validation

- Observe the first scheduled/manual Linux campaign for the implemented deterministic
  case-decision harness and retain its status/crash artifact.
- Extend only to pure parsers or state machines with bounded inputs and no external
  side effects.
- Keep outside the static publishability gate.

### P2.3 Other AI review tools

- Consider Qodo or PR-Agent only if CodeRabbit is unavailable or a measured comparison
  is approved.
- Keep all output advisory and separate from deterministic evidence.

## Deferred — Requires a new objective and approval

- DefectDojo deployment, persistent finding lifecycle, SLA, or triage history.
- Historical trends, commit ancestry, `NEW/MOVED/NOT_OBSERVED` as the primary product.
- GitHub Issue synchronization or Projects boards.
- Autofix, patches, dependency auto-merge, Copilot Autofix invocation, or AI remediation.
- Blocking branch protection or required custom Checks.
- Upstream/company repository integration or production deployment.
- Product-finding remediation, release assignment, and security-fix PRs. The accepted
  dashboard supplies the backlog, but changing Agentic SOC source requires a separate
  remediation objective, human triage, and normal reviewed commits.

## Explicit non-goals

- Do not hide old findings to make totals look smaller.
- Do not define success as zero issues.
- Do not claim the application is secure.
- Do not publish unsupported vulnerability-detection percentages.
- Do not treat an optional/deferred tool as completed coverage because its config exists.
