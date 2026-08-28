# Code Analysis — Pending Work

> **Prioritization date:** 2026-08-28
> **Primary objective:** improve issue detection and the unified current-findings view  
> **Not an active objective:** fixing findings or reducing the count to zero

Only work that advances trustworthy detection, evidence ingestion, visualization, or
approved hosting belongs in the near-term backlog.

## P0 — Finish current platform delivery

### P0.1 Repair and re-prove outbound dashboard publication

**Repository fix completed 2026-08-28:** the enterprise dashboard itself is accepted. Exact-Testing
orchestrator run `33102796200` and aggregation run `33103518514` succeeded for SHA
`0972ac0ab405161fc22255e622eae0bb52713d03`; artifact `9659488883` validates at 16/16
required channels with 37,372 canonical findings and 38,268 observations. GitHub CLI
download works. The Python pull worker now strips authorization on cross-origin
artifact redirects, retains same-origin authentication, validates every archive member,
and extracts only the bounded dashboard subtree. Live Windows recovery of artifact
`9659488883` succeeded. Ubuntu QA-host acceptance remains part of P0.4.

**Exit criteria:**

- reproduce the redirect behavior with a unit test that never contacts GitHub;
- follow redirects without forwarding GitHub authorization to the signed storage host;
- retain archive size, path, symlink, exact-branch/SHA, successful-run, and atomic
  last-known-good protections;
- validate manual `--artifact-id` recovery on Windows and the supported Ubuntu QA host.

### P0.2 Reconcile optional security-control truth

**Repository truth fixes completed 2026-08-28.** The optional-control board now retains
native status/family evidence and distinguishes complete, partial, and policy-finding
states. Remaining owner/vendor decisions are explicit:

- **GitHub secret protection:** owner-side inspection confirms both controls enabled and
  zero open alerts, but Actions has no `SECURITY_POSTURE_TOKEN`. Add the documented
  fork-only read token if retained workflow evidence must become `CONFIGURED_COMPLETE`.
- **Snyk:** the repository-owned job now installs all Python dependency trees in an
  isolated environment; cloud SCA and Code jobs pass. Measure unique contribution next.
  The separate Snyk PR service check is quota-blocked and is not repository-owned CI.
- **Shipping Image Trivy / OpenSSF Scorecard:** native status/family mapping and retained
  shipping-image status are implemented and regression-tested; cloud jobs pass.
- **SBOM policy:** exact SPDX matching, case/terminal-plus normalization, and within-SBOM
  deduplication are fixed. Valid denied-license findings remain visible pending owner
  attribution and exception decisions.

### P0.3 Activate and verify CodeRabbit cloud PR review

**Live integration proven 2026-08-28:** privacy/code-sharing approval received and the repository owner reports
the GitHub App installed. Automatic cloud review and incremental review after every PR
push now explicitly cover every base branch, without request-changes authority. GitHub
Checks wait for the scanner window, and exact-head inline review-comment ingestion plus
checkout-free dashboard refresh are implemented. Fork PR `#16` received a CodeRabbit
review and four native inline comments at exact head `928561b77121942bab2e054bfa3f172780cc1554`;
all four were independently verified and fixed. CodeRabbit reports that repositories
below ten stars require a manual `@coderabbitai review` trigger, so automatic delivery
cannot be claimed under the current vendor policy.

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

### P0.6 Developer issue wall and workflow controls

**Repository implementation completed 2026-08-28.** The external developer portal is
named **Issue Wall**, and its coordinated scanner system is the **Web of Scanners**. It has a
severity-first Fix queue over canonical finding identities plus developer controls for
full scanner orchestration, dashboard-only rebuild, live workflow activity, and the
scheduled latest-head supervisor. Controls link to GitHub's authenticated Actions pages;
the static board stores no token and receives no workflow-write authority. The supported
deployment remains the loopback-only nginx container behind company VPN/OIDC on the QA
VM. For the current zero-hosting path, every Actions artifact includes an offline
`dashboard/START_HERE.md` guide and a self-contained `dashboard/index.html`; GitHub run
summaries point directly to that flow. P0.4 still owns any later external host proof.
The separate local developer control plane is also complete: root
`web-of-scanners.ps1` can dispatch the trusted exact-commit orchestrator, wait for and
validate its artifact, atomically refresh ignored local state, and serve Issue Wall on
loopback. It is tooling-only and has no application runtime, image, Compose, import, or
deployment dependency. Developers can list GitHub branches and select one explicitly;
the service resolves its authoritative remote head and keeps the visualization local.

### P0.7 Local Issue Wall enterprise control experience

**Backlog added 2026-08-29.** Preserve the CLI as the automation contract while adding
an optional loopback control page that can select a permitted branch, show the resolved
commit before confirmation, dispatch Web of Scanners, display workflow/job progress,
cancel an authorized run, refresh the validated artifact, and switch among locally
retained branch snapshots. Add bounded retention, per-run audit metadata, clear stale/
failed/partial states, single-instance locking, and browser-visible diagnostics. Keep
GitHub authentication process-side, require explicit confirmation before workflow
dispatch/cancellation, use least-privilege repository permissions, and never expose a
token to HTML or JavaScript. The control page and local evidence must remain completely
outside Agentic SOC runtime, APIs, images, dependencies, telemetry, and deployment.
This boundary is policy-enforced: runtime source, dependency manifests, Dockerfiles, and
application Compose definitions are checked for reverse coupling on every analysis
policy run. Any future integration must remain observer-to-repository only.

## P1 — Improve detection breadth and evidence quality

### P1.1 Measure Snyk's unique contribution

**Completed 2026-08-28.** Exact-Testing artifact `9659304881` and the accepted snapshot
were reconciled, and post-repair artifact `9693781846` separately proved both
repository-owned Snyk surfaces complete. The dashboard now normalizes the native
`SnykCode` driver to the `Snyk` family and maps observed rules to canonical concepts.
Exact-Testing Snyk Code produced 226 observations: 14 same-concept/exact-location
overlaps, 12 additional same-location/different-concept observations, and 212 unmatched
candidates, of which 186 are low severity and only 27 are outside test files and `/test`
rule variants. Post-repair SCA produced 33 observations; 26 share a CVE/GHSA identity
with accepted OSV evidence and 7 do not. Snyk adds non-redundant evidence but remains
optional because the Code lane is noisy and the separate vendor PR check is quota-
blocked. See [`SNYK_UNIQUE_CONTRIBUTION.md`](SNYK_UNIQUE_CONTRIBUTION.md).

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
