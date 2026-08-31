# Code Analysis — Pending Work

> **Prioritization date:** 2026-08-31
> **Primary objective:** improve issue detection and the unified current-findings view  
> **Not an active objective:** fixing findings or reducing the count to zero

This file is the **only active code-analysis backlog**. Companion documents may record
current behavior, durable decisions, or historical evidence, but must link here instead
of maintaining another list of pending work or next steps.

Only work that advances trustworthy detection, evidence ingestion, visualization, or
authenticated artifact delivery belongs in the near-term backlog.

## P0 — Finish current platform delivery

### P0.1 Prove the latest-head pipeline and redesigned Issue Wall in Actions

- Push a new commit to a non-default fork branch and prove stale same-branch scanner and
  aggregation runs are canceled while the new exact SHA completes automatically.
- Run **Full Code Analysis (Manual)** with an explicit branch and prove GitHub resolves
  its authoritative head, reuses retained exact-SHA evidence, dispatches only missing
  groups, and streams all four groups concurrently.
- Prove the supervisor defers to active push/PR work and sends four complete retained
  evidence sets directly to aggregation without rescanning.
- Download the artifact and visually accept the report-first desktop and narrow layouts,
  source locations, severity colors, charts, filtering, evidence dialog, and CSV export.
- Capture actual elapsed time, billed runner minutes, cache behavior, artifact size, and
  reuse/cancellation savings. Set explicit budgets before further workflow expansion.
- Run pinned `actionlint` and ShellCheck in the authoritative Linux CI environment; the
  local Windows host does not provide `actionlint`.

**Exit criteria:** one immutable branch-head SHA passes automatic and manual paths with a
publishable 16-channel artifact, no duplicate full scan, a visually accepted Issue Wall,
recorded timing/cost evidence, and all workflow-policy checks green.

### P0.2 Reconcile fork pull requests after the default-branch upgrade

- Inventory the currently open Dependabot PRs; do not rely on the historical PR count or
  checks from before the current default-branch workflow contract.
- Rebase/regenerate each candidate, review breaking major-version upgrades separately,
  and close only demonstrably superseded duplicates.
- Do not bulk merge dependency changes; require current CI, scanner, release-image, and
  compatibility evidence per PR.
- GitHub Issues are disabled on the fork, so the dashboard remains the findings backlog
  unless a separate issue-synchronization objective is approved.

### P0.3 Upstream contribution minimalization gate

**Required before any upstream pull request; no upstream contribution is authorized
yet.** Convert the fork-proven Web of Scanners and Issue Wall work into the smallest
enterprise-maintainable change set. Fork history, experiments, and implementation
volume are not evidence that a file belongs upstream.

Required review:

- Produce a file-by-file manifest mapping every proposed file to an active workflow,
  required evidence contract, security control, regression test, or authoritative
  operator document. Remove anything without a current consumer and named owner.
- Restrict implementation ownership to the numbered cloud-analysis workflows,
  `config/code-analysis/`, `scripts/code_analysis/`, essential pinned tool configuration,
  and a minimal authoritative documentation set. Preserve the enforced prohibition on
  Agentic SOC runtime imports, dependencies, images, Compose, startup, or deployment
  coupling.
- Exclude generated dashboards, SARIF/JSON scanner output, downloaded Actions artifacts,
  caches, temporary proof, machine-specific state, credentials, personal paths, tenant
  details, local servers, pull workers, nginx/systemd/VM profiles, and workstation
  launchers.
- Remove dead modules, duplicate parsers or contracts, unused compatibility entry
  points, redundant workflow steps, superseded handoffs, repetitive status prose, and
  implementation journals from the proposed upstream diff. Durable decisions and
  necessary operational guidance must be consolidated rather than copied repeatedly.
- Do not include DefectDojo, SonarQube, CodeScene, new issue synchronization, remediation,
  autofix, or other speculative/deferred integrations until measured unique value,
  security boundaries, ownership, and maintenance cost are independently accepted.
- Measure and document workflow duration, runner usage, artifact size, retention,
  permissions, secret requirements, external services, dependency count, failure modes,
  and expected maintenance burden. Establish explicit budgets and explain exceptions.
- Re-run exact-upstream-head cloud proof from fork-owned workflows, all repository policy
  and regression gates, artifact reconciliation, and negative architecture-boundary
  tests against the minimal candidate—not the larger development branch.
- Split the eventual proposal into small reviewable phases with reversible adoption.
  Each phase must remain useful, secure, and internally coherent on its own; do not use
  a large platform-shaped pull request to hide unrelated changes.

**Exit artifact:** an upstream-candidate branch plus a review document containing the
file manifest, dependency/permission delta, measured cost and artifact budgets, removed
file list, residual risks, rollback plan, and exact fork-run proof. An owner must approve
that artifact before any upstream PR is opened.

### P0.4 Resolve license and external-tool eligibility

The repository is publicly readable but currently publishes no license. Its README
explicitly says source availability does not grant open-source rights. Do not describe
the project as OSS or apply for an OSS maintainer/sponsorship program until the owner
chooses and publishes an appropriate license after legal/ownership review.

The [Ossium OSS perks catalog](https://ossium.in/oss-perks) is useful discovery evidence,
not eligibility authority. Vendor terms and data-access permissions must be verified
directly before each activation.

| Candidate | Potential backlog value | Current disposition |
|---|---|---|
| [SonarQube Cloud](https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-subscription/subscription-plans) | P1.1 semantic quality/security comparison; the public-project Free plan is independent of the OSS sponsorship plan | **Analysis verified; native import credential pending:** bounded export/parser and the loop-safe outbound projection are implemented, but the existing execute-analysis token receives HTTP 403 from the Browse-protected issues API. Configure a separate `SONAR_API_TOKEN` belonging to a user with project Browse permission, then prove the artifact before promotion. |
| [Blacksmith](https://www.blacksmith.sh/) | Measure faster runners/cache downloads against P0.1 Actions duration and cost | **High-value performance candidate** after direct eligibility, permissions, runner trust, and data-boundary review |
| [BrowserStack OSS](https://www.browserstack.com/open-source) | Cross-browser and responsive Issue Wall acceptance | **License-blocked OSS application**; use no sponsored entitlement until eligibility is truthful |
| Argos/Chromatic | Automated visual-regression evidence for the self-contained dashboard | **Evaluate after BrowserStack**, with screenshot retention, GitHub App permissions, badge obligations, and unique value reviewed |
| Snyk | Existing optional SCA/SAST lane already contributes evidence | **Already configured and verified:** pinned CLI SCA + Code scans use `SNYK_TOKEN`, retain SARIF/status/log artifacts, and remain optional; do not add a second Snyk integration |
| [CodeRabbit](https://docs.coderabbit.ai/management/plans) | Exact-head AI review advisories for pull requests | **Already configured and verified:** the GitHub App, `.coderabbit.yaml`, exact-head evidence collector, and dashboard refresh path are present; public-repository access does not require an OSS entitlement claim |
| [Qodo](https://www.qodo.ai/pricing/) | Alternative AI pull-request review | **Do not activate in parallel with CodeRabbit:** the normal plan is trial/paid and free OSS access requires qualification; first approve a measured replacement comparison and resolve licensing |
| Codacy/DeepSource/Code Climate | Additional hosted quality/SAST dashboards | **Defer as overlapping** until SonarQube proves or fails unique contribution |
| 1Password OSS | Shared scanner/vendor credentials | **License-blocked and unnecessary today**; current secrets remain GitHub-managed |

**Exit criteria:** an owner decision on licensing; a per-vendor record of eligibility,
requested GitHub permissions, source/artifact data shared, retention, terms, revocation,
badge/attribution duties, expected unique evidence, and cost after the perk ends. Activate
only one bounded evaluation at a time and remove it if it does not add exportable value.

## P1 — Improve detection breadth and evidence quality

### P1.1 Evaluate SonarQube

- The bounded public-project evaluation is active without an OSS entitlement claim.
  Exact-commit run `33397472946` attempt 2 indexed 767 product files and uploaded
  revision `8d52a6156d4bcaed01f8ea2686af85299b3c7242`; both the Actions job and Sonar check
  passed. The first baseline took 14m18s, so automatic Sonar work is limited to product
  source/config changes while manual branch analysis remains available.
- Cloud-native issue export and normalized ingestion are implemented. Cloud runs
  `33404195186` and `33405919866` proved the scanner but truthfully retained
  `CONFIGURED_PARTIAL`: the current execute-analysis token receives HTTP 403 because
  `api/issues/search` requires project Browse permission. Add a separate GitHub Actions
  secret named `SONAR_API_TOKEN` from a Sonar user with Browse permission, then rerun
  Code Quality and verify `sonar-native-issues.json`. Imported external issues are
  excluded so projections cannot loop.
- The canonical build emits `normalized/sonar-external-issues.json` for compatible
  code-local deterministic findings. Sonar-native findings and `AI_ADVISORY` findings
  (including CodeRabbit) are excluded. Automatic re-analysis with that projection remains
  pending a measured design that does not double the expensive Sonar scan.
- Measure unique contribution and retain Sonar only if it adds useful issues not already
  represented.

### P1.2 Evaluate CodeScene

- Confirm OSS eligibility/license and a stable export API/file.
- Prioritize behavioral hotspots/health signals that static scanners do not provide.
- Do not scrape the visual UI or count non-exportable scores as canonical findings.

### P1.3 Expand project-specific detection

- Continue reviewing `AGENTS.md`, auth/RBAC, agent tools, LLM boundaries, Elasticsearch
  query construction, state reset, connectors, and middleware for narrowly testable rules.
- Add every new claimed concept to the canary contract with retained tool/rule/location
  evidence and false-positive fixtures.
- Prefer meaningful new surfaces over redundant scanner count.

### P1.4 Verify GitHub-native secret posture

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

- DefectDojo deployment, persistent finding lifecycle, or SLA tracking. Human triage is
  intentionally outside the Issue Wall product contract, not a pending feature.
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
