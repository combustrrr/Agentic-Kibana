# Code Analysis — Pending Work

> **Prioritization date:** 2026-09-01
> **Primary objective:** trustworthy detection and one normalized current-findings view
> **Not an objective:** triage workflows, fixing findings, or reducing the count to zero

This is the only active code-analysis backlog. Other documents describe current behavior,
durable decisions, or historical evidence and must link here instead of carrying their own
next-step lists.

Shutdown checkpoint: branch `feature/static-code-analysis` is pushed through `6c13d2e`.
Resume with P0 step 1; do not replace either PAT or repeat the Browse grant.

## P0 — Unblock and prove Sonar native ingestion

Both GitHub secrets are valid PATs and exact-SHA Sonar analysis succeeds. Run
`33429643637` authenticated both PATs as `combustrrr-Uw7cT@github` and Sonar accepted an
explicit project Browse grant with HTTP 204. The project is public and main-project issues
are anonymously readable, but the same user still receives HTTP 403 for both short- and
long-lived non-main branches. This matches the organization's current Free-plan behavior:
Sonar stores non-main analysis but does not expose its results until the organization has
Team, Enterprise, or the free OSS plan. The stable `branch-issue-wall-<hash>` projection
is ready and Issue Wall retains the real branch and exact SHA.

1. Complete Sonar's web-based **Get SonarQube for OSS** enrollment for organization
   `combustrrr`. Sonar exposes no supported CLI/Web API operation for changing to OSS.
   The repository is public but currently has no published license; complete the legal/
   ownership decision and publish an eligible license before claiming OSS eligibility.
2. After Sonar confirms OSS activation, re-run only **Code Quality** for the current
   branch head and confirm the projected branch issues API returns HTTP 200.
3. Require `sonar-status.json` = `CONFIGURED_COMPLETE` and retain
   `sonar-native-issues.json` with the exact branch, commit, analysis ID, bounded count,
   and zero imported `external_*` issues.
4. Let exact-SHA aggregation finish and prove Sonar findings appear in the canonical
   Issue Wall while `normalized/sonar-external-issues.json` contains compatible
   deterministic code-local non-Sonar findings only. CodeRabbit must remain excluded as
   `AI_ADVISORY`.

Cloud runs through `33429643637` completed native analysis and truthfully retained
`CONFIGURED_PARTIAL`. Anonymous main-project issue search returns HTTP 200 with 1,135
issues. The latest run proves this is no longer a token or Browse-grant problem; access to
stored non-main analysis is the remaining subscription entitlement. Do not call native
ingestion operational until the four checks above pass.

## P1 — Finish acceptance and cost budgets

- Download the final artifact and visually accept desktop and narrow layouts, fresh
  severity colors, charts, filtering, source locations, evidence dialog, and CSV export.
- Record billed runner minutes and cache behavior. Manual run `33414567342` already
  proved exact-head orchestration and immutable dashboard publication in 8m20s; dashboard
  run `33415271105` completed in 48s and retained a 16,429,426-byte artifact with 16/16
  required channels, 15,780 canonical findings, and 16,547 observations. Sonar run
  `33414505282` took 17m03s and remains the dominant lane; do not add a second automatic
  Sonar scan for the outbound projection.
- Run pinned `actionlint` and ShellCheck in Linux CI and retain their results.

## P2 — Measure optional evidence value

- Measure Sonar-native unique findings against the canonical scanner web. Retain Sonar
  only if it adds useful non-duplicate evidence.
- Evaluate CodeScene only after license/eligibility and machine-readable export review.
  Do not add overlapping hosted scanners merely to increase tool count.
- Consider Qodo or PR-Agent only if CodeRabbit becomes unavailable or a measured
  replacement comparison is explicitly approved. All such output stays advisory.

## P3 — Repository governance

### License and external-service eligibility

The repository is publicly readable but publishes no license. Do not describe it as OSS
or claim OSS sponsorship eligibility until the owner completes legal/ownership review and
publishes a suitable license. The Ossium catalog is discovery evidence, not eligibility
authority. Verify vendor permissions, shared data, retention, revocation, attribution,
cost, and expected unique evidence before any new activation.

Already active:

- Snyk: verified optional SCA/SAST; do not add a second integration.
- CodeRabbit: verified exact-head GitHub App evidence; permanently isolated under
  `AI_ADVISORY`.
- SonarQube Cloud: analysis, both PATs, and the explicit Browse grant are verified;
  native non-main import awaits Sonar OSS-plan activation and one exact-head proof run.

Candidates such as Blacksmith, BrowserStack, Argos/Chromatic, CodeScene, Qodo, Codacy,
DeepSource, Code Climate, and 1Password require a separate measured decision. Do not
activate overlapping services by default.

### Fork pull requests

- Inventory current Dependabot PRs, regenerate stale candidates, review major upgrades
  separately, and never bulk merge without current CI/scanner evidence.

### Any future upstream contribution

- Produce a minimal file-by-file manifest, permission/dependency delta, measured cost
  budget, rollback plan, and exact fork proof. No upstream PR is currently authorized.
- Exclude generated artifacts, credentials, local services, dead experiments, product
  remediation, and unmeasured external integrations.

## Outside the Issue Wall objective

These are not pending Issue Wall features:

- assignment, acceptance, suppression, closure, SLA, or other human-triage state;
- DefectDojo or another persistent finding lifecycle;
- historical/ancestry lifecycle as the primary product;
- GitHub Issue or Projects synchronization;
- autofix, patches, dependency auto-merge, Copilot Autofix, or AI remediation;
- blocking branch protection or required custom Checks;
- upstream/company integration or production deployment; and
- product-finding remediation, release assignment, or security-fix PRs.

## Non-goals

- Do not hide findings to make totals smaller or define success as zero issues.
- Do not claim the application is secure or publish unsupported detection percentages.
- Do not treat an optional tool as completed coverage because configuration exists.
