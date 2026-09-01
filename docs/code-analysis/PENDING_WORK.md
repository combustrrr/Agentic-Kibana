# Code Analysis — Pending Work

> **Prioritization date:** 2026-09-01
> **Primary objective:** trustworthy detection and one normalized current-findings view
> **Not an objective:** triage workflows, fixing findings, or reducing the count to zero

This is the only active code-analysis backlog. Other documents describe current behavior,
durable decisions, or historical evidence and must link here instead of carrying their own
next-step lists.

Shutdown checkpoint: branch `feature/static-code-analysis` is pushed through `f22246d`.
Resume with P0 step 1. Do not replace either PAT, repeat the Browse grant, migrate the
repository, or create another Sonar organization merely to unblock reporting.
The restart narrative and accepted evidence are recorded in
[`SESSION_HANDOFF_2026-09-01.md`](SESSION_HANDOFF_2026-09-01.md); this file remains the
only source of pending actions.

## P0 — Accept the unified Issue Wall as the deliverable

The product objective is one normalized, read-only visualization containing every result
that each configured service makes available for the selected branch and exact commit.
No optional vendor may block dashboard publication. A channel that is unavailable,
rate-limited, plan-limited, or not configured must appear truthfully with its status while
the remaining scanner web still publishes.

1. Download the latest complete Issue Wall artifact and visually accept desktop and narrow
   layouts, fresh severity colors, charts, filters, exact source locations, evidence
   dialog, channel-status explanations, and CSV export.
2. Prove the exact branch/SHA report includes every available deterministic quality,
   security, dependency, and repository channel in the canonical schema. Keep Snyk in
   that same view and CodeRabbit visible but clearly labelled `AI_ADVISORY`.
3. Prove an optional-channel failure still produces a successful Issue Wall artifact and
   a truthful channel card; it must not suppress findings from healthy scanners.
4. Record final runner minutes, cache behavior, artifact size, channel count, canonical
   finding count, and observation count.

Sonar is explicitly best-effort. Import its native findings for main and eligible PR
analyses when the API exposes them. On arbitrary branches under the current Free plan,
retain `CONFIGURED_PARTIAL` and publish all other findings. Run `33429643637` proved both
PATs and the Browse grant are correct; the remaining HTTP 403 is a plan entitlement, not
an Issue Wall blocker. OSS enrollment may be reconsidered later, but it is not required
for P0 and must not trigger repository/workspace migration by default.

## P1 — Finish platform-level acceptance

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
- SonarQube Cloud: best-effort optional input. Analysis, both PATs, and the explicit Browse
  grant are verified. Import exposed main/eligible-PR results; represent Free-plan non-main
  HTTP 403 as `CONFIGURED_PARTIAL` without blocking Issue Wall.

Candidates such as Blacksmith, BrowserStack, Argos/Chromatic, CodeScene, Qodo, Codacy,
DeepSource, Code Climate, and 1Password require a separate measured decision. Do not
activate overlapping services by default.

### Enterprise/OSS release hygiene

- Complete the repository ownership and license decision before marketing the work as
  open source. Public visibility alone is not an OSS license.
- Before an enterprise or public release, run the documentation consistency checker and
  verify that README/current-contract files contain no stale scanner, permission, plan,
  branch, or delivery claims.
- Keep the code-analysis documentation index grouped as current contracts, operator
  guides, and historical evidence. Put all unfinished work only in this file; do not add
  another status/TODO document.
- After final Issue Wall acceptance, mark the dated session handoff immutable and retain
  older handoffs only as historical evidence. Do not delete accepted run IDs, artifact
  hashes, security decisions, or provenance needed for audit.
- Produce a release-facing scanner/data-handling inventory from the existing architecture
  and activation contracts: service, purpose, data sent, credential scope, retention,
  failure behavior, and removal procedure. Do not claim certification or guaranteed
  security coverage.

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
