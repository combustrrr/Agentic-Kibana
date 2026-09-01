# Code Analysis — Pending Work

> **Prioritization date:** 2026-09-01
> **Primary objective:** trustworthy detection and one normalized current-findings view
> **Not an objective:** triage workflows, fixing findings, or reducing the count to zero

This is the only active code-analysis backlog. Other documents describe current behavior,
durable decisions, or historical evidence and must link here instead of carrying their own
next-step lists.

Closure checkpoint: Issue Wall acceptance is complete for implementation head `c92032a`
through orchestrator run `33527080901` and dashboard run `33528827999`. Do not replace
either PAT, repeat the Browse grant, migrate the
repository, or create another Sonar organization merely to unblock reporting.
The restart narrative and accepted evidence are recorded in
[`SESSION_HANDOFF_2026-09-01.md`](SESSION_HANDOFF_2026-09-01.md); this file remains the
only source of pending actions.

## P0 — Unified Issue Wall accepted

The product objective is one normalized, read-only visualization containing every result
that each configured service makes available for the selected branch and exact commit.
No optional vendor may block dashboard publication. A channel that is unavailable,
rate-limited, plan-limited, or not configured must appear truthfully with its status while
the remaining scanner web still publishes.

Accepted evidence: the 17m21s exact-head orchestrator published a 17,431,210-byte artifact
(SHA-256 `5a04e175015952d1d78637c00dd118e353a121f52821f070ac1f6387452f2ee7`)
for `feature/static-code-analysis@c92032a54e4159268abc91d4667c9bf47e9b5b28`.
The snapshot is publishable with 16/16 required channels, 16,257 canonical findings,
16,927 observations, and 0 AI advisories because no exact-head PR applied. Snyk contributes
382 findings/383 observations in the same view; CodeRabbit remains visibly isolated as
`AI_ADVISORY` and `NOT_APPLICABLE`. Sonar and repository security posture both remain
truthful `CONFIGURED_PARTIAL` cards without blocking publication. Desktop and 500px narrow
captures were visually accepted; the real artifact exposes severity colors, charts,
filters, exact source links, evidence dialog, and filtered CSV export. The narrow-layout
viewport correction was regression-checked by regenerating this accepted snapshot through
the updated template.

Sonar is explicitly best-effort. Import its native findings for main and eligible PR
analyses when the API exposes them. On arbitrary branches under the current Free plan,
retain `CONFIGURED_PARTIAL` and publish all other findings. Run `33429643637` proved both
PATs and the Browse grant are correct; the remaining HTTP 403 is a plan entitlement, not
an Issue Wall blocker. OSS enrollment may be reconsidered later, but it is not required
for P0 and must not trigger repository/workspace migration by default.

## P1 — Platform-level acceptance complete

- Final acceptance consumed approximately 64.6 summed runner minutes: Code Quality 18.7,
  Security/SAST 6.8, Dependency/Supply Chain 10.4, Code Health 10.8, dashboard 0.6, and
  orchestration 17.4. Wall-clock orchestration was 17m21s; Sonar remained the dominant lane.
- Accepted logs prove restored npm (44 MB), Python (49–127 MB), Gitleaks (5 MB), Trivy
  binary (42 MB), and Trivy database (77 MB) caches. No second automatic Sonar scan was
  added for outbound projection.
- Pinned actionlint 1.7.7 and ShellCheck 0.10.0 exposed and drove correction of the Check
  publisher's grouped redirects and intentional jq-variable literals. The suppressions are
  scoped only to jq programs and require a green Linux contract rerun.

## P2 — Conditional optional-evidence decisions

- Measure Sonar-native unique findings against the canonical scanner web only after an
  eligible same-commit branch API becomes available. Current Free-plan non-main HTTP 403
  makes a truthful comparison unavailable; do not infer zero unique findings.
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
- Final Issue Wall acceptance is recorded above; the dated session handoff is now immutable.
  Retain older handoffs only as historical evidence. Do not delete accepted run IDs, artifact
  hashes, security decisions, or provenance needed for audit.
- The release-facing scanner/data-handling inventory is complete in
  [`DATA_HANDLING_INVENTORY.md`](DATA_HANDLING_INVENTORY.md). Re-verify it against exact
  workflow and vendor settings before a release; do not claim certification or guaranteed
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
