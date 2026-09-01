# Code Analysis Implementation and Decision Record

> **As of:** 2026-08-31
> **Authority:** [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) and the checked-in workflows  
> **Working repository:** fork `combustrrr/Agentic-Kibana`  
> **Development branch:** `feature/static-code-analysis`  
> **Fork default/dispatcher branch:** `claude/main`  
> **Upstream:** `ARYDESTROYER/Agentic-Kibana` (read-only for this work)

This document consolidates the implementation decisions and verified results reached
during the code-analysis working sessions. It deliberately separates the current
system from the broader 2026 proposal so that candidate tools, scaffolds, and future
automation are not mistaken for working coverage.

Companion records: [`WORK_COMPLETED.md`](WORK_COMPLETED.md) inventories delivered work,
[`ADRS.md`](ADRS.md) records the accepted decisions, and
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) records the external-service
security and deployment gates, while
[`PENDING_WORK.md`](PENDING_WORK.md) defines the prioritized remaining work and exit criteria.

## 1. Final objective

The primary product is a current, complete, searchable view of issues detected in the
codebase:

```text
complementary scanner web
  -> retained raw observations
  -> normalization
  -> conservative cross-tool deduplication
  -> canonical current findings
  -> one authenticated offline Issue Wall artifact
```

The goal is **detection and visualization**, not reducing the count to zero. An increase
in findings can mean a new scanner or rule exposed previously unknown issues. History,
lifecycle analytics, remediation progress, and finding-count trends are not the active
product.

“All issues” means every canonical issue produced from the latest publishable scan plus
all contributing raw scanner observations. It does not mean that scanners can prove the
absence of unknown vulnerabilities.

## 2. Decisions that supersede the original proposal

| Proposal idea | Current decision |
|---|---|
| Many complementary analysis tools | Retained; tools are selected for non-redundant detection value, not tool count. |
| GitHub Security tab as the only view | Supplementary only; the custom dashboard is the unified developer view. |
| One GitHub Issue per alert | Deferred; thousands of findings must not flood Issues. |
| DefectDojo as the immediate portal | Deferred; no service is deployed or contacted by the active pipeline. |
| Baseline/lifecycle-first dashboard | Superseded by the latest trustworthy full-codebase snapshot. |
| Automated lint/security fixes | Deferred; no patch, autofix, commit, or remediation path is active. |
| Blocking gates | Deferred; the custom dashboard Check is advisory. |
| AI findings equal deterministic findings | Rejected; AI output is separate `AI_ADVISORY` evidence and never deterministic corroboration. |
| Scanner execution during application startup | Rejected; analysis is external to Agentic SOC runtime. |

The original proposal remains useful as the candidate-tool and long-term research
roadmap. It is not an authorization to activate cloud services, mutate code, or deploy
infrastructure.

## 3. Repository and safety boundary

- All implementation and testing occurs in the fork.
- The fork analysis branch and fork default branch are intentionally mirrored at the
  accepted analysis commit so the default-branch `workflow_run` dispatcher uses the
  approved definition. This is an internal fork invariant; it does **not** mean the
  analysis branch already contains every current commit from upstream `main`.
- Upstream synchronization is a separate, controlled operation. As verified on
  2026-08-26, fork `Testing` matched upstream `Testing`, while upstream `main` and the
  fork's analysis/default line had diverged. Upstream changes must be integrated into
  the development branch deliberately and revalidated before the fork default is
  advanced.
- The upstream company repository and live site are not modified.
- The analysis service does not become an Agentic SOC runtime dependency.
- Active workflows do not create Issues or PR comments, apply fixes, push branches,
  alter branch protection, deploy, contact DefectDojo, or mutate production.
- Raw evidence may contain sensitive paths/messages; access follows GitHub Actions and
  artifact permissions. No separate portal or host is supported.

## 4. How analysis runs

### Pushes and internally mirrored branches

Pushes run the four full-codebase scanner workflows when the pushed branch contains the
approved workflow definitions. Pull requests do the same when the base branch contains
them and analyze the exact PR head rather than the synthetic merge ref. Clean mirror
branches such as `Testing` currently use the manual cross-branch orchestrator:

1. `01-code-quality.yml`
2. `02-security-sast.yml`
3. `03-dependency-security.yml`
4. `04-code-health.yml`

When Code Health completes successfully, the default-branch
`05-issue-aggregation.yml` dispatcher uses `workflow_run.head_sha`, waits for successful
artifacts from all four workflows for that exact SHA, normalizes them, and publishes one
snapshot. It never uses the dispatcher's own SHA as the analyzed commit.

### Pull requests

Pull requests targeting any fork branch run the same scanner families against the exact
PR head SHA.
Dependency Review is PR-only. The dashboard remains advisory and is separate from
GitHub's native SARIF/code-scanning lifecycle.

### Manual analysis

**Full Code Analysis (Manual)** provides the one-click path: it validates the selected
fork branch head, runs the approved workflow definitions from the fork default branch,
pins the selected branch's exact SHA into all scanner checkouts, waits for all four
scanner groups, dispatches one exact-commit dashboard build, waits for publication, and
returns direct run/artifact links. Individual scanner dispatches remain available for
diagnosis. Manual dashboard-only builds may specify an exact `scan_sha` and branch, but
publication still requires same-commit artifacts and all required channels. Canary and
API fuzzing workflows remain isolated from the required static snapshot gate.

The selected target branch is the code under analysis; it is not required to contain
the analysis service itself. Jobs that need pinned scanner dependencies, custom rules,
or normalization code sparsely check out those trusted files from the fork default
branch into `.analysis-tooling`. Scanner commands continue to target the selected
branch's root source tree. Manual runs carry a deterministic branch/SHA display title,
which is used for run discovery because GitHub associates `workflow_dispatch` metadata
with the workflow-definition ref rather than the separately pinned source commit.

### Latest-head fleet supervisor

The trusted default-branch definition of `08-full-code-analysis.yml` runs every 15
minutes. It paginates the complete fork branch list, derives the deterministic dashboard
Check identity for each current SHA, and dispatches only uncovered heads. Scheduled work
never checks out or executes branch source itself; it passes the observed branch and SHA
to the existing bounded orchestrator. Active branch/SHA runs are deduplicated and failed
exact heads have a three-attempt ceiling, while a later commit is treated independently.
This closes the GitHub trigger gap for clean or old branches that do not contain the
analysis workflow files. Native same-repository PR events remain the exact-head fast
path; untrusted fork-PR execution is not elevated through `pull_request_target`.

### Issue Wall delivery

`scripts/code_analysis/pipeline.py` runs in Actions and builds a self-contained artifact.
Developers download it from the authenticated workflow or advisory Check and open
`dashboard/START_HERE.md` followed by `dashboard/index.html`. Local servers, pull
workers, QA hosts, and continuously hosted copies are retired and unsupported.

## 5. Implemented scanner web

The repository manifest `config/code-analysis/required-channels.json`
defines 16 required structured channels. The number is data, not hard-coded logic.

| Surface | Required tools/channels | State |
|---|---|---|
| Python quality and types | Ruff, Pyright | Verified |
| TypeScript/React quality and types | ESLint, `tsc` | Verified structured ingestion |
| Semantic/pattern SAST | CodeQL, Semgrep | Verified |
| Python security | Bandit | Verified |
| Dependency/SCA | OSV-Scanner | Verified |
| Secrets | Gitleaks | Verified |
| Filesystem/container dependencies | Trivy | Verified |
| IaC and Dockerfiles | Checkov, Hadolint | Verified |
| Dead code and complexity | Vulture, Radon, Xenon | Verified structured ingestion |
| Runtime coverage evidence | Coverage.py | Verified; parent-process scope is labelled |

Workflow ownership is explicit in the manifest and dashboard: Code Quality owns five
channels, Security/SAST owns two, Dependency/Supply Chain owns five, and Code Health
owns four. The dashboard's integrity panel links the exact contributing workflow runs
and exposes retained artifact names and hashes, so channel completeness is auditable.

Additional lanes:

- **Snyk Open Source + Snyk Code:** optional, scan-only, and now verified in fork
  Actions. It contributes SARIF when available but does not determine the 16-channel
  publishability gate.
- **Schemathesis:** manual/weekly isolated dynamic lane with 250 examples; JUnit
  failures normalize as `DYNAMIC`, including explicit API-500 classification. It is
  not static coverage.
- **CodeRabbit:** automatic/incremental cloud-review configuration, exact-head GitHub
  review evidence collection, and dashboard refresh are implemented. Findings remain
  a separate `AI_ADVISORY` lane and do not corroborate deterministic results. Repository
  exact-head advisory evidence has been observed; any future evaluation is tracked only
  in [`PENDING_WORK.md`](PENDING_WORK.md).
- **Shipping security:** the exact backend and web UI shipping images are built and
  scanned; CycloneDX/SPDX inventories, bounded denied-license policy results, and
  unsigned local provenance are retained.
- **Repository posture:** zizmor and OpenSSF Scorecard produce optional SARIF. A
  read-only GitHub API check records secret-scanning and push-protection state and only
  alert numbers, never detected secret material.
- **Custom security models:** CodeQL data extensions and Semgrep taint rules model
  FastAPI request input, SQL/path/SSRF sinks, authorization boundaries, React HTML
  injection, and LLM output reaching execution.
- **SonarQube Cloud:** exact-commit cloud analysis is verified. Bounded authenticated
  native-issue export, canonical normalization, and a generic external-issue projection
  are implemented. Both PATs authenticate as the same Sonar user and Sonar accepted an
  explicit Browse grant, but the current Free organization still hides stored non-main
  analysis with HTTP 403. Non-default Git branches map to a stable long-lived
  `branch-issue-wall-<hash>` Sonar analysis branch; operational proof awaits OSS-plan
  activation. Issue Wall still records the real Git branch and
  exact SHA. The projection excludes Sonar-native and
  `AI_ADVISORY` findings. CodeScene is not active.
- **Atheris:** a bounded weekly/manual Linux harness exercises deterministic
  case-decision state transitions for 25,000 inputs and retains crash evidence.
- **KICS/tfsec:** not activated. Checkov and Trivy config already cover IaC; KICS is
  deferred while its current Action has a public compromise advisory, and a future
  standalone comparison must demonstrate unique findings.
- **PR-Agent/Qodo/Qodana:** evaluated or documented alternatives, not active channels.

GitHub-native CodeQL, Copilot Autofix, AI findings, Dependabot, dependency graph, and
secret-protection settings may also be enabled on the fork. Their native UI counts are
not the canonical dashboard count, and Autofix is not invoked by this platform.

## 6. Evidence, normalization, and deduplication

The normalizer accepts SARIF and tool-specific JSON/text/JUnit formats and retains the
native tool, channel, rule, result identity, message, location, and raw-artifact
reference for each observation.

Equivalent observations become one canonical finding. Deduplication changes the
presentation only; it never discards evidence. Multiple rules from one engine remain
one scanner family for corroboration.

Identity is deliberately conservative. Paths are repository-relative and normalized;
region/snippet/column/native anchors prevent unrelated same-line observations from
receiving the same canonical identity. Ambiguous evidence remains separate rather than
being silently merged. Snapshot reconciliation fails if canonical IDs collide or counts
do not balance.

## 7. Publishable snapshot contract

Each snapshot records:

```text
snapshot_id, repository, commit_sha, branch, generated_at
workflow_run_ids, scanner_versions, channel_status, artifact_hashes
finding_count, observation_count, canonical_findings, ai_advisories
```

A snapshot is publishable only when all required channels succeeded, every artifact
matches the exact repository/commit, hashes and schemas validate, normalization and
deduplication succeed, and counts reconcile. Failed or mixed-commit refreshes cannot
replace the current site. The previous publication exists only for rollback.

## 8. Dashboard and where developers see results

The custom dashboard is the primary visualization. It shows:

- exact snapshot commit, generation time, and channel completeness;
- canonical and raw-observation totals;
- severity, category, component, directory, concept, and scanner distributions;
- one searchable/filterable row per canonical finding;
- evidence drill-down containing every contributing scanner observation;
- separate deterministic and `AI_ADVISORY` views; and
- complete snapshot/raw-observation downloads.

The visualization also exposes an **Additional analysis lanes** board. It displays the
current status and evidence counts for Snyk and other optional/dynamic sources, keeps
  CodeRabbit visibly labelled `AI_ADVISORY`, and shows inactive tools as catalog entries.
Only the separate required-channel board contributes to the publishability fraction.

Rendering is bounded to 50/100/250 rows; the browser never mounts the complete 8,000+
or 10,000-row dataset simultaneously.

Developers open the **Code Analysis Dashboard** Check on the commit and download the
linked authenticated Actions artifact. This is the only supported Issue Wall surface;
local and QA-host serving were retired by owner decision on 2026-08-29.

## 9. Delivery decision

No Issue Wall host, dashboard container, or pull worker is operated. GitHub Actions
supplies scanner compute, aggregation, artifact retention, access control, and audit
history. SonarQube Cloud is an optional external scanner; DefectDojo is not contacted.

## 10. Verified evidence

- Historical baseline dashboard: run `32578162932`, 8,535 canonical findings,
  14/14 then-configured channels, 81.16% parent-process coverage.
- Check idempotency rebuild: run `32580941289` updated the same commit Check.
- Current-platform acceptance: commit `48a1db2`; scanner workflows succeeded;
  canary run `32938363577` passed all 10 expectations; dashboard run `32938363593`
  published the complete artifact.
- Improved real dashboard: run `32940124398` published the refined UI over real
  scanner evidence.
- Scale benchmark: 10,000 canonical findings and 13,000 observations completed within
  the 30-second/512-MiB gate, with at most 250 rows mounted.
- Snyk activation: run `32965286130` at commit `e8caba62...` passed installation,
  Open Source SCA, Snyk Code, configured-status generation, and artifact upload;
  artifact `snyk-results` ID `9605455800` was retained.
- Sonar analysis/native-export proofs: runs `33404195186`, `33405919866`, and
  `33409996015` completed exact-SHA analysis in 14–15 minutes and then truthfully
  reported `CONFIGURED_PARTIAL` on issue-API HTTP 403.
- Analysis-service regression suite: 49/49 tests pass, including Sonar native parsing,
  projection loop prevention, and `AI_ADVISORY` exclusion.

These prove configured pipeline behavior and the defined canary set. They do not prove
that the application is secure or establish a universal vulnerability-detection rate.

## 11. Current external activation state

### Snyk

The fork repository secret `SNYK_TOKEN` is configured and both CI surfaces are verified.
The workflow never runs `monitor`, `report`, `fix`, patch, or PR commands. It retains
per-surface status and reports partial analysis when projects are unresolved or a Snyk
product is unavailable. Snyk remains optional until unique detection value is measured.

### CodeRabbit

`.coderabbit.yaml` enables cloud automatic review and incremental review after every
push to an eligible PR, explicitly includes every fork base branch, and disables
automatic pausing. Request-changes behavior and chat auto-replies remain disabled.
GitHub Checks context is explicitly enabled with the maximum 15-minute scanner wait.
Exact-head inline CodeRabbit comments now
normalize through a read-only GitHub evidence collector and a CodeRabbit review event
requests a dashboard-only refresh with explicit repository context; AI results remain
separate and never corroborate deterministic findings. The local CLI/WSL path is not
part of the deployment design. Fork-only exact-head GitHub App evidence has been
observed and verified.

### SonarQube Cloud

The scanner and exporter use separate GitHub secrets. Native issues normalize into the
same Issue Wall schema; compatible deterministic findings project outward in Sonar's
generic format. Sonar-native and `AI_ADVISORY` findings cannot feed that projection.
Main/eligible-PR native results are imported when Sonar exposes them. Free-plan arbitrary
branch HTTP 403 is a truthful optional-channel `CONFIGURED_PARTIAL` state and never blocks
Issue Wall publication. All remaining work lives only in
[`PENDING_WORK.md`](PENDING_WORK.md).

## 12. Work boundary

Issue Wall does not implement human triage, remediation, patches, lifecycle persistence,
or vendor-state synchronization. The sole current backlog is
[`PENDING_WORK.md`](PENDING_WORK.md). No future change should weaken evidence preservation,
exact-commit publication, fork isolation, or read-only defaults.
