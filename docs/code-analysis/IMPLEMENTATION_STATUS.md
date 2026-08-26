# Code Analysis Implementation and Decision Record

> **As of:** 2026-08-26  
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
  -> one read-only hosted dashboard
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
- The fork analysis and default branches are intentionally synchronized so the
  default-branch `workflow_run` dispatcher uses the approved definition.
- The upstream company repository and live site are not modified.
- The analysis service does not become an Agentic SOC runtime dependency.
- Active workflows do not create Issues or PR comments, apply fixes, push branches,
  alter branch protection, deploy, contact DefectDojo, or mutate production.
- Raw evidence may contain sensitive paths/messages; access follows GitHub artifact
  permissions and the future QA portal must sit behind company VPN/OIDC.

## 4. How analysis runs

### Pushes and synchronized branches

Pushes to every fork branch run the four full-codebase scanner workflows. Pull requests
analyze the exact PR head commit rather than the synthetic merge ref, and manual
dispatches analyze the selected ref:

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
fork branch head, pins that exact SHA into all scanner checkouts, waits for all four
scanner groups, dispatches one exact-commit dashboard build, waits for publication, and
returns direct run/artifact links. Individual scanner dispatches remain available for
diagnosis. Manual dashboard-only builds may specify an exact `scan_sha` and branch, but
publication still requires same-commit artifacts and all required channels. Canary and
API fuzzing workflows remain isolated from the required static snapshot gate.

### QA VM and local analysis

The same `scripts/code_analysis/pipeline.py` is used by Actions and the QA/local worker.
The VM pulls immutable GitHub artifacts outbound, validates them, stages the new site,
and atomically publishes it. GitHub needs no inbound path to the VM.

## 5. Implemented scanner web

The manifest [`required-channels.json`](../../config/code-analysis/required-channels.json)
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
- **Schemathesis:** manual dynamic lane; JUnit failures normalize as `DYNAMIC`, including
  explicit API-500 classification. It is not static coverage.
- **CodeRabbit:** automatic/incremental cloud-review configuration, exact-head GitHub
  review evidence collection, and dashboard refresh are implemented. Findings remain
  a separate `AI_ADVISORY` lane and do not corroborate deterministic results. Repository
  owner GitHub App authorization and first live review remain externally pending.
- **SonarQube and CodeScene:** deferred until a stable machine-readable export proves
  useful findings not already represented.
- **Atheris:** deferred research; no bounded production-relevant fuzz harness is active.
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
CodeRabbit visibly labelled `AI_ADVISORY`, and shows deferred tools as roadmap entries.
Only the separate required-channel board contributes to the publishability fraction.

Rendering is bounded to 50/100/250 rows; the browser never mounts the complete 8,000+
or 10,000-row dataset simultaneously.

Until the QA VM is ready, developers open the **Code Analysis Dashboard** Check on the
commit and download the linked Actions artifact. Local evaluation is available at
`http://127.0.0.1:8787` using the hardened read-only nginx Compose profile. The intended
daily surface is the same image on the company QA VM behind VPN/OIDC.

## 9. Hosting decision and VM sizing

The agreed initial host is Ubuntu LTS with **8 vCPU, 16 GiB RAM, and 200 GiB SSD** plus
outbound HTTPS access to GitHub. It is sufficient for the dashboard, pull worker, local
scanner evaluation, and one evaluation service. Do not co-locate production-grade
SonarQube, DefectDojo, their databases, and untrusted scans until resource and security
boundaries are measured.

The dashboard container binds to `127.0.0.1`, runs read-only with dropped capabilities,
and is placed behind company access controls. The worker uses Actions read access only
and publishes atomically.

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
- Analysis-service regression suite: 37/37 tests passed after enterprise workflow
  policy, Snyk partial-result, and conservative-identity hardening.

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
push to an eligible PR, with automatic pausing disabled. Request-changes behavior,
chat auto-replies, and bot reviews remain disabled. Code-sharing approval was received.
GitHub Checks context is explicitly enabled. Exact-head inline CodeRabbit comments now
normalize through a read-only GitHub evidence collector and a CodeRabbit review event
requests a dashboard-only refresh; AI results remain separate and never corroborate
deterministic findings. The local CLI/WSL path is not part of the deployment design. A
fork-only GitHub App installation and real PR review remain incomplete and must not be
claimed as verified.

## 12. Deferred roadmap

Separate approval is required for:

1. QA-VM deployment and company VPN/OIDC configuration.
2. CodeRabbit GitHub App activation and AI-advisory evidence-adapter evaluation.
3. Non-redundant SonarQube or CodeScene export ingestion.
4. Human triage operations, persistence, or DefectDojo evaluation.
5. Precision/false-positive measurement.
6. Review-only remediation suggestions.
7. Sandboxed patches and, only after measured evidence, narrowly scoped automation.

No later phase should weaken the current evidence-preservation, exact-commit,
fail-closed publication, fork isolation, or read-only defaults.
