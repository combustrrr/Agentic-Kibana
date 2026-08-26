# Static Code Analysis — Execution Plan

> **Current phase:** Current-findings snapshot platform accepted on the fork; QA-VM hosting pending
> **Branch:** `feature/static-code-analysis`
> **Operating mode:** fork-only, read-only full-codebase detection and visualization
> **Last updated:** 2026-08-26

This plan records implementation truth, not proposal intent. The consolidated handoff is
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md). A workflow file or Compose
draft is not considered an implemented service until it has executed and produced usable
evidence. Historical 14/14 results refer only to the manifest at that time; the current
required manifest has 16 channels and does not mean every shortlisted proposal tool is installed.

## Phase status

| Phase | Status | Work completed | Work remaining / exit condition |
|---|---|---|---|
| 0 — Dormant setup | **Complete** | Fork safety established; `feature/static-code-analysis` retained; fork default synchronized; existing `ci.yml` untouched; custom Semgrep, CodeQL, Bandit, Ruff, Gitleaks and canary configuration added. | Superseded by the active fork push/PR/manual trigger model; schedules remain disabled. |
| 1 — Manual baseline and diagnosis service | **Complete for collection; remediation deferred** | All four scanner families manually exercised; raw artifacts retained; recursive normalizer repaired; file+line+concept fingerprints; 298+ overlaps proven; searchable all-findings dashboard; 14/14 configured channels; 81.16% parent-process runtime coverage; bounded dry-run issue plan; review-only Ruff patch. | False-positive classification and application finding fixes remain intentionally out of scope. Shortlisted services not yet implemented are tracked below, not counted as Phase 1 coverage. |
| 2 — Canary validation | **Complete: 10/10 defined expectations** | The historical 7/10 run exposed SQL injection, path traversal, and React XSS gaps. Project-specific detection/normalization work closed them; run `32938363577` passed all 10 end-to-end expectations. | Preserve the canary contract as scanner configuration changes. Do not turn 10/10 defined fixtures into a universal security-coverage claim. |
| 3 — Selective advisory activation | **Complete** | Fork PRs #1/#2 verified exact-commit scanner collection and one idempotent advisory Check. Historical run `32578162932` produced 8,535 canonical findings and rebuild `32580941289` updated the same Check. | Superseded by the current full-snapshot product; baseline/lifecycle/triage work is deferred rather than required for acceptance. |
| 4 — Current findings platform | **Accepted on fork** | Added publishable `snapshot-v1` provenance and reconciliation, exact-commit artifact hashing, structured TypeScript/Xenon evidence, improved all-findings/evidence dashboard, bounded rendering, atomic publication, and a localhost-only container profile. All required workflows and 10/10 canaries passed; run `32940124398` published the improved real-data artifact. | Validate the same image on the company QA VM behind VPN/OIDC. |
| 5 — Additional detection surfaces | **Started; Snyk verified** | The proposal catalog is explicit. Pinned scan-only Snyk SCA/Code ran successfully in fork run `32965286130`; CI retains per-surface status and cannot hide partial analysis. Schemathesis JUnit ingestion is structured but remains an isolated dynamic lane. CodeRabbit cloud auto/incremental PR review is configured. | Install and verify the CodeRabbit GitHub App on the fork. Add SonarQube, CodeScene, or Atheris only after exportable, visible, non-redundant evidence is demonstrated. |

## Shortlisted tool implementation inventory

Statuses use these meanings:

- **Verified:** executed on the fork and produced retained, centrally consumable evidence.
- **Partial:** configuration/scaffold or workflow exists, but the complete promised path
  has not been validated or normalized.
- **Not implemented:** proposal candidate only; it must not be represented as coverage.

| Layer | Tool/service | Status | Current evidence or gap |
|---|---|---|---|
| Quality | Ruff | **Verified** | JSON normalized; 5,000+ findings; safe review patch verified. |
| Quality | Pyright | **Verified** | JSON artifact plumbing repaired and observed. |
| Quality | ESLint | **Verified** | JSON artifact plumbing repaired and observed. |
| Quality | TypeScript `tsc` | **Verified** | Stable text artifact and structured diagnostics feed the accepted current snapshot. |
| SAST | CodeQL (Python + JS/TS) | **Verified** | SARIF retained and normalized for both languages. |
| SAST | Semgrep OSS + custom rules | **Verified** | Raw JSON parser repaired; 2,736 findings entered the unified dashboard. |
| SAST | Bandit | **Verified** | JSON and normalized SARIF retained. |
| Supply chain | OSV-Scanner | **Verified** | SARIF retained and normalized. |
| Supply chain | Trivy filesystem/config | **Verified** | Both SARIF channels retained and normalized. |
| Secrets | Gitleaks | **Verified** | SARIF retained and normalized; the defined secret canary passes. |
| IaC/container | Hadolint | **Verified** | Workflow and artifact channel verified after upload repair. |
| IaC/container | Checkov | **Verified** | SARIF retained and normalized. |
| Health | Radon | **Verified** | Complexity JSON is retained and complexity blocks normalize into visible findings. |
| Health | Xenon | **Verified** | Retained text artifact and structured complexity findings feed the accepted snapshot. |
| Health | Vulture | **Verified** | Actual text format parser added; findings appear centrally. |
| Health | Coverage.py | **Verified** | Stable parent-process JSON/XML retained; dashboard shows 81.16%. Child-process coverage is not claimed. |
| Active testing | Schemathesis | **Implemented; isolated dynamic lane** | Manual workflow JUnit failures normalize as `DYNAMIC`, including API-500 classification; it is not part of static publishability. |
| Active testing | Atheris | **Not implemented** | Mentioned in proposal/docs only; no executable fuzz harness or workflow. |
| AI review | CodeRabbit | **Cloud auto-review configured; App verification pending** | Eligible PRs are configured for automatic review and incremental review after every push, with no request-changes workflow. The fork-only GitHub App is not yet verified. |
| AI review | PR-Agent | **Not implemented** | Fallback is documented only. |
| Behavioral health | CodeScene | **Partial scaffold** | Compose draft exists; no license/configured service, scan, or dashboard integration. |
| Finding management | DefectDojo | **Partial scaffold** | Compose draft exists; no deployed service, importer, persistence, or lifecycle sync. |
| Supply-chain alternative | Snyk | **Verified optional** | Fork run `32965286130` passed Open Source SCA, Snyk Code, status generation, and artifact upload. Local OAuth used a different organization where Code was disabled; CI evidence is authoritative. No monitor, report, fix, patch, or PR command exists. |
| Optional evaluator | Qodana | **Not selected / not implemented** | Appears in evaluation/parser compatibility only; it is not an active shortlisted lane. |
| GitHub native | Dependency Review | **Active PR-only** | Runs for PRs targeting `claude/main` or `Testing`; it is correctly skipped for push/manual runs. |

The authoritative detailed inventory should be kept aligned with
[`README.md`](README.md) and the workflow files. “Verified” does not imply findings are
true positives or remediated.

## Phase 1 evidence

- [Baseline report](PHASE1_BASELINE.md)
- Final coherent aggregation: [run 32574531333](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32574531333)
- 8,762 unique findings in `dashboard/index.html`
- 14/14 configured artifact channels observed
- 81.16% runtime line coverage
- 2,487 Ruff safe-fix candidates and a 510,318-byte review patch
- `apply_issues=false`: no Issues created or closed

## Phase 2 execution

### Objective

Prove that deliberately vulnerable fixtures are detected by the expected independent
tools. Scanner execution alone is not a pass: its output must normalize to the expected
file and canonical concept.

### Canary expectations

The source of truth is [`../../tests/security_canary/COVERAGE.md`](../../tests/security_canary/COVERAGE.md)
and `scripts/code_analysis/validate_canary.py`. Current expectations cover:

1. SQL injection
2. hardcoded secrets
3. JWT `none` algorithm
4. eval/exec injection
5. unsafe deserialization
6. path traversal
7. LLM-output-to-execution
8. React XSS
9. insecure Dockerfile/root
10. vulnerable dependencies

### Phase 2 safety and acceptance

- Run only by `workflow_dispatch` on the fork feature branch.
- Do not uncomment push, PR, schedule, or `workflow_run` triggers.
- Do not apply fixes or create Issues while validating coverage.
- Preserve raw and normalized canary artifacts even when validation fails.
- Exit with either 10/10 expectations passing or an acknowledged-gap table showing the
  missing tool, reason, and next implementation action.

### Phase 2 measured result

- Baseline run `32574844342`: **1/10**, proving the original harness was not coherent.
- Repaired intermediate runs: **3/10**, then **5/10**.
- Final run [32575538895](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32575538895):
  **7/10**, 202 normalized findings from Bandit, Semgrep, CodeQL, Gitleaks,
  OSV-Scanner, Hadolint, Checkov, and Ruff.
- Passing concepts: hardcoded secrets, JWT none algorithm, eval/exec injection, unsafe
  deserialization, LLM-output execution, insecure Dockerfile/root, vulnerable dependencies.
- Open concepts: SQL injection independence, path traversal dataflow, React XSS.
- Detailed evidence and next actions: [`ACKNOWLEDGED_GAPS.md`](ACKNOWLEDGED_GAPS.md).

The lines above are the historical diagnosis that drove the coverage work. They are not
the current result. Commit `48a1db2` and fork run
[`32938363577`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32938363577)
subsequently passed **10/10** defined canary expectations through detection,
normalization, and validation. [`ACKNOWLEDGED_GAPS.md`](ACKNOWLEDGED_GAPS.md) retains the
7/10 evidence as an audit record and marks those three gaps resolved by the later run.

## Phase 3 decision gate

Phase 3 was explicitly approved for monitoring-only work. Its original PR-only policy
has since been superseded by the accepted current-snapshot trigger contract:

- run full scanner workflows on pushes where the branch carries the approved definitions;
- use the exact-head manual orchestrator for clean mirror branches without those files;
- run them against the exact head of every eligible pull request;
- provide one-click **Full Code Analysis (Manual)** for a selected branch head and
  retain individual/manual dashboard dispatches for diagnosis or rebuild;
- aggregate only successful same-commit artifacts using `workflow_run.head_sha`;
- keep schedules disabled and keep API fuzzing isolated/manual;
- keep GitHub Issues read-only and retain only a dry-run plan;
- retain the downloadable HTML dashboard artifact for 30 days;
- keep ownership entirely in the fork, with no upstream or production mutation.

The current operator policy is advisory. Phase 3 must not add required status checks or
branch protection changes.

### Phase 3 acceptance evidence

- Fork-only PR: [#1](https://github.com/combustrrr/Agentic-Kibana/pull/1)
- Code Quality: [32576809623](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32576809623) — success
- Security / SAST: [32576809631](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32576809631) — success
- Dependency & Supply Chain: [32576809598](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32576809598) — success
- Code Health: [32576809637](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32576809637) — success
- Unified aggregation: [32577091369](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32577091369) — success; 8,536 findings, 14/14 configured channels, 81.16% runtime coverage, 30-day dashboard artifact
- The automatic path matched all scanner artifacts to PR commit
  `c3f1e730b5d17ca19944d542bfb3748d06d2ddfe` before aggregation.

### Findings-surface acceptance evidence

- Fork-only PR: [#2](https://github.com/combustrrr/Agentic-Kibana/pull/2)
- Neutral commit check: [Code Analysis Dashboard](https://github.com/combustrrr/Agentic-Kibana/runs/97043497690)
- Automatic dashboard run: [32578162932](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32578162932)
- Dashboard-only idempotency/link rebuild: [32580941289](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32580941289)
- Verified: exactly one check for the commit, `neutral` conclusion, explicit authenticated
  artifact link, 8,535 findings, no Issue-plan artifact, and client-side sliced pagination.

## Deferred remediation boundary

No autofix or patch generator is part of the active monitoring implementation. Any future
remediation phase requires a new explicit approval and must use this sequence:

1. operator selects fingerprints;
2. create an isolated fork branch;
3. apply only allowlisted deterministic fixes;
4. run targeted tests and scanners;
5. publish a human-reviewed PR;
6. never push directly to the default, `Testing`, upstream, or production branch.

Security-sensitive authentication, authorization, MFA, tokens, audit, connector scoping,
agent permissions, and state reset code remain manual-only.

## Phase 5 production boundary

Nothing in Phases 0–4 authorizes deployment. Production integration requires a separate
plan covering ownership, secrets, runner placement, persistent dashboard choice,
DefectDojo/CodeScene decisions, cost, rollback, and branch protection. The original
repository and live site remain untouched until that plan is explicitly approved.
