# Static Code Analysis — Execution Plan

> **Current phase:** Phase 2 — manual canary validation
> **Branch:** `feature/static-code-analysis`
> **Operating mode:** fork-only, manual, advisory; no upstream/production changes
> **Last updated:** 2026-08-22

This plan records implementation truth, not proposal intent. A workflow file or Compose
draft is not considered an implemented service until it has executed and produced usable
evidence. Likewise, the 14/14 dashboard coverage result refers to the configured artifact
channels; it does not mean every shortlisted proposal tool is installed.

## Phase status

| Phase | Status | Work completed | Work remaining / exit condition |
|---|---|---|---|
| 0 — Dormant setup | **Complete** | Fork safety established; `feature/static-code-analysis` retained; fork default synchronized; workflows manual-only; existing `ci.yml` untouched; custom Semgrep, CodeQL, Bandit, Ruff, Gitleaks and canary configuration added. | Preserve dormant triggers until Phase 3 is explicitly approved. |
| 1 — Manual baseline and diagnosis service | **Complete for collection; remediation deferred** | All four scanner families manually exercised; raw artifacts retained; recursive normalizer repaired; file+line+concept fingerprints; 298+ overlaps proven; searchable all-findings dashboard; 14/14 configured channels; 81.16% parent-process runtime coverage; bounded dry-run issue plan; review-only Ruff patch. | False-positive classification and application finding fixes remain intentionally out of scope. Shortlisted services not yet implemented are tracked below, not counted as Phase 1 coverage. |
| 2 — Canary validation | **In progress** | Deliberately vulnerable fixture suite and expectation registry exist; canary workflow remains manual-only; earlier plumbing run failed as expected and is not accepted as coverage proof. | Repair/run the canary web, record per-concept detections, and reach 10/10 or document explicit tool gaps with owners. No automatic triggers. |
| 3 — Selective advisory activation | **Not started** | Proposed triggers and schedules remain commented. The dashboard and issue planner are capable of advisory output. | Requires operator approval after Phase 2. Activate only selected PR/push triggers on the fork/approved target; issue apply remains a separate opt-in. No required checks. |
| 4 — Controlled remediation and optional gates | **Partially prototyped; not activated** | Ruff safe-fix candidates and a non-mutating patch artifact are verified. Issue synchronization is idempotent, HIGH/CRITICAL-only, capped, dry-run by default, and never auto-closes. | Add selected-finding approval, isolated fix branch, tests/rescan, human PR, and three-clean-scan lifecycle. Blocking gates contradict the current advisory directive and require a new explicit decision. AI patches and ESLint patch generation are not implemented. |
| 5 — Integration / deployment | **Not started** | None of the analysis workflows were added to `ci.yml`; no merge, branch protection, DefectDojo, CodeScene, Pages, or production deployment occurred. | Only after stable release and explicit approval: choose persistent dashboard backend, integrate approved lanes, merge to `Testing`, and separately plan production rollout. |

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
| Quality | TypeScript `tsc` | **Partial** | Executes in Code Quality, but console-only diagnostics are not normalized into the dashboard. |
| SAST | CodeQL (Python + JS/TS) | **Verified** | SARIF retained and normalized for both languages. |
| SAST | Semgrep OSS + custom rules | **Verified** | Raw JSON parser repaired; 2,736 findings entered the unified dashboard. |
| SAST | Bandit | **Verified** | JSON and normalized SARIF retained. |
| Supply chain | OSV-Scanner | **Verified** | SARIF retained and normalized. |
| Supply chain | Trivy filesystem/config | **Verified** | Both SARIF channels retained and normalized. |
| Secrets | Gitleaks | **Verified** | SARIF retained and normalized; canary-specific coverage still needs Phase 2 work. |
| IaC/container | Hadolint | **Verified** | Workflow and artifact channel verified after upload repair. |
| IaC/container | Checkov | **Verified** | SARIF retained and normalized. |
| Health | Radon | **Verified** | Complexity JSON retained and coverage manifest observes it; metrics are not yet converted into row-level findings. |
| Health | Xenon | **Partial** | Executes and exposes threshold failures in Actions; no structured finding parser. |
| Health | Vulture | **Verified** | Actual text format parser added; findings appear centrally. |
| Health | Coverage.py | **Verified** | Stable parent-process JSON/XML retained; dashboard shows 81.16%. Child-process coverage is not claimed. |
| Active testing | Schemathesis | **Partial** | Manual workflow exists; not validated in this work and JUnit/HTML outputs are not normalized into findings. |
| Active testing | Atheris | **Not implemented** | Mentioned in proposal/docs only; no executable fuzz harness or workflow. |
| AI review | CodeRabbit | **Not implemented** | No installed integration or verified review output. |
| AI review | PR-Agent | **Not implemented** | Fallback is documented only. |
| Behavioral health | CodeScene | **Partial scaffold** | Compose draft exists; no license/configured service, scan, or dashboard integration. |
| Finding management | DefectDojo | **Partial scaffold** | Compose draft exists; no deployed service, importer, persistence, or lifecycle sync. |
| Supply-chain alternative | Snyk | **Not implemented** | Mentioned as an optional future service; no enrollment/workflow/output. |
| Optional evaluator | Qodana | **Not selected / not implemented** | Appears in evaluation/parser compatibility only; it is not an active shortlisted lane. |
| GitHub native | Dependency Review | **Partial** | Configured PR-only; manual dispatch cannot exercise it and no PR trigger is active. |

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

## Phase 3 decision gate

Phase 3 is not automatic after Phase 2. Before activation, explicitly decide:

- which branches/events are in scope;
- which workflows remain manual due cost or noise;
- whether GitHub Issues stay dry-run or can be created;
- retention and visibility for the HTML dashboard;
- whether the fork or a future `Testing` integration owns the checks.

The current operator policy is advisory. Phase 3 must not add required status checks or
branch protection changes.

## Phase 4 remediation boundary

The only implemented autofix level is deterministic Ruff safe-fix **proposal** generation.
A future apply workflow must use this sequence:

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
