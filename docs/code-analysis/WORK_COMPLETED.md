# Code Analysis — Work Completed

> **Evidence date:** 2026-08-26  
> **Scope:** fork-only code detection, evidence normalization, and visualization  
> **Current implementation handoff:** [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)

This ledger records completed work, not proposal intent. “Completed” means code exists
and its relevant local or fork workflow acceptance was observed. It does not mean every
reported finding is a true positive or has been remediated.

## 1. Repository isolation and operating model

- Established `feature/static-code-analysis` as the development branch in the
  `combustrrr/Agentic-Kibana` fork.
- Added `ARYDESTROYER/Agentic-Kibana` as read-only upstream context and kept production
  and the company repository outside mutation scope.
- Synchronized the fork default `claude/main` with the accepted analysis branch so
  default-branch `workflow_run` dispatch uses the approved workflow definition.
- Preserved the existing application CI and implemented analysis as additive external
  workflows and services.

## 2. Scanner web

Implemented four full-codebase workflow families:

| Workflow | Implemented analysis |
|---|---|
| `01-code-quality.yml` | Ruff, Pyright, ESLint, TypeScript diagnostics |
| `02-security-sast.yml` | CodeQL Python/JS-TS, Semgrep OSS/custom, Bandit |
| `03-dependency-security.yml` | OSV-Scanner, Gitleaks, Trivy, Checkov, Hadolint, Dependency Review, optional Snyk SCA/Code |
| `04-code-health.yml` | Vulture, Radon, Xenon, Coverage.py |

The required manifest currently defines 16 fail-closed structured channels. Tool count
is not itself a coverage claim; each channel represents a complementary analysis surface.

Additional work:

- Project-specific Semgrep rules for security-sensitive Agentic SOC patterns.
- Structured parsers for TypeScript, Xenon, Vulture, Radon, Coverage.py, and scanner
  formats that did not natively arrive as usable SARIF.
- Manual Schemathesis JUnit ingestion as separate `DYNAMIC` evidence.
- Advisory `.coderabbit.yaml` with cloud automatic and per-push incremental PR review;
  exact-head inline-comment collection and AI-advisory dashboard refresh are implemented.
  Fork-only GitHub App execution remains pending and is not claimed complete.

## 3. Canary validation

- Built `tests/security_canary/` and the fail-closed canary workflow.
- Repaired the initial incoherent harness from 1/10 through 3/10, 5/10, and 7/10.
- Closed the defined SQL injection, FastAPI/path traversal, and React XSS fixture gaps
  through project-specific detection and normalization work.
- Fork run
  [`32938363577`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32938363577)
  passed all **10/10 defined expectations** at commit `48a1db2`.

This proves only the checked-in canary contract, not a universal detection percentage.

## 4. Normalization and canonical findings

- Repaired recursive artifact discovery and parsing across SARIF, JSON, text, and JUnit.
- Added canonical concepts so overlapping scanner rule IDs can represent one issue.
- Preserved every raw observation under the canonical finding.
- Added scanner family/channel, native result, rule, message, location, version,
  analysis category, and raw-artifact provenance.
- Hardened identity so unrelated same-line observations without snippet/column evidence
  cannot receive duplicate stable IDs.
- Fail closed on malformed artifacts, duplicate canonical IDs, mixed commits, hash
  mismatch, missing required channels, or count mismatch.

## 5. Exact-commit aggregation

- Pushes to every fork branch execute the scanner workflows.
- PRs use the same scanner web against the exact PR head; Dependency Review
  remains PR-only.
- Manual workflows support controlled re-analysis.
- The default-branch aggregator derives identity from `workflow_run.head_sha`, downloads
  successful artifacts for that exact commit, and rejects cross-commit mixtures.
- Snapshot artifacts include branch and full source SHA, preventing a dashboard from
  being mistaken for a different branch/commit.

## 6. Current-snapshot dashboard

- Replaced the lifecycle-first artifact concept with the latest publishable full-codebase
  snapshot as the primary product.
- Built a standalone searchable HTML dashboard with:
  - one row per canonical finding;
  - search and compound filters;
  - severity/category/component/directory/scanner distributions;
  - direct source links;
  - complete evidence drill-down;
  - raw observation and snapshot downloads;
  - separate deterministic and `AI_ADVISORY` scopes; and
  - bounded 50/100/250-row rendering.
- Added separate boards for the 16 required channels and optional/dynamic/AI/deferred
  lanes. Optional tools cannot inflate required coverage.
- Added scanner-family distribution and per-additional-lane finding/evidence totals.
- Published the improved real-data dashboard in run
  [`32940124398`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32940124398).

## 7. Publication and hosting

- Added atomic staging/current/previous publication; rejected refreshes leave the last
  valid dashboard active.
- Added a hardened read-only nginx image bound to `127.0.0.1:8787` for local evaluation.
- Added an outbound-only QA pull worker with protected-token-file support and ZIP path,
  symlink, count, and extraction-size validation.
- Documented the agreed initial QA VM: Ubuntu LTS, 8 vCPU, 16 GiB RAM, 200 GiB SSD,
  outbound HTTPS to GitHub, and company VPN/OIDC in front of the portal.
- Kept GitHub Actions artifacts as immutable evidence until the VM is available.

## 8. Snyk activation

- Added pinned Snyk CLI `1.1306.4`, scan-only SCA and Code commands, separate SARIF,
  per-surface logs, and explicit configuration status.
- Hardened the workflow so valid “findings found” exit code 1 remains advisory evidence,
  while unresolved projects or unavailable products become `CONFIGURED_PARTIAL`.
- Authenticated locally and proved SARIF normalization; local Python resolution was
  partial and was recorded truthfully.
- Added fork repository secret `SNYK_TOKEN` without exposing its value.
- Fork run
  [`32965286130`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32965286130)
  passed Open Source SCA, Snyk Code, status generation, and artifact upload. Retained
  artifact: `snyk-results` ID `9605455800`.
- No `monitor`, `report`, fix, patch, or PR command is present.

## 9. GitHub-native security features observed

The fork owner enabled CodeQL advanced setup, Copilot Autofix, and GitHub AI findings,
and added the Snyk Actions secret. Dependabot currently reports native dependency alerts.
These GitHub-native surfaces remain distinct from the canonical custom dashboard;
Copilot Autofix is not invoked by this platform.

## 10. Verification summary

- Analysis-service regression suite: **31/31 passed**.
- Defined canaries: **10/10 passed**.
- Scale gate: 10,000 canonical findings / 13,000 observations under 30 seconds and
  512 MiB; latest dashboard expansion measured 5.60 seconds / 80.20 MiB.
- Browser DOM: at most 250 finding rows.
- Dashboard JavaScript syntax, workflow/Compose YAML, catalog JSON, Ruff, documentation,
  and whitespace validation passed.
- No upstream, production, application, Issue, PR-comment, patch, autofix, remediation,
  deployment, branch-protection, or DefectDojo mutation occurred.

## 11. Key implementation commits

| Commit | Purpose |
|---|---|
| `48a1db2` | Accepted current-snapshot scanner and dashboard platform |
| `c1692ff` | Improved real-findings dashboard UI/UX |
| `833afc3` | Unified Actions and QA-VM publication path |
| `ab53481` | Bound dashboard artifacts to exact source commits |
| `91cc495` / `a78402a` | Conservative evidence correlation and stable-ID hardening |
| `ee3a90e` | Advisory/dynamic lane preparation |
| `9cd2d67` | Truthful partial Snyk status handling |
| `1c419be` | Consolidated implementation documentation |
| `6f0adfc` | Additional scanner-lane visualization |
