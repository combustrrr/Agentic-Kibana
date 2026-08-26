# Agentic SOC Current Findings Platform

> **Authority:** [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) records implementation truth.
> The original proposal remains a scanner-candidate roadmap; remediation, Issues,
> DefectDojo, history, and production integration are deferred.
> [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) is the consolidated architecture,
> trigger, tool-status, hosting, safety, and verified-evidence handoff from the 2026-08-26
> implementation discussions.

## Engineering document map

| Need | Read |
|---|---|
| What the platform is and how it works | [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |
| What has actually been completed | [`WORK_COMPLETED.md`](WORK_COMPLETED.md) |
| Why the architecture uses these boundaries | [`ADRS.md`](ADRS.md) |
| Production/QA-VM security and deployment gates | [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) |
| What remains, in priority order | [`PENDING_WORK.md`](PENDING_WORK.md) |
| Authoritative phase/status table | [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) |
| Where and how the dashboard is viewed | [`MONITORING_UI.md`](MONITORING_UI.md) |
| Local and company VM hosting contract | [`QA_VM.md`](QA_VM.md) |
| External service activation state | [`EXTERNAL_ACTIVATION.md`](EXTERNAL_ACTIVATION.md) |

## Objective

```text
Find → Normalize → Deduplicate → Show
```

The product is the latest trustworthy full-codebase snapshot. Every normalized canonical
issue is visible, while all scanner observations remain attached as evidence. A larger
count may reflect better detection and is not itself a failure.

The required-channel manifest spans semantic and pattern SAST, Python and TypeScript
quality/types, dependencies, secrets, containers, IaC, complexity, dead code, and
coverage evidence. No single scanner is treated as sufficient.

Every fork branch is monitored. Each push runs the four scanner workflows. Eligible
pull requests analyze the exact PR head rather than GitHub's synthetic merge ref, and
manual dispatch analyzes the selected workflow ref. When the final code-health workflow succeeds, one default-branch dispatcher gathers the
successful **same-commit** artifacts from all four workflows and publishes one unified
snapshot. Pull requests targeting `claude/main` or `Testing` use the same contract.

The current required web contains 16 structured channels:

| Cloud workflow | Required channels represented in the unified dashboard |
|---|---|
| `01-code-quality.yml` | Ruff, Pyright, ESLint, TypeScript, Bandit |
| `02-security-sast.yml` | CodeQL, Semgrep |
| `03-dependency-security.yml` | OSV-Scanner, Gitleaks, Trivy, Hadolint, Checkov |
| `04-code-health.yml` | Vulture, Radon, Xenon, Coverage.py |

The dashboard exposes this mapping per channel together with its completion state,
finding count, retained artifact names, workflow-run references, scanner versions,
and SHA-256 artifact proof. A green `16/16` therefore means structured evidence from
all 16 required channels was validated, not merely that four workflow shells ran.

An artifact is not enough by itself: malformed scanner output now fails normalization
and cannot publish a dashboard. Radon complexity blocks and Coverage.py file-level
coverage gaps are normalized as visible findings rather than appearing only as a green
channel-status badge.

## Output contract

The dashboard workflow creates:

- `current-snapshot.json` with exact commit, branch, run IDs, scanner versions, channel
  status, artifact hashes, canonical findings, AI advisories, and raw observations;
- one searchable HTML view with 50/100/250-row bounded rendering;
- evidence drill-down for every contributing scanner observation;
- separate raw-observation and snapshot downloads; and
- one read-only GitHub Check describing whether publication succeeded.

A snapshot is publishable only when required workflows succeeded, artifacts share the
exact commit and valid hashes, normalization completes, and counts reconcile. Failed
refreshes cannot replace the last publishable hosted snapshot.

See [`MONITORING_UI.md`](MONITORING_UI.md) for local and future QA-VM hosting.
See [`QA_VM.md`](QA_VM.md) for the outbound-only pull worker, shared local/Actions
pipeline command, systemd boundary, and VM deployment contract.

## Discovery lanes

- Deterministic findings are the primary canonical table.
- Optional AI output is labelled `AI_ADVISORY` and never counts as deterministic
  corroboration.
- Snyk has a scan-only, token-gated SARIF lane. The fork secret is configured and run
  `32965286130` verified both Open Source and Code scans plus retained evidence. It
  remains optional and reports `NOT_CONFIGURED` or `CONFIGURED_PARTIAL` truthfully when
  credentials or analysis surfaces are unavailable.
- CodeRabbit cloud automatic and per-push incremental PR review is configured as an
  advisory lane. Exact-head inline bot comments are collected through GitHub's read-only
  PR APIs and trigger a dashboard refresh into the separate `AI_ADVISORY` view. Fork-only
  GitHub App execution remains unverified. SonarQube, CodeScene, and
  additional tools enter only after an exportable, non-redundant contribution is verified.
- [`proposal-tool-catalog.json`](../../config/code-analysis/proposal-tool-catalog.json)
  accounts explicitly for every selected proposal tool and its activation boundary.

Scanners run in GitHub Actions or a dedicated QA worker, not in the Agentic SOC
application startup path. The VM serves the last validated snapshot continuously while
new evidence is built separately and published atomically.

For every analyzed commit, the advisory **Code Analysis Dashboard** Check links to its
complete searchable artifact. Branches never share artifact identities or Checks. The
outbound QA worker only publishes a snapshot when its analyzed SHA equals the selected
branch's current GitHub head, so a slower older run cannot become the latest dashboard.

### Automatic and manual operation

- **Automatic:** every fork branch push runs all four scanners; an eligible PR update
  analyzes its exact head; successful exact-commit evidence triggers dashboard aggregation.
- **Manual full scan:** Actions → **Full Code Analysis (Manual)** → **Run workflow**.
  Select the branch in GitHub or enter `scan_branch`; the orchestrator validates its
  current head and dispatches all four scanners. The dashboard then builds automatically.
- **Manual dashboard-only rebuild:** Actions → **Code Analysis Dashboard** → **Run
  workflow**, with the exact `scan_branch` and `scan_sha`. This reuses existing scanner
  evidence and fails closed if a required exact-commit run is unavailable.

## Safety

The platform is external and read-only. It cannot create Issues or PR comments, generate
or apply patches, push commits or refs, change branch protection, deploy Agentic SOC,
contact production, or mutate the original repository. It does not claim that the
application is secure or publish unsupported coverage percentages.

## Supersession

| Historical capability | Current status |
|---|---|
| Complementary scanner web and canaries | **Retained** |
| Canonical identity with preserved observations | **Retained** |
| Baseline/lifecycle/previous-run comparison | **Deferred** |
| DefectDojo and persistent triage | **Deferred** |
| Autofix, patches, Issues, and blocking gates | **Deferred** |
| Hosted read-only custom dashboard | **Current implementation target** |
