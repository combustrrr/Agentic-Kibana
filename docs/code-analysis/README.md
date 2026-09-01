# Agentic SOC Current Findings Platform

> **Authority:** [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) records implementation truth.
> The original proposal remains a scanner-candidate roadmap. Issue Wall is deliberately
> a read-only visualization/tracker; assignment, suppression, closure, remediation,
> Issues, DefectDojo lifecycle, and production integration are outside its contract.
> [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) is the consolidated architecture,
> trigger, tool-status, delivery, safety, and verified-evidence handoff. Historical
> session handoffs are retained as records and are not current operating instructions.

## Engineering document map

| Need | Read |
|---|---|
| Start from the current operational state | This README, then [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |
| What the platform is and how it works | [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |
| What has actually been completed | [`WORK_COMPLETED.md`](WORK_COMPLETED.md) |
| Why the architecture uses these boundaries | [`ADRS.md`](ADRS.md) |
| Cloud artifact security and readiness gates | [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) |
| External service package and dependency architecture | [`SERVICE_ARCHITECTURE.md`](SERVICE_ARCHITECTURE.md) |
| Sole active backlog and priority order | [`PENDING_WORK.md`](PENDING_WORK.md) |
| Latest development-session restart snapshot | [`SESSION_HANDOFF_2026-09-01.md`](SESSION_HANDOFF_2026-09-01.md) |
| Authoritative phase/status table | [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) |
| Where and how the dashboard is viewed | [`MONITORING_UI.md`](MONITORING_UI.md) |
| External service activation state | [`EXTERNAL_ACTIVATION.md`](EXTERNAL_ACTIVATION.md) |
| Snyk overlap and retention decision | [`SNYK_UNIQUE_CONTRIBUTION.md`](SNYK_UNIQUE_CONTRIBUTION.md) |

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

Analysis-branch pushes and eligible pull requests run the four scanner workflows. Pull
requests analyze the exact PR head rather than GitHub's synthetic merge ref. The manual
orchestrator can analyze any selected fork branch head using approved default-branch
workflow/tooling definitions. When the final code-health workflow succeeds, one default-branch dispatcher gathers the
successful **same-commit** artifacts from all four workflows and publishes one unified
snapshot. Automatic push/PR execution requires the relevant branch to contain the
workflow definitions; the manual orchestrator is the current safe cross-branch path for
clean mirror branches such as `Testing`.

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

Optional evidence now includes exact-commit shipping-image Trivy scans, CycloneDX and
SPDX SBOMs with license-policy results and unsigned local provenance, zizmor, OpenSSF
Scorecard, GitHub secret-scanning/push-protection posture, Snyk, SonarQube Cloud, and
CodeRabbit. Weekly isolated Schemathesis and Atheris jobs remain dynamic evidence. None
of these optional lanes can turn a missing required channel green.

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
refreshes cannot replace the last publishable artifact for that branch and commit.

See [`MONITORING_UI.md`](MONITORING_UI.md) for the authenticated GitHub artifact flow.

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
  PR APIs and trigger a dashboard refresh into the separate `AI_ADVISORY` view. Exact-head
  GitHub App execution is verified.
- SonarQube Cloud exact-commit analysis is verified. Bounded native issue export,
  canonical parsing, and a loop-safe generic external-issue projection are implemented.
  Native cloud ingestion currently reports `CONFIGURED_PARTIAL` because the PAT owner
  still lacks project Browse permission; the precise acceptance step lives only in
  [`PENDING_WORK.md`](PENDING_WORK.md). Sonar-native and all `AI_ADVISORY` findings are
  excluded from the outbound projection.
- CodeScene and additional tools enter only after an exportable, non-redundant
  contribution is approved and measured.
- `config/code-analysis/proposal-tool-catalog.json` (repository source; intentionally
  outside the packaged documentation tree)
  accounts explicitly for every selected proposal tool and its activation boundary.

Scanners run only in GitHub Actions, not in the Agentic SOC application startup path.
The supported Issue Wall is the authenticated, self-contained Actions artifact; there
is no local server, pull worker, QA host, or continuously hosted copy.

For every analyzed commit, the advisory **Code Analysis Dashboard** Check links to its
complete searchable artifact. Branches never share artifact identities or Checks. The
exact branch/SHA identity prevents a slower older run from masquerading as the latest
dashboard for a newer commit.

### Automatic and manual operation

- **Automatic latest-head coverage:** a trusted default-branch supervisor discovers
  every fork branch every 15 minutes and dispatches the existing full-analysis
  orchestrator for any current head without a valid dashboard Check. The observed SHA
  is carried into the dispatch. Native push/PR scans and active dashboard builds are
  detected before dispatch; complete retained evidence goes directly to aggregation
  instead of being rescanned. A broken exact head is attempted at most three times. A
  newer commit supersedes stale same-branch scanner and dashboard work.
- **Immediate coverage where workflow definitions exist:** a branch push runs all four
  scanners; an eligible same-repository PR update analyzes its exact head; successful
  exact-commit evidence triggers dashboard aggregation. GitHub does not execute newly
  added push/PR workflow definitions from a branch that does not contain them, which is
  why the default-branch supervisor is the completeness backstop.
- **Manual full scan:** Actions → **Full Code Analysis (Manual)** → **Run workflow**.
  Select the workflow ref, optionally enter any fork `scan_branch`, and press the green
  **Run workflow** button. The orchestrator resolves the named branch through GitHub's
  branch API and locks its authoritative head SHA; the workflow-ref selection never
  substitutes for that source identity. It reuses successful exact-SHA evidence only
  while retained artifacts still exist, dispatches missing groups, streams all four
  scanner runs concurrently, builds the exact-commit dashboard, and returns direct run
  and artifact links. A failed scanner or incomplete snapshot stops the flow without
  replacing the last valid dashboard.
- **Manual dashboard-only rebuild:** Actions → **Code Analysis Dashboard** → **Run
  workflow**, with the exact `scan_branch` and `scan_sha`. This reuses existing scanner
  evidence and fails closed if a required exact-commit run is unavailable.

The dashboard leads with security posture, critical/high counts, affected areas,
freshness, and the exact publication path. Hotspots and distribution bars apply filters
directly, while searchable findings, scanner coverage, optional lanes, source links,
workflow runs, artifact hashes, and raw downloads remain available for investigation.

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
| Baseline/lifecycle/previous-run comparison | **Outside current snapshot contract** |
| DefectDojo and persistent triage | **Outside Issue Wall contract** |
| Autofix, patches, Issues, and blocking gates | **Outside Issue Wall contract** |
| Authenticated offline Issue Wall artifact | **Current delivery** |
