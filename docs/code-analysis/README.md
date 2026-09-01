# Agentic SOC Current Findings Platform

> **Authority:** the checked-in workflows, scanner catalog, and current contracts listed
> below describe the supported implementation. Issue Wall is a read-only visualization
> artifact; it does not assign, suppress, close, or remediate findings.

## Start here

| Need | Read |
|---|---|
| Architecture and safety boundary | [`SERVICE_ARCHITECTURE.md`](SERVICE_ARCHITECTURE.md) |
| Production and GitHub readiness | [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) |
| Run and use Issue Wall | [`MONITORING_UI.md`](MONITORING_UI.md) |
| Upstream integration and enterprise acceptance | [`UPSTREAM_INTEGRATION.md`](UPSTREAM_INTEGRATION.md) |

## Supervisor demonstration

Use the accepted immutable artifact rather than a locally generated mock:

1. Open [GitHub Actions run `33528827999`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/33528827999) and download
   `current-findings-dashboard-feature-static-code-analysis-3856d26362d5-c92032a54e4159268abc91d4667c9bf47e9b5b28-33528827999`.
2. Verify the artifact digest is
   `sha256:5a04e175015952d1d78637c00dd118e353a121f52821f070ac1f6387452f2ee7`,
   extract it, read `dashboard/START_HERE.md`, and open `dashboard/index.html`.
3. Show exact branch/SHA provenance, `16/16` required channels, the security posture,
   severity and affected-area charts, searchable findings, one Evidence dialog, an
   immutable source link, filtered CSV export, optional-lane status, workflow run IDs,
   and artifact hashes. The accepted snapshot contains 16,257 canonical findings and
   16,927 retained observations.
4. To demonstrate fresh operation, use Actions → **Full Code Analysis (Manual)**,
   select the trusted default workflow ref, enter the target fork branch, and run it.
   The job summary provides the resolved source SHA, four scanner runs, dashboard run,
   and final artifact link. A failed or incomplete refresh cannot replace accepted
   evidence.

This is a read-only engineering report, not a claim that the application is secure.
Do not upload or republish the artifact outside its approved audience: raw scanner
messages can contain repository paths, snippets, dependency metadata, and rule evidence.

## Documentation structure

### Current contracts

These files describe behavior that implementations and workflows must continue to honor.

| Document | Purpose |
|---|---|
| [`SERVICE_ARCHITECTURE.md`](SERVICE_ARCHITECTURE.md) | External service, package, and dependency boundaries |
| [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Artifact security and readiness gates |
| [`DATA_HANDLING_INVENTORY.md`](DATA_HANDLING_INVENTORY.md) | Release-facing scanner, credential, retention, failure, and removal inventory |
| [`UPSTREAM_INTEGRATION.md`](UPSTREAM_INTEGRATION.md) | Scoped upstream application, enterprise gate, and supervisor demonstration |

### Operator guides

| Document | Purpose |
|---|---|
| [`MONITORING_UI.md`](MONITORING_UI.md) | How to run, open, and use Issue Wall |
| [`EXTERNAL_ACTIVATION.md`](EXTERNAL_ACTIVATION.md) | Optional service activation and credential boundaries |
| [`SNYK_UNIQUE_CONTRIBUTION.md`](SNYK_UNIQUE_CONTRIBUTION.md) | Snyk overlap and retention measurement |

Development history is retained in the repository `Journal.md`; this directory contains
only current operating contracts and scanner evidence notes.

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

Analysis-branch pushes and eligible pull requests may run the four scanner workflows and
retain evidence. Pull requests analyze the exact PR head rather than GitHub's synthetic
merge ref. Scanner completion never publishes Issue Wall automatically. The sole
publication entry point is **Full Code Analysis (Manual)**, which resolves the selected
branch and either its latest HEAD or an optional reachable exact SHA, reuses valid
same-commit evidence, runs missing scanners, and calls the reusable dashboard builder.

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
  advisory lane. A manually requested Issue Wall collects exact-head inline bot comments
  through GitHub's read-only PR APIs into the separate `AI_ADVISORY` view. Exact-head
  GitHub App execution is verified.
- SonarQube Cloud exact-commit analysis is verified. Bounded native issue export,
  canonical parsing, and a loop-safe generic external-issue projection are implemented.
  Both PATs authenticate and Sonar accepted the explicit Browse grant. Main and eligible
  PR results are imported when exposed; Free-plan arbitrary-branch issue access remains
  HTTP 403 and is represented truthfully as `CONFIGURED_PARTIAL` without blocking Issue
  Wall. Sonar-native and all `AI_ADVISORY` findings are excluded from the outbound
  projection.
- `config/code-analysis/proposal-tool-catalog.json` (repository source; intentionally
  outside the packaged documentation tree) lists the integrated scanner and assurance
  channels consumed by Issue Wall.

Scanners run only in GitHub Actions, not in the Agentic SOC application startup path.
The supported Issue Wall is the authenticated, self-contained Actions artifact; there
is no local server, pull worker, QA host, or continuously hosted copy.

For every analyzed commit, the advisory **Code Analysis Dashboard** Check links to its
complete searchable artifact. Branches never share artifact identities or Checks. The
exact branch/SHA identity prevents a slower older run from masquerading as the latest
dashboard for a newer commit.

### Manual publication and automatic evidence collection

- **Evidence collection:** a branch push may run all four scanners; an eligible
  same-repository PR update analyzes its exact head. These runs retain evidence only and
  never generate or replace Issue Wall.
- **Manual full scan:** Actions → **Full Code Analysis (Manual)** → **Run workflow**.
  Leave `scan_branch` blank for the repository default branch, or enter any other branch.
  Leave `scan_sha` blank for the branch's latest HEAD, or enter a reachable 40-character
  SHA from that branch for a historical exact-commit report. The workflow-ref selection
  never substitutes for source identity. It reuses successful exact-SHA evidence only
  while retained artifacts still exist, dispatches missing groups, streams all four
  scanner runs concurrently, invokes the private reusable dashboard job, and publishes
  the artifact in the same manual workflow run. A failed scanner or incomplete snapshot
  stops the flow without replacing the last valid dashboard. The final
  **Supervisor-ready artifact handoff** job provides one prominent download link,
  branch, exact SHA, artifact ID/digest, and three-step offline launch instructions.

The dashboard leads with security posture, critical/high counts, affected areas,
freshness, and the exact publication path. Hotspots and distribution bars apply filters
directly, while searchable findings, scanner coverage, optional lanes, source links,
workflow runs, artifact hashes, and raw downloads remain available for investigation.

## Safety

The platform is external and read-only. It cannot create Issues or PR comments, generate
or apply patches, push commits or refs, change branch protection, deploy Agentic SOC,
contact production, or mutate the original repository. It does not claim that the
application is secure or publish unsupported coverage percentages.
