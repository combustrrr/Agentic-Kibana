# Agentic SOC Static-Analysis Monitoring

> **Authority:** [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) is the current implementation
> contract. The August 2026 automation-heavy proposal is retained as a long-term scanner
> research roadmap. Its autofix, patch, Issue-sync, blocking-gate, hosted DefectDojo,
> external-AI, upstream, and production sections are deferred and are not authorized.

## Current objective

Turn a large scanner backlog into a manageable, searchable stream of changes while
preserving complete historical visibility:

```text
Find → Normalize → Compare → Show → Track
```

The deterministic scanner web spans semantic and pattern SAST, Python/TypeScript
analysis, dependency vulnerabilities, secrets, infrastructure, complexity, dead code,
and runtime coverage evidence. Its source of truth is
[`required-channels.json`](../../config/code-analysis/required-channels.json); the
implementation does not hard-code a channel count.

No single scanner is treated as sufficient. Multiple observations of the same source
concept become one canonical finding, while independent scanner-family evidence remains
visible as corroboration.

## Two discovery lanes

- **Deterministic monitoring:** canonical findings, accepted-baseline and prior-run
  comparison, dashboard, advisory Check, and human triage.
- **Optional AI review:** a future, separately approved PR-advisory lane. AI suggestions
  are not deterministic evidence, do not count as corroboration, and require human
  confirmation before canonical tracking.

The deterministic service works without an AI provider or external code-sharing service.

## States

The service keeps three dimensions separate:

| Dimension | Values |
|---|---|
| Scanner | `COMPLETED`, `FAILED`, `TIMED_OUT`, `SKIPPED`, `NOT_CONFIGURED`, `PARTIAL` |
| Lifecycle | `NEW`, `EXISTING`, `MOVED`, `NOT_OBSERVED`, `INDETERMINATE` |
| Human | `UNREVIEWED`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `DEFERRED` |

A scanner failure is not disappearance; disappearance is not remediation; a human risk
decision is not a technical fix.

## Developer surface

The **Code Analysis Dashboard** workflow publishes:

- One advisory custom Check per internal repository/commit/name/namespace key
- A bounded Attention view for new, serious, corroborated, moved, or uncertain findings
- A searchable complete backlog with 50/100/250-row pagination
- Scanner status, lifecycle reason codes, independent corroboration, and human state
- An attention-surface ratio that measures UI compression, not vulnerability coverage

See [`MONITORING_UI.md`](MONITORING_UI.md) for navigation.

## Persistent evidence

- Raw and normalized per-run evidence follows GitHub Actions artifact retention.
- The explicitly accepted baseline is reconstructed only from accepted run `32578162932`
  and validated against [`baseline-manifest.json`](../../config/code-analysis/baseline-manifest.json).
- Human decisions live in the sparse, versioned
  [`triage-registry.json`](../../config/code-analysis/triage-registry.json).
- A minimal DefectDojo fixture proves stable future identity mapping offline; there is
  no DefectDojo deployment or network integration.

## Safety boundary

The monitoring workflow grants only `contents: read`, `actions: read`, and
`checks: write`. It cannot create Issues or PR comments, commit or push changes, generate
patches, modify branch protection, deploy, contact production or DefectDojo, or mutate
the original/upstream repository.

Permitted completion claims are limited to:

> Static-analysis monitoring is validated across the configured required channels.

> The configured scanner web provides validated detection for the defined canary set.

The project does not claim that the application is secure or assign unsupported
vulnerability-detection percentages.

## ADR supersession matrix

| Historical decision | Current status |
|---|---|
| Complementary scanner web and canary suite | **Retained** |
| File + line + concept as sole identity | **Replaced** by versioned stable identity plus observations |
| Existing CI remains untouched and analysis workflows stay additive | **Retained** |
| GitHub Security plus deployed DefectDojo as current database | **Deferred**; dashboard artifact is authoritative now |
| Copilot/custom autofix | **Deferred** |
| Automatic GitHub Issues and Projects synchronization | **Deferred** |
| Blocking severity gates and coverage percentages | **Deferred/rejected for MVP** |
| AI reviewers as contextual advisers | **Deferred pending explicit privacy/service approval** |
