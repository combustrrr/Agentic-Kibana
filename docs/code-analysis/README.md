# Agentic SOC Current Findings Platform

> **Authority:** [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) records implementation truth.
> The original proposal remains a scanner-candidate roadmap; remediation, Issues,
> DefectDojo, history, and production integration are deferred.

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

## Discovery lanes

- Deterministic findings are the primary canonical table.
- Optional AI output is labelled `AI_ADVISORY` and never counts as deterministic
  corroboration.
- Snyk has a scan-only, token-gated SARIF lane. Until `SNYK_TOKEN` is configured it
  reports `NOT_CONFIGURED`, is not required, and cannot make the snapshot look complete.
- SonarQube, CodeScene, CodeRabbit, and additional tools enter only after an exportable,
  non-redundant detection contribution is verified.
- [`proposal-tool-catalog.json`](../../config/code-analysis/proposal-tool-catalog.json)
  accounts explicitly for every selected proposal tool and its activation boundary.

Scanners run in GitHub Actions or a dedicated QA worker, not in the Agentic SOC
application startup path. The VM serves the last validated snapshot continuously while
new evidence is built separately and published atomically.

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
