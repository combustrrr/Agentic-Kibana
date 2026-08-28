# External code-analysis service architecture

## Purpose

The service diagnoses security and engineering issues for developers. It analyzes an
exact repository revision, retains scanner-native proof, produces canonical findings,
and serves a searchable current snapshot. It is external to the application and has no
write path into source code, pull requests, Issues, deployment, or production.

## Repository structure

```text
.github/workflows/
  01..04                    scanner execution planes
  05                        exact-commit aggregation and Check
  06                        security-canary verification
  08                        manual branch-head orchestration
  09                        CodeRabbit advisory refresh

config/code-analysis/
  required-channels.json    required scanner/evidence contract
  proposal-tool-catalog.json researched activation catalog
  service-layout.json       executable module-ownership boundary

scripts/code_analysis/
  normalizer.py             scanner-native ingestion adapters
  collect_coderabbit.py     bounded AI-advisory GitHub adapter
  monitoring.py             identity/correlation domain
  evidence_contract.py      immutable artifact contract
  channel_status.py         required-channel completeness
  provenance.py             exact-revision source proof
  snapshot.py               current-snapshot assembly
  pipeline.py               application orchestration
  dashboard.py              presentation application
  dashboard_template.html   bounded developer UI
  audit_workflows.py        architecture/security policy
  validate_canary.py        detection-web contract
  benchmark_monitoring.py   scale gate
  test_service.py           service regression suite

docs/code-analysis/         operator, architecture, evidence, and handoff docs
```

## Dependency rule

The domain is deterministic and infrastructure-free. Adapters translate scanner or
GitHub data at the boundary. Application modules validate and assemble a snapshot.
Presentation consumes only that validated contract. GitHub Actions publishes the
immutable artifact. Nothing imports the Agentic SOC backend or frontend. All
implementation ownership stays in `.github/workflows/0[1-9]-*`,
`config/code-analysis/`, `scripts/code_analysis/`, and `docs/code-analysis/`.
No analysis implementation file is owned by `backend/`, `webui/`, or an application
Compose profile.

## Developer diagnosis path

```text
exact commit
  -> complementary security/quality scanners
  -> immutable native artifacts
  -> adapters and normalizer
  -> canonical finding + all observations
  -> reconciled publishable snapshot
  -> security-focused and complete dashboard views
```

A developer can start at a security count, filter by concept/component/path/scanner,
open one canonical finding, inspect every contributing rule and native result, and
follow the exact workflow/artifact proof. AI candidates remain a separate view.

## Change discipline

`service-layout.json` is validated in CI. Missing declared files, undeclared layer
names, forbidden application runtime dependencies, unsafe Actions, and unbounded jobs
fail the Code Quality workflow. Stable script paths remain compatibility entry points;
internal extraction into packages can occur incrementally without breaking automation.
