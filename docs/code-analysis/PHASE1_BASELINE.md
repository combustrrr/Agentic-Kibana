# Phase 1 findings baseline

> Captured: 2026-08-22  
> Branch: `feature/static-code-analysis`  
> Scope: findings collection and web visibility only; no finding was fixed or suppressed.
> This is historical Phase 1 evidence. For the current 16-channel platform, 10/10 canary
> acceptance, Snyk activation, and hosted-dashboard contract, see
> [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## Where to view findings

- [Code Quality run](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32571537375)
  — Ruff and Bandit artifacts.
- [Security / SAST run](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32572168634)
  — CodeQL and Semgrep SARIF/JSON artifacts.
- [Dependency & Supply Chain run](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32571539832)
  — OSV, Gitleaks, Trivy, and Checkov artifacts.
- [Code Health run](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32571540838)
  — Radon and Vulture artifacts plus coverage/complexity logs.
- [Canary validation run](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32571184115)
  — raw canary outputs and the expected Phase 2 coverage failure.
- [GitHub code-scanning view](https://github.com/combustrrr/Agentic-Kibana/security/code-scanning)
  — uploaded CodeQL and third-party SARIF where repository features permit it.

Open a run, select **Artifacts** near the bottom of its summary page, and download the
named result bundle. Artifacts retain the scanner-native JSON, SARIF, or text rather
than a remediated or suppressed view.

## Raw baseline counts

These are per-tool raw result counts. Tools overlap, so they must not be summed into a
unique-defect total.

| Tool | Raw results | Evidence |
|---|---:|---|
| Ruff extended | 5,392 | `ruff-results` |
| Bandit | 7 | `bandit-results` JSON and normalized SARIF |
| Semgrep | 2,738 across 888 scanned files | `semgrep-results` and `semgrep-sarif` |
| CodeQL Python | 333 | `codeql-python-sarif` |
| CodeQL JavaScript/TypeScript | 6 | `codeql-javascript-typescript-sarif` |
| OSV-Scanner | 335 | `osv-results` |
| Gitleaks | 18 | `gitleaks-results` SARIF |
| Trivy filesystem | 17 | `trivy-results/trivy-fs.sarif` |
| Trivy configuration | 6 | `trivy-results/trivy-config.sarif` |
| Checkov | 4 | `checkov-results` |
| Vulture | See text artifact | `vulture-results` |
| Radon | See JSON artifact | `radon-reports` |

## Run interpretation

- Red workflow or job status is not automatically a pipeline failure during this
  findings-only phase. OSV, Gitleaks, Xenon, and coverage may return non-zero when they
  report vulnerabilities, thresholds, or test/coverage problems.
- The final Code Quality and Security/SAST collection jobs completed and produced their
  intended artifacts. Dependency and Code Health retained their raw evidence even where
  scanner/threshold steps returned non-zero.
- Semgrep retained nine parser diagnostics alongside its 2,738 results. They are part of
  the baseline evidence and should be reviewed before any future blocking activation.
- Canary normalization/coverage is Phase 2 work. Its current failure does not invalidate
  this Phase 1 repository baseline.
- All automatic push, pull-request, and schedule triggers remain commented out.

## Deferred work

Finding classification, false-positive decisions, suppressions, remediation, canary
10/10 coverage, and blocking thresholds are deliberately deferred. None should be
performed merely to make the baseline green.
