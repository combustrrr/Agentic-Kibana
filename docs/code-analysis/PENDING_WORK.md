# Code Analysis — Pending Work

> **Prioritization date:** 2026-08-26  
> **Primary objective:** improve issue detection and the unified current-findings view  
> **Not an active objective:** fixing findings or reducing the count to zero

Only work that advances trustworthy detection, evidence ingestion, visualization, or
approved hosting belongs in the near-term backlog.

## P0 — Finish current platform delivery

### P0.1 Publish and verify the enterprise-hardened real-data board

**Current state:** workflow security, immutable dependencies, least privilege, branch
coverage, advisory Check semantics, deployment hardening, and the executable workflow
policy are implemented locally. Manual `Testing` runs #1/#2 exposed and drove fixes for
checkout-free CLI repository context, default-branch workflow definitions, separate
trusted `.analysis-tooling`, and manual run identity. Commit `14874b1` is on the fork
analysis/default branches; a new end-to-end cloud rerun is the immediate acceptance gate.

**Exit criteria:**

- all four scanner workflows succeed for the exact commit;
- aggregation publishes a snapshot containing `additional_channels`;
- Snyk displays its actual current status and evidence counts;
- CodeRabbit displays `PENDING_ACTIVATION` and `AI_ADVISORY`;
- required completion remains 16/16 and optional lanes do not affect publishability;
- the Check links to the new real-data artifact.

### P0.2 Activate and verify CodeRabbit cloud PR review

**Current state:** privacy/code-sharing approval received. Automatic cloud review and
incremental review after every PR push are configured, without request-changes
authority. Exact-head inline review-comment ingestion and dashboard refresh are
implemented. The GitHub App installation and a real fork PR review remain unverified.

**Exit criteria:**

- install/authorize the CodeRabbit GitHub App on this fork only;
- open or update an eligible fork PR and verify automatic incremental review after a push;
- verify dashboard adapter output is `AI_ADVISORY`, retains native evidence, rejects
  stale comments, and never contributes deterministic corroboration;
- determine whether it adds non-redundant findings;
- confirm the app has no upstream-company repository access and cannot apply patches.

### P0.3 Deploy the dashboard to the company QA VM

**Dependency:** company-provided Ubuntu LTS VM.

**Exit criteria:**

- 8 vCPU / 16 GiB RAM / 200 GiB SSD or measured equivalent;
- outbound GitHub HTTPS and no inbound GitHub webhook requirement;
- repository-scoped read credential loaded from a protected file/systemd credential;
- pull worker verifies and atomically publishes an exact-commit artifact;
- container binds `127.0.0.1` and runs read-only with dropped capabilities;
- company VPN/OIDC protects developer access;
- restart test proves the current snapshot remains available;
- failed refresh test proves the prior snapshot remains served.

## P1 — Improve detection breadth and evidence quality

### P1.1 Measure Snyk's unique contribution

- Download the authenticated `snyk-results` artifact from a verified run.
- Reconcile Snyk observations/canonical findings in the custom dashboard.
- Measure overlap with OSV, CodeQL, Semgrep, and other existing families.
- Keep Snyk optional unless unique value and acceptable reliability are demonstrated.

### P1.2 Evaluate SonarQube

- Use the QA VM only after core hosting is stable.
- Configure read-only analysis and authenticated machine-readable issue export.
- Ingest into the normalizer rather than making SonarQube a competing canonical UI.
- Retain only if it adds useful issues not already represented.

### P1.3 Evaluate CodeScene

- Confirm OSS eligibility/license and a stable export API/file.
- Prioritize behavioral hotspots/health signals that static scanners do not provide.
- Do not scrape the visual UI or count non-exportable scores as canonical findings.

### P1.4 Expand project-specific detection

- Continue reviewing `AGENTS.md`, auth/RBAC, agent tools, LLM boundaries, Elasticsearch
  query construction, state reset, connectors, and middleware for narrowly testable rules.
- Add every new claimed concept to the canary contract with retained tool/rule/location
  evidence and false-positive fixtures.
- Prefer meaningful new surfaces over redundant scanner count.

### P1.5 Verify GitHub-native secret posture

- Confirm secret-scanning alerts and push-protection state on the fork.
- Keep Gitleaks as retained cross-platform evidence.
- Do not expose detected secret values in dashboard artifacts.

## P2 — Optional dynamic and contextual discovery

### P2.1 Schemathesis operational evaluation

- Boot the bounded test backend in an isolated environment.
- Run the existing manual workflow and verify `DYNAMIC` dashboard visibility.
- Measure duration/flakiness before considering scheduled or per-commit execution.

### P2.2 Atheris harness research

- Select pure parsers/state-machine functions with bounded inputs and no external side
  effects.
- Add corpus, time/memory limits, crash artifact sanitization, and reproducibility.
- Keep outside the static publishability gate.

### P2.3 Other AI review tools

- Consider Qodo or PR-Agent only if CodeRabbit is unavailable or a measured comparison
  is approved.
- Keep all output advisory and separate from deterministic evidence.

## Deferred — Requires a new objective and approval

- DefectDojo deployment, persistent finding lifecycle, SLA, or triage history.
- Historical trends, commit ancestry, `NEW/MOVED/NOT_OBSERVED` as the primary product.
- GitHub Issue synchronization or Projects boards.
- Autofix, patches, dependency auto-merge, Copilot Autofix invocation, or AI remediation.
- Blocking branch protection or required custom Checks.
- Upstream/company repository integration or production deployment.

## Explicit non-goals

- Do not hide old findings to make totals look smaller.
- Do not define success as zero issues.
- Do not claim the application is secure.
- Do not publish unsupported vulnerability-detection percentages.
- Do not treat an optional/deferred tool as completed coverage because its config exists.
