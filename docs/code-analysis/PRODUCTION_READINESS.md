---
title: Code-analysis production readiness
description: Enterprise release controls, evidence gates, workflow security, and artifact delivery boundaries.
---

# External code-analysis service production readiness

## Service boundary

The service is an external engineering control plane. It analyzes the fork, downloads
immutable GitHub Actions evidence outbound, and serves a read-only current-findings
dashboard. It is not imported by, deployed with, or required by the Agentic SOC
application. It has no authority to patch code, create Issues or comments, alter refs,
change branch protection, deploy the application, or contact upstream.

## Security-first mission

The primary purpose of this service is to expose security weaknesses in the complete
SOC codebase. Semantic SAST, project-specific SAST, Python security, secrets,
dependency/SCA, container, and IaC evidence therefore receive first-class dashboard
visibility. Type, lint, complexity, dead-code, and coverage channels remain required
because they expose unsafe assumptions and untested or fragile security-sensitive
paths, but they do not replace security analysis.

AI review is used as a complementary threat-discovery mechanism for authorization,
trust-boundary, agent-tool, prompt-injection, and cross-file logic concerns that a
fixed rule may miss. AI output remains `AI_ADVISORY`: it is shown separately, retains
its source evidence, and requires human confirmation. It never counts as deterministic
corroboration and never gains patch, commit, blocking-check, or remediation authority.

## GitHub repository controls

As of 2026-09-01, GitHub Actions full-SHA enforcement is enabled for the fork and the
repository workflow audit verifies every `uses:` reference is immutable. Secret scanning
and push protection remain enabled. GitHub continues to report non-provider-pattern and
validity checks as disabled after versioned repository API enablement requests; the fork is
personally owned, while GitHub documents validity checks as requiring an organization-owned
GitHub Team or Enterprise Cloud repository with Secret Protection. No unrelated repository
setting was changed.

## Evidence collection and manual publication

- Every push/eligible PR on a branch carrying the approved definitions starts the four
  required scanner workflows, whose outputs map to 16 required structured channels.
- Push/PR scanner runs may collect evidence but cannot publish Issue Wall. Only **Full
  Code Analysis (Manual)** can call the reusable dashboard builder.
- Manual publication verifies the chosen branch, latest HEAD or optional reachable exact
  SHA, every required artifact/hash, and normalized count reconciliation.
- CodeRabbit reviews all PR targets in the cloud. Exact-head original bot comments use
  the separate `AI_ADVISORY` lane and never corroborate deterministic evidence.
- A valid snapshot with findings produces a neutral Check; a valid empty snapshot
  succeeds; invalid or incomplete analysis fails.
- Manual analysis verifies that the selected branch HEAD remains stable before each
  dispatch and after the set. Publication requires all four runs for one selected SHA,
  so branch movement cannot publish mixed evidence.

## Supply-chain and workflow controls

- GitHub Actions use full commit SHAs and directly installed scanner versions are
  pinned.
- Write permissions are job-scoped and limited to SARIF upload, dashboard Checks, or
  workflow dispatch. Analysis has no repository-content or collaboration write access.
- `audit_workflows.py` enforces immutable Actions, job timeouts, safe shell input,
  read-only analysis permissions, and private/pinned optional portal profiles.
- The manual analysis workflow derives the repository default branch at runtime; no
  fork-only default-branch name is embedded in its execution contract.

## Artifact-only delivery

GitHub Actions is the only supported Issue Wall execution, storage, authorization, and
delivery boundary. No workstation listener, local cache service, pull worker, nginx
container, or QA host is deployed.

## Acceptance evidence

Workflow policy and service tests pass; CodeRabbit exact-head review reaches only
`AI_ADVISORY`; exact-commit 16-channel artifacts and the authenticated self-contained
Issue Wall have been produced. SonarQube Cloud analysis, both PATs, and the explicit
Browse grant are verified; native non-main issue import remains honestly partial because
the current Free organization does not expose branch issues through the API.

Release evidence must be generated for the commit under review and taken from that
manual workflow run; this document intentionally carries no fixed run IDs, artifact
digests, finding counts, or historical output links. Local release revalidation on
2026-09-01 passed the CI-policy tests, analysis-service tests, workflow service-policy
audit, documentation consistency check, and bounded dashboard benchmark.
