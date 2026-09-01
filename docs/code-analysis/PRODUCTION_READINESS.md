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
- The manual supervisor workflow derives the repository default branch at runtime; no
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

The release-facing acceptance is dashboard run `33528827999` over implementation commit
`c92032a`: 16/16 required channels, 16,257 canonical findings, 16,927 observations, and
artifact SHA-256 `5a04e175015952d1d78637c00dd118e353a121f52821f070ac1f6387452f2ee7`.
The final workflow definition passed pinned actionlint 1.7.7 and ShellCheck 0.10.0 in CI
run `33532282654`, job `99938491711`, on implementation head `7a06380`. Local release
revalidation on 2026-09-01 passed the 63 CI-policy tests, 49 analysis-service tests,
workflow service-policy audit, 79-page documentation consistency check, and the
10,000-finding/13,000-observation bounded dashboard benchmark.
