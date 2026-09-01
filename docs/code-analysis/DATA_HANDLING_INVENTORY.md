# Code-analysis scanner and data-handling inventory

> **Scope:** release-facing inventory for the fork-only, read-only Issue Wall service.
> **Evidence authority:** checked-in workflows, `SERVICE_ARCHITECTURE.md`, and
> `EXTERNAL_ACTIVATION.md`. This inventory does not claim certification, complete
> vulnerability detection, or that the application is secure.

## Shared boundary

GitHub Actions checks out one exact fork commit and retains scanner-native artifacts plus a
self-contained Issue Wall. Required scanners run inside ephemeral GitHub-hosted runners.
The service cannot patch source, create Issues or PR comments, push refs, change protections,
deploy Agentic SOC, or contact upstream. Artifact access and retention follow the fork's
GitHub Actions settings; removing a workflow or integration does not retroactively erase
already retained workflow artifacts or audit events.

| Service | Purpose | Data sent or read | Credential scope | Retention | Failure behavior | Removal procedure |
|---|---|---|---|---|---|---|
| GitHub Actions and Checks | Execute scanners, retain evidence, publish the authenticated Issue Wall and advisory Check | Exact fork source, workflow metadata, scanner artifacts, canonical findings, observation evidence, hashes, run IDs | Job-scoped `GITHUB_TOKEN`; contents read by default; narrowly scoped actions/checks or workflow-dispatch writes only where declared | Repository Actions/check retention settings and explicit artifact retention in workflows | A missing or invalid required channel fails closed and cannot replace the last publishable snapshot | Disable/remove the analysis workflows and delete retained runs/artifacts under repository policy; remove the GitHub App/check integration if no longer wanted |
| Required local scanners: Ruff, Pyright, ESLint, TypeScript, Bandit, CodeQL, Semgrep, OSV-Scanner, Gitleaks, Trivy, Hadolint, Checkov, Vulture, Radon, Xenon, Coverage.py | Deterministic quality, type, SAST, dependency, secret, container/IaC, complexity, dead-code, and coverage evidence | Exact source is processed within the runner; structured outputs are uploaded to Actions | No vendor credential for normal scanner execution; GitHub SARIF upload uses job-scoped security-events permission where declared | Raw/normalized artifacts follow Actions retention; GitHub-native SARIF follows GitHub code-scanning retention | Any required scanner/artifact/schema failure blocks that snapshot; findings are never hidden to obtain a green result | Remove the scanner job, manifest channel, parser, and pinned dependency together after an approved coverage-impact review; delete retained artifacts separately if policy permits |
| GitHub repository-posture API | Observe secret-scanning/push-protection state and alert numbers without secret material | Repository settings state and alert identifiers/counts | Default token when sufficient, otherwise optional fine-grained `SECURITY_POSTURE_TOKEN` with Metadata read and Secret-scanning-alerts read only | Sanitized status artifact follows Actions retention; GitHub owns native alert retention | Unavailable or disabled evidence is `CONFIGURED_PARTIAL`; it never suppresses required findings | Delete `SECURITY_POSTURE_TOKEN`, disable the optional posture step, and revoke the fine-grained token |
| Snyk Open Source and Snyk Code | Optional SCA and SAST evidence in the same Issue Wall | Exact fork source, manifests, dependency metadata, and code required by enabled Snyk products | Repository secret `SNYK_TOKEN`; scan-only workflow use; no monitor, report, fix, patch, or PR authority | Snyk account policy plus retained SARIF/status artifacts under Actions retention | Missing token is `NOT_CONFIGURED`; partial/unavailable surfaces are `CONFIGURED_PARTIAL`; required publication continues | Delete `SNYK_TOKEN`, revoke the token in Snyk, disconnect the fork in Snyk, and remove/disable optional jobs and parsers if permanently retired |
| SonarQube Cloud | Optional exact-commit analysis, bounded native-issue import, and loop-safe deterministic external-issue projection | Exact fork source and analysis metadata are sent for analysis; issue exporter reads bounded issue fields; compatible code-local deterministic findings may be projected outward | Separate `SONAR_TOKEN` for analysis and `SONAR_API_TOKEN` for issue read; no repository-write or plan-mutation authority | Sonar organization/project policy plus retained status/native/projection artifacts under Actions retention | API, plan, or branch-entitlement limits are `CONFIGURED_PARTIAL`; Issue Wall still publishes healthy channels; no second automatic scan is launched for projection | Delete both GitHub secrets, revoke Sonar tokens, disable/remove Sonar steps, and delete the Sonar project through owner-controlled Sonar administration if desired |
| CodeRabbit GitHub App | Optional cross-file AI review evidence, isolated as `AI_ADVISORY` | PR diff/repository context available to the installed app; Issue Wall reads exact-head original bot comments and their file locations through GitHub APIs | GitHub App installation permissions; aggregator uses read-only PR/content metadata access | CodeRabbit policy and GitHub PR/check/comment history; normalized advisory artifact follows Actions retention | No PR is `NOT_APPLICABLE`; no exact-head review is `PENDING_REVIEW`; unavailable evidence never corroborates deterministic findings or blocks publication | Uninstall/restrict the GitHub App, remove `.coderabbit.yaml` and advisory-refresh workflow in an approved change, and revoke any app authorization |
| GitHub dependency graph and Dependabot | Repository-native dependency inventory and update proposals; not canonical Issue Wall findings | Repository manifests and dependency metadata | GitHub repository feature permissions; Dependabot creates its own proposal branches/PRs | GitHub repository retention | Independent of required Issue Wall publication; upgrades require separate review and CI | Disable the repository features and close/delete proposals only through explicit owner review |
| Schemathesis and Atheris | Manual/weekly bounded dynamic and fuzz evidence | Test instance API traffic and in-runner case-decision inputs; no production target is authorized | Workflow token for checkout/artifact upload only | Actions artifact retention | Isolated optional jobs; failures normalize as `DYNAMIC` evidence and do not satisfy static channels | Disable/remove the isolated workflow and delete retained artifacts if policy permits |

## Inactive candidates

CodeScene, Qodo/PR-Agent, Codacy, DeepSource, Code Climate, Blacksmith, BrowserStack,
Argos/Chromatic, 1Password, DefectDojo, KICS, and tfsec are not active Issue Wall services.
They receive no data or credentials from the supported pipeline. Activation requires a separate
owner-approved review of permissions, data sharing, retention, revocation, attribution, cost,
exportability, and measured non-duplicate evidence.

## Release check

Before enterprise or public presentation, verify this inventory against the exact workflow
revision, repository integration settings, secret names (never values), artifact-retention
configuration, and vendor account policies. Any mismatch is a documentation or governance
blocker; it must not be converted into an unsupported security or privacy claim.
