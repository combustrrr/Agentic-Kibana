---
title: External scanner activation
description: Optional CodeRabbit, SonarQube Cloud, and Snyk activation and credential boundaries.
---

# External analysis activation

The deterministic 16-channel current-findings platform works without external AI
or commercial services. The integrations below require repository-owner authority
and cannot be activated by a workflow commit alone.

## CodeRabbit (AI advisory)

Repository configuration is checked in at `.coderabbit.yaml`. Cloud automatic and
incremental reviews are enabled, so an eligible fork PR is reviewed when opened and
again after every pushed commit. `base_branches: [".*"]` explicitly covers PRs targeting
every fork branch; omitting that setting would cover only the default branch. Reviews remain advisory:
`request_changes_workflow` and chat auto-replies are disabled, and CodeRabbit evidence
never counts as deterministic scanner corroboration.

The dashboard integration uses GitHub as the evidence boundary. Every submitted
CodeRabbit review triggers `09-coderabbit-advisory-refresh.yml`, which retains an
evidence artifact but never publishes Issue Wall. The collector reads original inline comments authored by
`coderabbitai[bot]` for that exact PR-head SHA, normalizes them as `AI_ADVISORY`, and
retains the native GitHub comment ID/URL. Replies, stale-commit comments, external-fork
heads, summaries without file locations, and other authors are excluded. Without an
exact-head bot review, CodeRabbit is `NOT_APPLICABLE` and is not rendered as evidence.
This collector-level check deliberately handles a PR head advancing after CodeRabbit
submits its review; the workflow still runs instead of being silently skipped.

Verified state: the CodeRabbit GitHub App is installed on the fork, exact-head bot
comments have been observed, and the dashboard adapter retains them only under
`AI_ADVISORY` with native evidence links. They never corroborate deterministic findings.
Permission and privacy changes require an explicit repository-owner review.

The GitHub Checks integration waits up to 15 minutes for the required scanner workflows.
The review-event workflow retains evidence only. Manual Full Code Analysis independently
collects current exact-head advisory evidence while building Issue Wall.

The CodeRabbit CLI/WSL path is not part of the operating design. CodeRabbit runs as a
cloud GitHub App on pull requests; deterministic full-codebase scanners continue to
run in GitHub Actions and feed the hosted findings dashboard.

## SonarQube Cloud

`01-code-quality.yml` runs one source-change-gated exact-commit Sonar analysis in
parallel with the fast quality jobs. `SONAR_TOKEN` authenticates analysis;
`SONAR_API_TOKEN` is intentionally separate for read-only issue export. The exporter
waits for the exact compute task, caps pagination at 20,000 issues, and rejects imported
external issues so the outbound projection cannot feed back into Issue Wall.

The normalizer accepts `sonar-native-issues.json` into the same canonical schema used by
all scanners and emits `normalized/sonar-external-issues.json` for compatible code-local
deterministic findings. Sonar-native findings and CodeRabbit/other `AI_ADVISORY` findings
are excluded. The projection is retained as an outbound artifact; it does not launch a
second 14–15 minute Sonar scan automatically.

Current cloud state is `CONFIGURED_PARTIAL`: analysis succeeds, both GitHub secrets
authenticate as the same Sonar user, and an explicit Browse grant was accepted with HTTP
204. Non-main branch issues still return HTTP 403 because the organization has not yet
received Team/Enterprise or free OSS branch-analysis entitlement. Plan enrollment is a
Sonar web operation, not a supported CLI/Web API mutation.

## Snyk

The scan-only jobs are already present in `03-dependency-security.yml`. They never
run `monitor`, `fix`, patch, PR, or write commands.

Owner action:

1. Enroll/authorize the fork with Snyk.
2. Add the resulting token as the fork Actions secret `SNYK_TOKEN`.
3. Re-run Dependency & Supply Chain Security manually.
4. Confirm `snyk-open-source.sarif` and `snyk-code.sarif` are retained and parse.
5. Measure unique detection value before making Snyk a required channel.

Fork status: the repository-level `SNYK_TOKEN` Actions secret is configured. Current
validation passes pinned CLI installation, Open Source SCA, Snyk Code,
configured-status generation, and structured artifact upload. Snyk is therefore a
verified optional source, not a required channel. Use the latest exact-SHA workflow run
for review evidence; historical run and artifact identifiers are intentionally omitted.

Local validation on 2026-08-26 used the same pinned CLI version as CI. OAuth succeeded
and SCA emitted parseable SARIF for both npm projects, with no vulnerable paths found.
Three Python manifests were unresolved because their dependency environments were not
installed, so this is explicitly **partial evidence**, not a clean repository result.
Snyk Code returned `SNYK-CODE-0005` locally because Code analysis was not enabled for
the OAuth-selected organization. The fork Actions token uses an organization where
both SCA and Code succeeded. This distinction is retained so a local partial result is
not confused with the authoritative CI evidence. The workflow records unavailable
surfaces as `CONFIGURED_PARTIAL` instead of silently reporting a complete scan.

## GitHub secret scanning and push protection

Gitleaks already scans repository content/history. GitHub-native protection is a
separate repository setting and cannot be enabled by checked-in YAML. The dependency
workflow verifies both setting states and counts open alerts through read-only API
calls; retained evidence contains alert numbers only, never secret values.

Owner action:

1. In the fork, open Settings → Advanced Security / Code security and analysis.
2. Verify secret scanning alerts are enabled.
3. Enable push protection only after the company approves a blocking secret-only
   control; this does not make the advisory code-analysis Check blocking.
4. If the workflow's default `GITHUB_TOKEN` cannot observe those settings or list
   alerts, add a repository Actions secret named `SECURITY_POSTURE_TOKEN` containing
   a read-only fine-grained token scoped only to this fork. It explicitly needs
   **Metadata: read** and **Secret scanning alerts: read**, and its account must be a
   repository administrator, organization owner, or applicable organization security
   manager. It must not have settings-write, contents-write, or upstream-repository access.
5. Re-run Dependency & Supply Chain Security and confirm the retained posture status is
   `CONFIGURED_COMPLETE`. `CONFIGURED_PARTIAL` means either incomplete/unavailable
   evidence or a secret-scanning/push-protection control that is not enabled. Inspect
   the emitted control states and reason before deciding whether owner activation is
   required.
6. Do not change settings on the upstream repository as part of fork evaluation.

## Schemathesis

`07-api-fuzzing.yml` remains isolated and runs manually or on a weekly trusted-default-
branch schedule. Schemathesis uses 250 examples; its JUnit failures normalize to
structured `DYNAMIC` findings. The same workflow runs a bounded Atheris case-decision
campaign. Per-commit dynamic execution remains disabled to avoid untrusted PR code.
