# External analysis activation

The deterministic 16-channel current-findings platform works without external AI
or commercial services. The integrations below require repository-owner authority
and cannot be activated by a workflow commit alone.

## CodeRabbit (AI advisory)

Repository configuration is checked in at `.coderabbit.yaml`. Cloud automatic and
incremental reviews are enabled, so an eligible fork PR is reviewed when opened and
again after every pushed commit. The default branch is included by CodeRabbit and
`Testing` is an additional approved target. Reviews remain advisory:
`request_changes_workflow` and chat auto-replies are disabled, and CodeRabbit evidence
never counts as deterministic scanner corroboration.

The dashboard integration uses GitHub as the evidence boundary. After an exact-head
CodeRabbit review is submitted, `09-coderabbit-advisory-refresh.yml` requests a
dashboard-only rebuild. The aggregator reads original inline comments authored by
`coderabbitai[bot]` for that exact PR-head SHA, normalizes them as `AI_ADVISORY`, and
retains the native GitHub comment ID/URL. Replies, stale-commit comments, external-fork
heads, summaries without file locations, and other authors are excluded. If no open PR
exists, CodeRabbit is `NOT_APPLICABLE`; if a PR exists but no exact-head review has been
submitted, it is `PENDING_REVIEW`. Neither state blocks deterministic publication.

Owner action:

1. Complete the code-sharing/privacy review.
2. Install the CodeRabbit GitHub App on this fork only.
3. Confirm the app has no access to the upstream company repository.
4. Open or update a test PR against the fork default branch or `Testing`.
5. Confirm the automatic review appears after each pushed PR commit.
6. Confirm the subsequent dashboard rebuild shows its inline findings only under
   **AI advisory**, with native evidence links and no deterministic corroboration.

The CodeRabbit CLI/WSL path is not part of the operating design. CodeRabbit runs as a
cloud GitHub App on pull requests; deterministic full-codebase scanners continue to
run in GitHub Actions and feed the hosted findings dashboard.

## Snyk

The scan-only jobs are already present in `03-dependency-security.yml`. They never
run `monitor`, `fix`, patch, PR, or write commands.

Owner action:

1. Enroll/authorize the fork with Snyk.
2. Add the resulting token as the fork Actions secret `SNYK_TOKEN`.
3. Re-run Dependency & Supply Chain Security manually.
4. Confirm `snyk-open-source.sarif` and `snyk-code.sarif` are retained and parse.
5. Measure unique detection value before making Snyk a required channel.

Fork status: the repository-level `SNYK_TOKEN` Actions secret was added on
2026-08-26. Post-secret run
[`32965286130`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/32965286130)
then passed pinned CLI installation, Open Source SCA, Snyk Code, configured-status
generation, and artifact upload. Artifact `snyk-results` (`9605455800`, 66,570 bytes)
was retained. Snyk is therefore a verified optional source, not a required channel.

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
separate repository setting and cannot be asserted by checked-in YAML.

Owner action:

1. In the fork, open Settings → Advanced Security / Code security and analysis.
2. Verify secret scanning alerts are enabled.
3. Enable push protection only after the company approves a blocking secret-only
   control; this does not make the advisory code-analysis Check blocking.
4. Do not change settings on the upstream repository as part of fork evaluation.

## Schemathesis

`07-api-fuzzing.yml` remains manual and isolated. Its JUnit failures now normalize
to structured `DYNAMIC` findings. Automatic per-commit execution remains deferred
until the backend test service is stable, bounded, and approved for the extra CI cost.
