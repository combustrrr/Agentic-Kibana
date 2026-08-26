# External analysis activation

The deterministic 16-channel current-findings platform works without external AI
or commercial services. The integrations below require repository-owner authority
and cannot be activated by a workflow commit alone.

## CodeRabbit (AI advisory)

Repository configuration is checked in at `.coderabbit.yaml`. It is deliberately
opt-in: automatic review and request-changes behavior are disabled. A review starts
only when a PR description contains `coderabbit:review` or an authorized developer
uses CodeRabbit's manual review command.

Owner action:

1. Complete the code-sharing/privacy review.
2. Install the CodeRabbit GitHub App on this fork only.
3. Confirm the app has no access to the upstream company repository.
4. Open a test PR against the fork and opt in with `coderabbit:review`.
5. Confirm the output remains advisory and is not counted as deterministic evidence.

The CLI's supported Windows path uses WSL. On the current evaluation workstation the
WSL component has been enabled, but Windows restart code `3010` must be cleared before
the Ubuntu distribution and CLI can be installed. This local prerequisite does not
change the fork-only GitHub App boundary above.

## Snyk

The scan-only jobs are already present in `03-dependency-security.yml`. They never
run `monitor`, `fix`, patch, PR, or write commands.

Owner action:

1. Enroll/authorize the fork with Snyk.
2. Add the resulting token as the fork Actions secret `SNYK_TOKEN`.
3. Re-run Dependency & Supply Chain Security manually.
4. Confirm `snyk-open-source.sarif` and `snyk-code.sarif` are retained and parse.
5. Measure unique detection value before making Snyk a required channel.

Local validation on 2026-08-26 used the same pinned CLI version as CI. OAuth succeeded
and SCA emitted parseable SARIF for both npm projects, with no vulnerable paths found.
Three Python manifests were unresolved because their dependency environments were not
installed, so this is explicitly **partial evidence**, not a clean repository result.
Snyk Code returned `SNYK-CODE-0005` because Code analysis is not enabled for the
selected organization. The workflow records these states as `CONFIGURED_PARTIAL`
instead of silently reporting a complete scan. Enable Snyk Code and provide the fork
Actions secret before expecting both optional surfaces in an aggregated snapshot.

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
