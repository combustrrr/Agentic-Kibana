# Upstream integration and enterprise release gate

This code-analysis subsystem is external, read-only engineering infrastructure. It can
be integrated without making Agentic SOC depend on scanners or Issue Wall at runtime.

## Integration boundary

The upstream change must be reviewed as a scoped subsystem, not by merging the fork's
long-lived feature ancestry. The accepted integration paths are:

- `.coderabbit.yaml`
- `.github/codeql/**` and `.github/semgrep-rules/**`
- `.github/workflows/01-code-quality.yml` through `09-coderabbit-advisory-refresh.yml`
- `config/code-analysis/**`
- `scripts/code_analysis/**`
- `docs/code-analysis/**`
- narrowly reviewed code-analysis assertions in `scripts/check_ci_contract.py` and
  `scripts/test_check_ci_contract.py`

No `backend/app/**`, `webui/src/**`, application Compose file, deployment manifest,
runtime dependency, database migration, API, or product configuration belongs in the
integration patch.

## Upstream preparation

1. Start an integration branch from the latest upstream default branch.
2. Apply only the scoped paths above from the validated feature head.
3. Resolve upstream workflow-policy changes deliberately; never merge the feature
   branch wholesale or overwrite newer upstream CI/release definitions.
4. Keep every external Action pinned to a full commit SHA.
5. Run the CI contract tests, workflow service audit, code-analysis tests,
   documentation check, and diff-integrity check.
6. Review the GitHub App and optional vendor credentials in the upstream repository.
   Missing optional credentials must remain explicit and must not weaken the 16-channel
   publication gate.
7. Merge the reviewed integration through the upstream repository's normal approval
   process. The upstream owner controls all repository settings and secrets.

## Enterprise acceptance

An enterprise-facing release is accepted only when all of the following are true:

- **Full Code Analysis (Manual)** appears on the repository default branch and requires
  no input for the common default-branch demonstration.
- One manual run resolves an exact SHA, completes or safely reuses all four scanner
  groups, validates all 16 required channels, and publishes one immutable artifact.
- The final **Supervisor-ready artifact handoff** job provides the authenticated artifact
  link, branch, full SHA, artifact ID and digest, plus offline launch instructions.
- Extracting the artifact and opening `dashboard/index.html` requires no VM, service,
  token, package installation, CDN, or internet access.
- File links point to the immutable analyzed commit; Critical, High, and Medium findings
  are shown first; Low/informational results require an explicit toggle.
- CodeRabbit stays `AI_ADVISORY`; Sonar and other optional channels cannot satisfy or
  bypass a required channel.
- Failed, corrupt, expired, mixed-commit, or incomplete evidence cannot produce a
  supervisor-facing artifact.
- Workflows cannot patch code, create PRs or Issues, push refs, deploy the application,
  or contact production.

## Supervisor demonstration

1. Open **Actions → Full Code Analysis (Manual) → Run workflow**.
2. Leave both inputs blank to analyze the repository default branch at its latest HEAD.
3. When the run completes, open **Supervisor-ready artifact handoff** and select the
   prominent Issue Wall download link.
4. Extract the artifact, open `dashboard/START_HERE.md`, then open
   `dashboard/index.html`.
5. Show the branch/full SHA, 16-channel evidence, Actionable Issues view, immutable
   source link, evidence drawer, scanner status, and artifact-integrity section.

The dashboard is a current evidence report, not a certification that no vulnerabilities
exist and not an automated remediation system.
