# Code-analysis session handoff — 2026-08-28

## Resume here

The first three items in `docs/code-analysis/PENDING_WORK.md` were addressed in a
fork-only change set. The current local branch is `feature/static-code-analysis` at
`0d6a853`. The same commit is the head of fork PR
[`#16`](https://github.com/combustrrr/Agentic-Kibana/pull/16), branch
`test/coderabbit-security-controls-20260828`, targeting `claude/main`.

Do not stage or modify the user-owned untracked file
`docs/code-analysis/Issues.txt`. Do not push to `upstream`.

## Completed work

### 1. Dashboard artifact pull worker

- GitHub authorization is retained for same-origin redirects and stripped for
  cross-origin signed-storage redirects.
- Every ZIP entry is validated, traversal aliases using `/` or `\` are rejected,
  symlinks and limits remain fail-closed, and only the `dashboard/` subtree is
  extracted.
- Live Windows recovery of accepted artifact `9659488883` succeeded after the old
  redirect 401 and full-archive extraction-limit failures.
- Ubuntu QA-host proof remains part of the separate deployment backlog.

### 2. Optional-control truth

- Snyk creates an isolated Python 3.11 environment and installs all three Python
  requirement manifests before SCA. Repository-owned Snyk SCA and Code jobs pass.
- Shipping-image Trivy emits a native status document, and image SARIF is attributed
  to `Shipping Image Trivy` instead of contaminating filesystem `Trivy` counts.
- OpenSSF Scorecard evidence aliases its native `Scorecard` driver name. Non-default
  push events skip the Scorecard Action because that upstream Action rejects such refs;
  PR, default-branch, and manual exact-SHA analysis remain enabled.
- Repository posture reports `CONFIGURED_COMPLETE` only when both controls are enabled
  and alert visibility is observed. Otherwise it reports `CONFIGURED_PARTIAL` with the
  reason. `SECURITY_POSTURE_TOKEN` is documented as fork-only, read-only, with
  **Metadata: read** and **Secret scanning alerts: read**.
- SBOM policy now uses complete SPDX tokens, case normalization, terminal `+`
  normalization, and within-document deduplication. LGPL is no longer mistaken for GPL.
  Valid denied-license findings remain visible pending owner exception decisions.

### 3. CodeRabbit cloud proof

- Fork PR #16 proved the App and repository configuration work.
- CodeRabbit submitted a GitHub review and four inline comments at exact head
  `928561b77121942bab2e054bfa3f172780cc1554`.
- All four findings were independently verified and fixed: shipping-image family
  attribution, posture documentation precision, prefix traversal aliases, and SPDX
  case/plus variants.
- CodeRabbit reports that this repository requires a manual `@coderabbitai review`
  trigger while it has fewer than ten stars. Automatic review must not be claimed.
- AI evidence remains advisory and never corroborates deterministic findings.

## Additional pipeline repairs

Cloud acceptance exposed and fixed three strict-MkDocs links, branch-incompatible
Scorecard execution, bounded poll-loop ShellCheck warnings, canary summary quoting,
and aggregation jq/Markdown ShellCheck ambiguity. The exact pinned local combination
of actionlint 1.7.7 and ShellCheck 0.10.0 passes.

## Accepted evidence

- Local combined tests: **119/119** (`56` analysis-service + `63` CI-contract).
- Workflow/service policy passed.
- CI policy passed for **12 workflows and 3 shipping Dockerfiles**.
- Documentation consistency passed for **79 public pages**.
- `git diff --check` passed.
- Final code-head cloud Workflow & shell contracts job `98920619811` passed.
- Remediation dependency run
  [`33190866240`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/33190866240)
  completed successfully; shipping-image/SBOM and repository-owned Snyk jobs passed.
- The standalone Snyk PR service check is quota-blocked; it is not the repository-owned
  workflow and must not be reported as a code failure.

## Remaining decisions and external work

1. Review and merge fork PR #16. It has not been merged.
2. Add `SECURITY_POSTURE_TOKEN` only if retained workflow evidence must be complete.
   Never copy an existing local OAuth token into Actions secrets implicitly.
3. Resolve the separate Snyk service private-test quota if that vendor PR check is kept.
4. Review valid denied-license findings and approve explicit exceptions if appropriate.
5. Deploy and prove the pull worker on the approved Ubuntu QA host.
6. Reconcile the twelve Dependabot PRs individually; do not bulk merge.
7. Continue later detection work listed in `PENDING_WORK.md`, including dynamic proof,
   uniqueness measurement, and project-specific canary expansion.

## Safe continuation commands

```powershell
git status --short
git log --oneline --decorate -12
gh pr view 16 --repo combustrrr/Agentic-Kibana
gh pr checks 16 --repo combustrrr/Agentic-Kibana
python scripts/code_analysis/audit_workflows.py
python scripts/check_ci_contract.py
python -W error -m unittest scripts.code_analysis.test_service scripts.test_check_ci_contract
python scripts/check_docs.py
git diff --check
```

Expected local status after publication: only
`?? docs/code-analysis/Issues.txt`.
