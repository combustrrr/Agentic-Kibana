# Code-analysis development session handoff — 2026-09-01

> Restart snapshot, not an active backlog. All remaining work and priority order live
> only in [`PENDING_WORK.md`](PENDING_WORK.md).

## Resume here

The working branch is `feature/static-code-analysis`. The last pushed head before this
decision update is `f22246d`; use `git log -1` to obtain the update commit itself.
The worktree was clean at that checkpoint. Do not push to `upstream`, change branch
protection, or modify the user-owned `docs/code-analysis/Issues.txt` file.

Issue Wall is the normalized, read-only source of truth. It visualizes current findings;
it does not triage, fix, comment, dispatch workflows, or store GitHub credentials.
CodeRabbit remains isolated under `AI_ADVISORY` and must never be projected into Sonar as
deterministic evidence.

The owner chose operational simplicity: Issue Wall is the deliverable and every external
service is an input, never a dependency. Do not migrate the GitHub repository, create a
second company workspace, rotate valid tokens, or hold the dashboard for Sonar OSS-plan
work. Publish the unified report from all available channels and show unavailable channels
truthfully.

## Completed in this session

- Added bounded Sonar-native issue export into the canonical Issue Wall schema.
- Added the loop-safe outbound Sonar generic-issue projection for compatible deterministic,
  code-local, non-Sonar findings.
- Preserved the real Git branch and exact commit SHA while mapping non-default analysis to
  a stable long-lived `branch-issue-wall-<hash>` Sonar branch.
- Added secret-safe PAT probes and an explicit, idempotent Browse-grant helper.
- Verified both `SONAR_TOKEN` and `SONAR_API_TOKEN` authenticate as
  `combustrrr-Uw7cT@github`.
- Sonar accepted project Browse permission for that user with HTTP 204 in run
  [`33429643637`](https://github.com/combustrrr/Agentic-Kibana/actions/runs/33429643637).
- Updated the pipeline and dashboard documentation so `CONFIGURED_PARTIAL` is retained
  truthfully when native Sonar export is unavailable.

## Sonar limitation — non-blocking

The Sonar project `combustrrr_Agentic-Kibana` is public. Anonymous main-project issue
search returns HTTP 200 and 1,135 issues. Despite valid PATs and the accepted Browse grant,
both short- and long-lived non-main branch issue requests return HTTP 403.

This matches Sonar's current Free-plan entitlement: non-main analysis may execute and be
stored, but its results are inaccessible until the organization has Team, Enterprise, or
the free OSS plan. Sonar exposes OSS enrollment through its web billing/signup flow, not a
supported CLI or Web API mutation. Do not rotate tokens or repeat the Browse grant.

The repository is public but currently publishes no license. OSS enrollment remains an
optional later governance decision after ownership/legal review. It is not a prerequisite
for the unified Issue Wall.

## Exact continuation sequence

1. Read [`PENDING_WORK.md`](PENDING_WORK.md); it is authoritative.
2. Resolve the latest `feature/static-code-analysis` head and run the full exact-SHA
   analysis/aggregation path.
3. Download and visually accept the resulting Issue Wall on desktop and narrow layouts.
4. Verify every available deterministic quality, security, dependency, and repository
   result is normalized into the single report; verify Snyk shares the same view and
   CodeRabbit is visibly separated as `AI_ADVISORY`.
5. Verify unavailable optional services produce truthful channel status without failing
   dashboard publication. For a Free-plan arbitrary branch, Sonar may remain
   `CONFIGURED_PARTIAL`.
6. Record the final artifact and cost/performance evidence, then continue P1.

If Sonar OSS entitlement is added later, run one exact-head proof and allow native branch
findings to enter the same schema. Do not create a second source of truth or make Sonar a
publication gate.

## Accepted evidence

- Code-analysis regression suite: **49/49 passed**.
- Workflow service-policy audit passed.
- Workflow YAML parsed successfully.
- Documentation and source diffs passed `git diff --check`.
- Sonar proof run `33429643637`: Browse grant HTTP 204, analysis success, native export
  correctly retained as `CONFIGURED_PARTIAL` because branch issue access remained 403.
- Relevant published commits before this handoff:
  - `4c4e2e8` — protected-secret Browse grant helper and workflow control.
  - `e05bb18` — explicit branch-run trigger for the one-time grant.
  - `6c13d2e` — plan-entitlement evidence and pending-work correction.
  - `32b3ca4` — main shutdown handoff and restart checkpoint.

## Safe restart checks

```powershell
git status --short
git log --oneline --decorate -8
python scripts/code_analysis/audit_workflows.py
python -m unittest scripts.code_analysis.test_service
git diff --check
```

Expected status after the final handoff commit: clean, except for any explicitly
user-owned local file that was already present.
