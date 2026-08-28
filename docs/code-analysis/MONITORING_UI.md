# Issue Wall

The coordinated scanner and evidence system is the **Web of Scanners**. Its external,
developer-only portal is **Issue Wall**.

### Enforced one-way boundary

The relationship is deliberately one-way: Web of Scanners may read the repository and
its immutable GitHub evidence, while Agentic SOC may not import, start, package, call,
or depend on Web of Scanners. Repository policy scans backend and web UI runtime source,
dependency manifests, Dockerfiles, and application Compose definitions and fails CI if
an analysis-service path or launcher is introduced there. The analysis workflows and
artifact generator remain external developer/quality infrastructure.

The code-analysis product is one read-only, full-codebase snapshot. It does not create
one GitHub Issue per scanner result and it does not use baseline or lifecycle state to
hide older findings.

## Snapshot contract

The header identifies the exact commit, generation time, and required-channel status.
A snapshot is published only when every required scanner workflow succeeded, retained
artifacts match the same commit, hashes validate, normalization succeeds, and canonical
finding/observation counts reconcile. A failed refresh leaves the last publishable
snapshot active.

The main table contains one row per canonical issue. Opening **Evidence** shows every
contributing scanner family, rule, native result, message, location, version, and raw
artifact reference. Deduplication collapses presentation, never evidence.

The browser mounts at most 250 rows and supports search plus severity, category,
component, and scanner filters. Separate downloads expose the complete snapshot and raw
observation collection.

The board keeps supervisor assurance ahead of scanner detail: current branch/SHA and
freshness, deterministic security posture, highest-risk areas, required-channel
coverage, optional-control evidence, and the critical/high review queue are visible at
a glance. Optional detail is collapsed by default to prevent scanner noise from
overwhelming the operational view.

The **Fix queue** is a severity-first issue wall over the same complete canonical
snapshot. It previews the first five identities in each severity and hands a selected
column back to the full searchable evidence table. It does not create GitHub Issues,
hide the remaining backlog, or persist a second finding lifecycle.

The **Web of Scanners** bar links authenticated developers to GitHub's native
Actions pages for the full four-scanner orchestration, dashboard-only rebuild, live run
activity, and scheduled continuous-monitoring supervisor. The static page never holds
a GitHub token and cannot call the dispatch API directly. GitHub therefore remains the
permission, branch-selection, confirmation, audit, and run-status authority.

The board has two channel sections:

- **Required scanner channels** are the manifest-controlled 16-channel publication gate.
- **Security controls & optional assurance** expands to show shipping-image/SBOM,
  repository posture, Snyk, dynamic analysis, CodeRabbit `AI_ADVISORY` readiness, and
  deferred research tools with honest status.

Optional/deferred lanes never inflate the required completion fraction. The analytics
area includes a scanner-family distribution so contributors can see which engines
actually produced the canonical current findings.

## GitHub output

Actions retains `current-findings-dashboard-<branch>-<sha>-<run-id>` as immutable
evidence. The custom Check describes snapshot validity and links to that artifact.
This authenticated GitHub artifact is the only supported Issue Wall surface; no local
HTTP server, QA host, or continuously running workstation process is used.

For a scanned commit, open **Checks → Code Analysis Dashboard**. The Check identifies
the analyzed SHA and links to the immutable
`current-findings-dashboard-<branch>-<sha>-<run-id>` artifact. Download it and open
`dashboard/START_HERE.md`, then `dashboard/index.html`; this is the complete offline
Issue Wall, while GitHub's
Security and quality count remains a separate native-alert surface. Verified examples
include dashboard runs `32938363593` (platform acceptance) and `32940124398` (improved
real-data UI).

The former local and QA-host serving paths are retired. GitHub Actions artifact access
is the sole supported delivery path.

DefectDojo, history, triage analytics, Issues, remediation, and autofix are deferred.
