---
title: Issue Wall
description: Generate, open, verify, filter, and review the offline exact-commit Issue Wall artifact.
---

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

The header prominently identifies the branch and full exact commit SHA, generation time,
and required-channel status.
A snapshot is published only when every required scanner workflow succeeded, retained
artifacts match the same commit, hashes validate, normalization succeeds, and canonical
finding/observation counts reconcile. A failed refresh leaves the last publishable
snapshot active.

The main table contains one row per canonical issue. Opening **Evidence** shows every
contributing scanner family, rule, native result, message, location, version, and raw
artifact reference. Deduplication collapses presentation, never evidence.

The browser mounts at most 250 rows and supports search plus severity, category,
component, and scanner filters. Findings are severity-sorted Critical through Low.
**Actionable Issues** is the default view (Critical, High, and Medium); one toggle reveals
Low and informational notes. Separate downloads expose the complete snapshot and raw
observation collection.

The board keeps release assurance ahead of scanner detail: current branch/SHA and
freshness, deterministic security posture, highest-risk areas, required-channel
coverage, optional-control evidence, and the critical/high review queue are visible at
a glance. Optional detail is collapsed by default to prevent scanner noise from
overwhelming the operational view.

The **Fix queue** is a severity-first issue wall over the same complete canonical
snapshot. It previews the first five identities in each severity and hands a selected
column back to the full searchable evidence table. It does not create GitHub Issues,
hide the remaining backlog, or persist a second finding lifecycle.

The report-first developer summary adds an accessible severity distribution, weighted
top-affected-file ranking, and a concrete **Where to start** path. Every visible result
retains an exact file and line, supports location copying, links to the immutable source
commit when repository identity is available, and opens the contributing scanner
evidence. Charts and report rows filter the same canonical findings rather than a
sampled dataset. Developers can export the current filtered view as CSV without
changing the retained JSON evidence.

The **Web of Scanners** launchpad gives each authenticated GitHub operation its own
responsive action card: run the manual full four-scanner orchestration for a selected
branch or inspect workflow activity. Each card explains its effect before it
opens GitHub in a new tab. The static page never holds a GitHub token and cannot call the
dispatch API directly. GitHub therefore remains the permission, branch-selection,
confirmation, audit, and run-status authority.

The visual language uses a brighter developer-focused dark palette: cyan for navigation
and source links, violet for contextual/report accents, mint for healthy evidence, coral
and orange for urgent risk, amber for planned review, and blue for lower-risk findings.
Color never replaces labels, counts, focus outlines, or severity text, and the action
cards collapse from four columns to two and then one on narrower screens.

## Branch-head pipeline

Manual operation resolves `scan_branch` through GitHub; leaving it blank selects the
repository's current default branch, so the workflow remains portable to upstream.
Leaving `scan_sha` blank selects current HEAD. An entered full SHA must exist and be
reachable from that branch. The workflow freezes both the selected commit and the
observed branch HEAD before any scanner is selected.
Every scanner checkout, run title, artifact, Check, and report carries that exact source
identity.

Pushes and same-repository pull requests may collect exact-source scanner evidence, but
cannot publish Issue Wall. There is no scheduled or event-driven publication. The manual
orchestrator reuses retained exact-commit evidence and dispatches only missing groups.

The manual run exposes four visible phases in the Actions log and job summary: resolve
the authoritative branch head, resolve/reuse/dispatch scanner groups, validate all four
groups concurrently, and build the 16-channel Issue Wall. Artifact existence is checked
before reuse. Incomplete, expired, corrupt, or mixed-commit evidence fails closed.

The board has two channel sections:

- **Required scanner channels** are the manifest-controlled 16-channel publication gate.
- **Security controls & optional assurance** expands to show only scanners and
  controls carrying real status or finding evidence for the exact snapshot, including
  CodeRabbit `AI_ADVISORY`, SonarCloud, and the security assurance channels when evidenced.

Additional evidenced lanes never inflate the required completion fraction. The analytics
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
Security and quality count remains a separate native-alert surface. Always use the
latest successful manual run for the branch and exact commit being reviewed. Historical
run IDs, counts, and digests are intentionally not treated as current release evidence.

The former local and QA-host serving paths are retired. GitHub Actions artifact access
is the sole supported delivery path.

Issue Wall is a read-only visualization/tracker, not a triage system: it does not assign,
accept, suppress, close, or synchronize issue state. Sonar native issues are normalized
into this same view; compatible deterministic code-local findings are also emitted as a
loop-safe Sonar generic-issue projection. CodeRabbit remains visibly isolated in the
`AI_ADVISORY` lane and is never included in that projection.
