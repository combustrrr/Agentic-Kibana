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

The header leads with **Issue Wall ? Unified engineering & risk observation** and
snapshot evidence health across all catalogued channels. An always-visible source panel
shows the source repository, source branch, full analyzed commit SHA, catalogued analysis
workflow definitions, retained CI workflow run IDs, and snapshot generation time in UTC.
The commit identifies the captured source revision, not a live branch-HEAD check.
Workflow definitions and retained run IDs are listed separately because the snapshot
does not retain a verified one-to-one mapping or the run repository; the header does not
invent run links. Missing metadata is explicitly unavailable.
This panel precedes three headline columns: channels and completion, deterministic
canonical findings and Critical count, then corroborated findings and High count.
Corroboration uses the same 2+ independent scanner-family definition as the agreement
chart and excludes AI advisories. All counts come from the current snapshot.

The health badge is green **HEALTHY** only for a publishable snapshot with every channel
complete, amber **INCOMPLETE** for missing/partial evidence, and red **FAILED** for explicit
channel failures or rejected publication. It describes evidence health, not application
security or live scanner availability. Downloads,
copy control, secondary totals, and publication proof remain in **Snapshot details &
downloads**, collapsed beneath the headline.
A snapshot is published only when every required scanner workflow succeeded, retained
artifacts match the same commit, hashes validate, normalization succeeds, and canonical
finding/observation counts reconcile. A failed refresh leaves the last publishable
snapshot active.

The severity previews and canonical finding cards show **Reported by** scanner names
paired with their retained rule IDs, followed by a labeled source file and line. Preview
locations wrap instead of truncating. Cards and the evidence dialog also show retained
artifact names directly, without opening a disclosure. Duplicate origin tuples are
consolidated visually; every underlying observation remains accessible. Missing scanner,
rule, or artifact metadata is labeled unavailable rather than inferred.

The main workspace contains one card per canonical issue. Opening **Evidence** shows every
contributing scanner family, rule, native result, message, location, version, and raw
artifact reference. Deduplication collapses presentation, never evidence.

The browser mounts at most 250 canonical-finding cards and supports search plus severity, category,
component, and scanner filters. Findings are severity-sorted Critical through Low.
**Actionable Issues** is the default view (Critical, High, and Medium); one toggle reveals
Low and informational notes. Separate downloads expose the complete snapshot and raw
observation collection.

The board keeps release assurance ahead of scanner detail: current branch/SHA and
freshness, deterministic risk posture, highest-risk areas, channel
coverage, additional observation evidence, and the critical/high review queue are visible at
a glance. Optional detail is collapsed by default to prevent scanner noise from
overwhelming the operational view.

The page has two explicit zones. **Issue Wall — What was found?** contains the snapshot
summary, canonical findings, evidence, and analytical views. A compact branch, short-SHA,
and channel-completion chip keeps source context visible without mixing controls into the
review flow. **Analysis operations — Where did this snapshot come from?** appears lower
on the page and contains the GitHub workflow launch and inspection controls.

The wall entrance establishes a three-layer evidence journey. **Issue discovery** leads
to the searchable canonical wall and answers where problems are. **Issue understanding**
opens the leading canonical finding and its cross-scanner convergence, answering why
multiple observations form one issue. **Evidence provenance** leads to snapshot proof,
where GitHub workflow and artifact integrity records explain the retained observations.
The visible chain is Issue Wall -> canonical finding -> scanner evidence -> GitHub
workflow/artifact -> immutable source code. These are navigation aids over existing
evidence, never remediation or generated-fix actions.

A prominent **Snapshot health** strip separates evidence-pipeline status from code
findings. For an accepted wall it confirms unified analysis coverage, exact-commit
binding, artifact-integrity records, and publication acceptance. Its incomplete-state
renderer instead reports the completion fraction and names each failed channel with its
retained status/reason, plus workflow-activity, evidence-status, and proof actions. The
normal fail-closed pipeline still prevents an incomplete candidate from replacing the
last-known-good published wall; this UI does not weaken that gate.

**Observation Health** accounts for all 26 catalogued observation channels. Its
denominator always includes the 16 static lanes plus all 10 monitoring, dynamic, and
assurance lanes; its numerator requires both channel completion and a classifiable
observation outcome. Channels without exact-snapshot evidence remain visible as `NOT_AVAILABLE`
rather than disappearing. The coverage flow is 26 channels -> all evidence ->
canonicalization/correlation -> Issue Wall -> developer understanding. The primary UI
does not describe any channel as optional.

Coverage is also grouped by operational role without creating separate walls:

- **Code quality (7):** Ruff, Pyright, ESLint, TypeScript, Radon, Xenon, and Vulture.
- **Security (6):** Bandit, CodeQL, Gitleaks, Semgrep, Snyk, and CodeRabbit.
- **Dependencies (4):** OSV-Scanner, Trivy, Shipping Image Trivy, and SBOM Policy.
- **Infrastructure (5):** Checkov, Hadolint, Repository Security Posture, OpenSSF
  Scorecard, and zizmor.
- **Reliability (4):** Coverage.py, Schemathesis, Atheris, and SonarQube Cloud.

**Observation Health** breaks the full channel inventory into mutually exclusive
outcomes: completed channels with finding evidence (any native Critical/High/Medium/Low
observation), completed channels with an explicit zero and no retained observations,
and completed channels whose native observations are all informational. Incomplete
channels stay unavailable even if they retained partial findings. Completed channels
with missing or unclassifiable outcome evidence have their own explicit unavailable
outcome row. These buckets always reconcile to the channel total.

The evaluated numerator includes the three measured outcomes only. The progress bar
and **All channels evaluated** confirmation use that numerator, not the static
publication gate. No green all-evaluated claim appears for an empty inventory or unknown
outcomes. Native observations determine informational classification, so corroboration
with a higher-severity scanner cannot change another scanner's original evidence class.
A zero-finding completed scan still counts as evaluated evidence. Role coverage below
continues to describe channel completion, independently of outcome classification.

The **Channel Observatory** is one compact inventory with All, Code, Security,
Dependencies, Infrastructure, and Reliability filter buttons. Each row shows a scanner,
status symbol and label, and retained finding count. Complete rows are neutral;
incomplete/unavailable rows are amber; explicit failures are red. Rows expand to expose
the native status, role, reason, workflow reference, and available artifact names.
Only a completed channel with an explicit nonnegative integer count can show **0 findings**.
Missing evidence says **Coverage unavailable**, with **No artifact** when the retained
artifact list explicitly proves absence. Partial evidence with positive findings shows
a retained count and **Coverage incomplete**. A missing count on a completed channel
says **Finding count unavailable**; it is never coerced to zero. Native completed status
with zero observations does not manufacture a missing-evidence reason.
Role filters change only the visible rows and expose their selected state to assistive
technology; the channel total remains the complete inventory.

Its summary derives workflow-group counts from retained channel workflow references,
with explicit unavailability when absent. It says **exact commit** for a full commit
identity: the snapshot does not retain proof that a selected historical SHA was branch
HEAD. The Observatory replaces the split channel panels without changing the internal
publication gate or the separate AI advisory evidence lane.

Each role displays its own covered/total fraction and incomplete channel names. The role
denominators sum to 26 and the total remains the authoritative Analysis Coverage value;
every role continues into the same canonical Issue Wall.

Snapshot health (Observation Health) and Risk posture lead together after the header.
The **Issue Wall** and its searchable finding workspace follow Issue discovery and the
source chip, ahead of supporting analytics. **ALL ISSUES**
shows the complete deterministic canonical count alongside Critical, High, Medium, and
Low totals; additional informational/unknown findings remain explicitly counted when
present. The four severity columns preview the first five identities each and clearly
state that limit. Severity counts and ALL ISSUES reset filters and show all priorities,
so selecting Low cannot produce an empty queue merely because the default actionable
filter excluded it.

Every preview pairs a severity dot and finding concept with its independent scanner-family
source count. One source is neutral; two or more use green corroboration text. Source
counts describe evidence density, not severity or exploitability, and AI advisories remain
separate. Selecting a finding opens its existing Evidence Graph. These views do not create
GitHub Issues or persist a second finding lifecycle.

Each result card makes one deduplicated canonical finding the primary object. Severity,
concept, message, and immutable source location lead; category and component provide
context; the number of agreeing scanner families and their named badges appear beneath
a divider as supporting proof. A compact, count-driven flow makes deduplication explicit:
**N raw observations -> canonicalized -> 1 Issue Wall finding**, followed by **N
observations consolidated**. The **View N source observations** disclosure expands the
original rule, result ID/link, message, and retained artifact for every contributing
scanner directly in the card. **Where did this issue come from?** opens the full provenance,
while **GitHub** opens the exact file and line at the analyzed commit. Multiple scanner
observations are never presented as multiple issues.

Each card also exposes a **Related findings** panel with canonical-finding counts for
the same file, concept, primary retained scanner rule, and top-level directory. These
are shortcuts into the existing read-only workspace filters: file, concept, and rule
use the indexed search control, while directory uses its dedicated selector. Selecting
a relationship shows the complete deterministic scope, including low and informational
findings, so the displayed relationship is not silently clipped by the actionable-only
default. No relationship creates or persists a new cluster.

Opening a card presents an **Evidence Graph**, not a remediation assistant. The root
node is the canonical finding and each connected child is one retained scanner
observation. Every observation exposes its scanner and channel, rule, original message,
native result ID/link, observed location, tool version, reported severity, and artifact.
This graph explains why Issue Wall deduplicated the observations into the canonical
issue; it does not generate fixes, edit source, or make claims beyond retained evidence.

The provenance interaction uses progressive disclosure. It first shows the canonical
summary and location, then a visual convergence of named scanner-family nodes into one
canonical-finding node and the exact “source observations → canonical issue” count.
Detailed rules, messages, result IDs, artifacts, versions, and reported severities stay
collapsed until the developer chooses to inspect the source observations.

Each card also keeps **Evidence provenance** one disclosure away. It names the snapshot,
relevant scanner workflow files, artifact references, and any matching SHA-256 integrity
records already carried by the snapshot. Links open the captured GitHub workflow runs,
and the retained normalized observation download remains available beside them. Because
the snapshot does not carry individual GitHub artifact download URLs, the UI does not
invent per-file links; GitHub workflow runs remain the artifact-access authority.

The report-first developer summary adds an accessible severity distribution, weighted
top-affected-file ranking, and a concrete **Where to start** path. Every visible result
retains an exact file and line, supports location copying, links to the immutable source
commit when repository identity is available, and opens the contributing scanner
evidence. Charts and report rows filter the same canonical findings rather than a
sampled dataset. Developers can export the current filtered view as CSV without
changing the retained JSON evidence.

The visual-metrics row adds three current-snapshot views without inventing historical
state: a category-by-severity risk matrix, a cross-scanner agreement
breakdown, and severity-weighted concentration across top-level code areas. Matrix cells
and area chips drill into the same canonical filter workspace. Corroboration is
presented as review confidence only; it is independent of severity and never claims
exploitability.

The **Web of Scanners** launchpad gives each authenticated GitHub operation its own
responsive action card: run the manual full four-scanner orchestration for a selected
branch or inspect workflow activity. Each card explains its effect before it
opens GitHub in a new tab. The static page never holds a GitHub token and cannot call the
dispatch API directly. GitHub therefore remains the permission, branch-selection,
confirmation, audit, and run-status authority.

The **Signal / Control Room** visual language uses exact semantic tokens: background
`#070B12`, surface `#0D131D`, elevated surface `#121B28`, border `#253244`, text
`#F1F5F9`, muted text `#8B9AAF`, and primary cyan `#38D9FF`. Cyan is reserved for
navigation, selected filters, links, focus, evidence relationships, controls, and
snapshot identity. Success green `#35D399` means completed, validated, healthy, or
corroborated; warning amber `#F5B942` means incomplete, degraded, or attention required.
Critical red `#FF4D67` also represents failed channels and serious integrity failures;
high is `#FF8A3D`, medium `#F4C95D`, and low `#69A7FF`. Former violet, pink, and lime
accents resolve to semantic cyan or green rather than forming decorative categories.
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
cannot publish Issue Wall. There is no scheduled or event-driven publication. Every
manual invocation dispatches all four scanner groups afresh.
Scanner workflow definitions run from the operator-selected manual workflow branch;
`scan_branch` and `scan_sha` select source independently. Sonar helpers and project
configuration come from the fork's trusted default-branch tooling checkout, so an
upstream source commit need not contain the external analysis service.
OpenSSF Scorecard rejects non-default tooling refs for manual runs. Those runs retain
an explicit unavailable status for that channel rather than reporting zero findings.
Repeated native record IDs retain every raw occurrence. Deterministic occurrence IDs
disambiguate collisions within a snapshot; singleton observation IDs and canonical
finding identities stay stable. Repeated records from one scanner do not add sources.
Retained service-generated SARIF projections are not re-ingested as scanner evidence;
their native input artifacts remain authoritative. Snyk Code and Open Source share the
Snyk channel and count as one scanner family for corroboration.

The manual run exposes four visible phases in the Actions log and job summary: resolve
the authoritative branch head, dispatch four fresh scanner groups, validate those four
groups concurrently, and build the 26-channel observation inventory under the separate
static publication policy. The builder currently reselects successful exact-title runs;
it does not receive the freshly dispatched run IDs.
Incomplete, expired, corrupt, or mixed-commit evidence fails closed.

The board has one **Channel Observatory** inventory, followed by **Workflow Provenance**
and **Snapshot Proof**. All consume the authoritative `analysis_channels` snapshot-v2
array; role grouping uses each channel's catalog-owned `class`. It includes every static,
dynamic, monitoring, and assurance lane with its exact-snapshot status, findings, and
available proof or unavailability reason. The internal 16-channel manifest remains the
fail-closed exact-head publication gate for backward compatibility, but that split is
not presented as the product's monitoring model. The analytics area includes a
scanner-family distribution so contributors can see which engines actually produced
the canonical current findings.

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


The dark control-room appearance uses neutral page, card, and scanner surfaces. Health,
attention, failure, finding severity, evidence links, and selected controls carry color;
section identities do not. The old required/optional split is absent from emitted v2
snapshots and browser grouping. Historical native status literals (including
COMPLETED_OPTIONAL) retain their source spelling in evidence disclosures only.
