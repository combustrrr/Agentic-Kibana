# Code Analysis — Architectural Decision Records

> **Status vocabulary:** `Accepted`, `Superseded`, or `Deferred`  
> **Authority:** the current implementation and [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md)

These compact ADRs capture why the platform has its present shape. Changes to an
accepted decision require an explicit replacement ADR and updated acceptance evidence.

## ADR-CA-001 — Fork-only isolation

**Status:** Accepted

**Decision:** Develop, scan, publish, and host from `combustrrr/Agentic-Kibana`. Treat
the original company repository and live site as read-only upstream context.

**Reason:** Static-analysis development must not create accidental production or
upstream mutations.

**Consequence:** Workflows, secrets, Checks, artifacts, and future VM credentials are
fork-scoped. Promotion to company infrastructure requires separate approval.

## ADR-CA-002 — Current full snapshot is the product

**Status:** Accepted; supersedes lifecycle-first MVP design

**Decision:** The primary view is every canonical issue in the latest trustworthy
full-codebase scan.

**Reason:** The actual objective is to detect and show existing issues, not to reduce a
backlog to zero or build historical vulnerability management first.

**Consequence:** `NEW/EXISTING/MOVED`, trends, ancestry analytics, and long-term triage
are not required for the active dashboard.

## ADR-CA-003 — Complementary manifest-driven scanner web

**Status:** Accepted

**Decision:** Required channels are declared in a checked-in manifest and selected for
detection-surface gain rather than scanner count.

**Reason:** No single scanner covers semantic flows, patterns, language quality, types,
dependencies, secrets, infrastructure, dead code, complexity, and coverage.

**Consequence:** Removing or renaming a required channel cannot silently become a new
healthy denominator. Optional tools remain visibly separate.

## ADR-CA-004 — Collapse issues, preserve evidence

**Status:** Accepted; replaces file+line-only deduplication

**Decision:** Equivalent observations become one canonical finding, while every native
scanner observation is retained.

**Reason:** Developers need low-noise presentation and full provenance. File+line alone
can merge unrelated issues; scanner-native IDs alone create duplicates.

**Consequence:** Identity uses normalized path/concept plus conservative region/native
anchors. Ambiguity stays separate. Scanner families, rules, native IDs, messages,
locations, versions, and artifact references remain drill-down evidence.

## ADR-CA-005 — Exact-commit, fail-closed publication

**Status:** Accepted

**Decision:** Publish only when all required artifacts identify the same repository and
source SHA, hashes validate, normalization succeeds, and counts reconcile.

**Reason:** A polished mixed-commit or incomplete dashboard is more dangerous than
continuing to serve an older valid snapshot.

**Consequence:** The dispatcher uses `workflow_run.head_sha`; failed refreshes never
replace current; previous exists only for rollback.

## ADR-CA-006 — Custom dashboard is the unified developer view

**Status:** Accepted

**Decision:** Use a standalone static dashboard rather than GitHub Issues, GitHub's
Security tab alone, SonarQube, CodeScene, or DefectDojo as the canonical presentation.

**Reason:** The project needs all normalized quality/security findings and cross-tool
evidence in one controllable interface without flooding work-management systems.

**Consequence:** GitHub-native and specialist UIs remain contributing/supplementary
surfaces. The dashboard stays replaceable, static, searchable, and read-only.

## ADR-CA-007 — Shared Actions/local/QA pipeline

**Status:** Accepted

**Decision:** GitHub-hosted and local/QA collection feed the same `pipeline.py` contract.
The QA VM pulls artifacts outbound and atomically hosts the same image.

**Reason:** Separate implementations would drift and an inbound GitHub-to-VM endpoint
would unnecessarily expand attack surface.

**Consequence:** The VM requires Actions read access only, binds locally, and sits behind
company VPN/OIDC. Analysis never runs in Agentic SOC application startup.

## ADR-CA-008 — Deterministic and AI lanes remain distinct

**Status:** Accepted

**Decision:** CodeRabbit or another approved AI reviewer produces `AI_ADVISORY`, not
deterministic corroboration.

**Reason:** Contextual AI review can discover logic concerns but is not equivalent to a
reproducible scanner rule/data-flow result.

**Consequence:** AI has its own dashboard scope and activation status. No AI finding
creates Issues, patches, comments, or blocking checks in this phase.

## ADR-CA-009 — Advisory, read-only operation

**Status:** Accepted

**Decision:** Do not autofix, patch, create Issues/comments, or enforce branch protection.

**Reason:** Scanner output can contain false positives and apparently trivial fixes can
hide incomplete integrations or change logic.

**Consequence:** The system discovers and presents. Remediation requires a later,
separately approved and measured workflow.

## ADR-CA-010 — Snyk is optional and truthfully partial

**Status:** Accepted

**Decision:** Retain Snyk SCA/Code SARIF when configured, but do not add it to the
required 16-channel publication gate yet.

**Reason:** Snyk is external and overlaps existing SCA/SCA surfaces. Local evaluation
also proved a scan can complete after resolving only some projects.

**Consequence:** Per-surface logs/status are retained; partial/unavailable analysis is
visible; unique detection value must be measured before promotion to required.

## ADR-CA-011 — DefectDojo and lifecycle persistence are deferred

**Status:** Deferred; supersedes the original immediate-deployment ADR

**Decision:** Do not deploy or integrate DefectDojo in the current findings platform.

**Reason:** Persistence, SLA, lifecycle, and triage history are secondary to the current
requirement: find and visualize all current issues.

**Consequence:** No DefectDojo network request or database exists. A future evaluation
must not replace the normalizer's identity/evidence authority.

## ADR-CA-012 — Internal engineering documentation

**Status:** Accepted

**Decision:** Keep `docs/code-analysis/` outside the customer Help Center navigation.

**Reason:** These files contain fork workflows, scanner behavior, evidence references,
and private QA-hosting guidance rather than end-user Agentic SOC documentation.

**Consequence:** The root repository README and engineering handoff link here, while the
bundled public Help Center excludes this directory.

