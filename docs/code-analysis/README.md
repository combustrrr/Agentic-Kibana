---
title: Current Findings Platform
description: All-channel observation health, canonical findings, and immutable scanner evidence.
---

# Agentic SOC Current Findings Platform

**Web of Scanners** is the external analysis system. **Issue Wall** is its offline,
read-only developer report. All 26 analysis channels are first-class observations:
class describes purpose, never importance. The system finds, normalizes, deduplicates,
and explains evidence; it does not remediate, create Issues, or own finding lifecycle.

## Start here

| Need | Read |
|---|---|
| Architecture and snapshot contract | [SERVICE_ARCHITECTURE.md](SERVICE_ARCHITECTURE.md) |
| Run and review the report | [MONITORING_UI.md](MONITORING_UI.md) |
| Production acceptance | [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) |
| Data handling | [DATA_HANDLING_INVENTORY.md](DATA_HANDLING_INVENTORY.md) |
| Additional observation channel activation | [EXTERNAL_ACTIVATION.md](EXTERNAL_ACTIVATION.md) |
| Upstream scope and review gate | [UPSTREAM_INTEGRATION.md](UPSTREAM_INTEGRATION.md) |
| Current state | [CURRENT_STATE.md](CURRENT_STATE.md) |

## One observation inventory

Published `snapshot-v2` JSON has one `analysis_channels` array. It does not emit
`channel_status` and `additional_channels` as competing inventories. Every channel has
the same `channel`, `name`, `class`, `status`, `findings`, observation membership,
workflow definition, and retained-evidence fields. `analysis_channel_count` reconciles
the inventory. Missing finding evidence is `null`, never an invented clean zero.

| Class | Channels |
|---|---|
| Code (7) | Ruff, Pyright, ESLint, TypeScript, Radon, Xenon, Vulture |
| Security (6) | Bandit, CodeQL, Gitleaks, Semgrep, Snyk, CodeRabbit |
| Dependencies (4) | OSV-Scanner, Trivy, Shipping Image Trivy, SBOM Policy |
| Infrastructure (5) | Checkov, Hadolint, Repository Security Posture, OpenSSF Scorecard, zizmor |
| Reliability (4) | Coverage.py, Schemathesis, Atheris, SonarQube Cloud |

The catalog owns class assignments. The UI groups by that metadata; it contains no
second scanner-to-class roster. CodeRabbit observations retain `AI_ADVISORY` authority
and never corroborate deterministic findings. Equal inventory visibility does not
turn AI advice into deterministic proof.

**Observation Health** distinguishes completed finding evidence, completed zero-finding
scans, informational-only evidence, incomplete channels, and unclassifiable outcomes.
All buckets reconcile. **Risk posture** describes reported finding severity separately
from whether the evidence collection completed. Green means supported health or
corroboration, amber means attention/incomplete evidence, and red means failure or
Critical risk. Scanner identity receives no decorative color.

## Review path

1. Start with Snapshot health and Risk posture, then Issue discovery.
2. Use the severity columns or searchable canonical findings. A finding shows severity,
   independent-source count, immutable location, and its complete Evidence Graph.
3. Follow cross-scanner evidence to raw observations and retained GitHub artifacts.
4. Below discovery, inspect Channel Observatory, Workflow Provenance, and Snapshot Proof.
5. Download complete JSON evidence or a filtered CSV when needed. These are read-only
   views of the same snapshot, not separate issue lifecycles.

## Generate an immutable report

Open Actions, select **Full Code Analysis (Manual)**, and choose the source branch and
optional reachable full SHA. The selected SHA is analyzed, even when it is historical.
Workflow selection is separate from source identity. Only this manual workflow can
publish Issue Wall; push/PR scanner runs and CodeRabbit review events retain evidence.

The manual workflow dispatches four fresh scanner groups and waits for success. The
reusable builder currently selects successful exact-branch/SHA-title runs independently;
those dispatched run IDs are not passed to it. Do not claim strict fresh-run binding
until that handoff is migrated. All selected artifacts must still satisfy exact-commit,
hash, normalization, and count-reconciliation checks.

After success, use **Review-ready artifact handoff**, download and verify the artifact,
extract it, and open `dashboard/START_HERE.md`, then `dashboard/index.html`. No server,
VM, token, CDN, installation, or network connection is needed after download. The
artifact and custom Check identify the source commit and retain GitHub provenance.

## Observation coverage versus publication policy

The observation model is 26 channels. Publication eligibility is a separate explicit
`publication_gate` record with policy `static-evidence-v1`, channel identities, and its
satisfaction result. The existing manifest still requires structured evidence from 16
channels across workflows 01 through 04. This gate is unchanged by the unified model.

An accepted artifact may therefore show incomplete Observation Health. Missing Snyk,
Sonar, CodeRabbit, dynamic, or assurance evidence cannot disappear, become a clean zero,
or satisfy another channel. Moving publication blocking to all 26 is a separate
workflow/policy migration; changing class or display labels cannot perform it.

A valid snapshot with findings yields a neutral advisory Check, an empty valid snapshot
succeeds, and invalid publication evidence fails. Counts are observations, not a claim
that the application is secure. Failed refreshes do not replace accepted artifacts.

## Safety and integration

The service is external to the Agentic SOC backend and web UI. It has no source,
collaboration, deployment, or production mutation path. Native Sonar results are imported
into the same evidence model; outbound generic projection excludes Sonar-native and AI
advisory findings to prevent loops. Additional observation channels report vendor,
credential, entitlement, and availability limitations explicitly.

Retained scanner messages may include code snippets, paths, and dependency metadata.
Artifact access and retention follow GitHub repository policy. Upstream integration
requires the scoped review process in [UPSTREAM_INTEGRATION.md](UPSTREAM_INTEGRATION.md).
Historical `snapshot-v1` artifacts retain their own embedded offline renderer; regenerate
through the pipeline to obtain the v2 model. The current renderer rejects v1 input
instead of guessing missing observation metadata.
