---
title: Code-analysis current state
description: Release state, integration decisions, and explicit non-goals for the code-analysis subsystem.
---

# Code-analysis current state

The implemented scanner and Issue Wall subsystem is release-review ready. No product-code
integration or automated remediation work remains.

## Upstream review gate

- Prepare any proposal from the latest upstream `Testing` branch; `main` is the stable
  release branch and is not the development integration target.
- Apply only the scoped paths defined in [`UPSTREAM_INTEGRATION.md`](UPSTREAM_INTEGRATION.md).
- Run **Full Code Analysis (Manual)** for the proposed exact commit. Each invocation
  dispatches four fresh scanner groups. The reusable builder independently selects
  successful exact-title runs, so fresh-run exclusivity is not yet proven.
- Confirm additional observation channel availability at review time. CodeRabbit remains advisory;
  Snyk and SonarQube Cloud remain additional observation evidence lanes and cannot satisfy required channels.
- Obtain repository-owner approval before creating an upstream pull request.

## Explicit non-goals

- No hosted Issue Wall server or VM is required.
- No scanner may patch code, push branches, create issues, or remediate findings.
- No deferred scanner placeholder is part of the supported dashboard.
- No upstream branch, pull request, or repository setting is created by the subsystem.


The published data contract is now snapshot-v2 with one `analysis_channels` inventory,
class metadata owned by the catalog, and a separate static publication gate. Historical
v1 artifacts are not rewritten. The UI leads with Snapshot health and Risk posture,
then discovery, with Channel Observatory, Workflow Provenance, and Snapshot Proof below.
