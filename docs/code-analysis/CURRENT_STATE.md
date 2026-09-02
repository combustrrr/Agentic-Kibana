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
  dispatches four fresh scanner groups and builds the dashboard exclusively from those
  newly launched runs.
- Confirm optional vendor availability at review time. CodeRabbit remains advisory;
  Snyk and SonarQube Cloud remain optional evidence lanes and cannot satisfy required channels.
- Obtain repository-owner approval before creating an upstream pull request.

## Explicit non-goals

- No hosted Issue Wall server or VM is required.
- No scanner may patch code, push branches, create issues, or remediate findings.
- No deferred scanner placeholder is part of the supported dashboard.
- No upstream branch, pull request, or repository setting is created by the subsystem.
