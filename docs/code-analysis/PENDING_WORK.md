---
title: Code-analysis current decisions
description: Remaining integration decisions and explicit non-goals for the code-analysis subsystem.
---

# Code-analysis current decisions

The implemented scanner and Issue Wall subsystem is release-review ready. No product-code
integration or automated remediation work is pending.

## Before an upstream proposal

- Rebuild the scoped integration branch from the latest upstream `Testing` branch.
  `main` is a release branch and is not the integration target.
- Re-run **Full Code Analysis (Manual)** for the resulting exact commit and use only that
  run's artifact as review evidence.
- Confirm optional vendor availability at review time. CodeRabbit remains advisory;
  Snyk and SonarQube Cloud remain optional evidence lanes and cannot satisfy required channels.
- Obtain owner approval before creating any upstream pull request.

## Fork-only review state

- `integration/code-analysis-upstream` contains the scoped code-analysis implementation.
- Fork draft PR #18 and `review/upstream-main` were created only to exercise external review.
  They are not upstream integration vehicles and should not be merged.
- Cleanup of that temporary PR/base can occur after the review links are no longer needed.

## Explicitly not pending

- No hosted Issue Wall server or VM is required.
- No scanner may patch code, push branches, create issues, or remediate findings.
- No deferred scanner placeholder is part of the supported dashboard.
