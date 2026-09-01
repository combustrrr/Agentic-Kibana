---
title: Snyk contribution measurement
description: Measure Snyk findings that add unique value beyond the required scanner channels.
---

# Snyk unique-contribution measurement

> **Measured:** 2026-08-28
> **Decision:** retain Snyk as an optional scanner; do not promote it to required coverage.

## Evidence

The code comparison uses exact-Testing dependency run `33102828962`, artifact
`9659304881`, and the accepted snapshot for commit
`0972ac0ab405161fc22255e622eae0bb52713d03`. The artifact contains 226 Snyk Code
observations. Its Open Source surface was partial, so it is not used to claim SCA
completeness.

Post-repair run `33190866240`, artifact `9693781846`, separately proves that the
repository-owned workflow can complete both configured surfaces. It contains 388 Snyk
Code observations and 33 Open Source observations. This later run is reliability
evidence, not a replacement for the exact-Testing code baseline.

## Reconciliation correction

Snyk's SARIF driver calls itself `SnykCode`, while the optional-control contract and
dashboard use the family `Snyk`. Its rule IDs also had no canonical aliases. The old
normalization therefore displayed 226 apparently Snyk-only canonical rows even when
another scanner reported the same concept and location.

The normalizer now aliases `SnykCode` to `Snyk` and maps the observed Snyk rules to the
existing `hardcoded-secret`, `command-injection`, `weak-crypto`, and `path-traversal`
concepts, plus the new explicit `open-redirect` concept. Conservative canonical identity
remains unchanged: results without adequate shared anchors are not silently merged.

## Results

### Snyk Code on exact Testing

| Measure | Count |
|---|---:|
| Snyk Code observations | 226 |
| Same concept at the exact file and line from another deterministic family | 14 |
| Same file and line, but a different canonical concept | 12 |
| No same-concept exact-location match | 212 |
| Unmatched observations outside test files and `/test` rule variants | 27 |

The 14 semantic overlaps cover 12 hardcoded-secret and 2 weak-crypto observations.
Their other evidence comes from the project-specific static rules, Bandit, and Semgrep.
Of the 212 unmatched observations, 186 are low severity. The dominant unmatched class is
test-oriented hardcoded-value detection, so 212 is a candidate count rather than a claim
of 212 confirmed defects.

### Snyk Open Source after manifest repair

The successful post-repair SCA artifact contains 33 dependency observations. Matching
complete CVE/GHSA identifiers against the accepted exact-Testing OSV artifact gives:

| Measure | Count |
|---|---:|
| Snyk Open Source observations | 33 |
| Advisory identifier also present in OSV evidence | 26 |
| Advisory identifier not present in the accepted OSV evidence | 7 |

The seven Snyk-only advisory identities affect protobuf, langgraph, starlette,
mkdocs-material, and pymdown-extensions. They remain findings for owner triage; this
measurement does not validate exploitability or authorize dependency remediation.

## Interpretation

Snyk demonstrates non-redundant discovery, especially in dependency advisories, but its
Code output has a high-volume test/fixture signal and the separate vendor PR check is
quota-blocked. The repository-owned workflow should therefore remain scan-only and
optional. Required publication continues to rely on the existing deterministic channel
set; Snyk evidence enriches the dashboard when available and reports partial or
unavailable states truthfully when it is not.

No finding was hidden, suppressed, fixed, or reclassified as false positive by this
measurement.

## Targeted advisory follow-up

The documentation toolchain pin was upgraded from `mkdocs-material==9.6.19` to
`mkdocs-material==9.7.7`, the vendor-listed fixed version for the measured
`SNYK-PYTHON-MKDOCSMATERIAL-18752056` / `CVE-2026-73295` advisory. This is a bounded
build-time dependency remediation; the runtime Starlette and LangGraph major-version
advisories remain findings and require separate compatibility work. Strict Help Center
assembly is the acceptance gate for this pin change.
