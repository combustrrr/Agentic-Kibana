---
title: Scanner maintenance
description: Independent scanner adapters and validated dependency updates.
---

# Adding scanners and keeping them current

Each scanner is an independent producer. Adding a channel does not require a new
dashboard page, a fixed scanner enum, or changes to the other scanner adapters.
The existing finding and observation contract remains the dashboard interface.

## Add a channel

1. Copy `config/code-analysis/scanner-extension.example.json` into a new entry in
   `scanner_extensions` in `config/code-analysis/service.json`. Use a unique
   `ext-...` channel and scanner name. Commit the entry with its trusted adapter.
2. Implement the adapter under `scripts/code_analysis/adapters/`. The JSON and
   SARIF examples demonstrate the result contract. Accept `--request`, `--output`,
   and, for source scanners, `--source`. Pin installation dependencies.
3. Source adapters run on an exact checkout without vendor or publishing secrets.
   Vendor adapters run separately and must verify the export's actual revision.
   They must not execute code from the source repository.
4. Emit a result with source repository, source SHA, status, reason, and findings.
   Each finding has rule ID, explanation, severity, file, and line; include native
   IDs and tool/ruleset versions where supplied by the scanner. Never invent them.
5. Run `python -m scripts.code_analysis.generate_source_workflow`, the extension
   tests, and workflow policy checks. Commit the config, adapter, and generated
   workflows together. Validate a real branch and an applicable PR before claiming
   the channel is operational.

Each extension gets its own job, timeout, artifact, and private working directory.
An adapter crash, timeout, missing result, malformed result, or wrong revision is
reported for that channel. Healthy sibling evidence remains publishable. A rerun
cannot borrow the adapter's old output. Vendor checks unavailable through a plan
or credential stay unavailable; they are not silently deferred.

There is no application-maintained fixed list of extension slots. This is not
unlimited compute or storage: GitHub workflow/runner limits, vendor quotas, the
50 MB per-envelope bound, and the existing 900 MB site safety threshold still
apply. Large inventories may need batched workflows or sharded adapter output;
those are capacity changes, not extra UI implementations.

## Automatic maintenance

`13-scanner-updates.yml` reconciles dependencies daily and can be run manually.
It uses self-hosted Renovate on Actions; no hosted Renovate account is required.
It proposes at most two concurrent update PRs, keeps exact pins, ignores unstable
releases, and waits three days after a release. Failed checks leave current pins
and current reports in place. A failure to check for updates is an Actions failure,
not evidence that the scanners are current.

Coverage includes scanner Actions, `.ci` Python requirements, inline pinned Python
scanner packages, Snyk CLI, Gitleaks images, and Scorecard releases. Scorecard updates
fetch the official release checksum and retain verification at installation.
Generated workflows and generator Action constants are synchronized in the same PR.
Future adapters with ordinary `package==version` pins are detected automatically;
other package formats need another Renovate manager/annotation and a compatibility
test. SaaS-owned engines update at the provider. Source-owned ESLint/TypeScript
versions follow the selected repository's lockfile; the service does not rewrite
upstream dependencies to force a newer compiler.

`14-scanner-compatibility.yml` runs service/extension regression tests, workflow
checks, and native-output canaries with read-only permissions and no scanner or
publication secrets. Only stable patch updates to the explicitly canary-covered
Bandit, Radon, Vulture, and Xenon families can auto-merge after that check passes
(Ruff is registered but its current 0.x releases remain review-only). Other updates,
including major changes, vendor CLIs, Actions, and Scorecard, get reviewable PRs.
Add a scanner's real compatibility test before allowing its automatic merge.
Passing tests reduces upgrade risk; it cannot guarantee that arbitrary future
scanner versions or source projects will never break.

### One-time updater access

Set `SCANNER_UPDATE_TOKEN` in the analysis host, scoped to that repository only.
Use a fine-grained token with Contents, Pull requests, Workflows, Issues, and Commit
statuses read/write; metadata, checks, and Administration read access. The default
branch must require the `Scanner compatibility` check. The updater verifies this
protection before doing any work, and Renovate waits for all checks to pass.
The token belongs only to the trusted updater job, never scanner execution or the
browser. The workflow explicitly fails with setup guidance while this is absent.
The default `GITHUB_TOKEN` cannot provide the required workflow-editing access.

Official references:
[Renovate GitHub permissions](https://docs.renovatebot.com/modules/platform/github/),
[custom dependency managers](https://docs.renovatebot.com/modules/manager/regex/),
[automatic merge checks](https://docs.renovatebot.com/key-concepts/automerge/).

To recover a bad upgrade, revert its maintenance PR in the analysis host and request
a fresh scan. The new tooling revision preserves attribution; never relabel a
previous report as though it came from the reverted scanner version.
