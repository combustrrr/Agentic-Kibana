---
title: Scanner and repository integrations
description: Connect another scanner or repository to the static analysis dashboard.
---

# Scanner and repository integrations

The service uses this pattern for each repository instance:

```text
Source repository branch / PR / commit
  -> trusted observer Actions workflow
  -> built-in scanners + registered adapters
  -> exact-revision evidence -> canonical observations and findings
  -> current report Release assets -> one static dashboard
```

The current source is `ARYDESTROYER/Kavach-AgenticSOC`. Repository identity and
application commands are configuration; source repositories remain read-only.
New scanner channels appear in Issues, Scanners, overview counts and provenance
through the existing report contract. No frontend scanner-specific component is needed.

## Add a scanner

1. Implement a Python adapter under `scripts/code_analysis/adapters/` in the trusted
   observer repository. It receives `--request` and `--output`; source adapters also
   receive `--source`, pointing at an exact checked-out commit. The examples
   `example_json.py` and `example_sarif.py` illustrate ingestion of existing exports;
   they are not enabled scanners and do not install or execute a vendor product.
2. Add an entry to `scanner_extensions` in `config/code-analysis/service.json`:

   ```json
   {
     "channel": "ext-my-scanner",
     "name": "My scanner",
     "class": "security",
     "mode": "source",
     "adapter": "scripts/code_analysis/adapters/my_scanner.py",
     "timeout_minutes": 15,
     "evidence_source": "DETERMINISTIC",
     "sensitive": false
   }
   ```

3. Generate the workflow and validate it:

   ```shell
   python -m scripts.code_analysis.generate_source_workflow
   python -m unittest scripts.code_analysis.test_extensions scripts.code_analysis.test_hosted scripts.code_analysis.test_service
   python scripts/code_analysis/audit_workflows.py
   ```

4. Commit the adapter, configuration and generated workflow together to the observer's
   default branch. Deploy the matching service configuration and reporting scripts to
   the dashboard repository. Run one exact revision and inspect retained evidence.

An extension registration enables its producer automatically. Extensions are separate
from the built-in `enabled_scanners` list. An intentional exception uses a nonempty
`deferred_reason` on the registration; it stays visible. Credential failures are
`NOT_AVAILABLE` or `OPERATIONAL_FAILURE`, never silent deferrals.

Supported classes: `code`, `security`, `dependencies`, `infrastructure`, `reliability`.
Use `AI_ADVISORY` for AI review evidence; it remains separate from deterministic findings.
Extension IDs begin with `ext-`; scanner names and IDs cannot collide with built-ins.

## Adapter execution and result contract

The adapter owns installing pinned scanner dependencies, invoking its CLI or reading
its API, pagination, native output conversion and vendor-specific revision checks.
The runner executes the trusted adapter with Python isolated mode. Use explicit paths
and subprocess argument arrays. Do not import adapter code or configuration from the
source checkout. Keep scanner-generated files outside the source scan tree.

The request JSON contains `target` (including repository, source SHA, PR/base context)
and `producer_run_id`. The adapter writes this neutral result to `--output`:

```json
{
  "source_repository": "owner/project",
  "source_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "COMPLETED",
  "reason": "",
  "findings": [
    {
      "rule_id": "RULE-1",
      "message": "Explain the reported issue",
      "severity": "HIGH",
      "file": "src/example.rs",
      "start_line": 12,
      "native_result_id": "native-123",
      "tool_version": "1.2.3"
    }
  ]
}
```

The runner wraps this in `channel-evidence-v1`, adding channel, target and producer
identity, and uploads `<channel>.channel-evidence` from that workflow run. Aggregation
requires exactly one envelope and verifies its identities before canonicalization.
The exact-attempt artifact collector and immutable tooling checks also apply.
Malformed or mixed-revision envelopes become `INVALID_EVIDENCE`; no findings from
that envelope are accepted. Valid channels can still publish in a partial report.

`COMPLETED` with an empty findings array is a measured zero. `POLICY_FINDINGS` requires
a reason and represents completed policy analysis. `OPERATIONAL_FAILURE`,
`NOT_AVAILABLE` and `NOT_APPLICABLE` require a reason and an empty findings array;
their counts remain unavailable. A scanner finding must have a relative file path,
nonnegative line number, rule, message and supported severity. Repository-wide checks
without code locations should return an execution/status reason rather than invent a file.

Adapter stdout/stderr are not published. Put concise, sanitized operational explanations
in the result. Never include access tokens or secret values in the output envelope,
including rule IDs, native IDs, paths or explanations. `sensitive: true` additionally
withholds finding messages/identifiers and source previews in public reports. Raw
Actions artifacts still require adapter-side redaction before upload.

## Vendor API channels

Use `mode: "vendor"` and a `secrets` mapping such as:

```json
{
  "channel": "ext-vendor-review",
  "name": "Vendor review",
  "class": "security",
  "mode": "vendor",
  "adapter": "scripts/code_analysis/adapters/vendor_review.py",
  "timeout_minutes": 15,
  "evidence_source": "AI_ADVISORY",
  "secrets": { "VENDOR_TOKEN": "VENDOR_ACCESS_TOKEN" }
}
```

Create the named Actions secret in the observer repository. Vendor jobs checkout
trusted tooling only; they receive no source checkout. They must never execute source
scripts or install source dependencies. Source-mode registrations reject secrets.
Neither job type receives publishing permissions.

An API adapter must verify the vendor's actual analyzed SHA and, for PR-specific
evidence, the requested PR/base/head context. Do not copy the requested SHA onto an
unverified "latest" API response. Use `NOT_AVAILABLE` when exact-revision evidence or
vendor entitlement is unavailable. External scanner workflow evidence can be pulled
by an adapter when its native producer run, attempt and SHA are verified and the
origin is retained in the finding's native identifier. Polling/notifications for the
external service belong in its adapter; the browser never handles credentials.

## Configure another source repository

Create a separate observer and public dashboard repository for the new instance.
Copy and edit `config/code-analysis/repository-profile.example.json` for its project
roots, dependency manifests, test commands, API startup and fuzzing targets. The
example reflects the current Python/TypeScript application; review every field.

```shell
python -m scripts.code_analysis.configure_instance --source team/application --analysis-host team/application-analysis --publishing-repository team/application-dashboard --preferred-branch main --profile my-profile.json --output new-service.json
```

The command writes a new file exclusively and does not overwrite the active instance.
In the new observer, install that file as `config/code-analysis/service.json`, configure
vendor project identifiers/secrets, review built-in scanner applicability and explicit
deferrals, add any language-specific adapters, and regenerate workflow 11. Existing
built-in producers primarily cover the current Python/TypeScript profile; other
languages require appropriate scanner commands/adapters and fixture validation.

Copy the UI, reporting scripts and service configuration into the new dashboard
repository. Install `config/code-analysis/dashboard-pages.yml` there as
`.github/workflows/pages.yml`, enable Pages deployment through Actions, and enable the
observer discovery workflow. The existing GitHub Actions/Release/Pages architecture
is unchanged. The dashboard receives the observer's actual default branch from
discovery for its manual-run instructions.

Validate a branch and a PR end to end before declaring the new instance operational.
Check producer identity, failed/zero-result channels, source links, secret redaction,
partial reports and publication recovery. Registrations do not prove scanners work;
every active applicable scanner still needs usable live evidence.

## Portable onboarding for another GitHub repository

Use `config/code-analysis/portable-profile.example.json` for a source that does not
share this application's Python/TypeScript layout. It requires no `backend`, `webui`,
Python requirements file, or JavaScript package. The portable workflow enables the
repository-wide Semgrep, Gitleaks, Trivy, Checkov, repository-posture, Scorecard, and
PR CodeRabbit producers. CodeRabbit still requires actual matching PR review evidence;
repository permissions and vendor availability remain visible in results.

Other built-in channels remain `NOT_AVAILABLE` with a profile-configuration reason,
not silently deferred or declared successful. Add tested scanner extensions for the
repository's language/build/API/vendor checks. The portable profile is a reusable
baseline, not a claim of complete language coverage. The original profile remains
compatible but contains project-specific commands; copying it is not generic support.

From the analysis-host template checkout, generate coordinated overlays:

```shell
python -m scripts.code_analysis.configure_instance --source team/project --analysis-host team/project-analysis --publishing-repository team/project-dashboard --preferred-branch main --profile config/code-analysis/portable-profile.example.json --bundle-directory new-instance --launch-endpoint https://project-launcher.example.workers.dev --dashboard-url https://team.github.io/project-dashboard/ --app-client-id YOUR_APP_CLIENT_ID --worker-name project-launcher
```

The destination must not exist. This generates:

- `analysis/`: service configuration and discovery/exact-source workflows for a new
  analysis-host repository created from this template.
- `dashboard/`: the matching service configuration and Pages workflow for a copy of
  the standalone UI/reporting service.
- `launcher/wrangler.jsonc`: matching source/host/website identities and App client ID;
  install this beside the copied `worker.mjs` in `analysis-launcher/`.

Register a dedicated GitHub App with `register_github_app.py --app-name` and the new
callback/website URLs. Apply the overlays to the corresponding new repositories,
configure the App permissions and Worker secrets, and configure the publisher's
existing repository-scoped access to its analysis host. Deploy the Worker, enable
Pages, then use **Connections** to verify routing. No credentials are copied by the
onboarding command, and the current instance is not switched or cleared.

This is one configured source per reusable instance, not an unrestricted URL box or
a multi-tenant service. Public GitHub sources are the current default. Private sources
require explicit cross-repository checkout/API access and private report hosting;
do not publish their findings to a public Pages instance. Other Git providers need
an adapter for discovery, identity, source links, and authentication.

Tests cover unrelated Rust, Java, JavaScript-only, and documentation-only trees,
workflow isolation, unchanged original workflow generation, configuration agreement,
and prevention of accidental overwrite. A new instance still needs a live branch/PR
acceptance run before its scanner coverage can be called operational.

## Scanner access and Python resolver repair (2026-09-09)

Sonar's native API explicitly denies non-main-branch data for the current organization.
Both configured tokens authenticate, main-project issues are readable, and a Browse
grant succeeded. This is distinct from a missing/invalid token. The exact-source probe
now uses the same derived branch as the scanner. Sonar documents an OSS plan with
branch support; existing organization migration is not automated here and the service
does not delete organizations or purchase subscriptions.

Snyk's quota warning alone does not establish execution failure. Retained npm scans
and a local exact-manifest CLI check completed while displaying that warning. The
failed Python resolver needs its staged sibling modules on Python's import path.
The inspection bootstrap permits only the temporary Snyk resolver directory outside
the source checkout, preserving isolated startup and metadata-only dependencies.
Node and Python use an explicit shared staging root. The vendor-only
`12-scanner-diagnostics.yml` workflow accepts the same exact-source inputs and
retains evidence without publishing a target report. Its green job conclusion is
not completion evidence: inspect `snyk-status.json` and every manifest's SARIF.
Each required manifest still needs valid SARIF; failures are not suppressed.

Upstream secret-protection controls require upstream-authorized credentials; the
fork owner's account has read-only upstream access. A token with only fork permissions
cannot observe upstream settings. CodeRabbit requires an actual reviewed upstream PR
head; a branch scan does not manufacture review evidence.
