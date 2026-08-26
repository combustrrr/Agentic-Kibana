# Current Findings Dashboard

The code-analysis product is one read-only, full-codebase snapshot. It does not create
one GitHub Issue per scanner result and it does not use baseline or lifecycle state to
hide older findings.

## Snapshot contract

The header identifies the exact commit, generation time, and required-channel status.
A snapshot is published only when every required scanner workflow succeeded, retained
artifacts match the same commit, hashes validate, normalization succeeds, and canonical
finding/observation counts reconcile. A failed refresh leaves the last publishable
snapshot active.

The main table contains one row per canonical issue. Opening **Evidence** shows every
contributing scanner family, rule, native result, message, location, version, and raw
artifact reference. Deduplication collapses presentation, never evidence.

The browser mounts at most 250 rows and supports search plus severity, category,
component, and scanner filters. Separate downloads expose the complete snapshot and raw
observation collection.

## Local hosting

After generating `dashboard/`, publish and serve it with:

```bash
python scripts/code_analysis/publish_snapshot.py \
  --source dashboard \
  --publication-root var/code-analysis
docker compose -f deploy/code-analysis-dashboard/compose.yml up --build -d
```

Open <http://127.0.0.1:8787>. The container is read-only and binds only to localhost.
The future QA VM uses the same image behind company-approved OIDC/VPN access.

## GitHub output

Until the QA VM exists, Actions retains `current-findings-dashboard-<run-id>` as immutable
evidence. The custom Check describes snapshot validity and links to that artifact. The
hosted dashboard, not the artifact ZIP, is the intended daily developer surface.

DefectDojo, history, triage analytics, Issues, remediation, and autofix are deferred.
