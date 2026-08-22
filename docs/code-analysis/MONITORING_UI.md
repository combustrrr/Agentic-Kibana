# Where to View Code-Analysis Findings

The monitoring service deliberately does **not** create one GitHub Issue per finding.
At the current baseline that would create thousands of repository Issues, obscure human
work, and duplicate alerts reported by more than one scanner.

## GitHub web entry point

For a pull request into the fork's `claude/main` branch:

1. Open the pull request's **Checks** tab.
2. Select the single neutral **Code Analysis Dashboard** check for the commit.
3. Review the bounded severity, tool, affected-file, and issue-concept tables directly
   in GitHub.
4. Use **Download the full searchable dashboard artifact** inside that check summary,
   extract it, and open `dashboard/index.html` for every normalized finding.

The full HTML view is searchable and filtered by severity, tool, category, file, rule,
concept, and message. It renders 100 rows at a time by default (selectable 50/100/250),
so a 10,000-finding baseline does not create 10,000 browser table nodes at once.

The same summary and artifact link are available under **Actions → Code Analysis
Dashboard → latest run → Summary**. Artifacts are retained for 30 days.

## What the single check means

- `neutral` is intentional: findings are advisory and do not block merging.
- One check is updated per commit using the stable commit key; findings do not create
  GitHub Issues or individual check annotations.
- The HTML artifact contains the full current scan. The GitHub check contains bounded
  rollups so the repository UI stays usable.
- Fingerprints based on repository file, line, and canonical concept collapse overlapping
  scanner evidence into one displayed finding.

## Why this is not GitHub Pages

This fork is public, and the repository's Pages design is reserved for versioned product
documentation. Publishing the consolidated vulnerability inventory to Pages would make a
security-focused index openly browsable and could collide with the existing documentation
release workflow. The authenticated Actions artifact is therefore the current full-data
surface.

## Persistent vulnerability-management option

DefectDojo remains the recommended later service when the team supplies a private host,
TLS, backup/storage policy, and API credentials. It provides durable triage, reimport,
deduplication, ownership, and reporting without turning findings into GitHub Issues. The
existing Compose file is evaluation-only and is not considered deployed or production-safe.
