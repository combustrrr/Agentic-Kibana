# Where to View Code-Analysis Findings

The monitoring service deliberately does **not** create one GitHub Issue per finding.
At the current baseline that would create thousands of repository Issues, obscure human
work, and duplicate alerts reported by more than one scanner.

## GitHub web entry point

For a pull request into the fork's `claude/main` branch:

1. Open the pull request's **Checks** tab.
2. Select the single neutral **Code Analysis Dashboard** check for the commit.
3. Review the bounded lifecycle, severity, scanner-health, and attention totals directly
   in GitHub.
4. Use **Download the full searchable dashboard artifact** inside that check summary,
   extract it, and open `dashboard/index.html` for every normalized finding.

The full HTML view opens on **Attention only** and explains why each item was surfaced.
It is searchable and filtered by lifecycle, severity, human triage, concept, component,
location, and scanner evidence. It renders 100 rows at a time (selectable 50/100/250),
so a 10,000-finding baseline does not create 10,000 browser table nodes at once.

The same summary and artifact link are available under **Actions → Code Analysis
Dashboard → latest run → Summary**. Artifacts are retained for 30 days.

## What the single check means

- `neutral` means trustworthy analysis found attention items; `success` means the required
  scanner web completed with no attention items. `failure` means no trustworthy comparison
  could be produced, not that a vulnerability was necessarily found.
- One check is recovered and updated per internal repository/commit/name/namespace key;
  failed/restarted runs do not intentionally duplicate it. Findings do not create
  GitHub Issues or individual check annotations.
- The HTML artifact contains the full current scan. The GitHub check contains bounded
  rollups so the repository UI stays usable.
- Versioned stable identities and immutable observations collapse overlapping scanner
  evidence while preserving its independent families and native result identity.

## Why this is not GitHub Pages

This fork is public, and the repository's Pages design is reserved for versioned product
documentation. Publishing the consolidated vulnerability inventory to Pages would make a
security-focused index openly browsable and could collide with the existing documentation
release workflow. The authenticated Actions artifact is therefore the current full-data
surface.

## Future compatibility

The artifact contains a small deterministic DefectDojo-compatible fixture for future
evaluation. No DefectDojo request or deployment occurs in this MVP. The existing Compose
file remains evaluation-only and is not production-safe.
