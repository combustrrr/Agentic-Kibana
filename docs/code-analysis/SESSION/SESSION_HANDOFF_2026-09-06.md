# Issue Wall UI handoff — 2026-09-06

Copy the **Next-chat prompt** section into a fresh chat. This file records the verified
state of the current uncommitted Issue Wall work; it is not a claim that the changes are
committed, pushed, or published.

## Next-chat prompt

```text
Continue the Issue Wall work in C:\Projects\Agentic-Kibana.

Read docs/HANDOFF.md and AGENTS.md first, then read
docs/code-analysis/SESSION_HANDOFF_2026-09-06.md completely. Follow the mandatory
Journal.md start/milestone/end rules. Do not discard or overwrite the existing dirty
worktree; the current modifications are intentional and uncommitted. Do not develop the
archived Kibana plugin.

The active UI is scripts/code_analysis/dashboard_template.html (not the originally
quoted scripts/code/_analysis/dashboard/_template.html path). It generates a static,
offline, view-only GitHub Actions artifact. Preserve that boundary: no remediation
assistant, source mutation, issue creation, triage lifecycle, hidden network calls, or
invented provenance links.

Current product thesis: the wall explains many scanner observations becoming one
canonical finding, then lets a developer trace that conclusion through scanner evidence,
GitHub workflow/artifact provenance, and immutable source. All 26 catalogued channels
participate in Analysis Coverage, classified by role, but feed one canonical wall.

Before changing anything, inspect git status/diff and open the generated preview at
.tmp/issue-wall-preview/index.html. Continue from the current implementation rather than
rebuilding it. Validate with:
  python -m unittest scripts.code_analysis.test_service
  parse every embedded script in dashboard_template.html with Node vm.Script
  git diff --check
  python scripts/code_analysis/benchmark_monitoring.py --preview-dir .tmp/issue-wall-preview

Important caveat: the primary UX has a unified 26-channel denominator, while the existing
fail-closed publication contract still gates on the 16 static manifest channels for
backward compatibility. Do not silently change that gate. If asked to make all 26
publication-blocking, treat it as an explicit architecture/product-contract migration and
update workflows, fixtures, docs, and tests together.
```

## Implemented UX

- Canonical findings are cards and the clear hero objects, not table rows.
- Each card states scanner-family agreement and exposes every retained family badge.
- Deduplication is explicit: `N raw observations -> canonicalized -> 1 Issue Wall finding`,
  followed by `N observations consolidated` and `View N source observations`.
- The detail dialog is an Evidence Graph, not a Fix Assistant. It leads with named scanner
  nodes converging on the canonical finding and collapses raw observation fields.
- Evidence provenance is one disclosure away from each finding: snapshot, workflows,
  retained artifact references, matching hash coverage, captured workflow-run links, and
  the normalized evidence download. Per-artifact links are not fabricated.
- Related-finding counts are exposed for same file, concept, primary scanner rule, and
  directory. They filter the existing read-only workspace.
- Issue Wall (“What was found?”) is visually separated from Analysis Operations (“Where
  did this snapshot come from?”).
- Snapshot/analysis health is separated from developer-fixable findings.
- The page has a three-layer journey: Issue discovery -> Issue understanding -> Evidence
  provenance, plus the chain Issue Wall -> canonical finding -> scanner evidence ->
  GitHub workflow/artifact -> source code.
- Analysis Coverage always accounts for all 26 catalogued channels. Missing evidence is
  retained as `NOT_AVAILABLE` instead of disappearing. The primary UI has one channel
  inventory and does not frame ten lanes as “optional controls.”
- Channel roles reconcile exactly to 26:
  - Code quality (7): Ruff, Pyright, ESLint, TypeScript, Radon, Xenon, Vulture.
  - Security (6): Bandit, CodeQL, Gitleaks, Semgrep, Snyk, CodeRabbit.
  - Dependencies (4): OSV-Scanner, Trivy, Shipping Image Trivy, SBOM Policy.
  - Infrastructure (5): Checkov, Hadolint, Repository Security Posture, OpenSSF
    Scorecard, zizmor.
  - Reliability (4): Coverage.py, Schemathesis, Atheris, SonarQube Cloud.
- The Signal / Control Room palette uses exact semantic tokens:
  - background `#070B12`, surface `#0D131D`, elevated `#121B28`, border `#253244`
  - text `#F1F5F9`, muted `#8B9AAF`, cyan `#38D9FF`
  - success `#35D399`, warning `#F5B942`, critical `#FF4D67`
  - high `#FF8A3D`, medium `#F4C95D`, low `#69A7FF`
- Cyan is interaction/evidence flow/snapshot identity; green is verified health or
  corroboration; amber is degraded/incomplete; red is failure/critical. Finding severity
  colors are not decorative accents.

## Files changed

- `scripts/code_analysis/dashboard_template.html` — primary UI and embedded behavior.
- `scripts/code_analysis/snapshot.py` — always emits every non-static catalog channel;
  absent evidence becomes `NOT_AVAILABLE`.
- `scripts/code_analysis/dashboard.py` — GitHub summary and artifact walkthrough use
  unified Analysis Coverage.
- `scripts/code_analysis/test_service.py` — renderer, 26-channel, unavailable-state,
  palette, and interaction regression assertions.
- `docs/code-analysis/MONITORING_UI.md` — current view-only UI contract.
- `Journal.md` — mandatory session and milestone history.

Generated and intentionally untracked:

- `.tmp/issue-wall-preview/` — local benchmark/visual preview. Do not commit it unless a
  repository policy explicitly changes.

## Last verified state

- `python -m unittest scripts.code_analysis.test_service`: **51 tests passed**.
- Both embedded dashboard scripts parsed with Node `vm.Script`.
- `git diff --check`: passed; only CRLF conversion warnings were reported.
- Scale preview: **10,000 findings / 13,000 observations**, 26.04 seconds,
  148.15 MiB peak in the most recent run.
- No commit, push, workflow dispatch, or external publication was performed.

## Architectural constraints

- The dashboard is a static offline artifact and must remain useful in view-only mode.
- GitHub workflow runs and retained artifacts are the evidence authority.
- Exact commit identity, artifact hashes, channel state, observations, and canonical
  findings must not be inferred or fabricated by presentation code.
- `config/code-analysis/required-channels.json` still defines the 16 static channels in
  the fail-closed publishability gate.
- `config/code-analysis/proposal-tool-catalog.json` defines the complete 26-channel
  integrated catalog. `build_additional_channels()` now emits all ten non-static rows.
- Coverage-complete statuses are currently `COMPLETED`, `CONFIGURED_COMPLETE`, and
  `COMPLETED_OPTIONAL`; other statuses remain visible as incomplete/unavailable.
- Existing literal compatibility names and product naming rules in `AGENTS.md` remain
  binding.

## Sensible next steps

1. Visually inspect the preview at desktop and narrow widths, especially the finding-card
   density and five role-coverage tiles.
2. If browser automation is available locally, add interaction checks for related filters,
   Evidence Graph opening, and three-layer journey navigation. Do not add a dependency
   merely for this handoff.
3. Consider consolidating the two embedded scripts and the accumulated CSS override layer
   into maintainable sections in a separate, explicitly scoped refactor. Preserve output
   behavior byte-for-byte where practical and benchmark afterward.
4. Do not make all 26 channels publication-blocking without explicit approval and a full
   workflow/contract migration plan.



## Subsequent session update: unified channel model

This update supersedes the earlier snapshot/UI descriptions in this handoff. The current
uncommitted implementation emits snapshot-v2, with one `analysis_channels` array and
catalog-owned class metadata for all 26 channels. The old published `channel_status` /
`additional_channels` split is removed. `publication_gate` separately records the
unchanged static-evidence-v1 policy. Native status literals remain unchanged.

The page leads with Snapshot health / Observation Health and Risk posture, followed by
Issue discovery and the canonical Issue Wall. Channel Observatory groups by data class;
Workflow Provenance and Snapshot Proof follow it. Missing counts remain null, native
observations belong to exactly one channel, and only completed measured zeros display
0 findings. The visual surfaces are neutral dark observability panels.

The earlier fresh-run exclusivity claim is not implemented: workflow 08 dispatches and
waits for four fresh runs, but workflow 05 reselects successful exact-title runs instead
of receiving those run IDs. Exact-commit validation is unchanged. Do not claim that
handoff is fixed or migrate all 26 channels to publication blocking without a separate
explicit policy change. Read Journal.md for the latest validation results.
