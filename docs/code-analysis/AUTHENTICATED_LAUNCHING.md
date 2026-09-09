---
title: Authenticated analysis launching
description: Configure GitHub sign-in and direct source analysis from the public dashboard.
---

# Authenticated analysis launching

The public dashboard remains on GitHub Pages. Direct launching adds a small Cloudflare
Worker in `analysis-launcher/`; analysis still runs in GitHub Actions. The Worker
does not store reports, run scanners, or execute source-controlled scripts.

Developer flow:

1. Open **Run analysis** and sign in with GitHub.
2. Select the configured codebase and a live branch, open PR, PR number, or full commit SHA.
3. Select **Start analysis**. The Worker verifies access and the source revision, then
   dispatches discovery workflow 10 on the analysis fork's current default branch.
4. Follow the returned request link. Discovery resolves the source again and queues
   exact-source workflow 11 through the existing two-analysis limit.
5. The dashboard polls published results every minute. The publisher runs about every
   ten minutes; a submitted request is not proof that scanners completed.

An instance has one administrator-configured source/profile/analysis host. Repository
selection does not grant permission to scan arbitrary repositories or change scanner
commands. Use the [integration guide](INTEGRATIONS.md) to wire another instance.

## Administrator setup

Direct launching is disabled while `launch_endpoint` in `config/code-analysis/service.json`
is null. The GitHub Actions handoff remains usable. The endpoint is public configuration;
no credentials belong in that file.

The current Kavach instance uses
`https://code-analysis-launcher.icsarthak9.workers.dev`. Its private GitHub App is
installed only on `combustrrr/Agentic-Kibana`; viewing reports remains public.

1. In your Cloudflare account, enable Workers and choose the Worker URL. Set the
   non-secret repository identifiers and dashboard origin in
   `analysis-launcher/wrangler.jsonc`. Use a separate Worker/configuration for another
   codebase. `DASHBOARD_ORIGIN` is the origin only, such as `https://combustrrr.github.io`.
2. [Register a GitHub App](https://github.com/settings/apps/new). Set its homepage to
   the dashboard URL and its callback URL to `https://YOUR-WORKER/auth/callback`.
   Disable webhooks. Request repository **Actions: read and write**, **Contents: read**,
   **Pull requests: read**, and the mandatory **Metadata: read**. Request no content
   writing, organization administration, or publishing permissions.

   The bundled manifest helper performs this registration without printing or saving
   the returned client secret. It opens GitHub for approval, writes the non-secret
   client ID to Wrangler configuration, stores the secret directly in Cloudflare, and
   opens the installation page:

   ```shell
   python register_github_app.py \
     --worker-origin https://YOUR-WORKER.workers.dev \
     --dashboard-url https://OWNER.github.io/code-analysis-dashboard/
   ```
3. Install the App only on the analysis fork. Copy its client ID into the Worker vars
   and generate a client secret. Keep expiring user tokens enabled.
4. From `analysis-launcher/`, configure Worker secrets using Wrangler's interactive
   secret input, then deploy:

   ```shell
   npx wrangler@4.129.1 secret put GITHUB_CLIENT_SECRET
   npx wrangler@4.129.1 secret put SESSION_KEY
   npx wrangler@4.129.1 deploy
   ```

   `SESSION_KEY` must be 32 cryptographically random bytes encoded as base64url. Supply
   it through the secret prompt; do not commit it, put it in command arguments, or send
   it in chat. Cloudflare account access and the App registration are required external
   setup. Deployment has not been established merely by passing the local tests.
5. Set `launch_endpoint` to the HTTPS Worker origin, synchronize the configuration to
   the host and publisher, and publish the dashboard. Do not point it at a different
   instance: the UI rejects repository/host mismatches from live target discovery.
6. Verify a permitted developer can sign in and launch a branch and PR; a read-only
   user must receive an access error. Confirm the returned discovery run, exact-source
   producer, scanner evidence, and published SHA. Vendor scanner blockers remain
   independent of launcher authentication.

Use the existing Cloudflare account's applicable Workers plan; this change does not
purchase a plan or create a database, KV namespace, or report-storage service.

## Authentication and execution boundaries

GitHub App user access tokens are limited by both the App's permissions and the user's
access. The Worker rechecks write access to the configured analysis repository on every
API call and always chooses that repository's current default workflow branch. It
verifies the selected source via fixed GitHub API routes before dispatching. Caller-
supplied host repositories, tooling revisions, commands, or workflow names are ignored.

OAuth uses a short-lived encrypted state cookie, state comparison, and PKCE. The
callback posts an encrypted, expiring session to the exact dashboard origin. The UI
checks the popup source and a random login nonce. GitHub user tokens and the App client
secret never appear in page source or local storage. The opaque session is kept in
memory only, expires within one hour, and is cleared on sign-out or reload. Sign-out
clears this browser's session; revoke the App authorization in GitHub to revoke access
globally. Rotating `SESSION_KEY` invalidates all launcher sessions.

API requests require the exact dashboard Origin and a bearer session; they do not use
cross-site authentication cookies. Error responses omit provider bodies and tokens.
Authenticated developers retain GitHub's own workflow privileges; this service does
not grant public visitors dispatch credentials. Public Pages projects on the same
account share an origin, so those projects must be trusted or the dashboard should use
its own custom-domain origin.

The UI prevents duplicate clicks while submitting and never automatically retries a
dispatch with an uncertain response. Check Actions before retrying a failed network
request. GitHub's workflow concurrency rules still apply to simultaneous discovery
requests; the Worker is not a durable multi-user request queue. A successful dispatch
receipt does not guarantee that a pending discovery run was not subsequently canceled.

Current-only retention is unchanged: one latest report per active branch/open PR,
plus one replaceable manual target. At the 900 MB deployment threshold, publication
fails and the previous website remains; scanner execution remains independent.

## Verification

```shell
node --test analysis-launcher/worker.test.mjs
python -m unittest scripts.code_analysis.test_hosted
cd analysis-ui
npm run build
npm test
```

Worker tests cover session tampering/expiry, OAuth state and PKCE, cross-origin and
read-only rejection, exact configured dispatch routing, target pagination, fork PR
attribution, malformed selections, and provider failures. Browser tests mock the OAuth
popup and API to verify the launch interaction; they do not replace live App acceptance.

Protocol references: [GitHub App user authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app),
[Cloudflare Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/).
## Developer launch wizard and current storage

The launch wizard has four stages: Project, Revision, Review, and Results. Sign in
with GitHub on the project step, then choose a branch, PR number, or full
40-character commit SHA. Selections survive sign-in and back navigation. Review
the repository and revision policy before submitting. A branch or PR resolves
against fresh GitHub discovery when the workflow processes the request; a commit
stays pinned to the entered SHA. Manual submission requests fresh scanner execution
even when the same revision already has a report.

After submission, select **View results on dashboard**. The request banner remains
visible while published inventory refreshes every minute. Existing output does not
count as a new result: the banner compares the report reference with the one present
at submission. New output is labeled as a report for the selected target, not proof
that a specific request completed; use the linked request and producing runs for
that provenance. Publication runs about every ten minutes. Closing the banner or
reloading the page clears this local request tracker; GitHub retains the run.

The storage disclosure describes the currently published collection. It is not a
history of every scan. Current reports remain per active branch and open PR, with
one manual commit or closed-PR selection. After a successful deployment, cleanup
deletes unreferenced managed report assets and preserves referenced or unrelated
assets. There is no browser flush operation: clearing active reports would remove
useful output and does not make a scan fresher. If the current collection exceeds
the configured capacity, publication fails and retains the last working site.
