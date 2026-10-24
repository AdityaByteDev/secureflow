# SecureFlow: handoff prompt for the next agent

Copy everything below the line into the new agent, and attach or point it to this project folder.

---

You are continuing work on **SecureFlow**, a security reviewer for AI-generated websites (JU Techfest 2026, CY-02). The project folder is `C:\Users\rajad\Desktop\hackathon techfest\secureflow-web`. Read `README.md`, then this file, before changing anything.

## Ground rules (from the owner; do not break them)
- Never invent findings, test results, payment confirmations, push results, emails sent or deployment status. Never say "fixed" just because a rule stopped matching; use STILL DETECTED / NO LONGER DETECTED / NEW FINDING / NOT RECHECKED / INCONCLUSIVE / VERIFIED BY TEST (the last one only when a relevant test actually ran and passed).
- Secrets live only in `.dev.vars` (git-ignored) and as Cloudflare Worker secrets. They must never go into browser code, git, logs or the database in plaintext. GitHub tokens are stored AES-GCM encrypted (`TOKEN_ENC_KEY`).
- **Payments use Cashfree, not Razorpay**, in sandbox/test mode. The price is set only on the server. Access is granted only after the server itself asks Cashfree that the order is PAID for the exact amount. Webhooks must be signature-verified and deduplicated. Production mode is refused unless `ALLOW_LIVE_PAYMENTS=I_HAVE_OWNER_APPROVAL`.
- Source code goes to Gemini only after explicit consent. It is masked first, and the scanner never executes repository code.
- Push only after explicit user approval of a reviewed diff. Never force-push or auto-merge. Prefer a fix branch plus a pull request. Abort if the branch moved and touched the patched file.
- Keep the visual identity: dark brass/crimson theme, `src/site.css` tokens, Archivo / Instrument Serif / JetBrains Mono.
- Run the tests after every change: `npm test`, `npm run build`, `npm run e2e`, `npm run e2e:dist`. All must pass. Don't claim a test passed unless you ran it.

## What exists and works (tests pass: 159 unit/Worker/payment/CLI tests and 35 browser tests, as of the last run)
- `index.html` + `src/story.js` + `src/common.js` + `src/demo.js`: the landing page, a cinematic 3D story (three.js from jsDelivr; the cloth is in `src/cloth.js`). It has no code input; its links go to `app.html`.
- `app.html` + `src/workspace.js` + `src/ai.js`: the local workspace.
  - The engine scan (`src/engine.js`, 32 rules) runs in a Web Worker.
  - Overview, Findings, Fix Studio (deterministic patches), ProofLoop, Readiness, Reports, Trust.
  - **AI deep check** (opt-in, through the Worker to Gemini): two passes plus a hallucination guard; per-finding seriousness score, risk chain, fix guidance checked over 10 rounds, and an Ask chat.
  - **Codebase memory** (opt-in, D1 line fingerprints): recognises a returning project and verifies which fixes were made.
  - **₹699 paid repair** with Cashfree test checkout (`sdk.cashfree.com/js/v3`).
- `worker/index.js` is the router: AI (`/api/ai/*`), memory (`/api/memory/*`), payments (`/api/pay/config`, `/api/repair-requests*`, `/api/webhooks/cashfree`) and static assets.
  - `worker/core.js`: shared helpers (HttpError, json, masking, the Gemini client with model fallback, rate limits).
  - `worker/pay.js`: Cashfree (PG API `2023-08-01`; orders, server-side verification, HMAC webhooks).
- `migrations/0001_init.sql` (memory) and `0002_payments.sql` (repair requests, payment events).
- `tools/dev-server.mjs`: runs the Worker in Node with SQLite standing in for D1. `npm run dev` serves http://127.0.0.1:8788/app.html.
- `tools/deploy.mjs`: `npm run deploy` builds, logs in to Cloudflare, creates the D1 database `secureflow-memory`, applies the migrations, deploys and uploads the secrets. `tools/build.mjs` writes `dist/site` (for the Worker) and single-file `dist/*.html`.
- `tools/secureflow-cli.mjs`: CLI for CI with exit codes.
- Tests: `tests/engine.test.mjs`, `tests/worker.test.mjs`, `tests/pay.test.mjs`, `tests/cli.test.mjs`, `tests/e2e.mjs` (Playwright, all external services mocked).
- The old `server/` folder (Razorpay) is obsolete. Delete it.

## Started but NOT finished (continue from here)
The owner wants the full "ULTIMATE PREMIUM PLATFORM" spec built with **Cashfree instead of Razorpay**. Already written:
- `migrations/0003_platform.sql`: tables for customers, github_connections, oauth_states, repos, scans, scan_files, findings, finding_history, patches, push_ops, test_results, gh_events, deployments, subscriptions, billing_orders, usage, email_log and audit. It is not yet applied or tested.
- `worker/github.js`, a GitHub **OAuth App** module (syntax-checked only, not wired up or tested yet). It contains:
  - OAuth: authorize URL (scopes `read:user public_repo admin:repo_hook`, or `read:user repo` for private repos), code exchange, grant revoke;
  - AES-GCM token encryption;
  - a REST client with rate-limit and error mapping;
  - `authorizedRepo` (checks access through the user's own token);
  - repo listing and branch head;
  - bounded tarball download, gunzip and untar, then `E.validateIncoming`;
  - `fileAt`;
  - `pushCommit` (blob → tree, keeping the file mode → commit; fix branch + PR, or fast-forward-only direct push);
  - `changedBetween`;
  - webhook signature verification, hook create/delete, and CI results from check-runs and statuses.

### Still to build, in this order
1. **`worker/platform.js` + router wiring.** Give `handleApi` a `ctx` parameter. The default export needs `fetch(req, env, ctx)`, plus `queue()` and `scheduled()`.
   - **Firebase ID token verification.** RS256 against the JWKS at `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com`. Check `aud` = `FIREBASE_PROJECT_ID`, `iss` = `https://securetoken.google.com/<id>`, `exp`, `iat`, `auth_time` and `sub`. Require `email_verified` for every protected route except `GET /api/me` and `DELETE /api/me`. Upsert the customer by UID and never trust a UID sent by the client.
   - **`GET /api/public-config`** returns the Firebase apiKey, projectId and authDomain, plus which features are configured.
   - **GitHub connect.**
     - `POST /api/github/connect` stores the state hash with the UID and a 10-minute expiry, and returns the authorize URL.
     - `GET /api/github/callback` checks the state (one-time use), exchanges the code, gets `/user`, stores the encrypted token, then redirects to `/dashboard.html#github=connected`.
     - `DELETE /api/github` revokes the grant, deletes hooks and marks repos disconnected.
   - **Repos.**
     - `GET /api/github/repos` lists the repos the user can access.
     - `POST /api/repos {ghRepoId, branch, monitor}`: verify access through the user's token, check the plan's repo limit, then create the webhook. If you lack admin rights or the public URL is not https, fall back to polling from cron.
     - `DELETE /api/repos/:id` stops monitoring that repo.
   - **Scans.**
     - `POST /api/repos/:id/scan` creates a scan row. Run it from `env.SCAN_QUEUE`, or with `ctx.waitUntil` if there is no queue.
     - `runScan` does tarball → `E.scanProject` → stores `scan_files` (salted fnv line hashes) and findings with masked evidence and key = hash(rule|fp) → compares with the parent or previous scan → updates `finding_history` (including reappeared) → fetches CI results → sends alerts.
     - Listing and detail endpoints, all checked for ownership.
   - **ProofLoop.** `GET /api/proofloop?from=&to=` (same repo, owned) returns the statuses above, plus the commits, the patch diff, the CI tests and the remaining risk. VERIFIED BY TEST only applies when the user has mapped a CI check name to a finding key (`finding_history.test_check`) and that check succeeded on the new commit.
   - **AI fix.** `POST /api/patches {scanId, findingId}`:
     - Check the plan's monthly AI fix limit.
     - Fetch the file at the scan commit, mask it and send it to Gemini. The schema has summary, edits[{file,startLine,endLine,original[],replacement[]}], explanation, assumptions, sideEffects, regressionTests, limitations and confidence.
     - Validate: the file must be the finding's file; `original` must equal the masked lines; reject any replacement that contains a secret (where `E.mask(line) !== line`) or `••••`; limit the size.
     - Checks (all honest): applies cleanly; secret scan; rescan of the patched file (is the target still detected? any new findings?); a JSON parse or bracket-balance sanity check labelled as not a compiler. Tests are not run by SecureFlow.
     - Store the diff with `E.diffLines` (masked).
     - `PATCH /api/patches/:id` with accept / reject / undo / edit (edit re-validates); regenerate creates a new proposal.
   - **Push.** `POST /api/patches/:id/push {mode:'pr'|'direct', targetBranch, confirm:true}`:
     - The patch must be accepted. Prevent duplicates.
     - Re-check `authorizedRepo(...,'push')`. If the head moved, `changedBetween` must not include the file; otherwise return 409 `stale_patch`.
     - Re-apply the patch to the file at the head and verify the originals again.
     - Call `pushCommit`. Store the commit SHA, the commit URL and the PR URL, then queue a `push_rescan` of the new commit with `parent_scan_id` set to the original scan.
   - **GitHub webhook.** `POST /api/webhooks/github` verifies the signature and deduplicates on `X-GitHub-Delivery` (`gh_events`).
     - `push` to a monitored branch queues a scan; ignore all-zero SHAs.
     - `check_run` and `status` go to `test_results`.
     - `deployment_status` goes to `deployments` (kept separate from pushes).
     - `meta` (hook deleted) switches the repo to polling and sends a monitoring alert.
   - **Billing (Cashfree).**
     - PLANS: free = 1 repo, 3 AI fixes/month, alerts for new_high + monitoring + scan_failed, 14-day history. pro = ₹499 for a 30-day pass (no auto-renew), 10 repos, 100 AI fixes, all alerts, 180-day history, direct push allowed.
     - `GET /api/billing`, `POST /api/billing/checkout {plan, phone}`, `POST /api/billing/verify {orderId}` (activates or extends only after Cashfree says PAID for the exact amount; idempotent through `billing_orders.applied`), and `POST /api/billing/cancel` (access continues until the period ends).
     - In `pay.js`, route unknown webhook order IDs to the billing order lookup.
   - **Alerts.** Resend (`RESEND_API_KEY`, `ALERT_FROM`) with per-user preferences, at most 10 emails an hour, and every attempt logged in `email_log` as sent / failed / not_configured. No code in emails. Include a link to `/dashboard.html#repo=<id>`.
   - **Reports.** `GET /api/scans/:id/report?format=json|md|html` (owner only, masked). Include repo identity, commit, date, coverage, findings, remediation, applied patches, comparison, CI tests, remaining issues, unsupported checks and limitations.
   - **Account.** `GET`/`PATCH /api/me` (name and alert preferences) and `DELETE /api/me` (revoke GitHub, delete hooks and all rows). The client deletes the Firebase user through REST `accounts:delete`.
   - **Cron** (`scheduled`): poll the heads of polling repos, apply retention per plan, expire subscriptions, clean up oauth_states and rate rows.
2. **`dashboard.html` + `src/dashboard.js`** in the same theme, reusing the `.app` shell classes.
   - **Firebase Auth through its REST API** (identitytoolkit `accounts:signUp`, `signInWithPassword`, `update` for displayName, `sendOobCode` VERIFY_EMAIL / PASSWORD_RESET, `lookup`, `delete`; securetoken `token` refresh). Keep only the refresh token in localStorage and note that in the Trust section.
   - **Views:** Overview, Repositories (connect GitHub, choose public/private scope, pick a branch, monitor), Scans/history, Findings explorer, Fix Studio (diff, accept/reject/edit/regenerate/undo, checks, push panel showing the exact repo, branch and files, plus a confirm checkbox; then the commit SHA and URL), ProofLoop, Pushes, Reports, Billing (Cashfree checkout), Monitoring & alerts, Account (delete, disconnect, sign out).
   - **CSP:** add `identitytoolkit.googleapis.com`, `securetoken.googleapis.com`, `*.cashfree.com`, `sdk.cashfree.com` and `avatars.githubusercontent.com`. Update `tools/build.mjs` (_headers and the site file list) and `tools/dev-server.mjs` (static regex + CSP, pass a `ctx` with `waitUntil`).
   - Add a "Dashboard" link to the nav on `index.html` and `app.html`.
3. **Tests.** Write `tests/platform.test.mjs`, which mocks Firebase JWKS (sign test tokens with a generated RSA key), GitHub (a stateful fake for refs, contents, git data, pulls, compare and tarball built with zlib), Gemini, Cashfree and Resend. Cover every case in the spec's section 16: invalid OAuth state, unauthorized repo, stale head, conflicts, rate limits, duplicate webhooks, secret in patch, unverified email, expired token, cross-customer access, wrong payment amount, and so on. Extend `tests/e2e.mjs` with the full dashboard journey. Clearly label these as mock-based, not real integrations.
4. **Deploy.**
   - `wrangler.toml`:
     - vars `FIREBASE_PROJECT_ID`, `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `GITHUB_CLIENT_ID`, `PUBLIC_URL`, `ALERT_FROM`;
     - a `[[queues.producers]]`/`[[queues.consumers]]` queue `secureflow-scans`, with the code falling back to `waitUntil` if there is no queue;
     - `[triggers] crons = ["*/30 * * * *"]`.
   - `tools/deploy.mjs`:
     - generate `TOKEN_ENC_KEY` (32 random bytes, base64) and `GITHUB_WEBHOOK_SECRET` into `.dev.vars` if they are empty;
     - upload the secrets `GITHUB_CLIENT_SECRET`, `TOKEN_ENC_KEY`, `GITHUB_WEBHOOK_SECRET`, `RESEND_API_KEY`, `GEMINI_API_KEY`, `CASHFREE_APP_ID` and `CASHFREE_SECRET_KEY`;
     - create the queue (if that fails, remove the queue config and print why).
   - Repository scans are CPU-heavy. The Workers **Free plan allows 10 ms CPU per request**, so real repo scans need Workers Paid (`[limits] cpu_ms`). Document this.
   - The owner runs `npm install` then `npm run deploy` in PowerShell, or signs in to Cloudflare in the browser pane. The agent cannot enter passwords.
   - After deploying:
     - set the GitHub OAuth App's **Authorization callback URL** to `https://<worker>.workers.dev/api/github/callback`;
     - in Firebase, enable Email/Password sign-in and add the workers.dev domain to Authorized domains;
     - in Cashfree, add the webhook `https://<worker>.workers.dev/api/webhooks/cashfree`;
     - check `/api/health` and `/api/public-config`.

## Credentials (already in `.dev.vars` on the owner's PC; never print or commit them)
Gemini API key, Cashfree TEST App ID + Secret, Firebase web config (project `hackfest-ju`), GitHub OAuth App client ID `Ov23limMkWB5AvchAZYj` + client secret. Missing: Resend API key and sender (email alerts stay "not configured" until they're added). All of these were shared in chat, so the owner should regenerate them after launch.

## Final report to the owner
Cover: architecture changes, features, what was tested with real integrations vs mocks, test counts, build status, configuration for GitHub / Firebase / Cloudflare / Cashfree, environment variables, blockers, limitations and the exact commands to run. Be honest about anything that wasn't verified live.
