# SecureFlow

**AI can build your application in minutes. SecureFlow helps you inspect what it actually shipped.**
JU Techfest 2026 · CY-02: AI Security Reviewer for Vibe-Coded Websites.

SecureFlow is a security reviewer for AI-generated ("vibe-coded") websites. It has two pages:

- **`index.html`**: the cinematic story (the cloth unveil and the 3D evidence scroll). It has no code input.
- **`app.html`**: the workspace, a separate page with the same branding.

The lifecycle is:

**Import → Scan → AI deep check → Understand → Fix guidance (checked 10×) → Fix → Rescan → Verify → Remember**

The local engine runs in your browser. Two opt-in features need the Cloudflare Worker: **AI deep check** (Google Gemini) and **Codebase memory** (Cloudflare D1). Each one asks for consent first.

## Run it

| What | Command |
|---|---|
| Open directly (local engine only) | double-click `index.html` → **Open the workspace** (or `dist/app.html`) |
| Full app locally (Worker + AI + memory, no Cloudflare login) | put `GEMINI_API_KEY=...` in `.dev.vars`, then `npm run dev` → http://127.0.0.1:8788/app.html |
| **Deploy to Cloudflare** | `npm install`, then `npm run deploy` (see below) |
| CLI / CI scan | `npm run scan -- ./my-app --fail-on=high` |
| Unit, Worker, server and CLI tests (Node ≥ 22.5) | `npm test` |
| Build (`dist/site/` for Cloudflare + single-file `dist/index.html`, `dist/app.html`) | `npm run build` |
| Browser end-to-end tests | `npm install`, `npx playwright install chromium`, then `npm run e2e` and `npm run e2e:dist` |
| Everything | `npm run check` |

## Deploy to Cloudflare (Workers + D1)

```
npm install
npm run deploy
```

`tools/deploy.mjs` runs these steps:
1. Builds `dist/site`.
2. Opens the Cloudflare login in your browser if you are not logged in.
3. Creates the D1 database `secureflow-memory` once and writes its id into `wrangler.toml`.
4. Applies `migrations/`.
5. Deploys the Worker.
6. Uploads configured server secrets from `.dev.vars` as encrypted Worker secrets.

Paid project repair also requires the R2 bucket bound as `PROJECTS`. Create it once before deploying with `npx wrangler r2 bucket create secureflow-projects` (or create a bucket with that name in Cloudflare). The local `npm run dev` server stores project objects under ignored `.dev-data/project-objects`. Do not put source uploads in D1; D1 stores project metadata, scan results, payment/repair state and artifact manifests, while R2 stores the uploaded and repaired source.

Configure `FIREBASE_API_KEY`, `FIREBASE_PROJECT_ID`, and `FIREBASE_AUTH_DOMAIN` for Firebase sign-in and verified-email enforcement. Set `TOKEN_ENC_KEY` to a random value of at least 32 characters. For custom OTP email and alerts, set `RESEND_API_KEY` and a verified `ALERT_FROM` sender. For sandbox checkout, set Cashfree TEST credentials and leave `CASHFREE_ENV=sandbox`. GitHub repository access needs the GitHub OAuth client ID and secret. AI repair generation is not configured in this build: paid repairs use the existing deterministic patch engine, and unsupported findings return `manual_review`.

The key never goes into the site files or git. After deploying, open `https://<your-worker>.workers.dev/api/health`. It should show `"ai": true, "memory": true`.

Model fallback order (`GEMINI_MODELS` in `wrangler.toml`) is `gemini-3.8-flash`, then 3.7, 3.6, 3.5 and finally `gemini-flash-latest`. Busy (503/429) or retired (404) models are skipped automatically. Each network is limited to `RATE_PER_HOUR` units per hour: an analysis costs 6, every other AI call costs 1.

## AI deep check (opt-in)

- **Two passes.** Gemini reviews the masked code: secrets are masked in the browser and again in the Worker. A second Gemini pass then challenges every claim and rejects false positives.
- **Hallucination guard.** Every AI finding must quote a line that really exists near the line it cites. Otherwise it is dropped, and the UI reports how many were dropped. Line numbers are corrected to where the quote really is.
- **Badges.** Findings that match an engine rule are badged **Engine + AI**. New ones are badged **AI**.
- **Per-finding detail:**
  - a **seriousness score out of 10** (exploitability, impact and confidence for AI findings; an estimate from severity and confidence for engine findings);
  - a founder explanation and a developer explanation;
  - potential confidentiality/integrity/availability impact;
  - a **risk chain** from attacker input to impact. Steps seen in your code are solid and clickable; illustrative steps are dashed. A marker shows where a fix breaks the chain, and **Show what the fix changes** greys out the steps after it.
- **Fix guidance, checked 10×.** Round 1 drafts the guidance from your code. Rounds 2–10 each check it for:
  - not fixing the root cause;
  - missed occurrences;
  - wrong APIs;
  - new bugs;
  - bypasses;
  - vague steps.

  Each round revises the guidance. You watch the ladder, and the final guidance appears after round 10. **SecureFlow explains the fix and never writes it for you**: code blocks longer than 4 lines are stripped from every AI answer on the server.
- **Ask SecureFlow.** A per-finding chat about how to fix it, with the same no-rewrite rule.

## Codebase memory (opt-in, Cloudflare D1)

- **What is stored.** No source code. Only:
  - an 8-hex fingerprint per line (SHA-256 of the whitespace-normalised line, salted per project);
  - a 64-value MinHash signature;
  - hashed file paths;
  - finding metadata (title, severity, score, location, short fix directions);
  - per-visit score and counts.
- **Recognition.** You can come back after a reload, or another day. The project counts as the same if at least 50% of lines match, or if at least 60% of file paths match together with at least 15% of lines (small projects change a lot when fixed). Reading, updating or deleting a record needs a matching signature, which means you need the code itself.
- **Checking each earlier finding:**
  - The flagged line is still there (its fingerprint and context match): **still to fix**.
  - The line was reworded but the same engine rule still flags it: **still to fix**.
  - The line changed: with AI on, Gemini double-checks the current code (fixed, not fixed, partly fixed, can't tell). Without AI it is reported as **changed, not confirmed**, never as "fixed".
- **Results:**
  - When everything is verified: an **OK report**. Otherwise, the list of fixes still to do, with their directions.
  - A **security timeline across visits** and a downloadable fix-verification report.
  - **Forget this codebase** deletes the record.

## The workspace

A compact app shell with a sidebar. Every section shown is implemented.

- **Overview.** Onboarding (demo, upload, paste). After a scan you get the completion summary: severity counts, verdict, risk gauge, coverage (what was analysed, excluded or failed, and what is never checked), a **risk map** of your files grouped by layer with only *real* relative-import edges drawn, the top priorities (P1–P4) and one next action.
- **Source.** Folder, files, `.zip`, paste, drag-and-drop, demo. Replace / Add / Cancel when a project exists; clashing paths ask Keep / Replace / Rename / Cancel. An editor with line highlight for *Show in source*.
- **Findings.** Filterable list plus a detail panel: masked evidence, an explainer flow where only the first step is marked *Observed in your code* and the rest *Illustrative*, potential impact on confidentiality / integrity / availability (no invented money figures or probabilities), what could change the result, fix, regression test, detection limits, references (OWASP / CWE / MDN). You can copy a repair prompt, select several for a combined prompt, or mark a false positive with a reason (session only, excluded from the score).
- **Fix Studio.** For 18 rule types SecureFlow proposes a **deterministic** patch (fixed rewrite rules, no AI). You see a diff, can edit the replacement lines, and the patch is validated against the current file before it applies. Accept changes only the in-memory copy; every patch can be undone (in order). Rules that need human context are *prompt only*. After patching, rescan.
- **ProofLoop.** Compares the baseline scan with the latest, finding by finding: *Still detected · No longer detected · Newly detected · Not rechecked · Inconclusive · Verified by test*. It shows the score change with reasons, before/after evidence and the patch diff. **Tests executed: none.** SecureFlow never runs your code, so "No longer detected" is never called "fixed". A session timeline lists imports, scans, patches and warnings.
- **Readiness.** Production-readiness checks (secrets, injection, XSS, auth, transport, headers, debug, dependency checks, and so on). Each check says whether it ran. Overall result: *Fix Before Deployment / Assessment Incomplete / Ready for Review*, never "secure". Also a **business-logic test builder**: manual test specs (IDOR, price tampering, role escalation…), labelled as suggestions, copyable as Markdown.
- **Reports.** Founder-friendly summary. Export **HTML** (self-contained, fully escaped, own CSP, no scripts), **Markdown** or **JSON**, or copy the Markdown. Secrets are masked everywhere.
- **Trust Center.** What is checked, what is not, this session's numbers, and a table of exactly what leaves the browser in each workflow.

### Risk score

Each open (not dismissed) finding gets a weight `w = severity weight × confidence factor`. The severity weights are critical 0.35, high 0.20, medium 0.10, low 0.03 and info 0. The confidence factors are high 1, medium 0.75 and low 0.5.

`score = round(100 × (1 − Π(1 − w)))`

The score rises with every finding, has diminishing returns and never exceeds 100. It is a triage indicator, not a security rating. ProofLoop lists which findings moved it.

## Paid repair (₹699) with Cashfree, test mode

**Scope:** one selected finding, or one small change in one file. Deliverables and exclusions come from the server (`OFFERS` in `worker/pay.js`). **This build has no staffed repair team.** It promises no turnaround and has no refund policy configured, so requests stop at **Submitted**, and the UI marks the later states as unavailable. Do not take real money until those exist.

**How it works** (all in the Cloudflare Worker, stored in D1):
1. The user ticks consent. A JSON preview shows exactly what will be sent: finding metadata, plus masked evidence only if they opt in. Source code is never sent.
2. The Worker creates the request and returns a one-time access token. The token lives only in browser memory; the database stores its SHA-256 hash.
3. The Worker creates the Cashfree order (`POST /pg/orders`, API version `2023-08-01`). **The price comes only from the server**: ₹699 INR. A client-sent amount is ignored. Each request gets one order, which is reused on retries.
4. Cashfree's hosted checkout opens as a modal (`sdk.cashfree.com/js/v3`). Card and UPI details go only to Cashfree.
5. Whatever the browser reports, the Worker asks Cashfree directly: `GET /pg/orders/{id}` must be `PAID`, and `GET /pg/orders/{id}/payments` must contain a `SUCCESS` payment of exactly ₹699 INR. Only then does the request become *Submitted*. That happens once; repeat confirmations are ignored.
6. The webhook is `POST /api/webhooks/cashfree`. The Worker verifies `x-webhook-signature` = base64(HMAC-SHA256(timestamp + raw body, secret)), refuses timestamps older than 15 minutes, and drops duplicate deliveries. A success event is re-checked with Cashfree before it counts. Failure and user-dropped events mark the request *payment failed*.

**Setup**
1. In the Cashfree Merchant Dashboard (Test mode), go to Developers → API Keys. Put the App ID and Secret Key in `.dev.vars` as `CASHFREE_APP_ID` and `CASHFREE_SECRET_KEY`. Test App IDs start with `TEST`.
2. `npm run deploy` uploads them as encrypted Worker secrets.
3. In Cashfree, go to Developers → Webhooks and add `https://<your-worker>.workers.dev/api/webhooks/cashfree` for payment success, failed and user-dropped events. Orders created from an `https://` origin also send this URL as `notify_url` automatically.
4. Pay with Cashfree's sandbox test cards or UPI IDs.

`CASHFREE_ENV=production` is refused unless `ALLOW_LIVE_PAYMENTS=I_HAVE_OWNER_APPROVAL`. Production also needs a real customer phone number. Do not switch to production without owner approval, staffing, terms, a refund policy and a successful end-to-end test.

## CLI / CI

```
node tools/secureflow-cli.mjs <dir> [--fail-on=critical|high|medium|low|info|none] [--min-confidence=low|medium|high] [--format=text|json] [--strict]
```
Exit codes: `0` no findings at or above the threshold · `1` findings at or above it · `2` usage error or nothing analysable · `3` `--strict` and coverage incomplete. It reads files only, never executes project code and makes no network requests. GitHub Actions example:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 22 }
- run: node tools/secureflow-cli.mjs . --fail-on=high --format=text
```

## Privacy

- By default, code is processed **only in this tab**: the main thread plus a Blob-backed Web Worker. It is sent nowhere unless you switch on **AI deep check**. Then masked code goes to the SecureFlow Worker and on to the Google Gemini API, for that request only; it is never stored or logged. The landing page CSP sets `connect-src 'none'`; the workspace allows only `'self'`. The browser never contacts Google's AI API directly, and the key stays a server-side secret.
- Nothing is written to `localStorage`, `sessionStorage`, IndexedDB, Cache Storage or cookies. That includes the paid-repair access token. **Clear project & data** removes files, results, patches, history and repair state from the page. JavaScript cannot guarantee that memory is physically wiped.
- Secrets are masked in all output: evidence, prompts, diffs, exports, the paid-repair payload (masked again server-side) and the 3D slab.
- The workspace CSP allows `'self'` plus Cashfree's checkout script, its API calls and its payment frame (`*.cashfree.com`), nothing else. Repair requests live in D1. They hold no source code and no payment details.

## Files

(see also `worker/index.js`: Cloudflare Worker API · `src/ai.js`: AI + memory UI · `migrations/`: D1 schema · `tools/dev-server.mjs`, `tools/deploy.mjs`)

```
index.html               markup, styles, story copy, demo project, 3D stage
src/engine.js            scanner, masking, ProofLoop, patches, diff, readiness, reports, ZIP reader (browser + Node)
src/app.js               scroll story + workspace app shell
src/cloth.js             cloth physics for the hero cover
worker/pay.js            Cashfree paid-repair API (orders, server-side verification, signed webhooks)
tests/pay.test.mjs       Cashfree payment tests with a mocked gateway
tests/worker.test.mjs    Worker API tests (AI, memory, rate limits) with mocked Gemini
tools/secureflow-cli.mjs CLI for CI
tools/build.mjs          inlines src/*.js → dist/index.html
tests/engine.test.mjs    engine unit tests
tests/cli.test.mjs       CLI exit-code tests
tests/e2e.mjs            Playwright tests (UI flows, edge cases, Fix Studio, payment UI with a mocked Cashfree gateway and stub checkout)
.env.example             server configuration template (no real values)
```

## Deploying

- **Static only (no payments):** upload `dist/index.html` to Netlify, Vercel, GitHub Pages or Cloudflare Pages. No secrets are needed. If you can set headers, add the CSP from the meta tag, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `frame-ancestors 'none'`.
- **With paid repair (test mode):** run `server/server.mjs` on a Node host (Render, Railway, Fly, a VM) behind HTTPS. Set the env vars from `.env.example` and give it a persistent disk for `server/data/`. Then register the webhook.

**Deploy checklist**
1. `npm run check` passes.
2. Keys are `rzp_test_`.
3. `.env` is not committed.
4. The webhook is registered and its secret is set.
5. HTTPS is on.
6. A test-mode payment end-to-end reaches *Submitted* on the server.
7. The webhook delivery shows 200 in the dashboard.

Before going live you also need owner approval, staffing, terms, a refund policy and a real database.

## Limitations (stated in the app too)

- Pattern rules over lines and short statements. No cross-file data flow, framework-aware authorisation analysis, business-logic review or runtime testing.
- No dependency (CVE) checks: none are claimed.
- Patches are deterministic rewrites of single statements. A clean rescan means the pattern no longer matches, not that the vulnerability is gone.
- *Verified by test* appears only when an executed passing test result is supplied; the app never runs code.
- The 3D story loads three.js 0.160.0 from jsDelivr. For an offline deployment, vendor `three.module.js` and update the import map.
- The paid flow has been tested against a mocked Cashfree API only. No real sandbox transaction has been run from this build yet.
