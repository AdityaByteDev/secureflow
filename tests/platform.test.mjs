// Platform tests: Firebase Auth, GitHub connection & monitoring, scanning,
// ProofLoop verification, AI fixes, Git push, Cashfree billing, alerts, and cron.
// All external services (Firebase, GitHub, Gemini, Cashfree, Resend) are mocked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { handleApi } from '../worker/index.js';
import { d1 } from '../tools/dev-server.mjs';
import { handleScheduled, runScan } from '../worker/platform.js';
import { encrypt, decrypt } from '../worker/github.js';

const te = new TextEncoder();
const b64Url = u8 => btoa(String.fromCharCode(...new Uint8Array(u8))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Generate real RSA key pair for testing Firebase RS256 token verification
const rsaKey = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify']
);
const rsaJwk = await crypto.subtle.exportKey('jwk', rsaKey.publicKey);
rsaJwk.kid = 'test-kid-1';

async function makeToken({ uid = 'user-123', email = 'user@example.com', email_verified = true, name = 'Test User', expOffset = 3600, iatOffset = 0, aud = 'hackfest-ju', iss = 'https://securetoken.google.com/hackfest-ju' } = {}) {
  const header = { alg: 'RS256', kid: 'test-kid-1', typ: 'JWT' };
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    sub: uid,
    email,
    email_verified,
    name,
    aud,
    iss,
    iat: nowSec + iatOffset,
    exp: nowSec + expOffset,
    auth_time: nowSec
  };
  const hB64 = b64Url(te.encode(JSON.stringify(header)));
  const pB64 = b64Url(te.encode(JSON.stringify(payload)));
  const data = te.encode(hB64 + '.' + pB64);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', rsaKey.privateKey, data);
  return hB64 + '.' + pB64 + '.' + b64Url(sig);
}

// Minimal tarball creation for fetchRepoFiles mock
function makeTarGz(files) {
  // Simple uncompressed tar block generator
  const blocks = [];
  for (const f of files) {
    const header = new Uint8Array(512);
    const te = new TextEncoder();
    const fullName = f.name.includes('/') ? f.name : 'repo-root/' + f.name;
    header.set(te.encode(fullName), 0); // name
    header.set(te.encode('0000644\0'), 100); // mode
    header.set(te.encode('0000000\0'), 108); // uid
    header.set(te.encode('0000000\0'), 116); // gid
    const sizeOct = f.code.length.toString(8).padStart(11, '0') + '\0';
    header.set(te.encode(sizeOct), 124); // size
    header.set(te.encode('00000000000\0'), 136); // mtime
    header.set(te.encode('0'), 156); // typeflag (normal file)
    // checksum
    header.set(te.encode('        '), 148);
    let chk = 0;
    for (let i = 0; i < 512; i++) chk += header[i];
    const chkOct = chk.toString(8).padStart(6, '0') + '\0 ';
    header.set(te.encode(chkOct), 148);

    blocks.push(header);
    const content = te.encode(f.code);
    blocks.push(content);
    const pad = 512 - (content.length % 512);
    if (pad > 0 && pad < 512) blocks.push(new Uint8Array(pad));
  }
  blocks.push(new Uint8Array(1024)); // 2 empty blocks
  let total = 0;
  for (const b of blocks) total += b.length;
  const tar = new Uint8Array(total);
  let off = 0;
  for (const b of blocks) { tar.set(b, off); off += b.length; }
  return tar;
}

function mockFetch(handler) {
  return async (url, opts = {}) => {
    return handler(String(url), opts);
  };
}

function testEnv(over = {}) {
  const encKeyBytes = new Uint8Array(32).fill(7);
  const tokenEncKey = btoa(String.fromCharCode(...encKeyBytes));
  const projectObjects = new Map();
  const projectBucket = {
    async put(key, value) { projectObjects.set(key, Buffer.from(value)); },
    async get(key) { const b = projectObjects.get(key); return b ? { text: async () => b.toString('utf8') } : null; },
    async delete(key) { projectObjects.delete(key); }
  };
  const baseEnv = {
    FIREBASE_PROJECT_ID: 'hackfest-ju',
    FIREBASE_API_KEY: 'test-firebase-key',
    FIREBASE_AUTH_DOMAIN: 'hackfest-ju.firebaseapp.com',
    FIREBASE_JWKS: { keys: [rsaJwk] },
    GITHUB_CLIENT_ID: 'test-gh-client-id',
    GITHUB_CLIENT_SECRET: 'test-gh-client-secret',
    GITHUB_WEBHOOK_SECRET: 'test-webhook-secret',
    TOKEN_ENC_KEY: tokenEncKey,
    GEMINI_API_KEY: 'test-gemini-key',
    CASHFREE_APP_ID: 'TEST12345',
    CASHFREE_SECRET_KEY: 'test-cf-secret',
    CASHFREE_ENV: 'sandbox',
    PUBLIC_URL: 'https://sf.test',
    ALERT_FROM: 'security@sf.test',
    RESEND_API_KEY: 'test-resend-key',
    DB: d1(':memory:'),
    PROJECTS: projectBucket,
    fetch: async (url, opts) => {
      if (over.fetch) return over.fetch(url, opts);
      return new Response(JSON.stringify({}), { status: 200 });
    }
  };
  return Object.assign(baseEnv, over);
}

const req = (path, { method = 'GET', body = null, token = null, headers = {} } = {}) => {
  const h = Object.assign({}, headers);
  if (token) h['authorization'] = 'Bearer ' + token;
  if (body !== null && typeof body === 'object') {
    h['content-type'] = 'application/json';
    body = JSON.stringify(body);
  }
  return new Request('https://sf.test' + path, { method, headers: h, body });
};

const call = async (env, path, opts = {}) => {
  const r = await handleApi(req(path, opts), env, { waitUntil: p => p });
  const text = await r.text();
  let j;
  try { j = JSON.parse(text); } catch { j = text; }
  return { status: r.status, body: j, headers: r.headers };
};

/* ------------------- Tests ------------------- */

test('public config exposes Firebase and feature flags without secrets', async () => {
  const env = testEnv();
  const res = await call(env, '/api/public-config');
  assert.equal(res.status, 200);
  assert.equal(res.body.firebase.projectId, 'hackfest-ju');
  assert.equal(res.body.github.configured, true);
  assert.equal(res.body.cashfree.mode, 'sandbox');
  assert.equal(res.body.ai, true);
  assert.equal(res.body.alerts, true);
  assert.ok(!JSON.stringify(res.body).includes('test-gh-client-secret'));
  assert.ok(!JSON.stringify(res.body).includes('test-cf-secret'));
});

test('Firebase Auth: valid token authenticates and upserts customer', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'cust-1', email: 'alice@test.io', email_verified: true, name: 'Alice' });
  const res = await call(env, '/api/me', { token });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.uid, 'cust-1');
  assert.equal(res.body.user.email, 'alice@test.io');
  assert.equal(res.body.plan.id, 'free');
});

test('Firebase Auth: missing, malformed, expired, or wrong aud/iss tokens are rejected', async () => {
  const env = testEnv();
  assert.equal((await call(env, '/api/me')).status, 401);
  assert.equal((await call(env, '/api/me', { token: 'invalid.token' })).status, 401);

  const expiredToken = await makeToken({ expOffset: -3600 });
  assert.equal((await call(env, '/api/me', { token: expiredToken })).status, 401);

  const wrongAudToken = await makeToken({ aud: 'wrong-project' });
  assert.equal((await call(env, '/api/me', { token: wrongAudToken })).status, 401);

  const wrongIssToken = await makeToken({ iss: 'https://wrong.issuer.com' });
  assert.equal((await call(env, '/api/me', { token: wrongIssToken })).status, 401);
});

test('Firebase Auth: unverified email is allowed on /api/me but refused on protected operations', async () => {
  const env = testEnv();
  const unverifiedToken = await makeToken({ email_verified: false });
  // Legacy/self-service verification could leave a stale verified bit in D1; the signed Firebase token is authoritative.
  await env.DB.prepare(`INSERT INTO customers (uid, email, name, email_verified, created_at, updated_at) VALUES ('user-123', 'user@example.com', 'Test User', 1, 'now', 'now')`).run();
  // GET /api/me is allowed (user needs to check their profile to see they need verification)
  const meRes = await call(env, '/api/me', { token: unverifiedToken });
  assert.equal(meRes.status, 200);
  assert.equal(meRes.body.user.email_verified, false);

  // Connecting GitHub requires verified email
  const connectRes = await call(env, '/api/github/connect', { method: 'POST', token: unverifiedToken, body: {} });
  assert.equal(connectRes.status, 403);
  assert.equal(connectRes.body.error, 'email_not_verified');
});

test('Account: PATCH /api/me updates preferences, DELETE /api/me cleans up customer data', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'cust-pref', email: 'pref@test.io' });
  await call(env, '/api/me', { token }); // create

  const patchRes = await call(env, '/api/me', {
    method: 'PATCH',
    token,
    body: { name: 'Bob Updated', alertMinSeverity: 'critical', alertsEnabled: true, alertTypes: ['new_high'] }
  });
  assert.equal(patchRes.status, 200);

  const updated = await call(env, '/api/me', { token });
  assert.equal(updated.body.user.name, 'Bob Updated');
  assert.equal(updated.body.alerts.minSeverity, 'critical');

  const delRes = await call(env, '/api/me', { method: 'DELETE', token });
  assert.equal(delRes.status, 200);
  assert.equal(delRes.body.deleted, true);

  const check = await env.DB.prepare('SELECT * FROM customers WHERE uid = ?').bind('cust-pref').first();
  assert.equal(check, null);
});

test('GitHub Connect & Callback: state check, code exchange, encrypted token storage', async () => {
  const env = testEnv({
    fetch: async (url) => {
      if (url.includes('/access_token')) {
        return new Response(JSON.stringify({ access_token: 'gh-test-token-123', scope: 'read:user,public_repo' }), { status: 200 });
      }
      if (url.includes('/user')) {
        return new Response(JSON.stringify({ id: 98765, login: 'octocat', avatar_url: 'https://github.com/octo.png' }), { status: 200 });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const token = await makeToken({ uid: 'gh-user' });
  const conn = await call(env, '/api/github/connect', { method: 'POST', token, body: { scope: 'public' } });
  assert.equal(conn.status, 200);
  assert.ok(conn.body.url.includes('client_id=test-gh-client-id'));

  const state = new URL(conn.body.url).searchParams.get('state');
  assert.ok(state);

  // Reusing or forged state is rejected
  assert.equal((await call(env, `/api/github/callback?code=foo&state=invalid_state`)).status, 400);

  // Valid callback exchanges code and redirects
  const cb = await call(env, `/api/github/callback?code=good_code&state=${state}`);
  assert.equal(cb.status, 302);
  assert.ok(cb.headers.get('location').includes('#github=connected'));

  const row = await env.DB.prepare('SELECT * FROM github_connections WHERE uid = ?').bind('gh-user').first();
  assert.equal(row.login, 'octocat');
  assert.equal(await decrypt(env, row.token_enc), 'gh-test-token-123');
});

test('Repos: enforces plan repo limits (Free plan allows 1 repo)', async () => {
  const env = testEnv({
    fetch: async (url) => {
      if (url.includes('/repositories/100') || url.includes('/repositories/200')) {
        const id = url.includes('/100') ? 100 : 200;
        return new Response(JSON.stringify({ id, full_name: `user/repo${id}`, default_branch: 'main', permissions: { pull: true } }));
      }
      if (url.includes('/branches/main')) {
        return new Response(JSON.stringify({ commit: { sha: 'abcdef1234567890abcdef1234567890abcdef12' } }));
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const token = await makeToken({ uid: 'limit-user' });
  // Add GitHub connection
  const encTok = await encrypt(env, 'gh-tok');
  await env.DB.prepare(`INSERT INTO github_connections (uid, gh_user_id, login, token_enc, status, created_at, updated_at) VALUES ('limit-user', 1, 'test', ?, 'active', 'now', 'now')`).bind(encTok).run();

  // First repo succeeds
  const r1 = await call(env, '/api/repos', { method: 'POST', token, body: { ghRepoId: 100, branch: 'main' } });
  assert.equal(r1.status, 201);

  // Second repo rejected on free plan
  const r2 = await call(env, '/api/repos', { method: 'POST', token, body: { ghRepoId: 200, branch: 'main' } });
  assert.equal(r2.status, 403);
  assert.equal(r2.body.error, 'repo_limit_reached');
});

test('Scans: runScan analyzes repository files, creates findings & history', async () => {
  const repoFiles = [
    { name: 'app.js', code: 'const x = 1;\nel.innerHTML = req.query.bio;\n' }
  ];
  const tarBytes = makeTarGz(repoFiles);

  const env = testEnv({
    fetch: async (url) => {
      if (url.includes('/tarball/')) {
        // Stream decompression in fetchRepoFiles expects gzip
        const cs = new CompressionStream('gzip');
        const writer = cs.writable.getWriter();
        writer.write(tarBytes);
        writer.close();
        return new Response(cs.readable, { status: 200 });
      }
      if (url.includes('/check-runs')) {
        return new Response(JSON.stringify({ check_runs: [{ name: 'unit-tests', status: 'completed', conclusion: 'success' }] }));
      }
      if (url.includes('/status')) {
        return new Response(JSON.stringify({ statuses: [] }));
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const encTok = await encrypt(env, 'gh-tok');
  await env.DB.prepare(`INSERT INTO customers (uid, email, email_verified, alerts_enabled, alert_types, created_at, updated_at) VALUES ('scanner-user', 's@test.io', 1, 1, '[]', 'now', 'now')`).run();
  await env.DB.prepare(`INSERT INTO github_connections (uid, gh_user_id, login, token_enc, status, created_at, updated_at) VALUES ('scanner-user', 1, 'scanner', ?, 'active', 'now', 'now')`).bind(encTok).run();
  await env.DB.prepare(`INSERT INTO repos (id, uid, gh_repo_id, full_name, branch, monitoring, salt, status, created_at, updated_at) VALUES ('repo-1', 'scanner-user', 555, 'org/app', 'main', 'off', '12345678', 'active', 'now', 'now')`).run();
  await env.DB.prepare(`INSERT INTO scans (id, uid, repo_id, commit_sha, ref, trigger, status, created_at) VALUES ('scan-1', 'scanner-user', 'repo-1', 'sha111', 'refs/heads/main', 'manual', 'queued', 'now')`).run();

  await runScan(env, 'scan-1');

  const scan = await env.DB.prepare('SELECT * FROM scans WHERE id = ?').bind('scan-1').first();
  assert.equal(scan.status, 'complete');
  assert.ok(JSON.parse(scan.counts).critical > 0 || JSON.parse(scan.counts).high > 0);

  const findings = await env.DB.prepare('SELECT * FROM findings WHERE scan_id = ?').bind('scan-1').all();
  assert.ok(findings.results.length > 0);
  assert.equal(findings.results[0].rule_id, 'dom-xss');

  const history = await env.DB.prepare('SELECT * FROM finding_history WHERE repo_id = ?').bind('repo-1').all();
  assert.equal(history.results[0].status, 'open');

  const ci = await env.DB.prepare('SELECT * FROM test_results WHERE repo_id = ?').bind('repo-1').all();
  assert.equal(ci.results[0].name, 'unit-tests');
  assert.equal(ci.results[0].conclusion, 'success');
});

test('ProofLoop: compares scans honestly and honors verified by test', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'pl-user' });

  await env.DB.prepare(`INSERT INTO repos (id, uid, gh_repo_id, full_name, branch, salt, created_at, updated_at) VALUES ('repo-pl', 'pl-user', 777, 'org/pl', 'main', 'salt', 'now', 'now')`).run();
  await env.DB.prepare(`INSERT INTO scans (id, uid, repo_id, commit_sha, trigger, status, created_at) VALUES ('s1', 'pl-user', 'repo-pl', 'sha1', 'manual', 'complete', 'now')`).run();
  await env.DB.prepare(`INSERT INTO scans (id, uid, repo_id, commit_sha, trigger, status, created_at) VALUES ('s2', 'pl-user', 'repo-pl', 'sha2', 'manual', 'complete', 'now')`).run();

  // Scan 1 has finding key_a
  await env.DB.prepare(`INSERT INTO findings (scan_id, id, key, rule_id, title, severity, file, line) VALUES ('s1', 'f1', 'key_a', 'sql-injection', 'SQL', 'critical', 'a.js', 1)`).run();
  // History maps key_a to CI test 'security-test'
  await env.DB.prepare(`INSERT INTO finding_history (repo_id, key, status, test_check) VALUES ('repo-pl', 'key_a', 'resolved', 'security-test')`).run();
  // CI test passed on s2 commit
  await env.DB.prepare(`INSERT INTO test_results (repo_id, commit_sha, name, status, conclusion, source, updated_at) VALUES ('repo-pl', 'sha2', 'security-test', 'completed', 'success', 'check_run', 'now')`).run();

  const res = await call(env, '/api/proofloop?from=s1&to=s2', { token });
  assert.equal(res.status, 200);
  assert.equal(res.body.comparison[0].status, 'VERIFIED BY TEST');
  assert.equal(res.body.comparison[0].testCheck, 'security-test');
});

test('AI Fix: enforces monthly limit and honest patch validation', async () => {
  const env = testEnv({
    fetch: async (url) => {
      if (url.includes('/contents/')) {
        return new Response(JSON.stringify({ type: 'file', content: btoa('el.innerHTML = req.query.bio;\n'), sha: 'blob1' }));
      }
      if (url.includes(':generateContent')) {
        return new Response(JSON.stringify({
          candidates: [{
            content: {
              parts: [{
                text: JSON.stringify({
                  summary: 'Sanitize text assignment',
                  edits: [{
                    file: 'app.js',
                    startLine: 1,
                    endLine: 1,
                    original: ['el.innerHTML = req.query.bio;'],
                    replacement: ['el.textContent = req.query.bio;']
                  }],
                  explanation: 'Replaces innerHTML with textContent to neutralize XSS.',
                  assumptions: ['DOM element'],
                  sideEffects: ['None'],
                  regressionTests: ['assert(el.children.length === 0)'],
                  limitations: ['HTML rendering not supported'],
                  confidence: 'high'
                })
              }]
            }
          }]
        }));
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const token = await makeToken({ uid: 'fix-user' });
  const encTok = await encrypt(env, 'gh-tok');
  await env.DB.prepare(`INSERT INTO github_connections (uid, gh_user_id, login, token_enc, status, created_at, updated_at) VALUES ('fix-user', 1, 'test', ?, 'active', 'now', 'now')`).bind(encTok).run();
  await env.DB.prepare(`INSERT INTO repos (id, uid, gh_repo_id, full_name, branch, salt, created_at, updated_at) VALUES ('repo-fix', 'fix-user', 888, 'org/app', 'main', 'salt', 'now', 'now')`).run();
  await env.DB.prepare(`INSERT INTO scans (id, uid, repo_id, commit_sha, trigger, status, created_at) VALUES ('scan-fix', 'fix-user', 'repo-fix', 'shafix', 'manual', 'complete', 'now')`).run();
  await env.DB.prepare(`INSERT INTO findings (scan_id, id, key, rule_id, title, severity, file, line, why, fix, tests) VALUES ('scan-fix', 'f-fix', 'key_xss', 'dom-xss', 'XSS', 'critical', 'app.js', 1, 'why', 'fix', 'test')`).run();

  const patchRes = await call(env, '/api/patches', {
    method: 'POST',
    token,
    body: { scanId: 'scan-fix', findingId: 'f-fix' }
  });

  assert.equal(patchRes.status, 201);
  assert.equal(patchRes.body.patch.checks.appliesCleanly, true);
  assert.equal(patchRes.body.patch.checks.targetEliminated, true);

  // Accept patch
  const patchId = patchRes.body.patch.id;
  const acceptRes = await call(env, `/api/patches/${patchId}`, {
    method: 'PATCH',
    token,
    body: { action: 'accept' }
  });
  assert.equal(acceptRes.status, 200);
  assert.equal(acceptRes.body.status, 'accepted');
});

test('Cashfree Billing: Pro Pass checkout and server-to-server verification', async () => {
  const env = testEnv({
    fetch: async (url, opts) => {
      if (url.includes('/orders') && opts.method === 'POST') {
        return new Response(JSON.stringify({ cf_order_id: 'cf_123', payment_session_id: 'sess_123' }));
      }
      if (url.includes('/orders/sf_pro_test')) {
        return new Response(JSON.stringify({ order_id: 'sf_pro_test', order_status: 'PAID', order_amount: 699 }));
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const token = await makeToken({ uid: 'bill-user', email: 'bill@test.io' });
  const co = await call(env, '/api/billing/checkout', { method: 'POST', token, body: { plan: 'pro', phone: '9876543210' } });
  assert.equal(co.status, 200);
  assert.equal(co.body.amount, 699);

  // Mock verify order
  await env.DB.prepare(`INSERT INTO billing_orders (id, uid, plan, amount, currency, status, cf_order_id, created_at) VALUES ('sf_pro_test', 'bill-user', 'pro', 699, 'INR', 'created', 'cf_123', 'now')`).run();

  const v = await call(env, '/api/billing/verify', { method: 'POST', token, body: { orderId: 'sf_pro_test' } });
  assert.equal(v.status, 200);
  assert.equal(v.body.paid, true);

  const sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE uid = ?').bind('bill-user').first();
  assert.equal(sub.plan, 'pro');
  assert.equal(sub.status, 'active');

  // Business Rule: while entitlement is active, duplicate checkout returns 409 already_entitled
  const coDup = await call(env, '/api/billing/checkout', { method: 'POST', token, body: { plan: 'pro', phone: '9876543210' } });
  assert.equal(coDup.status, 409);
  assert.equal(coDup.body.error, 'already_entitled');

  // Business Rule: verification is idempotent; calling again does not change expiry or error
  const vAgain = await call(env, '/api/billing/verify', { method: 'POST', token, body: { orderId: 'sf_pro_test' } });
  assert.equal(vAgain.status, 200);
  assert.equal(vAgain.body.paid, true);
  assert.equal(vAgain.body.alreadyApplied, true);

  // Business Rule: cross-user order verification is rejected (404 order_not_found)
  const otherToken = await makeToken({ uid: 'other-user', email: 'other@test.io' });
  const vOther = await call(env, '/api/billing/verify', { method: 'POST', token: otherToken, body: { orderId: 'sf_pro_test' } });
  assert.equal(vOther.status, 404);
});

test('Cron handleScheduled: polls repos and expires subscriptions', async () => {
  const env = testEnv({
    fetch: async (url) => {
      if (url.includes('/branches/main')) {
        return new Response(JSON.stringify({ commit: { sha: 'new_head_sha_999' } }));
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
  });

  const encTok = await encrypt(env, 'gh-tok');
  await env.DB.prepare(`INSERT INTO github_connections (uid, gh_user_id, login, token_enc, status, created_at, updated_at) VALUES ('cron-user', 1, 'test', ?, 'active', 'now', 'now')`).bind(encTok).run();
  await env.DB.prepare(`INSERT INTO repos (id, uid, gh_repo_id, full_name, branch, monitoring, salt, last_sha, status, created_at, updated_at) VALUES ('r-cron', 'cron-user', 999, 'org/cron', 'main', 'polling', 'salt', 'old_sha', 'active', 'now', 'now')`).run();

  // Expired sub
  const past = new Date(Date.now() - 3600 * 1000).toISOString();
  await env.DB.prepare(`INSERT INTO subscriptions (uid, plan, status, period_end, updated_at) VALUES ('exp-user', 'pro', 'active', ?, 'now')`).bind(past).run();

  await handleScheduled({}, env, { waitUntil: () => {} });

  // A new scan should be queued for r-cron
  const queuedScan = await env.DB.prepare('SELECT * FROM scans WHERE repo_id = ? AND commit_sha = ?').bind('r-cron', 'new_head_sha_999').first();
  assert.ok(queuedScan);
  assert.equal(queuedScan.trigger, 'polling');

  // Subscription expired
  const expSub = await env.DB.prepare('SELECT * FROM subscriptions WHERE uid = ?').bind('exp-user').first();
  assert.equal(expSub.status, 'expired');
});

test('Auth: Email OTP send and verify flow creates valid session and customer', async () => {
  let deliveredOtp = '';
  const env = testEnv({ fetch: async (url, opts = {}) => {
    if (String(url).includes('api.resend.com/emails')) {
      const mail = JSON.parse(opts.body);
      deliveredOtp = (mail.text.match(/code is: (\d{6})/) || [])[1] || '';
      return new Response(JSON.stringify({ id: 'email-test-id' }), { status: 200 });
    }
    return new Response('{}', { status: 200 });
  } });
  const email = 'developer@example.com';

  // 1. Send OTP
  const s1 = await call(env, '/api/auth/send-otp', {
    method: 'POST',
    body: { email }
  });
  assert.equal(s1.status, 200);
  assert.ok(s1.body.ok);
  assert.equal(s1.body.email, email);
  assert.equal(s1.body.sent, true);
  assert.equal(Object.hasOwn(s1.body, 'devOtp'), false);

  const otp = deliveredOtp;
  assert.equal(otp.length, 6);

  // 2. Rate limit: immediate re-send should be rejected (cooldown 60s)
  const s2 = await call(env, '/api/auth/send-otp', {
    method: 'POST',
    body: { email }
  });
  assert.equal(s2.status, 429);
  assert.equal(s2.body.error, 'rate_limited');

  // 3. Verify OTP with incorrect code fails
  const vBad = await call(env, '/api/auth/verify-otp', {
    method: 'POST',
    body: { email, otp: '000000' }
  });
  assert.equal(vBad.status, 400);
  assert.equal(vBad.body.error, 'invalid_otp');

  // 4. Verify OTP with correct code succeeds and returns session token
  const vGood = await call(env, '/api/auth/verify-otp', {
    method: 'POST',
    body: { email, otp }
  });
  assert.equal(vGood.status, 200);
  assert.ok(vGood.body.ok);
  assert.ok(vGood.body.token);
  assert.equal(vGood.body.user.email, email);
  assert.equal(vGood.body.user.email_verified, true);

  // 5. Use session token to call protected /api/me
  const meRes = await call(env, '/api/me', {
    method: 'GET',
    token: vGood.body.token
  });
  assert.equal(meRes.status, 200);
  assert.equal(meRes.body.user.email, email);
  assert.equal(meRes.body.user.email_verified, true);

  // 6. Single-use semantics: verifying the same OTP again fails
  const vReused = await call(env, '/api/auth/verify-otp', {
    method: 'POST',
    body: { email, otp }
  });
  assert.equal(vReused.status, 400);
  assert.equal(vReused.body.error, 'otp_expired_or_not_found');
});

test('Auth: a failed password sign-in never silently creates an account', async () => {
  const calls = [];
  const env = testEnv({ fetch: async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ error: { message: 'EMAIL_NOT_FOUND' } }), { status: 400 });
  } });
  const res = await call(env, '/api/auth/login', { method: 'POST', body: { email: 'new@example.com', password: 'a-long-password' } });
  assert.equal(res.status, 400);
  assert.deepEqual(calls, ['https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=test-firebase-key']);
});

test('Auth: password signup sends Firebase verification and returns no authenticated session', async () => {
  const calls = [];
  const env = testEnv({ fetch: async (url) => {
    const u = String(url);
    calls.push(u);
    if (u.includes('accounts:signUp')) return new Response(JSON.stringify({ idToken: 'firebase-token', localId: 'new-uid', email: 'new@example.com' }), { status: 200 });
    if (u.includes('accounts:sendOobCode')) return new Response(JSON.stringify({ email: 'new@example.com' }), { status: 200 });
    return new Response('{}', { status: 200 });
  } });
  const res = await call(env, '/api/auth/signup', { method: 'POST', body: { email: 'new@example.com', password: 'a-long-password', action: 'signup' } });
  assert.equal(res.status, 200);
  assert.equal(res.body.verification_required, true);
  assert.equal(res.body.token, undefined);
  assert.ok(calls.some(u => u.includes('accounts:sendOobCode')));
});

test('Auth: missing email provider fails closed without returning an OTP', async () => {
  const env = testEnv({ RESEND_API_KEY: '', ALERT_FROM: '' });
  const res = await call(env, '/api/auth/send-otp', { method: 'POST', body: { email: 'nobody@example.com' } });
  assert.equal(res.status, 503);
  assert.equal(Object.hasOwn(res.body, 'devOtp'), false);
  assert.equal(await env.DB.prepare('SELECT COUNT(*) AS n FROM otps').first().then(x => x.n), 0);
});

test('Auth: an unverified Firebase token cannot self-verify through the API', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'unverified-self', email_verified: false });
  const res = await call(env, '/api/me/verify-email', { method: 'POST', token, body: {} });
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'email_not_verified');
});

test('Projects: uploaded source persists in object storage, scans actual code, and access is owner/session scoped', async () => {
  const env = testEnv();
  const code = 'const value = req.query.value;\nelement.innerHTML = value;\n';
  const created = await call(env, '/api/projects', { method: 'POST', body: { name: 'Test site', files: [{ path: 'src/app.js', size: Buffer.byteLength(code) }] } });
  assert.equal(created.status, 201);
  const id = created.body.id, sessionToken = created.body.sessionToken;
  const uploaded = await call(env, `/api/projects/${id}/files?path=src%2Fapp.js`, { method: 'POST', body: code, headers: { 'content-type': 'text/javascript', 'x-project-session': sessionToken } });
  assert.equal(uploaded.status, 200);
  assert.equal((await call(env, `/api/projects/${id}/finalize`, { method: 'POST', headers: { 'x-project-session': sessionToken }, body: {} })).body.status, 'uploaded');
  const ownerToken = await makeToken({ uid: 'project-owner', email: 'owner@test.io' });
  const claim = await call(env, `/api/projects/${id}/claim`, { method: 'POST', token: ownerToken, body: { sessionToken } });
  assert.equal(claim.status, 200);
  const scan = await call(env, `/api/projects/${id}/scan`, { method: 'POST', token: ownerToken, body: {} });
  assert.equal(scan.status, 200);
  assert.ok(scan.body.findings.some(f => f.file === 'src/app.js' && f.line === 2));
  assert.equal((await call(env, `/api/projects/${id}`)).status, 401);
  const other = await makeToken({ uid: 'other-user', email: 'other@test.io' });
  assert.equal((await call(env, `/api/projects/${id}`, { token: other })).status, 404);
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(id).first();
  assert.equal(project.uid, 'project-owner');
});

test('User Data Recovery: /api/user/codebases and /api/user/repairs return stored records', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'recovery-user', email: 'rec@example.com' });

  // Insert mock codebase and repair request into D1
  const cid = 'mock_cid_1234567890abcdef12345678';
  await env.DB.prepare(`INSERT INTO codebases (id, created_at, updated_at, minhash, paths, digest, salt, file_count, line_count, visits)
    VALUES (?, '2026-10-24T00:00:00Z', '2026-10-24T01:00:00Z', '[]', '["my-project/index.js","my-project/server.js"]', 'digest123', 'salt1234567890ab', 2, 100, 3)`).bind(cid).run();

  await env.DB.prepare(`INSERT INTO issues (cid, id, source, rule_id, title, severity, score, category, file, line, anchor, ctx, howto, status, first_seen, updated_at)
    VALUES (?, 'iss-1', 'engine', 'hardcoded-secret', 'API Key in code', 'critical', 9, 'Secrets', 'my-project/index.js', 10, '12345678', '', '[]', 'open', 'now', 'now')`).bind(cid).run();

  const reqId = 'req_123456789012345678';
  await env.DB.prepare(`INSERT INTO repair_requests (id, token_hash, offer_id, status, finding, evidence, order_id, created_at, updated_at, uid)
    VALUES (?, 'thash', 'single_repair', 'submitted', '{"title":"Fix API key","severity":"critical","file":"my-project/index.js","line":10}', '[]', 'sf_order_999', 'now', 'now', ?)`).bind(reqId, 'recovery-user').run();

  // Test /api/user/codebases
  const cbRes = await call(env, '/api/user/codebases', { method: 'GET', token });
  assert.equal(cbRes.status, 200);
  assert.ok(cbRes.body.ok);
  assert.equal(cbRes.body.codebases.length, 1);
  assert.equal(cbRes.body.codebases[0].name, 'my-project');
  assert.equal(cbRes.body.codebases[0].fileCount, 2);
  assert.equal(cbRes.body.codebases[0].issueCount, 1);

  // Test /api/user/repairs
  const repRes = await call(env, '/api/user/repairs', { method: 'GET', token });
  assert.equal(repRes.status, 200);
  assert.ok(repRes.body.ok);
  assert.equal(repRes.body.repairs.length, 1);
  assert.equal(repRes.body.repairs[0].id, reqId);
  assert.equal(repRes.body.repairs[0].status, 'submitted');
  assert.equal(repRes.body.repairs[0].orderId, 'sf_order_999');
  const otherToken = await makeToken({ uid: 'other-user', email: 'other@example.com' });
  const otherList = await call(env, '/api/user/repairs', { method: 'GET', token: otherToken });
  assert.deepEqual(otherList.body.repairs, [], "another account cannot list this user's repair request");
  const otherDetail = await call(env, `/api/user/repairs/${reqId}`, { method: 'GET', token: otherToken });
  assert.equal(otherDetail.status, 404, 'another account cannot read this repair by ID');
});

test('Auth: expired OTP and 5-attempt lockout are enforced', async () => {
  let deliveredOtp = '';
  const env = testEnv({
    fetch: async (url, opts) => {
      if (url.includes('api.resend.com')) {
        const payload = JSON.parse(opts.body);
        const match = payload.text.match(/\b\d{6}\b/);
        deliveredOtp = match ? match[0] : '';
        return new Response(JSON.stringify({ id: 'res_exp_test' }), { status: 200 });
      }
      return new Response('{}', { status: 200 });
    }
  });

  const email = 'lockout@example.com';
  // Send OTP
  const s1 = await call(env, '/api/auth/send-otp', { method: 'POST', body: { email } });
  assert.equal(s1.status, 200);
  assert.ok(deliveredOtp);

  // Expire the OTP artificially in DB
  await env.DB.prepare('UPDATE otps SET expires_at = ? WHERE email = ?').bind(Date.now() - 1000, email).run();
  const vExp = await call(env, '/api/auth/verify-otp', { method: 'POST', body: { email, otp: deliveredOtp } });
  assert.equal(vExp.status, 400);
  assert.equal(vExp.body.error, 'otp_expired_or_not_found');

  // Request a fresh OTP (bypass 60s cooldown by backdating created_at/expires_at)
  await env.DB.prepare('DELETE FROM otps WHERE email = ?').bind(email).run();
  const s2 = await call(env, '/api/auth/send-otp', { method: 'POST', body: { email } });
  assert.equal(s2.status, 200);

  // Fail 5 times with incorrect code
  for (let i = 0; i < 5; i++) {
    const vFail = await call(env, '/api/auth/verify-otp', { method: 'POST', body: { email, otp: '000000' } });
    assert.equal(vFail.status, 400);
  }

  // 6th attempt with correct OTP must fail due to too_many_attempts lockout
  const vLocked = await call(env, '/api/auth/verify-otp', { method: 'POST', body: { email, otp: deliveredOtp } });
  assert.equal(vLocked.status, 400);
  assert.equal(vLocked.body.error, 'too_many_attempts');
});

test('Billing: verified payment reconciliation restores active subscription without duplicate charge', async () => {
  const env = testEnv();
  const token = await makeToken({ uid: 'reconcile-user', email: 'recon@example.com' });

  // Simulate an active paid order in billing_orders with no active subscription row yet
  const paidAt = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO billing_orders (id, uid, plan, amount, currency, status, applied, paid_at, created_at)
    VALUES ('sf_pro_recon', 'reconcile-user', 'pro', 699, 'INR', 'PAID', 1, ?, ?)
  `).bind(paidAt, paidAt).run();

  // /api/me should automatically reconcile and return plan = pro
  const me = await call(env, '/api/me', { method: 'GET', token });
  assert.equal(me.status, 200);
  assert.equal(me.body.plan.id, 'pro');
  assert.equal(me.body.subscription.status, 'active');

  // Verify duplicate checkout is prevented
  const co = await call(env, '/api/billing/checkout', { method: 'POST', token, body: { plan: 'pro' } });
  assert.equal(co.status, 409);
  assert.equal(co.body.error, 'already_entitled');
});

test('Auth: designated test email rajaditya20071002@gmail.com and rajaditya2007102@gmail.com authenticate via test codes 112233 and 4455', async () => {
  const env = testEnv({ RESEND_API_KEY: '', ALERT_FROM: '' });
  const email1 = 'rajaditya20071002@gmail.com';
  const email2 = 'rajaditya2007102@gmail.com';

  // 1. Send OTP for email1 (returns test code even without Resend)
  const s1 = await call(env, '/api/auth/send-otp', { method: 'POST', body: { email: email1 } });
  assert.equal(s1.status, 200);
  assert.equal(s1.body.devOtp, '112233');

  // 2. Verify with test code 112233
  const v1 = await call(env, '/api/auth/verify-otp', { method: 'POST', body: { email: email1, otp: '112233' } });
  assert.equal(v1.status, 200);
  assert.ok(v1.body.token);
  assert.equal(v1.body.user.email, email1);

  // 3. Verify email2 with test code 4455
  const v2 = await call(env, '/api/auth/verify-otp', { method: 'POST', body: { email: email2, otp: '4455' } });
  assert.equal(v2.status, 200);
  assert.ok(v2.body.token);
  assert.equal(v2.body.user.email, email2);
});
