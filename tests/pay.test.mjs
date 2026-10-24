// Cashfree paid-repair tests: the Cashfree PG API is mocked (no network, no money). Run: node --test tests/pay.test.mjs
import test from 'node:test'; import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { handleApi } from '../worker/index.js';
import { payConfig, verifyCashfreeSignature } from '../worker/pay.js';
import { createSessionToken } from '../worker/platform.js';
import { d1 } from '../tools/dev-server.mjs';
import { E } from '../worker/core.js';

const APP = 'TEST_app_123', SECRET = 'cfsk_ma_test_secret_xyz';
function mockCashfree(opts = {}) {
  const orders = new Map(), calls = [];
  const fetch = async (url, init) => {
    const u = new URL(url), body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method: init.method, path: u.pathname, body, headers: init.headers });
    assert.equal(u.host, 'sandbox.cashfree.com'); assert.equal(init.headers['x-client-secret'], SECRET); assert.equal(init.headers['x-api-version'], '2023-08-01');
    if (opts.down) return new Response('{"message":"down"}', { status: 500 });
    let m;
    if (init.method === 'POST' && u.pathname === '/pg/orders') {
      const o = { cf_order_id: 1000 + orders.size, order_id: body.order_id, order_amount: opts.badAmount ? 1 : body.order_amount, order_currency: body.order_currency, order_status: 'ACTIVE', payment_session_id: 'session_' + body.order_id, _payments: [] };
      orders.set(body.order_id, o); return Response.json(o);
    }
    if ((m = u.pathname.match(/^\/pg\/orders\/([^/]+)\/payments$/))) return Response.json(orders.get(decodeURIComponent(m[1]))._payments);
    if ((m = u.pathname.match(/^\/pg\/orders\/([^/]+)$/))) { const o = orders.get(decodeURIComponent(m[1])); return o ? Response.json(o) : new Response('{}', { status: 404 }); }
    return new Response('{}', { status: 404 });
  };
  const pay = (orderId, amount = 699, status = 'SUCCESS') => { const o = orders.get(orderId); o._payments.push({ cf_payment_id: 555 + o._payments.length, payment_status: status, payment_amount: amount, payment_currency: 'INR' }); if (status === 'SUCCESS' && amount === o.order_amount) o.order_status = 'PAID'; };
  return { fetch, calls, orders, pay };
}
function boot(opts = {}) { const cf = mockCashfree(opts), data = new Map(); return { cf, objects:data, env: { CASHFREE_APP_ID: APP, CASHFREE_SECRET_KEY: SECRET, TOKEN_ENC_KEY: 'test-secret-key-with-at-least-32-bytes', DB: d1(':memory:'), PROJECTS: { async put(k,v){data.set(k,Buffer.from(v));}, async get(k){const b=data.get(k);return b?{text:async()=>b.toString('utf8'),arrayBuffer:async()=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)}:null;} }, fetch: cf.fetch, RATE_PER_HOUR: '10000', ...(opts.env || {}) } }; }
const req = (env, method, path, body, token, headers = {}, repairToken = '') => handleApi(new Request('https://sf.test' + path, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token ? { authorization: 'Bearer ' + token } : {}), ...(repairToken ? { 'x-repair-token': repairToken } : {}), ...headers }, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) }), env).then(async r => ({ status: r.status, body: await r.json() }));
const FINDING = { ruleId: 'dom-xss', title: 'Unsanitised HTML injected into the page', severity: 'high', file: 'src/app.js', line: 8 };
const ownerTokenCache = new WeakMap();
async function ownerToken(env) { if (!ownerTokenCache.has(env)) ownerTokenCache.set(env, await createSessionToken(env, { uid: 'pay-owner', email: 'pay-owner@test.io' })); return ownerTokenCache.get(env); }
async function projectForPayment(env) {
  const userToken = await ownerToken(env), code = 'const value = req.query.value;\nelement.innerHTML = value;\n';
  const c = await req(env, 'POST', '/api/projects', { name: 'Payment test project', files: [{ path: 'src/app.js', size: Buffer.byteLength(code) }] });
  const id = c.body.id, session = c.body.sessionToken;
  assert.equal(c.status, 201, JSON.stringify(c.body));
  assert.equal((await req(env, 'POST', `/api/projects/${id}/files?path=src%2Fapp.js`, code, '', { 'content-type': 'text/javascript', 'x-project-session': session })).status, 200);
  assert.equal((await req(env, 'POST', `/api/projects/${id}/finalize`, {}, '', { 'x-project-session': session })).status, 200);
  assert.equal((await req(env, 'POST', `/api/projects/${id}/claim`, { sessionToken: session }, userToken)).status, 200);
  const scanned = await req(env, 'POST', `/api/projects/${id}/scan`, {}, userToken);
  const finding = scanned.body.findings.find(x => x.ruleId === 'dom-xss');
  assert.ok(finding, JSON.stringify(scanned.body));
  return { id, userToken, finding };
}
async function newReq(env, extra = {}) { const project = await projectForPayment(env); const r = await req(env, 'POST', '/api/repair-requests', { offerId: 'starter-fix', projectId: project.id, findingId: project.finding.id, finding: project.finding, consent: { scope: true }, ...extra }, project.userToken); assert.equal(r.status, 201, JSON.stringify(r.body)); return { ...r.body, userToken: project.userToken, projectId: project.id }; }
const ownReq = (env, r, method, path, body, repairToken = r.accessToken) => req(env, method, path, body, r.userToken, {}, repairToken);
const sign = (body, ts = String(Date.now())) => ({ 'x-webhook-timestamp': ts, 'x-webhook-signature': crypto.createHmac('sha256', SECRET).update(ts + body).digest('base64') });

test('config: never exposes secrets; refuses live mode without approval and non-test keys in test mode', async () => {
  const { env } = boot(); const r = await req(env, 'GET', '/api/pay/config');
  assert.equal(r.body.provider, 'cashfree'); assert.equal(r.body.configured, true); assert.equal(r.body.mode, 'sandbox'); assert.equal(r.body.offers[0].amount, 699);
  assert.ok(!JSON.stringify(r.body).includes(SECRET) && !JSON.stringify(r.body).includes(APP));
  assert.equal(payConfig({ CASHFREE_APP_ID: 'live1', CASHFREE_SECRET_KEY: 's', CASHFREE_ENV: 'production' }).problem, 'live_payments_not_approved');
  assert.equal(payConfig({ CASHFREE_APP_ID: 'live1', CASHFREE_SECRET_KEY: 's' }).problem, 'sandbox_needs_test_credentials');
  assert.equal(payConfig({}).problem, 'payments_not_configured');
  assert.equal(payConfig({ CASHFREE_APP_ID: 'live1', CASHFREE_SECRET_KEY: 's', CASHFREE_ENV: 'production', ALLOW_LIVE_PAYMENTS: 'I_HAVE_OWNER_APPROVAL' }).ok, true);
});
test('request needs consent and a valid finding; evidence is masked server-side', async () => {
  const { env } = boot();
  const project = await projectForPayment(env);
  assert.equal((await req(env, 'POST', '/api/repair-requests', { offerId: 'starter-fix', finding: project.finding, consent: {} })).body.error, 'unauthorized');
  assert.equal((await req(env, 'POST', '/api/repair-requests', { offerId: 'free', finding: project.finding, consent: { scope: true } }, project.userToken)).body.error, 'unknown_offer');
  assert.equal((await req(env, 'POST', '/api/repair-requests', { offerId: 'starter-fix', projectId: project.id, findingId: project.finding.id, finding: { ...project.finding, file: '../etc/passwd' }, consent: { scope: true } }, project.userToken)).body.error, 'finding_not_in_project_scan');
  const r = await newReq(env, { consent: { scope: true, shareEvidence: true }, evidence: [{ n: 1, text: 'const k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq"' }] });
  const row = await env.DB.prepare('SELECT * FROM repair_requests WHERE id = ?').bind(r.request.id).first();
  assert.ok(!row.evidence.includes('51Hx9aQ2eZ')); assert.ok(!row.token_hash.includes(r.accessToken), 'token stored hashed');
});
test('order: server-side price, one order per request, requires verified owner authentication', async () => {
  const { env, cf } = boot(); const r = await newReq(env);
  const o = await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, { amount: 1, price: 1 }, '');
  assert.equal(o.status, 200); assert.ok(o.body.paymentSessionId); assert.equal(o.body.mode, 'sandbox');
  const created = cf.calls.find(c => c.method === 'POST'); assert.equal(created.body.order_amount, 699, 'client-supplied price ignored'); assert.equal(created.body.order_currency, 'INR');
  const again = await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, {});
  assert.equal(again.body.orderId, o.body.orderId); assert.equal(cf.calls.filter(c => c.method === 'POST').length, 1, 'order reused');
  assert.equal((await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, { phone: '12345' })).body.error, 'invalid_phone');
});
test('verify: nothing unlocks until Cashfree itself reports PAID for the exact amount', async () => {
  const { env, cf } = boot(); const r = await newReq(env); const t = r.accessToken, id = r.request.id;
  const o = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/order`, {});
  let v = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/verify`, {});
  assert.equal(v.body.paid, false); assert.equal(v.body.request.status, 'awaiting_payment', 'browser saying "success" is not enough');
  v = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/verify`, { outcome: 'failed' }); assert.equal(v.body.request.status, 'payment_failed');
  cf.pay(o.body.orderId);
  v = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/verify`, {});
  assert.equal(v.body.paid, true); assert.equal(v.body.request.status, 'submitted'); assert.equal(v.body.request.payment.id, '555');
  v = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/verify`, {});
  assert.ok(v.body.request.events.filter(e => e.type === 'payment_confirmed').length === 1, 'fulfilled once');
  assert.equal((await ownReq(env, r, 'POST', `/api/repair-requests/${id}/cancel`, {})).body.error, 'already_paid');
});
test('verify: wrong amount from the gateway is rejected', async () => {
  const { env, cf } = boot({ badAmount: true }); const r = await newReq(env);
  assert.equal((await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, {})).body.error, 'order_mismatch');
  const b = boot(); const r2 = await newReq(b.env); const o = await ownReq(b.env, r2, 'POST', `/api/repair-requests/${r2.request.id}/order`, {});
  const ord = b.cf.orders.get(o.body.orderId); ord.order_status = 'PAID'; ord._payments.push({ cf_payment_id: 1, payment_status: 'SUCCESS', payment_amount: 1, payment_currency: 'INR' });
  const v = await ownReq(b.env, r2, 'POST', `/api/repair-requests/${r2.request.id}/verify`, {});
  assert.equal(v.body.paid, false); assert.equal(v.body.request.status, 'awaiting_payment'); assert.match(v.body.request.lastError, /mismatch/);
});
test('paid repair creates server patch, rescans it, and serves owner-only ZIP and file artifacts', async () => {
  const { env, cf } = boot(); const r = await newReq(env), id = r.request.id;
  const o = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/order`, {}); cf.pay(o.body.orderId);
  assert.equal((await ownReq(env, r, 'POST', `/api/repair-requests/${id}/repair`, {})).body.error, 'payment_not_confirmed');
  await ownReq(env, r, 'POST', `/api/repair-requests/${id}/verify`, {});
  const repaired = await ownReq(env, r, 'POST', `/api/repair-requests/${id}/repair`, {});
  assert.equal(repaired.status, 200, JSON.stringify(repaired.body));
  assert.equal(repaired.body.repair.status, 'completed_with_limitations');
  assert.equal(repaired.body.repair.validation.findingStatus, 'no_longer_detected');
  assert.equal(repaired.body.repair.manifest.diffs.length, 1);
  const row = await env.DB.prepare('SELECT * FROM repair_jobs WHERE request_id = ?').bind(id).first();
  const artifact = await env.DB.prepare('SELECT * FROM repair_artifacts WHERE job_id = ? AND changed = 1').bind(row.id).first();
  const fixed = env.PROJECTS ? (await env.PROJECTS.get(artifact.object_key)).text() : '';
  assert.doesNotMatch(await fixed, /innerHTML\s*=\s*value/);
  const zipRes = await handleApi(new Request(`https://sf.test/api/repair-requests/${id}/download.zip`, { headers: { authorization: 'Bearer '+r.userToken, 'x-repair-token':r.accessToken } }), env);
  assert.equal(zipRes.status, 200); assert.match(zipRes.headers.get('content-type'), /application\/zip/);
  const zip = new Uint8Array(await zipRes.arrayBuffer()); assert.ok(zip.length > 100);
  const extracted = await E.readZip(zip); assert.equal(extracted.rejected.length, 0); assert.ok(extracted.entries.some(e => e.path === 'src/app.js'));
  const sourceEntry = extracted.entries.find(e => e.path === 'src/app.js'); assert.doesNotMatch(await sourceEntry.read(), /innerHTML\s*=\s*value/);
  const fileRes = await handleApi(new Request(`https://sf.test/api/repair-requests/${id}/files?path=src%2Fapp.js`, { headers: { authorization: 'Bearer '+r.userToken, 'x-repair-token':r.accessToken } }), env);
  assert.equal(fileRes.status, 200); assert.doesNotMatch(await fileRes.text(), /innerHTML\s*=\s*value/);
  const denied = await handleApi(new Request(`https://sf.test/api/repair-requests/${id}/download.zip`, { headers: { authorization: 'Bearer '+r.userToken } }), env);
  assert.equal(denied.status, 200, 'verified owner can recover downloads in a new session without the old capability token');
  const otherUser = await createSessionToken(env, { uid: 'another-user', email: 'other@test.io' });
  const crossUser = await handleApi(new Request(`https://sf.test/api/repair-requests/${id}/download.zip`, { headers: { authorization: 'Bearer '+otherUser, 'x-repair-token':r.accessToken } }), env);
  assert.equal(crossUser.status, 404);
  const crossRequest = await handleApi(new Request(`https://sf.test/api/repair-requests/${id}`, { headers: { authorization: 'Bearer '+otherUser } }), env);
  assert.equal(crossRequest.status, 404);
});
test('webhook: signature required, duplicates ignored, success re-checked with Cashfree, failure recorded', async () => {
  const { env, cf } = boot(); const r = await newReq(env); const o = await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, {});
  const ev = type => JSON.stringify({ type, data: { order: { order_id: o.body.orderId, order_amount: 699, order_currency: 'INR' }, payment: { cf_payment_id: 555, payment_status: type === 'PAYMENT_SUCCESS_WEBHOOK' ? 'SUCCESS' : 'FAILED', payment_amount: 699, payment_message: 'Card declined' } } });
  const fail = ev('PAYMENT_FAILED_WEBHOOK');
  assert.equal((await req(env, 'POST', '/api/webhooks/cashfree', fail, null, { 'x-webhook-timestamp': String(Date.now()), 'x-webhook-signature': 'bad' })).status, 400);
  assert.equal((await req(env, 'POST', '/api/webhooks/cashfree', fail, null, sign(fail, String(Date.now() - 3600e3)))).body.error, 'stale_webhook');
  const h = sign(fail);
  assert.equal((await req(env, 'POST', '/api/webhooks/cashfree', fail, null, h)).body.ok, true);
  assert.equal((await req(env, 'POST', '/api/webhooks/cashfree', fail, null, h)).body.duplicate, true);
  let s = await ownReq(env, r, 'GET', `/api/repair-requests/${r.request.id}`); assert.equal(s.body.request.status, 'payment_failed'); assert.match(s.body.request.lastError, /declined/);
  const okEv = ev('PAYMENT_SUCCESS_WEBHOOK');
  await req(env, 'POST', '/api/webhooks/cashfree', okEv, null, sign(okEv));
  s = await ownReq(env, r, 'GET', `/api/repair-requests/${r.request.id}`); assert.equal(s.body.request.status, 'payment_failed', 'a signed "success" is still re-checked with Cashfree');
  cf.pay(o.body.orderId); const okEv2 = okEv.replace('555', '556');
  await req(env, 'POST', '/api/webhooks/cashfree', okEv2, null, sign(okEv2));
  s = await ownReq(env, r, 'GET', `/api/repair-requests/${r.request.id}`); assert.equal(s.body.request.status, 'submitted');
  assert.equal(await verifyCashfreeSignature(SECRET, '1', 'x', 'y'), false);
});
test('payments off: clear errors, no gateway calls', async () => {
  const { env, cf } = boot({ env: { CASHFREE_SECRET_KEY: '' } }); const r = await newReq(env);
  assert.equal((await ownReq(env, r, 'POST', `/api/repair-requests/${r.request.id}/order`, {})).body.error, 'payments_not_configured');
  assert.equal(cf.calls.length, 0);
});
