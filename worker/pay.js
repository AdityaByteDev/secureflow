// SecureFlow paid repair (₹699) with Cashfree Payments (PG API v2023-08-01), TEST MODE by default.
import { runPaidProjectRepair, repairDownload, getProjectStorage } from './projects.js';
// Secrets: CASHFREE_APP_ID, CASHFREE_SECRET_KEY (Worker secrets). CASHFREE_ENV = "sandbox" (default) | "production".
// Production is refused unless ALLOW_LIVE_PAYMENTS = "I_HAVE_OWNER_APPROVAL".
// Rules: the price comes only from the server; a payment counts only when Cashfree itself reports the order PAID for the
// exact amount (checked server-to-server, or via a signed webhook that is then re-checked); fulfilment happens once.
export const OFFERS = {
  'starter-fix': {
    id: 'starter-fix', amount: 699, currency: 'INR', label: '₹699', title: 'Starter fix: one selected issue',
    scope: 'One selected finding, or one clearly scoped small change in a single file.',
    deliverables: ['Review of the selected finding', 'A proposed code patch with a diff', 'A short change summary', 'A rescan with SecureFlow’s rules and a note on remaining limitations'],
    exclusions: ['Multi-file refactors, architecture changes or production incidents', 'Guarantees that the issue is fully resolved or that the code compiles in your environment', 'Dependency upgrades, hosting or database configuration', 'Anything outside the selected finding'],
    turnaround: null, staffed: false, refundPolicy: null
  }
};
const API_VERSION = '2023-08-01';
const te = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function sha256(t) { return hex(await crypto.subtle.digest('SHA-256', te.encode(t))); }
async function hmacB64(secret, data) {
  const k = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', k, te.encode(data)))));
}
function safeEq(a, b) { a = String(a || ''); b = String(b || ''); if (!a || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
export async function verifyCashfreeSignature(secret, timestamp, rawBody, signature) { return !!secret && !!timestamp && safeEq(await hmacB64(secret, String(timestamp) + rawBody), signature); }

export function payConfig(env) {
  const appId = env.CASHFREE_APP_ID || '', secret = env.CASHFREE_SECRET_KEY || '', live = env.CASHFREE_ENV === 'production';
  let problem = null;
  if (!appId || !secret) problem = 'payments_not_configured';
  else if (live && env.ALLOW_LIVE_PAYMENTS !== 'I_HAVE_OWNER_APPROVAL') problem = 'live_payments_not_approved';
  else if (!live && !/^TEST/i.test(appId)) problem = 'sandbox_needs_test_credentials';
  return { appId, secret, live, mode: live ? 'production' : 'sandbox', base: live ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg', ok: !problem, problem };
}
async function cf(env, cfg, method, path, body) {
  const r = await (env.fetch || fetch)(cfg.base + path, { method, headers: { 'content-type': 'application/json', 'x-api-version': API_VERSION, 'x-client-id': cfg.appId, 'x-client-secret': cfg.secret }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error('cashfree_' + r.status); e.status = r.status; e.cf = j && j.code; throw e; }
  return j;
}

const now = () => new Date().toISOString();
function pub(r) {
  const o = OFFERS[r.offer_id];
  return { id: r.id, status: r.status, offer: { id: o.id, label: o.label, title: o.title }, finding: JSON.parse(r.finding), evidenceShared: !!r.evidence,
    order: r.order_id ? { id: r.order_id, amount: o.amount, currency: o.currency } : null, payment: r.payment_id ? { id: r.payment_id, status: 'SUCCESS' } : null,
    lastError: r.last_error || null, events: JSON.parse(r.events || '[]'), staffed: o.staffed, createdAt: r.created_at };
}
async function load(env, id) { return env.DB.prepare('SELECT * FROM repair_requests WHERE id = ?').bind(id).first(); }
async function save(env, r, type, extra) {
  const ev = JSON.parse(r.events || '[]'); if (type) ev.push(Object.assign({ type, at: now() }, extra || {})); r.events = JSON.stringify(ev.slice(-50)); r.updated_at = now();
  await env.DB.prepare('UPDATE repair_requests SET status=?, order_id=?, cf_order_id=?, payment_id=?, last_error=?, events=?, updated_at=?, fulfilled_at=? WHERE id=?')
    .bind(r.status, r.order_id || null, r.cf_order_id || null, r.payment_id || null, r.last_error || null, r.events, r.updated_at, r.fulfilled_at || null, r.id).run();
}
async function authed(env, req, id, requireAuth) {
  const r = /^req_[0-9a-f]{18}$/.test(id) ? await load(env, id) : null;
  if (!r) return null;
  const user = await requireAuth(req, env);
  if (!r.uid || r.uid !== user.uid) return null;
  return r;
}
// The single place where a request becomes paid: Cashfree must say the order is PAID with a SUCCESS payment for the exact amount.
async function confirmFromCashfree(env, cfg, r, via) {
  const o = OFFERS[r.offer_id];
  const order = await cf(env, cfg, 'GET', '/orders/' + encodeURIComponent(r.order_id));
  if (order.order_status !== 'PAID') return { paid: false, orderStatus: order.order_status };
  const pays = await cf(env, cfg, 'GET', '/orders/' + encodeURIComponent(r.order_id) + '/payments');
  const ok = (Array.isArray(pays) ? pays : []).find(p => p.payment_status === 'SUCCESS' && Number(p.payment_amount) === o.amount && (p.payment_currency || order.order_currency) === o.currency);
  if (Number(order.order_amount) !== o.amount || order.order_currency !== o.currency || !ok) { r.last_error = 'Amount or currency mismatch: not accepted.'; await save(env, r, 'amount_mismatch', { via }); return { paid: false, mismatch: true }; }
  if (r.status === 'cancelled') { r.last_error = 'Payment received for a cancelled request. Contact support for a refund.'; await save(env, r, 'payment_after_cancel', { via }); return { paid: true }; }
  if (r.fulfilled_at) { await save(env, r, 'duplicate_confirmation_ignored', { via }); return { paid: true }; }   // idempotent
  r.payment_id = String(ok.cf_payment_id || ''); r.status = 'submitted'; r.fulfilled_at = now(); r.last_error = null;
  await save(env, r, 'payment_confirmed', { via }); await save(env, r, 'submitted');
  return { paid: true };
}

export async function handlePay(req, env, path, body, raw, { HttpError, str, safePath, mask, rate, requireAuth }) {
  const m = req.method, cfg = payConfig(env);
  if (m === 'GET' && path === '/api/pay/config') {
    const o = OFFERS['starter-fix'];
    const projectStorage = !!getProjectStorage(env);
    return [200, { provider: 'cashfree', configured: cfg.ok && projectStorage, problem: !projectStorage ? 'project_storage_not_configured' : cfg.problem, mode: cfg.mode, projectStorage, offers: [{ id: o.id, label: o.label, amount: o.amount, currency: o.currency, title: o.title, scope: o.scope, deliverables: o.deliverables, exclusions: o.exclusions, turnaround: o.turnaround, staffed: o.staffed, refundPolicy: o.refundPolicy }] }];
  }
  if (!env.DB) throw new HttpError(503, 'database_not_configured');
  if (m === 'POST' && path === '/api/webhooks/cashfree') {
    if (!cfg.ok) throw new HttpError(503, cfg.problem);
    const ts = req.headers.get('x-webhook-timestamp'), sig = req.headers.get('x-webhook-signature');
    if (!(await verifyCashfreeSignature(cfg.secret, ts, raw, sig))) throw new HttpError(400, 'invalid_signature');
    const tsMs = Number(ts) < 1e12 ? Number(ts) * 1000 : Number(ts);   // Cashfree sends epoch milliseconds; accept seconds too
    if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > 15 * 60 * 1000) throw new HttpError(400, 'stale_webhook');
    const evId = 'cf:' + (await sha256(ts + ':' + sig)).slice(0, 40);
    const fresh = await env.DB.prepare('INSERT INTO payment_events (id, at, type) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING RETURNING id').bind(evId, now(), str(body.type, 60)).first();
    if (!fresh) return [200, { ok: true, duplicate: true }];
    const orderId = body.data && body.data.order && body.data.order.order_id;
    const r = orderId ? await env.DB.prepare('SELECT * FROM repair_requests WHERE order_id = ?').bind(String(orderId)).first() : null;
    if (!r) {
      const bo = orderId ? await env.DB.prepare('SELECT * FROM billing_orders WHERE cf_order_id = ? OR id = ?').bind(String(orderId), String(orderId)).first() : null;
      if (bo && body.type === 'PAYMENT_SUCCESS_WEBHOOK') {
        const order = await cf(env, cfg, 'GET', '/orders/' + encodeURIComponent(bo.cf_order_id || bo.id));
        if (order.order_status === 'PAID' && Number(order.order_amount) === bo.amount && !bo.applied) {
          const nowStr = now();
          const sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE uid = ?').bind(bo.uid).first();
          let periodStart = nowStr;
          let periodEnd = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          if (sub && sub.status === 'active' && new Date(sub.period_end) > new Date()) {
            periodStart = sub.period_start;
            periodEnd = new Date(new Date(sub.period_end).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
          }
          await env.DB.prepare(`INSERT INTO subscriptions (uid, plan, status, period_start, period_end, updated_at)
            VALUES (?, ?, "active", ?, ?, ?)
            ON CONFLICT(uid) DO UPDATE SET plan=excluded.plan, status="active", period_start=excluded.period_start, period_end=excluded.period_end, updated_at=excluded.updated_at`)
            .bind(bo.uid, bo.plan, periodStart, periodEnd, nowStr).run();
          await env.DB.prepare('UPDATE billing_orders SET status="PAID", applied=1, paid_at=? WHERE id=?').bind(nowStr, bo.id).run();
          return [200, { ok: true, billing: true }];
        }
      }
      if (bo && /PAYMENT_FAILED|USER_DROPPED/.test(body.type || '')) {
        await env.DB.prepare('UPDATE billing_orders SET status = "FAILED", last_error = ? WHERE id = ?')
          .bind(String((body.data && body.data.payment && body.data.payment.payment_message) || 'declined or abandoned').slice(0, 120), bo.id).run().catch(() => {});
        return [200, { ok: true, billing: 'failed' }];
      }
      return [200, { ok: true, ignored: 'unknown_order' }];
    }
    if (body.type === 'PAYMENT_SUCCESS_WEBHOOK') { await confirmFromCashfree(env, cfg, r, 'webhook'); return [200, { ok: true }]; }
    if (/PAYMENT_FAILED|USER_DROPPED/.test(body.type || '') && !r.fulfilled_at && r.status !== 'cancelled') {
      r.status = 'payment_failed'; r.last_error = 'Payment did not complete: ' + String((body.data.payment && body.data.payment.payment_message) || 'declined or abandoned').slice(0, 120);
      await save(env, r, 'payment_failed', { via: 'webhook' }); return [200, { ok: true }];
    }
    await save(env, r, 'webhook_ignored', { event: str(body.type, 40) }); return [200, { ok: true }];
  }
  if (m === 'POST' && path === '/api/repair-requests') {
    const user = await requireAuth(req, env);
    await rate(1);
    const offer = OFFERS[body.offerId]; if (!offer) throw new HttpError(400, 'unknown_offer');
    const f = body.finding || {};
    const pid = str(body.projectId, 40), project = pid ? await env.DB.prepare('SELECT * FROM projects WHERE id = ? AND uid = ? AND status = ?').bind(pid, user.uid, 'scanned').first() : null;
    if (!project) throw new HttpError(404, 'project_not_found');
    const latest = await env.DB.prepare('SELECT result FROM project_scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1').bind(pid).first();
    const scan = latest ? JSON.parse(latest.result) : null;
    const actual = scan && Array.isArray(scan.findings) ? scan.findings.find(x => x.id === str(body.findingId, 80)) : null;
    if (!actual || !str(f.ruleId, 60) || actual.ruleId !== f.ruleId || actual.file !== safePath(str(f.file, 300)) || actual.line !== f.line || actual.title !== str(f.title, 160)) throw new HttpError(400, 'finding_not_in_project_scan');
    if (!body.consent || body.consent.scope !== true) throw new HttpError(400, 'consent_required');
    let evidence = null;
    if (body.consent.shareEvidence === true) {
      if (!Array.isArray(body.evidence) || body.evidence.length > 12) throw new HttpError(400, 'invalid_evidence');
      evidence = JSON.stringify(body.evidence.map(e => ({ n: Number(e.n) | 0, text: mask(String(e.text || '').slice(0, 400)) })));
    }
    const id = 'req_' + hex(crypto.getRandomValues(new Uint8Array(9))), token = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24)))).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
    const finding = JSON.stringify({ id: actual.id, ruleId: actual.ruleId, title: actual.title, severity: actual.severity, file: actual.file, line: actual.line });
    const events = JSON.stringify([{ type: 'created', at: now() }]);
    await env.DB.prepare('INSERT INTO repair_requests (id, token_hash, offer_id, status, finding, evidence, events, created_at, updated_at, uid, project_id, finding_id, scope) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, await sha256(token), offer.id, 'awaiting_payment', finding, evidence, events, now(), now(), user.uid, pid, actual.id, JSON.stringify({ findingIds: [actual.id] })).run();
    return [201, { request: pub(await load(env, id)), accessToken: token }];
  }
  const mm = path.match(/^\/api\/repair-requests\/(req_[0-9a-f]{18})(?:\/(order|verify|cancel|repair|files|download\.zip))?$/);
  if (!mm) return null;
  const r = await authed(env, req, mm[1], requireAuth); if (!r) throw new HttpError(404, 'not_found');
  const act = mm[2];
  if (m === 'GET' && !act) {
    const job = await env.DB.prepare('SELECT * FROM repair_jobs WHERE request_id = ? AND uid = ?').bind(r.id, r.uid).first();
    return [200, { request: pub(r), repair: job ? { status: job.status, jobId: job.id, summary: job.summary, validation: JSON.parse(job.validation), manifest: JSON.parse(job.manifest) } : null }];
  }
  if (act === 'repair' && m === 'POST') {
    if (!r.fulfilled_at || r.status !== 'submitted') throw new HttpError(409, 'payment_not_confirmed');
    const repair = await runPaidProjectRepair(env, { request: r, user: { uid: r.uid } });
    return [200, { paid: true, request: pub(await load(env, r.id)), repair }];
  }
  if ((act === 'files' || act === 'download.zip') && m === 'GET') {
    const job = await env.DB.prepare('SELECT * FROM repair_jobs WHERE request_id = ? AND uid = ?').bind(r.id, r.uid).first();
    if (!job || !['completed_with_limitations', 'completed'].includes(job.status)) throw new HttpError(404, 'repair_artifact_not_found');
    return repairDownload(env, { job, path: act === 'download.zip' ? null : new URL(req.url).searchParams.get('path') });
  }
  if (m !== 'POST') throw new HttpError(405, 'method_not_allowed');
  if (act === 'cancel') { if (r.fulfilled_at) throw new HttpError(409, 'already_paid'); if (r.status !== 'cancelled') { r.status = 'cancelled'; await save(env, r, 'cancelled'); } return [200, { request: pub(r) }]; }
  if (!cfg.ok) throw new HttpError(503, cfg.problem);
  if (act === 'order') {
    await rate(1);
    if (r.status === 'cancelled') throw new HttpError(409, 'cancelled');
    if (r.fulfilled_at) throw new HttpError(409, 'already_paid', { request: pub(r) });
    const phone = String(body.phone || '').replace(/\D/g, '');
    if (phone && !/^[6-9]\d{9}$/.test(phone)) throw new HttpError(400, 'invalid_phone');
    if (!r.order_id) {   // one Cashfree order per request; the amount comes from OFFERS, never from the browser
      const o = OFFERS[r.offer_id];
      if (!phone && cfg.live) throw new HttpError(400, 'phone_required');
      const origin = new URL(req.url).origin, https = origin.startsWith('https://');
      const order = await cf(env, cfg, 'POST', '/orders', {
        order_id: 'sf_' + r.id.slice(4), order_amount: o.amount, order_currency: o.currency, order_note: o.title,
        customer_details: { customer_id: 'sf_' + r.id.slice(4, 16), customer_phone: phone || '9999999999' },
        order_meta: Object.assign({}, https ? { notify_url: origin + '/api/webhooks/cashfree', return_url: origin + '/app.html?cf_order={order_id}' } : {})
      }).catch(e => { throw new HttpError(502, 'order_failed', { detail: e.cf || e.message }); });
      if (!order || order.order_id !== 'sf_' + r.id.slice(4) || Number(order.order_amount) !== o.amount || order.order_currency !== o.currency || !str(order.payment_session_id, 2000)) throw new HttpError(502, 'order_mismatch');
      r.order_id = order.order_id; r.cf_order_id = String(order.cf_order_id || ''); r.session = order.payment_session_id;
      await save(env, r, 'order_created');
      return [200, { orderId: r.order_id, paymentSessionId: order.payment_session_id, mode: cfg.mode, request: pub(r) }];
    }
    const again = await cf(env, cfg, 'GET', '/orders/' + encodeURIComponent(r.order_id)).catch(() => null);   // reuse the same order: fetch a fresh session
    if (!again || !again.payment_session_id) throw new HttpError(502, 'order_failed');
    if (again.order_status === 'PAID') { await confirmFromCashfree(env, cfg, r, 'order_reuse'); throw new HttpError(409, 'already_paid', { request: pub(await load(env, r.id)) }); }
    return [200, { orderId: r.order_id, paymentSessionId: again.payment_session_id, mode: cfg.mode, request: pub(r) }];
  }
  if (act === 'verify') {
    await rate(1);
    if (!r.order_id) throw new HttpError(400, 'no_order');
    const res = await confirmFromCashfree(env, cfg, r, 'checkout').catch(e => { throw new HttpError(502, 'verify_failed', { detail: e.cf || e.message }); });
    const cur = await load(env, r.id);
    if (!res.paid && body.outcome === 'failed' && !cur.fulfilled_at && cur.status !== 'cancelled') { cur.status = 'payment_failed'; cur.last_error = 'Payment did not complete. You can try again.'; await save(env, cur, 'payment_failed', { via: 'checkout' }); }
    return [200, { paid: res.paid, orderStatus: res.orderStatus || 'PAID', request: pub(await load(env, r.id)) }];
  }
  return null;
}
