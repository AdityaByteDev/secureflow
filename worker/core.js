// Shared Worker helpers: HTTP errors and JSON responses, masking, hashing, Gemini client with model fallback, rate limits.
import '../src/engine.js';
export const E = globalThis.SFEngine;
export const DEFAULT_MODELS = 'gemini-3.5-flash-lite,gemini-3.5-flash,gemini-3.1-flash-lite,gemini-flash-lite-latest,gemini-3-flash-preview,gemini-3.8-flash,gemini-3.7-flash,gemini-3.6-flash,gemini-flash-latest';
export const LIMITS = { body: 1_500_000, aiChars: 360_000, files: 300, lines: 120_000, issues: 60, history: 8, question: 1200, ratePerHour: 150 };
export const SEV = ['critical', 'high', 'medium', 'low', 'info'];
/* ------------------------------ helpers ------------------------------ */
export const HDR = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' };
export const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: HDR });
export const err = (status, error, extra) => json(Object.assign({ error }, extra || {}), status);
export class HttpError extends Error { constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra; } }
export const str = (v, max) => typeof v === 'string' && v.length <= max ? v : '';
export const clampN = (v, a, b, d) => { v = Number(v); return Number.isFinite(v) ? Math.min(b, Math.max(a, v)) : d; };
export async function sha(text) { const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)); return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join(''); }
export const norm = s => String(s || '').replace(/\s+/g, ' ').trim();
export const maskText = s => String(s || '').split('\n').map(E.mask).join('\n');
// "no full fixes" guard: the assistant explains how to fix; long code blocks are removed from every text it returns
export function stripLongCode(s) {
  return String(s || '').replace(/```(?:[\w-]*\n)?([\s\S]*?)```/g, (m, body) => body.trim().split('\n').length > 4
    ? '[code example removed: SecureFlow explains the fix, you write it]' : '`' + body.trim().replace(/\n/g, ' ⏎ ') + '`');
}
export function deepStrip(v) { if (typeof v === 'string') return stripLongCode(maskText(v)).slice(0, 4000); if (Array.isArray(v)) return v.map(deepStrip); if (v && typeof v === 'object') { const o = {}; for (const k in v) o[k] = deepStrip(v[k]); return o; } return v; }

/* ------------------------------ Gemini ------------------------------ */
export async function gemini(env, { system, user, schema, temperature = 0.2, onStatus = () => {}, timeoutMs = 25_000 }) {
  if (!env.GEMINI_API_KEY) throw new HttpError(503, 'ai_not_configured');
  const models = String(env.GEMINI_MODELS || DEFAULT_MODELS).split(',').map(s => s.trim()).filter(Boolean);
  const doFetch = env.fetch || fetch;
  let last = 'no_model';
  for (const model of models) {
    let thinking = true;
    for (let attempt = 0; attempt < 2; attempt++) {
      const gc = { temperature, responseMimeType: 'application/json', responseSchema: schema };
      if (thinking) gc.thinkingConfig = { thinkingLevel: 'low' };
      let r, timer, controller = new AbortController();
      onStatus({ state: 'request_sent', model, attempt: attempt + 1 });
      try {
        timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
        r = await doFetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
          method: 'POST', headers: { 'content-type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
          body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents: [{ role: 'user', parts: [{ text: user }] }], generationConfig: gc }), signal: controller.signal
        });
      } catch (e) { clearTimeout(timer); last = controller.signal.aborted ? 'timeout' : 'network'; onStatus({ state: last, model }); if (attempt < 1) continue; break; }
      finally { clearTimeout(timer); }
      onStatus({ state: 'response_received', model, status: r.status });
      if (r.status === 429 || r.status >= 500) { last = 'busy_' + r.status; if (attempt < 1) continue; break; }
      const j = await r.json().catch(() => ({}));
      if (r.status === 400 && thinking && /think/i.test(JSON.stringify(j))) { thinking = false; continue; }
      if (!r.ok) { last = 'http_' + r.status; if ([401, 403].includes(r.status)) { onStatus({ state: 'failed', model, status: r.status, detail: last }); throw new HttpError(502, 'gemini_auth_failed', { providerStatus: r.status }); } break; }
      const cand = j.candidates && j.candidates[0];
      const text = ((cand && cand.content && cand.content.parts) || []).filter(p => !p.thought).map(p => p.text || '').join('');
      try { const data = JSON.parse(text); onStatus({ state: 'response_validated', model }); return { data, model }; } catch { last = 'bad_json'; onStatus({ state: 'invalid_response', model }); continue; }
    }
  }
  throw new HttpError(503, 'ai_unavailable', { detail: last });
}

export const S = { // Gemini responseSchema helpers (OpenAPI subset)
  s: d => ({ type: 'STRING', description: d }), n: d => ({ type: 'NUMBER', description: d }), i: d => ({ type: 'INTEGER', description: d }), b: d => ({ type: 'BOOLEAN', description: d }),
  a: (items, d) => ({ type: 'ARRAY', items, description: d }), o: (properties, required, d) => ({ type: 'OBJECT', properties, required: required || Object.keys(properties), description: d }),
  e: (vals, d) => ({ type: 'STRING', enum: vals, description: d })
};
/* ------------------------------ rate limit ------------------------------ */
export const memRate = new Map();
export async function rate(env, req, units) {
  const ip = req.headers.get('cf-connecting-ip') || 'local', hour = Math.floor(Date.now() / 3.6e6);
  const k = (await sha('rl:' + ip)).slice(0, 20) + ':' + hour, limit = clampN(env.RATE_PER_HOUR, 1, 1e6, LIMITS.ratePerHour);
  let n;
  if (env.DB) { const r = await env.DB.prepare('INSERT INTO rate (k, n) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET n = n + excluded.n RETURNING n').bind(k, units).first(); n = r ? r.n : units; }
  else { n = (memRate.get(k) || 0) + units; memRate.set(k, n); }
  if (n > limit) throw new HttpError(429, 'rate_limited', { retryAfterMinutes: 60 - new Date().getMinutes() });
}

