// GitHub OAuth App integration: OAuth (state + CSRF), encrypted tokens, REST client with rate-limit handling,
// repository authorisation (from the user's own token, never a username), tarball download + untar, and a safe
// commit/PR push using the Git Data API (fast-forward only, never force, never merge).
import { HttpError, E } from './core.js';

const te = new TextEncoder(), td = new TextDecoder();
export const b64 = u8 => btoa(String.fromCharCode(...u8));
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
export const randomHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
export async function sha256hex(t) { return hex(await crypto.subtle.digest('SHA-256', te.encode(t))); }
export function safeEq(a, b) { a = String(a || ''); b = String(b || ''); if (!a || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
export async function hmacHex(secret, data) { const k = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return hex(await crypto.subtle.sign('HMAC', k, te.encode(data))); }

/* ---------- token encryption (AES-256-GCM, key = TOKEN_ENC_KEY base64 32 bytes) ---------- */
async function encKey(env) {
  const raw = env.TOKEN_ENC_KEY ? unb64(env.TOKEN_ENC_KEY) : null;
  if (!raw || raw.length !== 32) throw new HttpError(503, 'token_key_not_configured');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function encrypt(env, text) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await encKey(env), te.encode(text))); const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return b64(out); }
export async function decrypt(env, s) { const u = unb64(s); return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12) }, await encKey(env), u.subarray(12))); }

/* ---------- configuration ---------- */
export function ghConfig(env) { return { ok: !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET && env.TOKEN_ENC_KEY), clientId: env.GITHUB_CLIENT_ID || '', secret: env.GITHUB_CLIENT_SECRET || '', webhookSecret: env.GITHUB_WEBHOOK_SECRET || '' }; }
export const SCOPES = { public: 'read:user public_repo admin:repo_hook', private: 'read:user repo' };

/* ---------- REST client ---------- */
export async function gh(env, token, method, path, body, opts = {}) {
  const url = path.startsWith('https://') ? path : 'https://api.github.com' + path;
  const headers = { accept: opts.accept || 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'SecureFlow' };
  if (token) headers.authorization = 'Bearer ' + token;
  if (body !== undefined) headers['content-type'] = 'application/json';
  let r;
  try { r = await (env.fetch || fetch)(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'follow' }); }
  catch (e) { throw new HttpError(502, 'github_unreachable'); }
  if ((r.status === 403 || r.status === 429) && (r.headers.get('x-ratelimit-remaining') === '0' || r.headers.get('retry-after'))) {
    const reset = Number(r.headers.get('x-ratelimit-reset')) || Math.floor(Date.now() / 1000) + Number(r.headers.get('retry-after') || 60);
    throw new HttpError(429, 'github_rate_limited', { resetAt: new Date(reset * 1000).toISOString() });
  }
  if (r.status === 401) throw new HttpError(401, 'github_token_invalid');
  if (opts.raw) { if (!r.ok) throw ghError(r.status, await r.text().catch(() => '')); return r; }
  const text = await r.text(); let j = null; try { j = text ? JSON.parse(text) : null; } catch { j = null; }
  if (!r.ok) { if (opts.allow && opts.allow.includes(r.status)) return { _status: r.status, ...(j || {}) }; throw ghError(r.status, j && j.message); }
  return j;
}
function ghError(status, message) {
  const code = status === 404 ? 'github_not_found' : status === 403 ? 'github_forbidden' : status === 409 ? 'github_conflict' : status === 422 ? 'github_unprocessable' : 'github_error';
  return new HttpError(status === 404 ? 404 : status === 403 ? 403 : status === 409 || status === 422 ? 409 : 502, code, { detail: String(message || '').slice(0, 200) });
}
export const encPath = p => p.split('/').map(encodeURIComponent).join('/');

/* ---------- OAuth ---------- */
export function authorizeUrl(env, { state, scope, redirectUri }) {
  const u = new URL('https://github.com/login/oauth/authorize');
  u.searchParams.set('client_id', env.GITHUB_CLIENT_ID); u.searchParams.set('redirect_uri', redirectUri); u.searchParams.set('scope', SCOPES[scope] || SCOPES.public);
  u.searchParams.set('state', state); u.searchParams.set('allow_signup', 'false');
  return u.toString();
}
export async function exchangeCode(env, code, redirectUri) {
  const r = await (env.fetch || fetch)('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'SecureFlow' },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: redirectUri }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new HttpError(400, 'github_code_exchange_failed', { detail: String(j.error || r.status) });
  return { token: j.access_token, scopes: String(j.scope || '').split(/[ ,]+/).filter(Boolean) };
}
export async function revokeGrant(env, token) {   // removes SecureFlow's authorisation from the user's GitHub account
  const r = await (env.fetch || fetch)(`https://api.github.com/applications/${env.GITHUB_CLIENT_ID}/grant`, { method: 'DELETE',
    headers: { authorization: 'Basic ' + btoa(env.GITHUB_CLIENT_ID + ':' + env.GITHUB_CLIENT_SECRET), accept: 'application/vnd.github+json', 'content-type': 'application/json', 'user-agent': 'SecureFlow' }, body: JSON.stringify({ access_token: token }) }).catch(() => null);
  return !!r && (r.status === 204 || r.status === 404);
}

/* ---------- repository authorisation: always from the user's token ---------- */
export async function authorizedRepo(env, token, ghRepoId, need = 'pull') {
  const repo = await gh(env, token, 'GET', '/repositories/' + Number(ghRepoId), undefined, { allow: [404] });
  if (!repo || repo._status === 404) throw new HttpError(403, 'repo_not_authorized');
  if (repo.id !== Number(ghRepoId)) throw new HttpError(403, 'repo_identity_mismatch');
  const p = repo.permissions || {};
  if (need === 'push' && !p.push) throw new HttpError(403, 'missing_push_permission');
  if (need === 'admin' && !p.admin) throw new HttpError(403, 'missing_admin_permission');
  if (!p.pull && !p.push && !p.admin) throw new HttpError(403, 'repo_not_authorized');
  return repo;
}
export async function listRepos(env, token) {
  const out = [];
  for (let page = 1; page <= 5; page++) {
    const r = await gh(env, token, 'GET', `/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member&page=${page}`);
    out.push(...r.map(x => ({ id: x.id, full_name: x.full_name, private: x.private, default_branch: x.default_branch, pushed_at: x.pushed_at, permissions: { admin: !!(x.permissions || {}).admin, push: !!(x.permissions || {}).push } })));
    if (r.length < 100) break;
  }
  return out;
}
export async function branchHead(env, token, full, branch) {
  const r = await gh(env, token, 'GET', `/repos/${full}/branches/${encodeURIComponent(branch)}`, undefined, { allow: [404] });
  if (!r || r._status === 404) throw new HttpError(404, 'branch_not_found');
  return r.commit.sha;
}

/* ---------- tarball: download, gunzip (bounded), untar ---------- */
const MAX_GZ = 30 * 1024 * 1024, MAX_TAR = 120 * 1024 * 1024;
async function readBounded(stream, max, code) {
  const reader = stream.getReader(), parts = []; let n = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; if (n > max) { reader.cancel(); throw new HttpError(413, code); } parts.push(value); }
  const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out;
}
export function* untar(u8) {
  let off = 0, longName = null, paxPath = null;
  const field = (h, a, b) => td.decode(h.subarray(a, b)).replace(/\0[\s\S]*$/, '');
  while (off + 512 <= u8.length) {
    const h = u8.subarray(off, off + 512); if (h.every(b => b === 0)) break;
    let name = field(h, 0, 100); const size = parseInt(field(h, 124, 136).trim() || '0', 8) || 0, type = String.fromCharCode(h[156] || 48), prefix = field(h, 345, 500);
    if (prefix) name = prefix + '/' + name;
    const start = off + 512, data = u8.subarray(start, start + size); off = start + Math.ceil(size / 512) * 512;
    if (type === 'L') { longName = field(data, 0, data.length); continue; }
    if (type === 'x') { const m = td.decode(data).match(/\d+ path=([^\n]*)\n/); paxPath = m ? m[1] : null; continue; }
    if (type === 'g') continue;
    const full = paxPath || longName || name; paxPath = longName = null;
    if (type === '0' || type === '\0' || type === '7') yield { path: full, data };
  }
}
export async function fetchRepoFiles(env, token, full, sha) {
  const r = await gh(env, token, 'GET', `/repos/${full}/tarball/${sha}`, undefined, { raw: true });
  const gz = await readBounded(r.body, MAX_GZ, 'repo_too_large');
  const tar = await readBounded(new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip')), MAX_TAR, 'repo_too_large');
  const entries = []; for (const e of untar(tar)) { const p = e.path.split('/').slice(1).join('/'); if (p) entries.push({ path: p, size: e.data.length, data: e.data }); }
  const v = E.validateIncoming(entries.map(e => ({ path: e.path, size: e.size })));
  const byPath = new Map(entries.map(e => [e.path, e]));
  const files = [], skipped = v.skipped.slice(); let total = 0;
  for (const k of v.keep) {
    const text = td.decode(byPath.get(k.path).data);
    if (!text.trim()) skipped.push({ path: k.path, reason: 'empty' });
    else if (E.isBinary(text)) skipped.push({ path: k.path, reason: 'binary' });
    else if (total + text.length > E.LIMITS.maxTotalBytes) skipped.push({ path: k.path, reason: 'over-total-size' });
    else { total += text.length; files.push({ name: k.path, code: text }); }
  }
  return { files, skipped, entries: entries.length };
}
export async function fileAt(env, token, full, path, ref) {
  const r = await gh(env, token, 'GET', `/repos/${full}/contents/${encPath(path)}?ref=${encodeURIComponent(ref)}`, undefined, { allow: [404] });
  if (!r || r._status === 404 || r.type !== 'file') throw new HttpError(404, 'file_not_found_in_repo');
  const bytes = unb64(String(r.content || '').replace(/\n/g, ''));
  return { text: td.decode(bytes), blobSha: r.sha };
}
async function fileMode(env, token, full, treeSha, path) {   // keep the existing file mode (e.g. executable bit)
  let tree = treeSha; const parts = path.split('/');
  for (let i = 0; i < parts.length; i++) {
    const t = await gh(env, token, 'GET', `/repos/${full}/git/trees/${tree}`);
    const ent = (t.tree || []).find(x => x.path === parts[i]); if (!ent) return '100644';
    if (i === parts.length - 1) return ent.mode === '100755' ? '100755' : '100644';
    tree = ent.sha;
  }
  return '100644';
}

/* ---------- push: one approved patch → one commit (fix branch + PR, or fast-forward direct push) ---------- */
export async function pushCommit(env, token, { full, targetBranch, mode, baseSha, path, newText, message, fixBranch, prTitle, prBody, expectedBlobAtHead }) {
  const head = await branchHead(env, token, full, targetBranch);
  const headCommit = await gh(env, token, 'GET', `/repos/${full}/git/commits/${head}`);
  const blob = await gh(env, token, 'POST', `/repos/${full}/git/blobs`, { content: newText, encoding: 'utf-8' });
  const mode0 = await fileMode(env, token, full, headCommit.tree.sha, path);
  const tree = await gh(env, token, 'POST', `/repos/${full}/git/trees`, { base_tree: headCommit.tree.sha, tree: [{ path, mode: mode0, type: 'blob', sha: blob.sha }] });
  const commit = await gh(env, token, 'POST', `/repos/${full}/git/commits`, { message, tree: tree.sha, parents: [head] });
  if (mode === 'direct') {
    const r = await gh(env, token, 'PATCH', `/repos/${full}/git/refs/heads/${encPath(targetBranch)}`, { sha: commit.sha, force: false }, { allow: [409, 422] });
    if (r && (r._status === 409 || r._status === 422)) throw new HttpError(409, 'branch_moved_during_push');   // someone pushed meanwhile: nothing overwritten
    return { head, commitSha: commit.sha, branch: targetBranch, prUrl: null, prNumber: null };
  }
  let branch = fixBranch, made = null;
  for (let i = 0; i < 5 && !made; i++) {
    const r = await gh(env, token, 'POST', `/repos/${full}/git/refs`, { ref: 'refs/heads/' + branch, sha: commit.sha }, { allow: [422] });
    if (r && r._status === 422) branch = fixBranch + '-' + randomHex(2); else made = r;
  }
  if (!made) throw new HttpError(409, 'fix_branch_exists');
  const pr = await gh(env, token, 'POST', `/repos/${full}/pulls`, { title: prTitle, head: branch, base: targetBranch, body: prBody, maintainer_can_modify: true });
  return { head, commitSha: commit.sha, branch, prUrl: pr.html_url, prNumber: pr.number };
}
export async function changedBetween(env, token, full, base, head) {
  if (base === head) return [];
  const c = await gh(env, token, 'GET', `/repos/${full}/compare/${base}...${head}`, undefined, { allow: [404] });
  if (!c || c._status === 404) throw new HttpError(409, 'base_commit_unknown');
  if (c.status === 'diverged' || c.status === 'behind') throw new HttpError(409, 'branch_history_rewritten');
  return (c.files || []).map(f => f.filename).concat((c.files || []).filter(f => f.previous_filename).map(f => f.previous_filename));
}

/* ---------- webhooks + CI results ---------- */
export async function verifyGithubSignature(secret, raw, header) { if (!secret || !header || !header.startsWith('sha256=')) return false; return safeEq('sha256=' + await hmacHex(secret, raw), header); }
export async function createHook(env, token, full, url) {
  return gh(env, token, 'POST', `/repos/${full}/hooks`, { name: 'web', active: true, events: ['push', 'check_run', 'status', 'deployment_status', 'meta'], config: { url, content_type: 'json', secret: env.GITHUB_WEBHOOK_SECRET, insecure_ssl: '0' } }, { allow: [403, 404, 422] });
}
export async function deleteHook(env, token, full, id) { if (id) await gh(env, token, 'DELETE', `/repos/${full}/hooks/${id}`, undefined, { allow: [404, 403] }).catch(() => null); }
export async function ciResults(env, token, full, sha) {
  const out = [];
  const runs = await gh(env, token, 'GET', `/repos/${full}/commits/${sha}/check-runs?per_page=100`, undefined, { allow: [403, 404] }).catch(() => null);
  if (runs && runs.check_runs) runs.check_runs.forEach(c => out.push({ name: c.name, status: c.status, conclusion: c.conclusion || null, url: c.html_url || null, source: 'check_run' }));
  const st = await gh(env, token, 'GET', `/repos/${full}/commits/${sha}/status`, undefined, { allow: [403, 404] }).catch(() => null);
  if (st && st.statuses) st.statuses.forEach(s => out.push({ name: s.context, status: s.state === 'pending' ? 'in_progress' : 'completed', conclusion: s.state === 'pending' ? null : (s.state === 'success' ? 'success' : 'failure'), url: s.target_url || null, source: 'status' }));
  return out;
}
