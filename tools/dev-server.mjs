// Local server that runs the Cloudflare Worker (worker/index.js) in Node, without wrangler:
//   node tools/dev-server.mjs [--port=8788] [--dist] [--db=path|:memory:]
// - static files from the project root (or dist/site with --dist), with the same security headers as production
// - /api/* handled by the real Worker code
// - D1 replaced by node:sqlite (file .dev-data/memory.db by default), migrations applied on start
// - GEMINI_API_KEY read from the environment or from .dev.vars (git-ignored). It is never sent to the browser.
import http from 'node:http'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { handleApi } from '../worker/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function d1(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  class Stmt {
    constructor(sql, args) { this.sql = sql; this.args = args || []; }
    bind(...a) { return new Stmt(this.sql, a.map(v => v === undefined ? null : v)); }
    async all() { return { results: db.prepare(this.sql).all(...this.args) }; }
    async first() { return db.prepare(this.sql).get(...this.args) ?? null; }
    async run() { db.prepare(this.sql).run(...this.args); return { success: true }; }
    _run() { db.prepare(this.sql).run(...this.args); }
  }
  for (const f of fs.readdirSync(path.join(root, 'migrations')).sort()) db.exec(fs.readFileSync(path.join(root, 'migrations', f), 'utf8'));
  return { prepare: sql => new Stmt(sql), batch: async stmts => { db.exec('BEGIN'); try { for (const s of stmts) s._run(); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; } return []; }, _db: db };
}
export function localProjectBucket(dir) {
  const root = path.resolve(dir); fs.mkdirSync(root, { recursive: true });
  const objectPath = key => {
    if (typeof key !== 'string' || !/^[a-z0-9_-]+\/[a-f0-9]{24}$/.test(key)) throw new Error('invalid object key');
    const full = path.resolve(root, ...key.split('/'));
    if (!full.startsWith(root + path.sep)) throw new Error('invalid object key');
    return full;
  };
  return {
    async put(key, value) { const full = objectPath(key); fs.mkdirSync(path.dirname(full), { recursive: true }); fs.writeFileSync(full, Buffer.from(value)); },
    async get(key) {
      const full = objectPath(key); if (!fs.existsSync(full)) return null;
      const bytes = fs.readFileSync(full);
      return { text: async () => bytes.toString('utf8'), arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), body: bytes };
    },
    async delete(key) { const full = objectPath(key); if (fs.existsSync(full)) fs.unlinkSync(full); }
  };
}
export function readDevVars(file = path.join(root, '.dev.vars')) {
  const out = {}; if (!fs.existsSync(file)) return out;
  for (const l of fs.readFileSync(file, 'utf8').split(/\r?\n/)) { const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*"?(.*?)"?\s*$/); if (m) out[m[1]] = m[2]; }
  return out;
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.md': 'text/markdown; charset=utf-8' };
const CSP = "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const CSP_APP = "default-src 'none'; script-src 'self' 'unsafe-inline' https://sdk.cashfree.com https://*.cashfree.com; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://*.cashfree.com https://sandbox.cashfree.com; connect-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com https://api.cashfree.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; frame-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; child-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; object-src 'none'; base-uri 'none'; form-action 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; frame-ancestors 'none'";
const CSP_DASHBOARD = "default-src 'none'; script-src 'self' 'unsafe-inline' https://sdk.cashfree.com https://*.cashfree.com; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://*.cashfree.com https://sandbox.cashfree.com https://avatars.githubusercontent.com; connect-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com https://api.cashfree.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; frame-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; child-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; object-src 'none'; base-uri 'none'; form-action 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; frame-ancestors 'none'";

export function createDevServer({ env, staticDir }) {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
      if (url.pathname.startsWith('/api/')) {
        const chunks = []; for await (const c of req) chunks.push(c);
        const headers = new Headers(); for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
        headers.set('cf-connecting-ip', req.socket.remoteAddress || 'local');
        const r = await handleApi(new Request(url, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), env);
        res.writeHead(r.status, Object.fromEntries(r.headers)); return res.end(Buffer.from(await r.arrayBuffer()));
      }
      let rel = decodeURIComponent(url.pathname); if (rel === '/') rel = '/index.html'; if (rel === '/app') rel = '/app.html'; if (rel === '/dashboard') rel = '/dashboard.html';
      const safe = path.normalize(rel).replace(/^([/\\])+/, '');
      if (safe.startsWith('..') || !/^(index\.html|app\.html|dashboard\.html|src[/\\][\w.-]+\.(js|css))$/.test(safe)) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('Not found'); }
      let data = fs.readFileSync(path.join(staticDir, safe));
      if (safe.endsWith('.html')) data = Buffer.from(String(data).replace(/<meta http-equiv="Content-Security-Policy"[^>]*>\n?/, ''));
      const cspHeader = safe === 'dashboard.html' ? CSP_DASHBOARD : (safe === 'app.html' ? CSP_APP : CSP + "; connect-src 'none'");
      res.writeHead(200, { 'content-type': MIME[path.extname(safe)] || 'application/octet-stream', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
        ...(safe.endsWith('.html') ? { 'content-security-policy': cspHeader } : {}) });
      res.end(data);
    } catch (e) { console.error('dev-server error', e.message); res.writeHead(500, { 'content-type': 'text/plain' }); res.end('Internal error'); }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const opt = Object.fromEntries(process.argv.slice(2).map(a => a.replace(/^--/, '').split('=')).map(([k, v]) => [k, v ?? true]));
  const vars = { ...readDevVars(), ...process.env };
  const env = {
    ENVIRONMENT: 'development',
    GEMINI_API_KEY: vars.GEMINI_API_KEY || '',
    GEMINI_MODELS: vars.GEMINI_MODELS,
    RATE_PER_HOUR: vars.RATE_PER_HOUR || '1000',
    CASHFREE_APP_ID: vars.CASHFREE_APP_ID || '',
    CASHFREE_SECRET_KEY: vars.CASHFREE_SECRET_KEY || '',
    CASHFREE_ENV: vars.CASHFREE_ENV || 'sandbox',
    ALLOW_LIVE_PAYMENTS: vars.ALLOW_LIVE_PAYMENTS || '',
    FIREBASE_API_KEY: vars.FIREBASE_API_KEY || '',
    FIREBASE_PROJECT_ID: vars.FIREBASE_PROJECT_ID || '',
    FIREBASE_AUTH_DOMAIN: vars.FIREBASE_AUTH_DOMAIN || '',
    GITHUB_CLIENT_ID: vars.GITHUB_CLIENT_ID || '',
    GITHUB_CLIENT_SECRET: vars.GITHUB_CLIENT_SECRET || '',
    TOKEN_ENC_KEY: vars.TOKEN_ENC_KEY || '',
    GITHUB_WEBHOOK_SECRET: vars.GITHUB_WEBHOOK_SECRET || '',
    PUBLIC_URL: vars.PUBLIC_URL || '',
    ALERT_FROM: vars.ALERT_FROM || '',
    RESEND_API_KEY: vars.RESEND_API_KEY || '',
    DB: d1(opt.db || path.join(root, '.dev-data', 'memory.db')),
    PROJECTS: localProjectBucket(path.join(root, '.dev-data', 'project-objects'))
  };
  const port = +(opt.port || 8788), staticDir = opt.dist ? path.join(root, 'dist', 'site') : root;
  createDevServer({ env, staticDir }).listen(port, '127.0.0.1', () => {
    console.log(`SecureFlow dev server: http://127.0.0.1:${port}/  (workspace: /app.html)`);
    console.log(`AI deep check: ${env.GEMINI_API_KEY ? 'on (key loaded from ' + (process.env.GEMINI_API_KEY ? 'environment' : '.dev.vars') + ')' : 'off (add GEMINI_API_KEY to .dev.vars)'} · Codebase memory: local SQLite`);
  });
}
