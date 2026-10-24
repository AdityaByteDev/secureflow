// Build:
//  dist/site/        files for Cloudflare Workers static assets (index.html, app.html, src/*, _headers)
//  dist/index.html   single self-contained landing page (scripts + CSS inlined)
//  dist/app.html     single self-contained workspace page (local engine only; AI and memory need the Worker)
// No bundler needed. Usage: node tools/build.mjs
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rd = rel => fs.readFileSync(path.join(root, rel), 'utf8');
const out = (rel, data) => { const p = path.join(root, 'dist', rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, data); };

// 1. static site for the Worker
const site = ['index.html', 'app.html', 'dashboard.html', 'src/site.css', 'src/engine.js', 'src/demo.js', 'src/common.js', 'src/story.js', 'src/cloth.js', 'src/workspace.js', 'src/ai.js', 'src/dashboard.js'];
fs.rmSync(path.join(root, 'dist', 'site'), { recursive: true, force: true });
for (const f of site) out('site/' + f, rd(f));
const CSP_BASE = "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
// the workspace may additionally load Cashfree's hosted checkout (script, API calls from that script, and its payment frame)
const CSP_APP = "default-src 'none'; script-src 'self' 'unsafe-inline' https://sdk.cashfree.com https://*.cashfree.com; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://*.cashfree.com https://sandbox.cashfree.com; connect-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com https://api.cashfree.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; frame-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; child-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; object-src 'none'; base-uri 'none'; form-action 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; frame-ancestors 'none'";
const CSP_DASH = "default-src 'none'; script-src 'self' 'unsafe-inline' https://sdk.cashfree.com https://*.cashfree.com; worker-src blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://*.cashfree.com https://sandbox.cashfree.com https://avatars.githubusercontent.com; connect-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com https://api.cashfree.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; frame-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; child-src 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; object-src 'none'; base-uri 'none'; form-action 'self' https://*.cashfree.com https://sandbox.cashfree.com https://payments-test.cashfree.com https://payments.cashfree.com; frame-ancestors 'none'";
out('site/_headers', `/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
/
  Content-Security-Policy: ${CSP_BASE}; connect-src 'none'
/index.html
  Content-Security-Policy: ${CSP_BASE}; connect-src 'none'
/app.html
  Content-Security-Policy: ${CSP_APP}
/app
  Content-Security-Policy: ${CSP_APP}
/dashboard.html
  Content-Security-Policy: ${CSP_DASH}
/dashboard
  Content-Security-Policy: ${CSP_DASH}
`);

// 2. single-file pages
function inline(file, expect) {
  let html = rd(file), n = 0;
  html = html.replace(/<script src="(src\/[\w.-]+\.js)"><\/script>/g, (m, rel) => {
    n++; return `<script>/* ${rel} */\n${rd(rel).replace(/<\/script/gi, '<\\/script').replace(/<!--/g, '<\\!--')}\n</script>`;
  });
  html = html.replace(/<link rel="stylesheet" href="src\/site\.css">/, () => `<style>\n${rd('src/site.css').replace(/<\/style/gi, '<\\/style')}\n</style>`);
  if (n !== expect) throw new Error(`${file}: expected to inline ${expect} scripts, inlined ${n}`);
  if (/<script src="src\//.test(html) || /href="src\/site\.css"/.test(html)) throw new Error(file + ': un-inlined local file left');
  for (const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) if (m[1].includes('<!--')) throw new Error(file + ': inline script contains <!--');
  out(file, html);
  console.log(`dist/${file} written (${(html.length / 1024).toFixed(1)} KB, ${n} scripts inlined)`);
}
inline('index.html', 5);
inline('app.html', 5);
console.log(`dist/site/ written (${site.length} files + _headers)`);
