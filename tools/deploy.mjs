// One-command Cloudflare deployment:  npm run deploy
// 1. builds dist/site  2. logs in to Cloudflare if needed (opens your browser)  3. creates the D1 database "secureflow-memory"
// once and writes its id into wrangler.toml  4. applies migrations  5. deploys the Worker  6. uploads GEMINI_API_KEY from
// .dev.vars (or the environment) as an encrypted Worker secret. The key is never written into the site or into git.
import { spawnSync } from 'node:child_process'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
import { readDevVars } from './dev-server.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const win = process.platform === 'win32';
function wr(args, opts = {}) {
  const r = spawnSync(win ? 'npx.cmd' : 'npx', ['wrangler', ...args], { cwd: root, encoding: 'utf8', shell: win, stdio: opts.capture ? ['inherit', 'pipe', 'pipe'] : (opts.input !== undefined ? ['pipe', 'inherit', 'inherit'] : 'inherit'), input: opts.input });
  if (opts.capture && r.stdout) process.stdout.write(opts.quiet ? '' : r.stdout);
  if (r.status !== 0 && !opts.allowFail) { console.error(`\n✗ wrangler ${args.join(' ')} failed${r.stderr ? ':\n' + r.stderr : ''}`); process.exit(1); }
  return r;
}
const step = t => console.log('\n▸ ' + t);

step('Building the site'); if (spawnSync(process.execPath, ['tools/build.mjs'], { cwd: root, stdio: 'inherit' }).status !== 0) process.exit(1);

step('Checking your Cloudflare login');
const who = wr(['whoami'], { capture: true, allowFail: true, quiet: true });
if (who.status !== 0 || /not authenticated|not logged in/i.test((who.stdout || '') + (who.stderr || ''))) wr(['login']); else console.log('  logged in');

step('Database (Cloudflare D1)');
const tomlPath = path.join(root, 'wrangler.toml'); let toml = fs.readFileSync(tomlPath, 'utf8');
if (toml.includes('REPLACE_WITH_D1_ID')) {
  let id = null;
  const list = wr(['d1', 'list', '--json'], { capture: true, allowFail: true, quiet: true });
  try { const found = JSON.parse(list.stdout).find(d => d.name === 'secureflow-memory'); if (found) id = found.uuid; } catch {}
  if (!id) { const c = wr(['d1', 'create', 'secureflow-memory'], { capture: true }); const m = (c.stdout + c.stderr).match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/); id = m && m[0]; }
  if (!id) { console.error('Could not read the new database id. Run `npx wrangler d1 list` and paste the id into wrangler.toml (database_id).'); process.exit(1); }
  toml = toml.replace('REPLACE_WITH_D1_ID', id); fs.writeFileSync(tomlPath, toml); console.log('  database_id ' + id + ' written to wrangler.toml');
} else console.log('  using the database already in wrangler.toml');
wr(['d1', 'migrations', 'apply', 'secureflow-memory', '--remote'], { input: 'y\n' });

step('Deploying the Worker'); const dep = wr(['deploy'], { capture: true });
const url = (dep.stdout.match(/https:\/\/[^\s]+\.workers\.dev/) || [])[0];

step('Secrets (encrypted Worker secrets)');
const vars = { ...readDevVars(), ...process.env };
for (const name of ['GEMINI_API_KEY', 'CASHFREE_APP_ID', 'CASHFREE_SECRET_KEY', 'GITHUB_CLIENT_SECRET', 'TOKEN_ENC_KEY', 'GITHUB_WEBHOOK_SECRET', 'RESEND_API_KEY']) {
  if (vars[name]) { wr(['secret', 'put', name], { input: vars[name] + '\n' }); console.log('  ' + name + ' uploaded'); }
  else console.log('  ' + name + ' skipped: add it to .dev.vars and run `npm run deploy` again.');
}
if (vars.CASHFREE_ENV === 'production') console.log('  CASHFREE_ENV=production is NOT uploaded by this script. Live payments need owner approval; set CASHFREE_ENV and ALLOW_LIVE_PAYMENTS in the dashboard deliberately.');

console.log(`\n✓ SecureFlow is live${url ? ' at ' + url : ''}.\n  Workspace: ${url ? url + '/app' : '/app'}\n  Check: ${url ? url + '/api/health' : '/api/health'} should say "ai": true and "memory": true.`);
