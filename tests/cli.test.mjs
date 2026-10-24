// CLI pass/fail behaviour.  Run: node --test tests/cli.test.mjs
import test from 'node:test'; import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'secureflow-cli.mjs');
const run = (...a) => spawnSync(process.execPath, [CLI, ...a], { encoding: 'utf8' });
function proj(files) { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-cli-')); for (const [n, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, n)), { recursive: true }); fs.writeFileSync(path.join(d, n), c); } return d; }

test('exit 1 when findings meet the threshold; JSON is machine-readable and masked', () => {
  const d = proj({ 'src/a.js': 'const k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";\neval(x);', 'node_modules/x/i.js': 'eval(y)' });
  const r = run(d, '--format=json'); assert.equal(r.status, 1, r.stderr);
  const j = JSON.parse(r.stdout); assert.equal(j.counts.critical, 2); assert.ok(!r.stdout.includes('51Hx9aQ2eZ'));
  assert.ok(j.skipped.some(s => s.path.startsWith('node_modules')), 'dependency folder excluded');
});
test('exit 0 when only findings below the threshold', () => {
  const d = proj({ 'a.js': "fetch('http://api.x.io');" });
  assert.equal(run(d, '--fail-on=high').status, 0); assert.equal(run(d, '--fail-on=low').status, 1); assert.equal(run(d, '--fail-on=none').status, 0);
});
test('min-confidence filters low-confidence findings', () => {
  const d = proj({ 'a.js': "app.delete('/admin/users', (req, res) => {});" });
  assert.equal(run(d, '--fail-on=medium').status, 1); assert.equal(run(d, '--fail-on=medium', '--min-confidence=medium').status, 0);
});
test('usage errors and empty projects exit 2; --strict exits 3 on partial coverage', () => {
  assert.equal(run().status, 2); assert.equal(run('/definitely/missing').status, 2); assert.equal(run(proj({ 'a.js': 'x' }), '--fail-on=bogus').status, 2);
  assert.equal(run(proj({ 'README.md': '# hi' })).status, 2);
  const d = proj({ 'a.js': 'const a = 1;', 'b.js': '' });
  assert.equal(run(d).status, 0); assert.equal(run(d, '--strict').status, 3);
});
test('text output names file:line:column and states the limitation', () => {
  const r = run(proj({ 'x/y.js': '  el.innerHTML = v;' }), '--fail-on=none');
  assert.match(r.stdout, /x\/y\.js:1:3/); assert.match(r.stdout, /not a full audit/);
});
