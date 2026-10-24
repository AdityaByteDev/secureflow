// Unit tests for src/engine.js. Run with:  node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import zlib from 'node:zlib';
const require = createRequire(import.meta.url);
const E = require('../src/engine.js')();

const scan1 = (name, code) => E.scanFile({ name, code }).findings || [];
const ids = (name, code) => scan1(name, code).map(f => f.ruleId);

/* ----------------------------------------------------------- every rule */
// [ruleId, file, positive code, negative code]
const CASES = [
  ['hardcoded-secret', 'a.js', 'const STRIPE_SECRET = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";', 'const STRIPE_SECRET = process.env.STRIPE_SECRET;'],
  ['hardcoded-secret', 'a.py', 'password = "Sup3rS3cret!2026"', 'password = os.environ["DB_PASSWORD"]'],
  ['public-env-secret', 'a.js', 'const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE;', 'const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;'],
  ['db-credentials-url', 'a.js', 'const url = "postgres://admin:hunter2pass@db.internal/app";', 'const url = process.env.DATABASE_URL;'],
  ['env-file', '.env', 'STRIPE_SECRET=sk_test_123456789', '# only a comment'],
  ['sql-injection', 'a.js', "const sql = `SELECT * FROM orders WHERE id = '${req.query.id}'`;", "const sql = 'SELECT * FROM orders WHERE id = $1';"],
  ['sql-injection', 'a.py', 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")', 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'],
  ['nosql-injection', 'a.js', "return users.findOne(req.body);", "return users.findOne({ email: String(req.body.email) });"],
  ['command-injection', 'a.js', 'exec(`convert ${req.query.file} out.png`);', "execFile('convert', [file, 'out.png']);"],
  ['command-injection', 'a.py', 'subprocess.run(cmd, shell=True)', 'subprocess.run(["ls", path])'],
  ['code-eval', 'a.js', 'const r = eval(req.body.expr);', 'const r = evaluateMath(req.body.expr);'],
  ['code-eval', 'a.py', 'result = eval(request.args["q"])', 'result = ast.literal_eval(value)'],
  ['ssrf', 'a.js', 'const r = await fetch(req.query.url);', "const r = await fetch('https://api.example.com/x');"],
  ['path-traversal', 'a.js', "res.sendFile('/files/' + req.query.name);", "res.sendFile(path.basename(name), { root: '/files' });"],
  ['insecure-deserialization', 'a.py', 'obj = pickle.loads(request.data)', 'obj = json.loads(request.data)'],
  ['reflected-xss', 'a.js', 'res.send(`<h1>${req.body.title}</h1>`);', 'res.json({ title: req.body.title });'],
  ['dom-xss', 'a.js', "el.innerHTML = profile.bio;", "el.textContent = profile.bio;"],
  ['dom-xss', 'a.jsx', '<div dangerouslySetInnerHTML={{ __html: post.body }} />', '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />'],
  ['unsafe-template', 'v.ejs', '<p><%- user.bio %></p>', '<p><%= user.bio %></p>'],
  ['dynamic-script', 'a.js', "script.src = params.get('cdn') + '/lib.js';", "script.src = 'https://cdn.example.com/lib.js';"],
  ['jwt-unverified', 'a.js', 'const user = jwt.decode(req.headers.authorization);', "const user = jwt.verify(token, KEY, { algorithms: ['HS256'] });"],
  ['plaintext-password', 'a.js', 'if (user.password === req.body.password) login();', 'if (await bcrypt.compare(req.body.password, user.hash)) login();'],
  ['token-localstorage', 'a.js', "localStorage.setItem('token', t);", "localStorage.setItem('theme', 'dark');"],
  ['cookie-flags', 'a.js', 'const c = { httpOnly: false, secure: false };', "const c = { httpOnly: true, secure: true, sameSite: 'lax' };"],
  ['missing-auth', 'a.js', "app.delete('/api/users/:id', async (req, res) => {", "app.delete('/api/users/:id', requireAdmin, async (req, res) => {"],
  ['open-redirect', 'a.js', 'res.redirect(req.query.next);', "res.redirect(isSafe(req.query.next) ? req.query.next : '/');"],
  ['weak-hash', 'a.js', "crypto.createHash('md5').update(password).digest('hex');", "crypto.createHash('sha256').update(data).digest('hex');"],
  ['insecure-random', 'a.js', 'const resetToken = Math.random().toString(36);', 'const jitter = Math.random() * 100;'],
  ['tls-disabled', 'a.js', 'https.request({ rejectUnauthorized: false });', 'https.request({ ca: myCa });'],
  ['cors-wildcard', 'a.js', "app.use(cors({ origin: '*' }));", "app.use(cors({ origin: ['https://shop.example.com'] }));"],
  ['error-leak', 'a.js', 'res.status(500).json(err.stack);', "res.status(500).json({ error: 'Something went wrong', id });"],
  ['debug-mode', 'a.py', 'app.run(debug=True)', 'app.run(debug=os.getenv("DEBUG") == "1")'],
  ['plain-http', 'a.js', "fetch('http://api.shop.io/ping');", "fetch('https://api.shop.io/ping');"],
  ['docker-root', 'Dockerfile', 'USER root', 'USER node'],
  ['permissive-rls', 'p.sql', 'create policy "all" on orders\n  for select using (true);', 'create policy "own" on orders for select using (auth.uid() = user_id);'],
  ['cpp-buffer-overflow', 'main.cpp', 'gets(buffer);', 'fgets(buffer, sizeof(buffer), stdin);'],
  ['cpp-format-string', 'main.cpp', 'printf(user_name);', 'printf("%s", user_name);'],
];
for (const [rule, file, pos, neg] of CASES) {
  test(`rule ${rule} (${file}): positive`, () => assert.ok(ids(file, pos).includes(rule), `${rule} should fire on: ${pos}`));
  test(`rule ${rule} (${file}): negative`, () => assert.ok(!ids(file, neg).includes(rule), `${rule} should NOT fire on: ${neg}`));
}
test('every per-file rule has a test case', () => {
  const covered = new Set(CASES.map(c => c[0]));
  for (const r of E.RULES) assert.ok(covered.has(r.id), 'missing test for ' + r.id);
});

/* ------------------------------------------------------- false positives */
test('comments never produce findings', () => {
  const code = '// const k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";\n/* el.innerHTML = x;\n eval(y) */\nconst a = 1; // eval(z)';
  assert.deepEqual(ids('a.js', code), []);
});
test('python and SQL comments are ignored', () => {
  assert.deepEqual(ids('a.py', '# eval(request.args["x"])\nx = 1'), []);
  assert.deepEqual(ids('a.sql', '-- create policy p using (true)\nselect 1;'), []);
});
test('words inside ordinary strings do not trigger code rules', () => {
  assert.deepEqual(ids('a.js', 'const help = "never call eval( on input";'), []);
});
test('URLs with // inside strings are not treated as comments', () => {
  assert.ok(ids('a.js', "const r = eval('http://x'); ").includes('code-eval'));
});
test('multi-line SQL template is reported once, at the statement start', () => {
  const code = "const sql = `SELECT *\n  FROM orders\n  WHERE id = '${req.query.id}'`;\nconst y = 2;";
  const fs = scan1('a.js', code).filter(f => f.ruleId === 'sql-injection');
  assert.equal(fs.length, 1); assert.equal(fs[0].line, 1);
});
test('CRLF line endings keep correct line numbers', () => {
  const fs = scan1('a.js', 'const a = 1;\r\nconst b = 2;\r\nel.innerHTML = x;\r\n');
  assert.equal(fs[0].line, 3);
});
test('very long (minified) files are skipped, not scanned', () => {
  const r = E.scanFile({ name: 'big.js', code: 'var a=1;'.repeat(1000) });
  assert.equal(r.skipped, 'minified-or-generated');
});
test('binary content is skipped', () => assert.equal(E.scanFile({ name: 'x.js', code: 'abc\u0000def' }).skipped, 'binary'));

/* --------------------------------------------- finding shape, ids, evidence */
test('findings carry all required fields', () => {
  const r = E.scanProject([{ name: 'a.js', code: 'const a=1;\nconst b=2;\nel.innerHTML = x;\nconst c=3;' }]);
  const f = r.findings[0];
  for (const k of ['id', 'ruleId', 'title', 'severity', 'confidence', 'category', 'file', 'line', 'evidence', 'why', 'fix', 'tests', 'detection'])
    assert.ok(f[k] !== undefined && f[k] !== '', 'missing ' + k);
  assert.equal(f.line, 3); assert.equal(f.detection, 'static-heuristic');
  assert.deepEqual(f.evidence.map(e => e.n), [1, 2, 3, 4]);
  assert.ok(f.evidence.find(e => e.hit).text.includes('innerHTML'));
  assert.match(f.id, /^SF-[0-9A-F]{8}$/);
});
test('finding ids are stable across scans and unique within a scan', () => {
  const files = [{ name: 'a.js', code: 'el.innerHTML = a;\nel.innerHTML = a;\neval(x);' }];
  const a = E.scanProject(files).findings.map(f => f.id), b = E.scanProject(files).findings.map(f => f.id);
  assert.deepEqual(a, b); assert.equal(new Set(a).size, a.length);
});
test('severity and confidence are separate fields', () => {
  const f = scan1('a.js', "app.delete('/admin/users', (req, res) => {")[0];
  assert.equal(f.severity, 'medium'); assert.equal(f.confidence, 'low');
});

/* ------------------------------------------------------------- masking */
test('secret in evidence, context and prompt is masked', () => {
  const code = 'const cfg = { apiKey: "AIzaSyD4f8kQ2vX9LmN3pQrStUvWxYz012345" };\nel.innerHTML = cfg.apiKey + input;\nconst db = "postgres://admin:hunter2pass@db.internal/app";';
  const r = E.scanProject([{ name: 'a.js', code }]);
  const blob = JSON.stringify(r.findings) + r.findings.map(E.promptFor).join('\n') + E.batchPrompt(r.findings) +
    E.reportMarkdown(E.reportData({ project: 'p', generatedAt: 'now', scan: r, findings: r.findings }));
  assert.ok(!/AIzaSyD4f8kQ2vX9|hunter2pass/.test(blob), 'raw secret leaked');
});
test('mask keeps ordinary code readable', () => {
  assert.equal(E.mask("const url = 'https://xyzcompany.supabase.co';"), "const url = 'https://xyzcompany.supabase.co';");
  assert.match(E.mask('STRIPE_SECRET=sk_test_abcdefgh12345'), /sk_test_••••••/);
  assert.match(E.mask('-----BEGIN RSA PRIVATE KEY-----MIIEow'), /••••••/);
});

/* ------------------------------------------------------ score & verdict */
test('score is derived from severities and info adds nothing', () => {
  const mk = s => ({ severity: s });
  assert.equal(E.score([]), 0);
  assert.equal(E.score([mk('info'), mk('info')]), 0);
  assert.equal(E.score([mk('critical')]), 35);
  assert.equal(E.score([mk('critical'), mk('high')]), Math.round((1 - .65 * .8) * 100));
});
test('verdict never mentions critical issues when there are none', () => {
  const v = E.verdict([{ severity: 'high' }], 'complete');
  assert.equal(v.title, 'Fix before launch'); assert.ok(!/critical issue/i.test(v.detail.replace('No critical', '')));
  assert.equal(E.verdict([{ severity: 'critical' }], 'complete').title, 'Do not ship yet');
  assert.match(E.verdict([], 'complete').title, /No findings detected by the enabled rules/);
  assert.equal(E.verdict([], 'failed').title, 'Scan failed');
  assert.match(E.verdict([{ severity: 'low' }], 'complete-with-exclusions').detail, /coverage is partial/);
});

/* ------------------------------------------------------------- coverage */
test('coverage reports exclusions honestly', () => {
  const r = E.scanProject([{ name: 'a.js', code: 'eval(x)' }, { name: 'b.js', code: '   ' }, { name: 'c.bin', code: 'x' }]);
  assert.equal(r.status, 'complete-with-exclusions'); assert.equal(r.coverage.imported, 3); assert.equal(r.coverage.analyzed, 1);
  assert.deepEqual(r.coverage.skipped.map(s => s.reason).sort(), ['empty', 'unsupported-type']);
  assert.equal(r.coverage.rules, E.RULE_COUNT);
});
test('empty project fails instead of reporting "secure"', () => {
  assert.equal(E.scanProject([]).status, 'failed');
  assert.equal(E.scanProject([{ name: 'readme.md', code: 'hi' }]).status, 'failed');
});
test('cancellation returns no partial findings', () => {
  let n = 0; const r = E.scanProject([{ name: 'a.js', code: 'eval(x)' }, { name: 'b.js', code: 'eval(y)' }], { shouldCancel: () => n++ > 0 });
  assert.equal(r.status, 'cancelled'); assert.deepEqual(r.findings, []);
});
test('project-level checks are informational and low confidence', () => {
  const r = E.scanProject([{ name: 's.js', code: "const app = express();\napp.post('/login', (req, res) => {});" }]);
  const p = r.findings.filter(f => ['no-security-headers', 'no-rate-limit'].includes(f.ruleId));
  assert.equal(p.length, 2); p.forEach(f => { assert.equal(f.severity, 'info'); assert.equal(f.confidence, 'low'); });
  const r2 = E.scanProject([{ name: 's.js', code: "const app = express();\napp.use(helmet());\napp.post('/login', limiter, (req, res) => {});" }]);
  assert.equal(r2.findings.filter(f => f.severity === 'info').length, 0);
});

/* ------------------------------------------------------------ ProofLoop */
const snap = files => { const r = E.scanProject(files); const map = {}; files.forEach(f => map[f.name] = f.code); return { findings: r.findings, files: map }; };
const filler = Array.from({ length: 12 }, (_, i) => `const keep${i} = ${i};`).join('\n');
test('fixed pattern → "no longer detected", never "verified"', () => {
  const a = snap([{ name: 'a.js', code: filler + '\nel.innerHTML = x;' }]), b = snap([{ name: 'a.js', code: filler + '\nel.textContent = x;' }]);
  const c = E.compareScans(a, b); assert.equal(c.summary.gone, 1); assert.equal(c.summary.verified, 0);
});
test('unchanged pattern → still detected', () => {
  const a = snap([{ name: 'a.js', code: 'eval(x);' }]); assert.equal(E.compareScans(a, a).summary.still, 1);
});
test('removed file → not rechecked (not resolved)', () => {
  const a = snap([{ name: 'a.js', code: 'eval(x);' }, { name: 'b.js', code: 'const ok = 1;' }]), b = snap([{ name: 'b.js', code: 'const ok = 1;' }]);
  const c = E.compareScans(a, b); assert.equal(c.summary.notrechecked, 1); assert.equal(c.summary.gone, 0);
});
test('issue moved to another file → still detected, with reason', () => {
  const a = snap([{ name: 'a.js', code: 'eval(x);' }]), b = snap([{ name: 'lib/b.js', code: 'eval(x);' }]);
  const c = E.compareScans(a, b); assert.equal(c.summary.still, 1); assert.equal(c.summary.new, 0); assert.match(c.rows[0].reason, /moved to lib\/b\.js/);
});
test('rewritten file → inconclusive', () => {
  const a = snap([{ name: 'a.js', code: 'const a=1;\nconst b=2;\neval(x);' }]), b = snap([{ name: 'a.js', code: 'function totallyNew() {\n  return 42;\n}' }]);
  assert.equal(E.compareScans(a, b).summary.inconclusive, 1);
});
test('new issue → newly detected', () => {
  const a = snap([{ name: 'a.js', code: 'const a=1;' }]), b = snap([{ name: 'a.js', code: 'const a=1;\neval(x);' }]);
  assert.equal(E.compareScans(a, b).summary.new, 1);
});
test('"verified" only with an executed, passing test result', () => {
  const a = snap([{ name: 'a.js', code: filler + '\neval(x);' }]), b = snap([{ name: 'a.js', code: filler + '\nsafe(x);' }]);
  const id = a.findings[0].id;
  assert.equal(E.compareScans(a, b, { [id]: { passed: true, executed: false } }).summary.verified, 0);
  assert.equal(E.compareScans(a, b, { [id]: { passed: true, executed: true, name: 't' } }).summary.verified, 1);
});

/* ----------------------------------------------------- import validation */
test('validation: traversal, absolute, unsupported, duplicate, size and count limits', () => {
  const lim = { ...E.LIMITS, maxFiles: 2, maxFileBytes: 100, maxTotalBytes: 150 };
  const v = E.validateIncoming([
    { path: '../etc/passwd.js', size: 1 }, { path: '/abs/a.js', size: 1 }, { path: 'C:\\win\\a.js', size: 1 },
    { path: 'img.png', size: 1 }, { path: 'node_modules/x/a.js', size: 1 },
    { path: 'src/a.js', size: 10 }, { path: 'src\\a.js', size: 10 }, { path: 'big.js', size: 500 },
    { path: 'b.js', size: 100 }, { path: 'c.js', size: 10 }, { path: 'd.js', size: 10 }], lim);
  assert.deepEqual(v.keep.map(k => k.path), ['src/a.js', 'b.js']);
  const reasons = v.skipped.map(s => s.reason);
  for (const r of ['unsafe-path', 'unsupported-type', 'excluded-folder-or-lockfile', 'duplicate-path', 'too-large', 'over-file-limit']) assert.ok(reasons.includes(r), 'missing reason ' + r);
});
test('safePath rejects escapes and normalises separators', () => {
  assert.equal(E.safePath('a/../../b.js'), null); assert.equal(E.safePath('/etc/x'), null); assert.equal(E.safePath('D:/x'), null);
  assert.equal(E.safePath('a\0b.js'), null); assert.equal(E.safePath('.\\src\\app.js'), 'src/app.js');
});
test('merge: add mode never overwrites silently', () => {
  const ex = [{ name: 'a.js', code: 'old' }], inc = [{ name: 'a.js', code: 'new' }, { name: 'b.js', code: 'b' }];
  assert.throws(() => E.mergeProject(ex, inc, 'add'), /conflict-choice-required/);
  assert.equal(E.mergeProject(ex, inc, 'add', 'keep').files.find(f => f.name === 'a.js').code, 'old');
  assert.equal(E.mergeProject(ex, inc, 'add', 'replace').files.find(f => f.name === 'a.js').code, 'new');
  const r = E.mergeProject(ex, inc, 'add', 'rename'); assert.deepEqual(r.files.map(f => f.name), ['a (2).js', 'a.js', 'b.js']);
  assert.deepEqual(E.mergeProject(ex, inc, 'replace').files.map(f => f.name), ['a.js', 'b.js']);
  assert.equal(ex[0].code, 'old', 'input not mutated');
  assert.deepEqual(E.conflicts(ex, inc).map(f => f.name), ['a.js']);
});

/* ------------------------------------------------------------------ ZIP */
function makeZip(entries) { // entries: [{name, data(Buffer), method:0|8, usize?}]
  const locals = [], centrals = []; let off = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name), raw = e.data, comp = e.method === 8 ? zlib.deflateRawSync(raw) : raw;
    const usize = e.usize ?? raw.length;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.flags || 0, 6); lh.writeUInt16LE(e.method, 8);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(usize, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(e.flags || 0, 8); ch.writeUInt16LE(e.method, 10);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(usize, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, comp); centrals.push(ch, name); off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals), eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return new Uint8Array(Buffer.concat([...locals, cd, eocd]));
}
test('zip: reads stored and deflated entries', async () => {
  const z = makeZip([{ name: 'src/a.js', data: Buffer.from('eval(x);'), method: 8 }, { name: 'b.py', data: Buffer.from('print(1)'), method: 0 }, { name: 'dir/', data: Buffer.alloc(0), method: 0 }]);
  const r = await E.readZip(z);
  assert.deepEqual(r.entries.map(e => e.path), ['src/a.js', 'b.py']);
  assert.equal(await r.entries[0].read(), 'eval(x);'); assert.equal(await r.entries[1].read(), 'print(1)');
});
test('zip: traversal and absolute entry paths are rejected', async () => {
  const z = makeZip([{ name: '../../evil.js', data: Buffer.from('x'), method: 0 }, { name: '/etc/x.js', data: Buffer.from('x'), method: 0 }, { name: 'ok.js', data: Buffer.from('x'), method: 0 }]);
  const r = await E.readZip(z);
  assert.deepEqual(r.entries.map(e => e.path), ['ok.js']); assert.equal(r.rejected.filter(x => x.reason === 'unsafe-path').length, 2);
});
test('zip: bomb guards (ratio, declared size, lying size, encrypted)', async () => {
  const bomb = Buffer.alloc(300 * 1024, 65); // compresses ~1000:1
  let r = await E.readZip(makeZip([{ name: 'bomb.js', data: bomb, method: 8 }]));
  assert.equal(r.rejected[0].reason, 'compression-ratio');
  r = await E.readZip(makeZip([{ name: 'huge.js', data: Buffer.from('x'), method: 0, usize: 10 * 1024 * 1024 }]));
  assert.equal(r.rejected[0].reason, 'too-large');
  r = await E.readZip(makeZip([{ name: 'liar.js', data: Buffer.alloc(50 * 1024, 66), method: 8, usize: 10 }]), { ...E.LIMITS, maxRatio: 1e9 });
  await assert.rejects(r.entries[0].read(), /exceeds-declared-size/);
  r = await E.readZip(makeZip([{ name: 'enc.js', data: Buffer.from('x'), method: 0, flags: 1 }]));
  assert.equal(r.rejected[0].reason, 'encrypted');
});
test('zip: corrupt, oversized and too-many-entries archives are refused', async () => {
  await assert.rejects(E.readZip(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23])), /zip-corrupt/);
  await assert.rejects(E.readZip(new Uint8Array(40), { ...E.LIMITS, maxZipBytes: 10 }), /zip-too-large/);
  const many = makeZip(Array.from({ length: 5 }, (_, i) => ({ name: i + '.js', data: Buffer.from('x'), method: 0 })));
  await assert.rejects(E.readZip(many, { ...E.LIMITS, maxZipEntries: 3 }), /too-many-entries/);
});
test('writeZip: creates valid zip readable by readZip', async () => {
  const blob = E.writeZip([{ name: 'main.cpp', code: '#include <iostream>\nint main(){ return 0; }' }, { name: 'utils.h', code: 'void test();' }]);
  const buf = await blob.arrayBuffer();
  const read = await E.readZip(buf);
  assert.equal(read.entries.length, 2);
  assert.equal(await read.entries[0].read(), '#include <iostream>\nint main(){ return 0; }');
  assert.equal(await read.entries[1].read(), 'void test();');
});
test('cpp files: recognized and scanned', () => {
  assert.equal(E.isSupported('main.cpp'), true);
  assert.equal(E.isSupported('helper.h'), true);
  const bad = E.scanFile({ name: 'main.cpp', code: 'int main(){ char buf[10]; gets(buf); return 0; }' });
  assert.ok(bad.findings.some(f => f.ruleId === 'cpp-buffer-overflow'));
  const clean = E.scanFile({ name: 'clean.cpp', code: '#include <iostream>\nint main(){ std::cout << "Hello"; return 0; }' });
  assert.equal(clean.findings.length, 0);
});

/* -------------------------------------------------------------- reports */
test('report: HTML-like payloads and backtick fences are neutralised', () => {
  const code = 'el.innerHTML = "<img src=x onerror=alert(1)>";\n// docs: ``` fenced ```\neval(t);';
  const files = [{ name: '<script>alert(1)</script>.js', code }];
  const r = E.scanProject(files);
  const md = E.reportMarkdown(E.reportData({ project: '<b>proj</b>', generatedAt: 'now', scan: r, findings: r.findings }));
  assert.ok(!md.includes('<b>proj</b>')); assert.ok(md.includes('&lt;b&gt;proj&lt;/b&gt;'));
  assert.ok(!/^#.*<script>/m.test(md));
  assert.ok(md.includes('````'), 'uses a longer fence when code contains ```');
});
test('report JSON contains coverage, limitations and no raw secrets', () => {
  const r = E.scanProject([{ name: 'a.js', code: 'const k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";' }]);
  const d = E.reportData({ project: 'p', generatedAt: 'now', scan: r, findings: r.findings });
  assert.ok(d.coverage && d.limitations.length >= 3); assert.ok(!JSON.stringify(d).includes('51Hx9aQ2eZ'));
});

/* -------------------------------------------------------- demo project */
test('demo project (from src/demo.js) scans as expected', async () => {
  const fs = await import('node:fs'); const sandbox = {};
  new Function('window', fs.readFileSync(new URL('../src/demo.js', import.meta.url), 'utf8'))(sandbox);
  const get = id => sandbox.SF_DEMO[id].replace(/^\s*\n/, '').replace(/\s+$/, '');
  const vuln = [['src/client/app.js', 'v-client'], ['api/orders/route.js', 'v-api'], ['lib/db.js', 'v-data']].map(([n, id]) => ({ name: n, code: get(id) }));
  const fixed = [['src/client/app.js', 'f-client'], ['api/orders/route.js', 'f-api'], ['lib/db.js', 'f-data']].map(([n, id]) => ({ name: n, code: get(id) }));
  const a = snap(vuln), b = snap(fixed), c = E.compareScans(a, b);
  assert.ok(a.findings.filter(f => f.severity === 'critical').length >= 4);
  assert.ok(E.score(b.findings) < 10, 'patched demo should score low, got ' + E.score(b.findings));
  assert.equal(c.summary.new, 0, 'patch introduced findings: ' + JSON.stringify(c.rows.filter(r => r.state === 'new').map(r => r.cur.ruleId)));
});

/* ============================== v0.4: metadata, scoring, Fix Studio, graph, readiness, reports */
test('every rule has impact, flow, context, limits and references', () => {
  for (const r of [...E.RULES, ...E.PROJECT_RULES]) {
    const m = E.metaFor({ ruleId: r.id, cwe: r.cwe, severity: r.sev, confidence: r.conf });
    assert.ok(m.flow.length >= 3 && m.context && m.limits, 'meta incomplete for ' + r.id);
    assert.ok(m.refs.length && m.refs.every(x => /^https:\/\/(cwe\.mitre\.org|cheatsheetseries\.owasp\.org)\//.test(x.url)), 'refs for ' + r.id);
    for (const k of ['confidentiality', 'integrity', 'availability']) assert.ok(['high', 'medium', 'low', 'none'].includes(m.impact[k]));
  }
});
test('score weighs confidence: a low-confidence critical counts less than a high-confidence one', () => {
  assert.equal(E.score([{ severity: 'critical', confidence: 'high' }]), 35);
  assert.equal(E.score([{ severity: 'critical', confidence: 'low' }]), 18);
  assert.equal(E.score([{ severity: 'info', confidence: 'high' }]), 0);
});
test('scoreChange explains why the score moved', () => {
  const a = snap([{ name: 'a.js', code: filler + '\neval(x);\nel.innerHTML = y;' }]), b = snap([{ name: 'a.js', code: filler + '\nsafe(x);\nel.innerHTML = y;\nlocalStorage.setItem("token", t);' }]);
  const ch = E.scoreChange(a.findings, b.findings, E.compareScans(a, b));
  assert.ok(ch.delta < 0); assert.ok(ch.reasons.some(r => /no longer detected/.test(r)) && ch.reasons.some(r => /newly detected/.test(r)));
});
test('finding has a column', () => { const f = scan1('a.js', '    el.innerHTML = x;')[0]; assert.equal(f.column, 5); });

// Fix Studio: each patchable rule → propose → apply → rescan → that finding is gone, nothing else touched
const PATCH_CASES = [
  ['dom-xss', 'a.js', 'el.innerHTML = profile.bio;'],
  ['hardcoded-secret', 'a.js', 'const stripeSecret = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";'],
  ['hardcoded-secret', 'a.py', 'DB_PASSWORD = "Sup3rS3cret!2026"'],
  ['jwt-unverified', 'a.js', 'const user = jwt.decode(req.headers.authorization);'],
  ['insecure-random', 'a.js', 'const resetToken = Math.random().toString(36).slice(2);'],
  ['token-localstorage', 'a.js', "localStorage.setItem('token', t);"],
  ['cors-wildcard', 'a.js', "app.use(cors({ origin: '*', credentials: true }));"],
  ['cookie-flags', 'a.js', 'const c = { httpOnly: false, secure: false };'],
  ['plain-http', 'a.js', "fetch('http://api.shop.io/ping');"],
  ['open-redirect', 'a.js', 'res.redirect(req.query.next);'],
  ['open-redirect', 'a.js', "location.href = new URLSearchParams(location.search).get('next');"],
  ['weak-hash', 'a.js', "const etag = crypto.createHash('md5').update(body).digest('hex');"],
  ['tls-disabled', 'a.js', 'https.request({ rejectUnauthorized: false });'],
  ['debug-mode', 'a.py', 'app.run(debug=True)'],
  ['error-leak', 'a.js', 'res.status(500).json(err.stack);'],
  ['insecure-deserialization', 'a.py', 'cfg = yaml.load(data)'],
  ['unsafe-template', 'v.ejs', '<p><%- user.bio %></p>'],
  ['docker-root', 'Dockerfile', 'USER root'],
  ['sql-injection', 'a.js', "const rows = await db.query(`SELECT * FROM orders WHERE id = '${req.query.id}' AND u = ${uid}`);"],
];
for (const [rule, file, line] of PATCH_CASES) {
  test(`patch ${rule} (${file}): proposes, applies cleanly and the pattern is no longer detected`, () => {
    const code = 'const keepA = 1;\n' + line + '\nconst keepB = 2;';
    const files = [{ name: file, code }];
    const f = E.scanProject(files).findings.find(x => x.ruleId === rule); assert.ok(f, 'finding expected');
    const p = E.proposePatch(f, files); assert.ok(p.available, p.reason); assert.equal(p.kind, 'deterministic'); assert.match(p.disclaimer, /not by AI/);
    const r = E.applyPatch(files, p); assert.ok(r.ok, r.error);
    assert.equal(files[0].code, code, 'input untouched');
    const after = E.scanProject(r.files).findings.filter(x => x.ruleId === rule);
    assert.equal(after.length, 0, 'still detected after patch: ' + r.files[0].code);
    assert.ok(r.files[0].code.includes('const keepA = 1;') && r.files[0].code.includes('const keepB = 2;'), 'unrelated lines changed');
    assert.equal(r.undo.code, code);
  });
}
test('no automatic patch for password hashing, eval, SSRF etc. (prompt only)', () => {
  for (const [file, code] of [['a.js', "crypto.createHash('md5').update(password)"], ['a.js', 'eval(req.body.x);'], ['a.js', 'await fetch(req.query.url);']]) {
    const files = [{ name: file, code }]; const f = E.scanProject(files).findings[0];
    assert.equal(E.proposePatch(f, files).available, false, f.ruleId);
  }
});
test('stale patch is refused when the target line changed', () => {
  const files = [{ name: 'a.js', code: 'el.innerHTML = x;' }]; const f = E.scanProject(files).findings[0];
  const p = E.proposePatch(f, files); const r = E.applyPatch([{ name: 'a.js', code: 'el.innerHTML = somethingElse;' }], p);
  assert.equal(r.ok, false); assert.match(r.error, /changed since/);
});
test('patch to an unknown file is refused; user-edited proposal is applied as edited', () => {
  assert.equal(E.applyPatch([], { file: 'x.js', edits: [] }).ok, false);
  const files = [{ name: 'a.js', code: 'el.innerHTML = x;' }]; const f = E.scanProject(files).findings[0];
  const p = E.proposePatch(f, files); p.edits[0].after = 'el.textContent = String(x);';
  assert.equal(E.applyPatch(files, p).files[0].code, 'el.textContent = String(x);');
});
test('patch insert (helper line) keeps CRLF endings', () => {
  const files = [{ name: 'a.js', code: "const a = 1;\r\nres.redirect(req.query.next);\r\n" }]; const f = E.scanProject(files).findings[0];
  const r = E.applyPatch(files, E.proposePatch(f, files)); assert.ok(r.ok); assert.ok(r.files[0].code.startsWith('const isSafeRedirect')); assert.ok(!/[^\r]\n/.test(r.files[0].code));
});
test('diffLines shows only the changed region with context, and masks secrets', () => {
  const a = 'l1\nl2\nl3\nconst k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";\nl5\nl6', b = 'l1\nl2\nl3\nconst k = process.env.K;\nl5\nl6';
  const d = E.diffLines(a, b, 1);
  assert.deepEqual(d.map(r => r.t), [' ', '-', '+', ' ']); assert.ok(!JSON.stringify(d).includes('51Hx9aQ2eZ'));
});
test('dependency graph only contains real import edges; layers are inferred', () => {
  const g = E.dependencyGraph([
    { name: 'src/client/app.js', code: "import { api } from '../lib/api';\nimport React from 'react';\ndocument.title='x'" },
    { name: 'src/lib/api.js', code: "const x = require('./missing');\nexport const api = 1;" },
    { name: 'api/routes.js', code: "const db = require('../lib/db.js');\nconst app = express();" },
    { name: 'lib/db.js', code: 'const c = new MongoClient(url);' }]);
  assert.deepEqual(g.edges, [{ from: 'src/client/app.js', to: 'src/lib/api.js' }, { from: 'api/routes.js', to: 'lib/db.js' }]);
  assert.deepEqual(g.nodes.map(n => n.layer), ['client', 'other', 'server', 'data']);
});
test('readiness never says "secure" and reports which checks did not run', () => {
  const files = [{ name: 'server.js', code: "const app = express();\nconst stripe = require('stripe');\napp.post('/pay', (req, res) => {});" }];
  const r = E.scanProject(files), rd = E.readiness(r, files);
  assert.ok(!/secure|production ready/i.test(rd.overall)); assert.match(rd.scope, /not a certification/);
  const byId = Object.fromEntries(rd.checks.map(c => [c.id, c]));
  assert.equal(byId.payments.status, 'fail'); assert.equal(byId.build.ran, false); assert.equal(byId.deps.status, 'notchecked'); assert.equal(byId.headers.status, 'warn');
  const files2 = [{ name: 'server.js', code: "const app = express();\napp.use(helmet());\nconst ok = razorpay.validatePaymentVerification(x);" }];
  const rd2 = E.readiness(E.scanProject(files2), files2); assert.equal(Object.fromEntries(rd2.checks.map(c => [c.id, c])).payments.status, 'warn');
  assert.equal(E.readiness(E.scanProject([{ name: 'a.js', code: 'eval(x)' }]), [{ name: 'a.js', code: 'eval(x)' }]).overall, 'Fix Before Deployment');
  assert.equal(E.readiness({ status: 'failed', findings: [], coverage: null }, []).overall, 'Failed Check');
});
test('business-logic test specs are suggestions, ranked by relevance', () => {
  const s = E.testSpecs([{ name: 'a.js', code: 'razorpay.orders.create({ amount }); coupon' }]);
  assert.ok(s[0].relevant && s.find(x => x.id === 'pay-replay').relevant && s.find(x => x.id === 'coupon-expired').relevant);
  assert.ok(s.every(x => x.steps.length && x.expected));
});
test('HTML report escapes everything and has its own restrictive CSP', () => {
  const files = [{ name: '<img src=x onerror=alert(1)>.js', code: 'el.innerHTML = "<script>alert(1)</script>" + x;\nconst k = "' + 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq";' }];
  const r = E.scanProject(files);
  const html = E.reportHTML(E.reportData({ project: '<b>p</b>', generatedAt: 'now', scan: r, findings: r.findings, readiness: E.readiness(r, files) }));
  assert.ok(!html.includes('<img src=x') && !html.includes('<script>alert') && !html.includes('<b>p</b>') && !html.includes('51Hx9aQ2eZ'));
  assert.match(html, /Content-Security-Policy" content="default-src 'none'/); assert.match(html, /Tests executed by SecureFlow: none/);
});
test('ProofLoop: a failing or non-executed test never yields "verified"', () => {
  const a = snap([{ name: 'a.js', code: filler + '\neval(x);' }]), b = snap([{ name: 'a.js', code: filler + '\nsafe(x);' }]), id = a.findings[0].id;
  assert.equal(E.compareScans(a, b, { [id]: { executed: true, passed: false } }).summary.verified, 0);
  assert.equal(E.compareScans(a, b, { [id]: { executed: true, passed: false } }).summary.gone, 1);
});
