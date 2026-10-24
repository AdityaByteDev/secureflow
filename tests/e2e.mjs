// End-to-end browser tests (Playwright + Chromium). Run:  npm run e2e   (or: node tests/e2e.mjs [dir containing index.html + app.html])
// Network is blocked for everything except the local file, which also proves the app needs no server.
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import zlib from 'node:zlib'; import { fileURLToPath, pathToFileURL } from 'node:url';
let chromium;
try { ({ chromium } = await import('playwright')); } catch { ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || '/opt/npm-tools/node_modules/playwright/index.mjs')); }

const here = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(process.argv[2] || path.join(here, '..'));
const PAGE = pathToFileURL(path.join(DIR, 'app.html')).href, STORY = pathToFileURL(path.join(DIR, 'index.html')).href;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-e2e-'));
const W = (rel, data) => { const p = path.join(tmp, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, data); return p; };
function makeZip(entries) {
  const locals = [], centrals = []; let off = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name), raw = Buffer.from(e.data), comp = e.method === 8 ? zlib.deflateRawSync(raw) : raw;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.method, 8); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(e.method, 10); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, comp); centrals.push(ch, name); off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals), eo = Buffer.alloc(22); eo.writeUInt32LE(0x06054b50, 0); eo.writeUInt16LE(entries.length, 8); eo.writeUInt16LE(entries.length, 10); eo.writeUInt32LE(cd.length, 12); eo.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eo]);
}
// fixtures
const SECRET = 'AIzaSyD4f8kQ2vX9LmN3pQrStUvWxYz012345', DBPW = 'hunter2pass';
const projDir = path.join(tmp, 'shop');
W('shop/src/app.js', `const cfg = { apiKey: "${SECRET}" };\nel.innerHTML = cfg.apiKey + userInput;\nconst db = 'postgres://admin:${DBPW}@db.internal/app';\n`);
W('shop/src/routes.js', "app.get('/x', (req, res) => {\n  res.redirect(req.query.next);\n});\n");
W('shop/node_modules/lib/index.js', 'eval(x)');
W('shop/logo.png', '\x89PNG....');
const unsupported = [W('notes.md', '# hi'), W('img.png', 'PNG')];
const fakeZip = W('broken.zip', 'this is not a zip');
const travZip = W('trav.zip', makeZip([{ name: '../../evil.js', data: 'eval(x)', method: 0 }, { name: 'ok/app.js', data: 'eval(y)', method: 8 }]));
const bigZip = W('big.zip', Buffer.alloc(31 * 1024 * 1024, 1));
const dupA = W('dup/a.js', 'eval(1)'); const binFile = W('bin.js', 'abc\u0000\u0001\u0002def');
const htmlName = { name: '<img src=x onerror=alert(1)>.js', mimeType: 'text/javascript', buffer: Buffer.from('el.innerHTML = "<script>alert(1)</script>" + x;\n') };
const many = []; for (let i = 0; i < 280; i++) many.push(W(`many/f${i}.js`, Array.from({ length: 1400 }, (_, j) => j % 50 === 0 ? `el.innerHTML = v${j};` : `const v${j} = compute(${j}, "x${j}");`).join('\n')));

const results = []; let browser;
async function newPage(opts = {}) {
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, reducedMotion: opts.reducedMotion || 'no-preference', acceptDownloads: true });
  if (opts.init) await ctx.addInitScript(opts.init);
  const p = await ctx.newPage(); p.errors = []; p.dialogs = 0;
  p.on('pageerror', e => p.errors.push(e.message)); p.on('dialog', d => { p.dialogs++; d.dismiss(); });
  await p.route('**/*', r => r.request().url().startsWith('file:') ? r.continue() : r.abort());
  await p.goto(opts.url || PAGE); await p.waitForTimeout(400);
  return p;
}
const S = p => p.evaluate(() => { const s = SF.debug.state; return { files: s.files.map(f => f.name), scans: s.scans.length, scanning: !!s.scanning, name: s.name, demo: s.demo }; });
const scanDone = p => p.waitForFunction(() => !SF.debug.state.scanning, null, { timeout: 30000 });
async function scan(p) { await p.click('#run'); await scanDone(p); await p.waitForTimeout(50); }
async function upload(p, sel, files) { await p.setInputFiles(sel, files); await p.waitForFunction(() => document.getElementById('import-status').hidden || document.getElementById('import-status').classList.contains('stay') || !document.getElementById('choice').hidden, null, { timeout: 15000 }).catch(() => {}); await p.waitForTimeout(150); }
const go = (p, v) => p.click('#vn-' + v);
async function openFinding(p) { await go(p, 'findings'); await p.waitForSelector('#detail .ev'); }
async function grabClipboard(p) { await p.evaluate(() => { window.__clip = []; navigator.clipboard.writeText = t => { window.__clip.push(t); return Promise.resolve(); }; }); }
async function T(name, fn) {
  if (process.env.E2E_ONLY && !name.toLowerCase().includes(process.env.E2E_ONLY.toLowerCase())) return;
  const t0 = Date.now();
  process.stdout.write(`• ${name}... `);
  try {
    await fn();
    const ms = Date.now() - t0;
    results.push([name, 'pass', ms]);
    console.log(`ok (${ms}ms)`);
  } catch (e) {
    const ms = Date.now() - t0;
    const msg = (e.message || e).split('\n')[0];
    results.push([name, 'FAIL: ' + msg, ms]);
    console.log(`FAIL: ${msg} (${ms}ms)`);
  }
}
const ok = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };

browser = await chromium.launch();

await T('integration: import folder → scan → open finding → evidence → copy prompt → edit → rescan → compare → export → clear', async () => {
  const p = await newPage();
  await upload(p, '#up-folder', projDir);
  let st = await S(p); ok(st.name === 'shop', 'project name ' + st.name); ok(st.files.join() === 'src/app.js,src/routes.js', 'files ' + st.files);
  ok((await p.innerText('#import-status')).includes('dependency/build folder'), 'node_modules exclusion reported');
  await scan(p);
  ok(/scan complete/i.test(await p.innerText('#r-status')), 'status');
  ok(await p.isVisible('#ov-results'), 'overview results after first scan');
  await openFinding(p); ok(await p.isVisible('#detail .ev .hit'), 'evidence visible');
  await grabClipboard(p); await p.click('#detail [data-act=copy]');
  const prompt = (await p.evaluate(() => window.__clip[0])) || ''; ok(prompt.includes('Regression test') && !prompt.includes(SECRET), 'prompt sanitized');
  // show in editor
  await p.click('#detail [data-act=jump]'); ok(await p.isVisible('#view-source'), 'source view');
  ok(await p.isVisible('#lnhl'), 'line highlight shown'); ok((await p.evaluate(() => { const c = document.getElementById('code'); return c.value.slice(c.selectionStart, c.selectionEnd); })).length > 3, 'line selected');
  // edit: fix the redirect, rescan
  await p.click('.tf[data-i="1"]'); await p.fill('#code', "app.get('/x', (req, res) => {\n  res.redirect('/');\n});\n");
  ok(await p.isVisible('#stale'), 'stale banner');
  await scan(p);
  ok(await p.isVisible('#vlist'), 'ProofLoop opens on rescan');
  const v = await p.innerText('#vlist'); ok(/1\s*No longer detected/i.test(v), 'gone count: ' + v.slice(0, 300));
  // export markdown + json
  await go(p, 'reports');
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#exp-md')]);
  const md = fs.readFileSync(await dl.path(), 'utf8'); ok(md.includes('Rescan comparison') && !md.includes(SECRET) && !md.includes(DBPW), 'markdown export sanitized');
  const [dj] = await Promise.all([p.waitForEvent('download'), p.click('#exp-json')]);
  const js = JSON.parse(fs.readFileSync(await dj.path(), 'utf8')); ok(js.coverage && js.verification && js.limitations.length, 'json export');
  // clear
  await p.click('#clear-btn'); ok(await p.isVisible('#clear-dlg'), 'confirm dialog'); await p.click('#dlg-confirm');
  st = await S(p); ok(st.files.length === 0 && st.scans === 0, 'cleared'); ok((await p.inputValue('#code')) === '', 'editor cleared');
  ok(!(await p.evaluate(() => SF.debug.hasWorker())), 'worker terminated');
  ok(p.errors.length === 0, p.errors.join('; '));
});

await T('E1 empty project cannot be scanned and reports nothing as "secure"', async () => {
  const p = await newPage(); await p.click('#clear-btn'); await p.click('#dlg-confirm'); await p.click('#run');
  ok((await S(p)).scans === 0); ok((await p.innerText('#toast')).includes('Add some code'));
});
await T('E2/E16 no supported files: nothing changes, reasons shown', async () => {
  const p = await newPage(); await upload(p, '#up-files', unsupported);
  ok((await S(p)).demo, 'demo kept'); ok((await p.innerText('#import-status')).includes('unsupported file type'));
});
await T('E3 binary / malformed files are skipped, malformed JS still scans', async () => {
  const p = await newPage(); await upload(p, '#up-files', [binFile, W('bad.js', 'const s = "unterminated;\neval(x)\n/* never closed')]);
  ok((await S(p)).files.join() === 'bad.js', 'only bad.js kept'); await scan(p);
  ok(/scan complete/i.test(await p.innerText('#r-status')), 'scanned'); ok((await p.innerText('#coverage-sum')).includes('1 excluded'), 'binary excluded in coverage');
});
await T('E4 malformed zip: project preserved, error explained', async () => {
  const p = await newPage(); await upload(p, '#up-files', [fakeZip]);
  ok((await S(p)).demo); ok((await p.innerText('#import-status')).includes('corrupt'));
});
await T('E5 zip with traversal paths: only safe entries imported', async () => {
  const p = await newPage(); await upload(p, '#up-files', [travZip]);
  const st = await S(p); ok(st.files.join() === 'ok/app.js', 'files ' + st.files); await scan(p);
  await p.click('#coverage-sum'); ok((await p.innerText('#coverage-body')).includes('unsafe path'));
});
await T('E6 oversized zip is refused before reading', async () => {
  const p = await newPage(); await upload(p, '#up-files', [bigZip]); ok((await S(p)).demo); ok((await p.innerText('#import-status')).includes('.zip over 30 MB'));
});
await T('E7 duplicate filenames: add-mode asks, rename keeps both', async () => {
  const p = await newPage(); await upload(p, '#up-files', [dupA]); await scan(p);
  await upload(p, '#up-files', [dupA]); ok(await p.isVisible('#choice')); await p.click('[data-ch=add]');
  ok((await p.innerText('#choice-msg')).includes('same path')); await p.click('[data-ch=rename]');
  ok((await S(p)).files.join() === 'a (2).js,a.js', 'files ' + (await S(p)).files);
});
const bigProject = async p => { await upload(p, '#up-files', many); return S(p); };
await T('E8/E9 filename, editor and project changes are locked while scanning', async () => {
  const p = await newPage(); await bigProject(p); await p.click('#run');
  ok(await p.evaluate(() => SF.debug.state.scanning !== null), 'scan running');
  ok(await p.evaluate(() => document.getElementById('fname').readOnly && document.getElementById('code').readOnly), 'readonly');
  ok(await p.isDisabled('#up-files') && await p.isDisabled('#load-demo') && await p.isDisabled('#new-file'), 'import disabled');
  await scanDone(p);
});
await T('E10 cancel midway: no partial results kept', async () => {
  const p = await newPage(); await bigProject(p); await p.click('#run'); await p.waitForTimeout(30); await p.click('#cancel-scan');
  const st = await S(p); ok(!st.scanning && st.scans === 0, JSON.stringify(st)); ok(/cancelled/i.test(await p.innerText('#r-status')), 'status says cancelled');
  await p.waitForTimeout(1500); ok((await S(p)).scans === 0, 'late worker result was not committed');
});
await T('E11-13 secrets masked in evidence, context and prompts', async () => {
  const p = await newPage(); await upload(p, '#up-folder', projDir); await scan(p);
  await openFinding(p); const ids = await p.evaluate(() => [...document.querySelectorAll('#list .frow')].map(r => r.dataset.id)); let html = await p.innerHTML('#list');
  for (const id of ids) { await p.click(`#list .frow[data-id="${id}"] .t`); html += await p.innerHTML('#detail'); }
   ok(!html.includes(SECRET) && !html.includes(DBPW), 'list leaks');
  await grabClipboard(p); await p.check('#sel-all'); await p.click('#copy-selected');
  const t = await p.evaluate(() => window.__clip.join('\n')); ok(t.length > 100 && !t.includes(SECRET) && !t.includes(DBPW), 'batch prompt leaks');
});
await T('E14 removed file → Not rechecked; E15 moved issue → Still detected (moved)', async () => {
  const p = await newPage(); await scan(p);
  await go(p, 'source'); await p.click('.tf[data-i="2"]'); await p.click('#rm-file');          // remove lib/db.js
  await p.click('.tf[data-i="0"]'); await p.fill('#fname', 'src/client/main.js'); await p.dispatchEvent('#fname', 'change'); // move client file
  await scan(p); const v = await p.innerText('#vlist');
  ok(/5\s*Not rechecked/i.test(v), 'not rechecked: ' + v.slice(0, 400)); ok(v.includes('moved to src/client/main.js'), 'moved');
});
await T('E17 3D library unavailable: static fallback, no stuck loader', async () => {
  const p = await newPage({ url: STORY }); await p.waitForTimeout(800);
  ok(await p.evaluate(() => document.documentElement.classList.contains('no-webgl') && document.getElementById('loader').classList.contains('done')));
});
await T('E17b Web Worker unavailable: scan still works on the main thread', async () => {
  const p = await newPage({ init: () => { delete window.Worker; } }); await scan(p);
  ok((await S(p)).scans === 1); ok(!(await p.evaluate(() => SF.debug.hasWorker())));
});
await T('E18 clipboard blocked: manual copy dialog with sanitized text', async () => {
  const p = await newPage({ init: () => { Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) } }); document.execCommand = () => false; } });
  await scan(p); await openFinding(p); await p.click('#detail [data-act=copy]');
  ok(await p.isVisible('#copy-dlg'), 'dialog'); const t = await p.inputValue('#manual-copy-text'); ok(t.includes('Fix this potential security issue') && !t.includes('51Hx9aQ2eZ'), 'text');
});
await T('E19 WebGL unavailable: immediate fallback', async () => {
  const p = await newPage({ url: STORY, init: () => { const g = HTMLCanvasElement.prototype.getContext; HTMLCanvasElement.prototype.getContext = function (t, o) { return /webgl/.test(t) ? null : g.call(this, t, o); }; } });
  ok(await p.evaluate(() => document.documentElement.classList.contains('no-webgl')));
});
await T('E20 clear during an active scan: results never appear', async () => {
  const p = await newPage(); await bigProject(p); await p.click('#run'); await p.waitForTimeout(30);
  await p.click('#clear-btn'); await p.click('#dlg-confirm'); await p.waitForTimeout(1500);
  const st = await S(p); ok(st.files.length === 0 && st.scans === 0 && !st.scanning, JSON.stringify(st));
});
await T('E21 scans finishing out of order: only the latest is committed', async () => {
  const p = await newPage(); await bigProject(p); await p.click('#run'); await p.waitForTimeout(20); await p.click('#cancel-scan');
  await go(p, 'source'); await p.click('.tf[data-i="0"]'); await p.click('#rm-file');
  await scan(p); const n = await p.evaluate(() => SF.debug.state.scans[0].result.coverage.imported);
  ok(n === 279, 'committed scan has ' + n + ' files'); ok((await S(p)).scans === 1);
});
await T('E22 HTML-like file names and code are rendered as text', async () => {
  const p = await newPage(); await upload(p, '#up-files', [htmlName]); await scan(p);
  await openFinding(p); await go(p, 'source'); await go(p, 'reports');
  ok(await p.evaluate(() => !document.querySelector('#workspace img[src="x"], #workspace script')), 'markup injected'); ok(p.dialogs === 0, 'alert fired');
  await grabClipboard(p); await p.click('#copy-md'); const md = await p.evaluate(() => window.__clip[0]); ok(!md.includes('<img src=x'), 'markdown escaped');
});
await T('E23 reduced motion: story and workspace work without animation', async () => {
  const s = await newPage({ reducedMotion: 'reduce', url: STORY });
  await s.evaluate(() => window.scrollTo(0, document.getElementById('verify').offsetTop)); await s.waitForTimeout(200);
  ok(await s.evaluate(() => Math.abs(SF.sp.verify - SF.progress.verify) < 1e-6 && SF.sp.scan === 1), 'no easing');
  const p = await newPage({ reducedMotion: 'reduce' }); await scan(p); ok((await S(p)).scans === 1);
});
await T('E24 narrow screen (375px): no horizontal scroll, workspace usable', async () => {
  const p = await newPage({ viewport: { width: 375, height: 812 } }); await scan(p);
  await p.evaluate(() => document.getElementById('workspace').scrollIntoView()); await openFinding(p);
  ok(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'horizontal overflow'); ok(await p.isVisible('#detail .ev'));
  for (const v of ['fix', 'proof', 'ready', 'reports', 'trust', 'overview']) { await go(p, v); ok(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'overflow in ' + v); }
});
await T('false positive marking is session-local and excluded from the score', async () => {
  const p = await newPage(); await scan(p); const before = await p.evaluate(() => SF.SFscore = document.querySelector('#small-gauge .num').textContent);
  await openFinding(p); await p.click('#detail [data-act=fp]'); await p.fill('#detail .fp-form input', 'test fixture'); await p.click('#detail .fp-form button.btn-solid');
  const after = await p.evaluate(() => document.querySelector('#small-gauge .num').textContent); ok(+after < +before, before + ' → ' + after);
  ok(await p.evaluate(() => { try { return localStorage.length === 0 && sessionStorage.length === 0; } catch { return true; } }), 'nothing persisted');
});
await T('keyboard: tabs reachable with arrow keys, dialog closes with Escape', async () => {
  const p = await newPage(); await scan(p); await p.click('#load-fixed'); await scan(p);
  ok((await p.innerText('#vlist')).includes('Known test case'), 'demo labelled');
  await p.focus('#vn-proof'); await p.keyboard.press('ArrowUp'); ok(await p.evaluate(() => document.activeElement.id === 'vn-fix' && !document.getElementById('view-fix').hidden), 'arrow nav');
  await p.keyboard.press('ArrowDown'); await p.keyboard.press('ArrowDown'); ok(await p.evaluate(() => document.activeElement.id === 'vn-memory'), 'arrow down');
  await p.click('#clear-btn'); await p.keyboard.press('Escape'); ok(!(await p.isVisible('#clear-dlg')) && (await S(p)).files.length === 3, 'escape cancels');
});

await T('Fix Studio: propose → review diff → accept → undo → re-apply → rescan → No longer detected', async () => {
  const p = await newPage(); await scan(p); await go(p, 'fix');
  const id = await p.evaluate(() => { const r = [...document.querySelectorAll('#fix-list .frow')].find(x => /patch available/.test(x.textContent) && /innerHTML|Math\.random|Unsanitised/i.test(x.textContent + SF.debug.state.scans[0].result.findings.find(f => f.id === x.dataset.id).ruleId)); return r && r.dataset.id; });
  ok(id, 'a patchable finding'); await p.click(`#fix-list .frow[data-id="${id}"]`);
  const file = await p.evaluate(id => SF.debug.state.scans[0].result.findings.find(f => f.id === id).file, id);
  const orig = await p.evaluate(f => SF.debug.state.files.find(x => x.name === f).code, file);
  await p.click('[data-fix-act=propose]'); ok(await p.isVisible('#fix-detail .diff .m') && await p.isVisible('#fix-detail .diff .p'), 'diff rows');
  ok(/Validated/.test(await p.innerText('#fix-detail .valid')), 'validated');
  ok((await p.evaluate(f => SF.debug.state.files.find(x => x.name === f).code, file)) === orig, 'nothing changed before accept');
  await p.click('[data-fix-act=reject]'); ok((await p.evaluate(() => SF.debug.state.patches.length)) === 0, 'reject applies nothing');
  await p.click('[data-fix-act=propose]'); await p.click('[data-fix-act=accept]');
  ok((await p.evaluate(() => SF.debug.state.patches.length)) === 1, 'patch recorded'); ok((await p.evaluate(f => SF.debug.state.files.find(x => x.name === f).code, file)) !== orig, 'file changed');
  ok(await p.isVisible('#stale'), 'stale after patch');
  await p.click('[data-undo]'); ok((await p.evaluate(f => SF.debug.state.files.find(x => x.name === f).code, file)) === orig, 'undo restores exact content');
  await p.click(`#fix-list .frow[data-id="${id}"]`); await p.click('[data-fix-act=propose]'); await p.click('[data-fix-act=accept]');
  await scan(p); ok(await p.isVisible('#vlist'), 'ProofLoop after rescan'); const v = await p.innerText('#vlist');
  ok(/[1-9]\s*No longer detected/i.test(v) && /patched here/i.test(v) && /Tests executed:\s*none/i.test(v), v.slice(0, 500));
  ok(!/\bfixed\b/i.test(v.replace(/Fix Studio|prepared patched|not proof the vulnerability is fixed/gi, '')), 'never claims fixed');
  await p.click('#vlist .vrow.x'); ok(await p.isVisible('#vlist .vx'), 'row expands with evidence');
  await go(p, 'proof'); ok((await p.innerText('#timeline')).includes('Patch applied'), 'timeline event');
  ok(p.errors.length === 0, p.errors.join('; '));
});
await T('Fix Studio: stale proposal is refused instead of corrupting the file', async () => {
  const p = await newPage(); await scan(p); await go(p, 'fix');
  const id = await p.evaluate(() => [...document.querySelectorAll('#fix-list .frow')].find(x => /patch available/.test(x.textContent)).dataset.id);
  await p.click(`#fix-list .frow[data-id="${id}"]`); await p.click('[data-fix-act=propose]');
  await p.evaluate(id => { const s = SF.debug.state, f = s.scans[0].result.findings.find(x => x.id === id), file = s.files.find(x => x.name === f.file); file.code = '// changed elsewhere\n' + file.code.split('\n').map((l, i) => i === f.line - 1 ? '// line rewritten' : l).join('\n'); }, id);
  await p.click('[data-fix-act=accept]'); ok((await p.evaluate(() => SF.debug.state.patches.length)) === 0, 'not applied');
});
await T('Overview: scan-completion summary, risk map nodes, priorities and next action use real data', async () => {
  const p = await newPage(); await scan(p);
  ok(await p.evaluate(() => document.getElementById('ov-results').classList.contains('just-done')), 'completion moment');
  await p.waitForTimeout(800);
  const crit = await p.evaluate(() => SF.debug.state.scans[0].result.findings.filter(f => f.severity === 'critical').length);
  ok((await p.innerText('#c-critical')) === String(crit), 'count matches scan');
  ok((await p.$$('#riskmap .rm-node')).length === 3, 'one node per file'); ok((await p.$$('#priority li')).length >= 1, 'priorities');
  await p.click('#riskmap .rm-node'); ok(await p.isVisible('#view-findings'), 'node opens findings filtered');
  await go(p, 'overview'); await p.click('#next-action button'); ok(await p.isVisible('#detail .ev'), 'next action opens evidence');
});
await T('Findings detail: explainer marks observed vs illustrative, CIA impact, references', async () => {
  const p = await newPage(); await scan(p); await openFinding(p);
  const d = await p.innerText('#detail');
  ok(/Observed in your code/i.test(d) && /Illustrative/i.test(d) && /not a demonstrated attack/i.test(d), 'observed vs illustrative');
  ok(/confidentiality/i.test(d) && /integrity/i.test(d) && /availability/i.test(d) && /not observed/i.test(d), 'CIA, not observed damage');
  ok(!/₹|\$\s?\d|probability|% chance/i.test(d), 'no invented money or probabilities');
  ok((await p.$$('#detail .refs a[rel~=noopener]')).length >= 1, 'references');
});
await T('Readiness, Trust Center and Reports: honest flags and an escaped HTML report', async () => {
  const p = await newPage(); await upload(p, '#up-folder', projDir); await scan(p);
  await go(p, 'ready'); const r = await p.innerText('#ready');
  ok(/did not run|not checked/i.test(r) && /Fix Before Deployment|Assessment Incomplete|Failed Check|Ready for Review/i.test(r), 'readiness flags');
  ok(/not discovered vulnerabilities/i.test(r), 'test specs labelled as suggestions');
  await go(p, 'trust'); const t = await p.innerText('#trust'); ok(/What leaves the browser/i.test(t) && /AI services: only Google Gemini, and only after you switch on AI deep check/i.test(t), 'trust center');
  await go(p, 'reports'); const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#exp-html')]);
  const html = fs.readFileSync(await dl.path(), 'utf8');
  ok(html.includes('Content-Security-Policy') && !html.includes(SECRET) && !html.includes(DBPW) && !/<script/i.test(html), 'html report safe');
  ok(/Tests executed/i.test(html) || /not a full audit|pattern/i.test(html), 'limits stated');
});
await T('Paid repair offline: no server call, honest "not available" card', async () => {
  const p = await newPage(); const reqs = []; p.on('request', r => { if (!r.url().startsWith('file:')) reqs.push(r.url()); });
  await scan(p); await go(p, 'fix'); await p.waitForSelector('#paid'); await p.waitForTimeout(100);
  const t = await p.innerText('#paid'); ok(/Not available in this view/i.test(t) && /test/i.test(t) && /no turnaround is promised/i.test(t), t.slice(0, 300));
  ok(!reqs.some(u => /\/api\/|cashfree/.test(u)), 'no network: ' + reqs.join());
});
await T('Paid repair with Cashfree (mocked gateway, stub checkout): consent → order → checkout → server re-check → submitted', async () => {
  const { createDevServer, d1, localProjectBucket } = await import(pathToFileURL(path.join(here, '..', 'tools', 'dev-server.mjs')).href);
  const { createSessionToken } = await import(pathToFileURL(path.join(here, '..', 'worker', 'platform.js')).href);
  const http = await import('node:http'); const orders = new Map(), posts = [];
  const fetch = async (url, init) => {
    const u = new URL(url), body = init.body ? JSON.parse(init.body) : null; let m;
    if (init.method === 'POST' && u.pathname === '/pg/orders') { posts.push(body); const o = { cf_order_id: 1, order_id: body.order_id, order_amount: body.order_amount, order_currency: 'INR', order_status: 'ACTIVE', payment_session_id: 'sess_' + body.order_id, _p: [] }; orders.set(body.order_id, o); return Response.json(o); }
    if ((m = u.pathname.match(/^\/pg\/orders\/([^/]+)\/payments$/))) return Response.json(orders.get(m[1])._p);
    if ((m = u.pathname.match(/^\/pg\/orders\/([^/]+)$/))) return Response.json(orders.get(m[1]));
    return new Response('{}', { status: 404 });
  };
  const authEnv = { TOKEN_ENC_KEY: 'e2e-token-signing-key-with-more-than-32-bytes' };
  const testToken = await createSessionToken(authEnv, { uid: 'e2e-owner', email: 'e2e@example.test' });
  const srv = createDevServer({ env: { ...authEnv, CASHFREE_APP_ID: 'TEST_e2e', CASHFREE_SECRET_KEY: 'cfsk_e2e', DB: d1(':memory:'), PROJECTS: localProjectBucket(path.join(tmp, 'project-objects')), fetch, RATE_PER_HOUR: '10000' }, staticDir: DIR });
  await new Promise(r => srv.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + srv.address().port;
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } }); const p = await ctx.newPage(); p.errors = []; p.on('pageerror', e => p.errors.push(e.message));
    await p.addInitScript(token => localStorage.setItem('sf_id_token', token), testToken);
    const STUB = "window.Cashfree=function(cfg){return{checkout:function(o){window.__cf={cfg:cfg,opts:o};return new Promise(function(res){window.__resolveCheckout=res;});}};};";
    await p.route('**/*', r => { const u = r.request().url(); if (u.startsWith(base)) return r.continue(); if (u === 'https://sdk.cashfree.com/js/v3/cashfree.js') return r.fulfill({ contentType: 'text/javascript', body: STUB }); return r.abort(); });
    await p.goto(base + '/app.html'); await p.waitForTimeout(300); await scan(p); await go(p, 'fix');
    await p.waitForSelector('#pc-scope'); ok(await p.isDisabled('#pc-create'), 'consent required first'); ok(/Cashfree test mode/i.test(await p.innerText('#paid')), 'labelled test mode');
    ok(!/"code"|evidence/.test(await p.innerText('#pc-preview')), 'no code or evidence unless opted in');
    await p.check('#pc-scope'); await p.click('#pc-create');
    await p.waitForFunction(() => document.querySelector('#pc-pay') || /Could not|No supported|not configured|did not reproduce|associate this project/i.test(document.getElementById('toast')?.textContent||''), null, { timeout: 15000 });
    if (!(await p.$('#pc-pay'))) throw new Error('checkout preparation: '+await p.innerText('#toast'));
    await p.click('#pc-pay'); await p.waitForFunction(() => window.__cf);
    const cfOpts = await p.evaluate(() => window.__cf); ok(cfOpts.cfg.mode === 'sandbox' && /^sess_sf_/.test(cfOpts.opts.paymentSessionId) && cfOpts.opts.redirectTarget === '_modal', JSON.stringify(cfOpts));
    ok(posts.length === 1 && posts[0].order_amount === 699, 'server-side price');
    // the checkout says "success" but Cashfree has no payment: nothing unlocks
    await p.evaluate(() => window.__resolveCheckout({ paymentDetails: { paymentMessage: 'ok' } })); await p.waitForTimeout(400);
    ok(/awaiting payment/i.test(await p.innerText('#paid')), 'browser success alone does not unlock');
    await p.evaluate(() => { window.__cf = null; }); await p.click('#pc-pay'); await p.waitForFunction(() => window.__cf);
    await p.evaluate(() => window.__resolveCheckout({ error: { message: 'closed' } })); await p.waitForTimeout(400);
    ok(/payment failed/i.test(await p.innerText('#paid')), 'failure shown');
    const o = [...orders.values()][0]; o.order_status = 'PAID'; o._p.push({ cf_payment_id: 9, payment_status: 'SUCCESS', payment_amount: 699, payment_currency: 'INR' });
    await p.click('#pc-refresh'); await p.waitForTimeout(400);
    const t = await p.innerText('#paid'); ok(/submitted/i.test(t) && !(await p.$('#pc-pay')), 'submitted after the server re-checked Cashfree: ' + t.slice(-200));
    ok(posts.length === 1, 'one order per request');
    ok(await p.evaluate(() => { const r=JSON.parse(sessionStorage.getItem('sf-repair-request')||'null'); return !!localStorage.getItem('sf_id_token') && !!r && !!r.token && !!r.projectId && document.cookie === ''; }), 'signed-in repair and project capability persist in this tab');
    ok(p.errors.length === 0, p.errors.join('; '));
    await ctx.close();
  } finally { await new Promise(r => srv.close(r)); }
});

/* ---------- AI deep check + Codebase memory: real Worker code via the dev server, Gemini mocked ---------- */
async function aiServer() {
  const { createDevServer, d1 } = await import(pathToFileURL(path.join(here, '..', 'tools', 'dev-server.mjs')).href);
  const http = await import('node:http'); const calls = [];
  const reply = obj => new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(obj) }] } }] }), { status: 200 });
  const fetch = async (url, init) => {
    const text = JSON.parse(init.body).contents[0].parts[0].text; calls.push(text);
    if (/Hard-check this project/.test(text)) {
      const m = text.match(/=== FILE: api\/orders\/route\.js ===[\s\S]*?\n\s*(\d+)\| (\s*const sql = `SELECT \* FROM orders[^\n]*)/);
      return reply({ issues: m ? [{ title: 'Orders readable by any user (IDOR)', file: 'api/orders/route.js', line: +m[1], snippet: m[2].trim(), category: 'Access control', cwe: 'CWE-639', severity: 'high', score: 8.1, exploitability: 8, impact: 8, confidence: 'high',
        explainSimple: 'Anyone can see other customers’ orders by changing a number.', explainTechnical: 'The id comes from the query string instead of the verified session.',
        chain: [{ kind: 'source', label: 'id taken from ?id=', file: 'api/orders/route.js', line: +m[1] }, { kind: 'weakness', label: 'no ownership check', file: '', line: 0 }, { kind: 'impact', label: 'other customers’ orders exposed', file: '', line: 0 }],
        cutAt: 1, afterFix: 'Only the signed-in user’s orders are returned.', howToFix: ['Take the user id from the verified session', 'Return 403 for other ids'], relatedRule: '', cia: { confidentiality: 'high', integrity: 'none', availability: 'none' } },
        { title: 'Invented issue', file: 'api/orders/route.js', line: 2, snippet: 'eval(req.body.x)', category: 'Injection', severity: 'critical', score: 10, exploitability: 10, impact: 10, confidence: 'high', explainSimple: 'x', explainTechnical: 'x', chain: [], cutAt: 0, afterFix: 'x', howToFix: [], cia: {} }] : [] });
    }
    if (/second reviewer/.test(text)) return reply({ verdicts: [{ index: 0, verdict: 'confirmed', reason: 'id is attacker-controlled', score: 8.1 }] });
    if (/Write fix guidance/.test(text)) return reply({ summary: 'Scope the query to the signed-in user', steps: [{ title: 'Use the session user', detail: 'Read the id from `jwt.verify(...)`' }], pitfalls: ['Do not trust ?id='], verify: ['Request another user’s id and expect 403'], cutAt: 1, afterFix: 'safe', confidence: 'high' });
    const vr = text.match(/Verification round (\d+) of 10/);
    if (vr) { const n = +vr[1]; return reply({ ok: n >= 5, problems: n < 5 ? [{ severity: n < 3 ? 'major' : 'minor', text: 'Round ' + n + ': also cover the admin route' }] : [], revised: { summary: 'Scope the query to the signed-in user (rev ' + n + ')', steps: [{ title: 'Use the session user', detail: 'Read the id from the verified token' }, { title: 'Parameterise', detail: 'Pass it as $1' }], pitfalls: [], verify: ['Try another id'], cutAt: 1, afterFix: 'safe', confidence: 'high' } }); }
    if (/Developer asks/.test(text)) return reply({ answer: 'Change line 12: build the query from the **verified** user id.', followUps: [] });
    if (/says they fixed/.test(text)) return reply({ status: /\$1/.test(text) ? 'fixed' : 'not_fixed', evidence: /\$1/.test(text) ? 'query now uses $1 with the session user' : 'still concatenated', remaining: '' });
    return reply({});
  };
  const srv = createDevServer({ env: { GEMINI_API_KEY: 'test', DB: d1(':memory:'), fetch, RATE_PER_HOUR: '10000' }, staticDir: DIR });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  return { base: 'http://127.0.0.1:' + srv.address().port, calls, close: () => new Promise(r => srv.close(r)) };
}
async function aiPage(base, ctxOpts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, ...ctxOpts }); const p = await ctx.newPage(); p.errors = []; p.ext = [];
  p.on('pageerror', e => p.errors.push(e.message)); p.on('dialog', d => d.accept());
  await p.route('**/*', r => { const u = r.request().url(); if (u.startsWith(base)) return r.continue(); p.ext.push(u); return r.abort(); });
  await p.goto(base + '/app.html'); await p.waitForFunction(() => !document.getElementById('ai-toggle').disabled, null, { timeout: 10000 }); return p;
}
async function consentOn(p, sel) { await p.click(sel); await p.waitForSelector('#consent-dlg[open]'); if (await p.$('#cs-own')) { ok(await p.isDisabled('#cs-ok'), 'needs the ownership tick'); await p.check('#cs-own'); } await p.click('#cs-ok'); }
const aiS = await aiServer();
await T('AI deep check: consent → Gemini review → second reviewer → only quotable findings merged', async () => {
  const p = await aiPage(aiS.base); await scan(p);
  ok(aiS.calls.length === 0, 'nothing sent before consent');
  await consentOn(p, '#ai-toggle');
  await p.waitForFunction(() => SF.debug.state.scans[0].ai === true, null, { timeout: 15000 });
  await p.waitForFunction(() => { const xs=document.querySelectorAll('#ai-bar .ai-stages li'); return xs.length===10 && xs[9].classList.contains('completed'); }, null, { timeout: 5000 });
  ok(aiS.calls.every(t => !t.includes('51Hx9aQ2eZ')), 'secret reached Gemini');
  const bar = await p.innerText('#ai-bar'); ok(/1 claim could not be quoted/i.test(bar) && /1 new beyond the engine/i.test(bar), bar);
  const progress=await p.$$eval('#ai-bar .ai-stages li',xs=>xs.map(x=>({status:x.className,label:x.querySelector('b')?.textContent})));ok(progress.length===10&&progress[4].status==='completed'&&progress[9].status==='completed'&&progress[0].label==='Stage 1 of 10'&&progress.every(x=>!/^Round /.test(x.label)),'ten transparent stages, not fabricated Gemini rounds: '+JSON.stringify(progress));
  const ai = await p.evaluate(() => SF.debug.state.scans[0].result.findings.filter(f => f.source === 'ai').map(f => f.title)); ok(ai.join() === 'Orders readable by any user (IDOR)', ai.join());
  await p.click('#vn-findings'); ok((await p.innerText('#list')).includes('Orders readable by any user'), 'listed with tag');
  ok(p.ext.every(u => !/generativelanguage/.test(u)), 'browser never calls Gemini directly');
  ok(p.errors.length === 0, p.errors.join('; '));
  await p.context().close();
});
await T('AI finding: seriousness score, risk chain with fix cut, guidance checked 10×, Ask SecureFlow', async () => {
  const p = await aiPage(aiS.base); await scan(p); await consentOn(p, '#ai-toggle');
  await p.waitForFunction(() => SF.debug.state.scans[0].ai === true, null, { timeout: 15000 });
  const id = await p.evaluate(() => SF.debug.state.scans[0].result.findings.find(f => f.source === 'ai').id);
  await p.click('#vn-findings'); await p.click(`#list .frow[data-id="${id}"] .t`);
  ok(/8\.1/.test(await p.innerText('#detail .sev-score')) && /AI assessment/.test(await p.innerText('#detail .sev-score')), 'score');
  ok((await p.$$('#detail .chain .cn')).length === 3 && await p.isVisible('#detail .chain .cut'), 'chain + cut');
  await p.click('#detail [data-chain]'); ok(await p.isVisible('#detail .chain .after'), 'after-fix view');
  await p.click('#detail [data-exp="tech"]'); ok(/query string/.test(await p.innerText('#detail .explain')), 'technical explanation');
  await p.click('#detail [data-ai="guide"]');
  await p.waitForSelector('#detail .verified-note', { timeout: 20000 });
  const lad = await p.$$eval('#detail .ladder li', l => l.map(x => x.className)); ok(lad.length === 10 && lad[0] === 'draft' && lad[1] === 'fix' && lad[9] === 'ok', lad.join());
  ok(aiS.calls.filter(t => /Verification round/.test(t)).length >= 9, 'nine verification rounds');
  ok(/rev 10/.test(await p.innerText('#detail .guide')), 'final guidance is the round-10 version');
  await p.click('#detail [data-ask]'); await p.waitForFunction(() => /verified/i.test(document.querySelector('#detail .msg.bot:last-child')?.textContent||''), null, { timeout: 10000 }); ok(/verified/i.test(await p.innerText('#detail .msg.bot')), 'answer');
  ok(p.errors.length === 0, p.errors.join('; '));
  await p.context().close();
});
await T('Codebase memory: first visit saves fingerprints; after reload the same code is recognised and remaining fixes are listed; fixes are verified', async () => {
  let p = await aiPage(aiS.base); await scan(p); await consentOn(p, '#mem-toggle');
  await p.waitForFunction(() => SF.aiDebug.mem.phase === 'done', null, { timeout: 15000 });
  await p.click('#vn-memory'); ok(/new codebase/i.test(await p.innerText('#memory')), 'memory status is shown in its own view');
  await p.context().close();
  // a fresh tab: nothing kept in the browser, the server recognises the code
  p = await aiPage(aiS.base); await scan(p); await consentOn(p, '#mem-toggle');
  await p.waitForFunction(() => SF.aiDebug.mem.phase === 'done', null, { timeout: 15000 });
  await p.click('#vn-memory'); let bar = await p.innerText('#memory'); ok(/Recognised/i.test(bar) && /still to fix/i.test(bar), bar.slice(0,400));
  const still = await p.evaluate(() => SF.aiDebug.mem.report.checked.filter(r => r.status === 'still_open').length); ok(still >= 10, 'all unchanged findings still open: ' + still);
  // apply the prepared patched demo, switch AI on so changed lines get a second opinion, rescan
  await consentOn(p, '#ai-toggle'); await p.waitForFunction(() => SF.debug.state.scans[0].ai === true, null, { timeout: 15000 });
  await p.click('#load-fixed'); await scan(p);
  await p.waitForFunction(() => SF.aiDebug.mem.phase === 'done' && SF.debug.state.scans.length === 2 && SF.aiDebug.mem.report && SF.aiDebug.mem.report.at > SF.debug.state.scans[1].at, null, { timeout: 30000 });
  const st = await p.evaluate(() => { const c = {}; SF.aiDebug.mem.report.checked.forEach(r => c[r.status] = (c[r.status] || 0) + 1); return c; });
  ok((st.verified_fixed || 0) >= 5, JSON.stringify(st));
  ok(aiS.calls.some(t => /says they fixed/.test(t)), 'changed lines were double-checked by the AI');
  await p.click('#vn-memory'); const m = await p.innerText('#memory'); ok(/Verified fixed/i.test(m) && /Security timeline/i.test(m) && /Recognised/i.test(m), m.slice(0, 400));
  ok((await p.$$('#memory .mem-tl circle')).length >= 2, 'timeline has visits');
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-mem="report"]')]); const rep = fs.readFileSync(await dl.path(), 'utf8');
  ok(/fix-verification report/i.test(rep) && /Verified fixed/.test(rep) && !rep.includes('51Hx9aQ2eZ'), 'report');
  ok(await p.evaluate(() => { try { return localStorage.length === 0 && sessionStorage.length === 0; } catch { return true; } }), 'nothing in browser storage');
  await p.click('[data-mem="forget"]'); await p.waitForFunction(() => SF.aiDebug.mem.report === null);
  const p2 = await aiPage(aiS.base); await scan(p2); await consentOn(p2, '#mem-toggle'); await p2.waitForFunction(() => SF.aiDebug.mem.phase === 'done', null, { timeout: 15000 });
  await p2.click('#vn-memory'); ok(/new codebase/i.test(await p2.innerText('#memory')), 'forgotten');
  ok(p.errors.length === 0 && p2.errors.length === 0, p.errors.concat(p2.errors).join('; '));
  await p.context().close(); await p2.context().close();
});
await T('Without the server: AI and memory are clearly unavailable and nothing is requested', async () => {
  const p = await newPage(); ok(await p.isDisabled('#ai-toggle') && await p.isDisabled('#mem-toggle'), 'disabled');
  await scan(p); await go(p, 'findings'); await p.waitForSelector('#detail .sev-score');
  ok(/Needs the SecureFlow server/i.test(await p.innerText('#detail')), 'explains');
  await go(p, 'memory'); ok(/Not available in this copy/i.test(await p.innerText('#memory')), 'memory explains');
});
await T('Landing page: story only, workspace on its own page', async () => {
  const p = await newPage({ url: STORY }); ok(!(await p.$('#app')) && (await p.$$('a[href="app.html"]')).length >= 2, 'links');
  ok(p.errors.length === 0, p.errors.join('; '));
});
await aiS.close();

await browser.close();
fs.rmSync(tmp, { recursive: true, force: true });
const fails = results.filter(r => r[1] !== 'pass');
for (const [n, r, ms] of results) console.log((r === 'pass' ? 'ok    ' : 'NOT OK') + ' ' + n + (r === 'pass' ? '' : '  → ' + r) + `  (${ms} ms)`);
console.log(`\n${results.length - fails.length}/${results.length} e2e tests passed`);
process.exit(fails.length ? 1 : 0);
