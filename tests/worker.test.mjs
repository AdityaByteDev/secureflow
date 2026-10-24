// Worker API tests: Gemini is mocked (no network), D1 is node:sqlite in memory.  Run: node --test tests/worker.test.mjs
import test from 'node:test'; import assert from 'node:assert/strict';
import { handleApi, locate, stripLongCode, similarity } from '../worker/index.js';
import { d1 } from '../tools/dev-server.mjs';
import { createSessionToken } from '../worker/platform.js';

const SECRET = 'sk_' + 'live_51Hx9aQ2eZvKYlo2C8fT3nPq';
const FILES = [{ name: 'api/user.js', code: `const key = "${SECRET}";\napp.get('/u', (req, res) => {\n  db.query("SELECT * FROM users WHERE id=" + req.query.id);\n});\n` }];
const ISSUES = [
  { title: 'SQL injection in user lookup', file: 'api/user.js', line: 1, snippet: 'db.query("SELECT * FROM users WHERE id=" + req.query.id);', category: 'Injection', cwe: 'CWE-89', severity: 'critical', score: 9.4, exploitability: 9, impact: 9.5, confidence: 'high',
    explainSimple: 'Anyone can read your users table.', explainTechnical: 'req.query.id is concatenated into SQL.', chain: [{ kind: 'source', label: 'id from query string', file: 'api/user.js', line: 2 }, { kind: 'sink', label: 'string-built SQL', file: 'api/user.js', line: 3 }, { kind: 'impact', label: 'database dump', file: '', line: 0 }],
    cutAt: 1, afterFix: 'Input is treated as data.', howToFix: ['Use a parameterised query'], relatedRule: 'sql-injection', cia: { confidentiality: 'high', integrity: 'high', availability: 'low' } },
  { title: 'Invented eval call', file: 'api/user.js', line: 2, snippet: 'eval(req.body.code)', category: 'Injection', severity: 'critical', score: 10, exploitability: 10, impact: 10, confidence: 'high', explainSimple: 'x', explainTechnical: 'x', chain: [], cutAt: 0, afterFix: 'x', howToFix: [], cia: {} },
  { title: 'Missing rate limit', file: 'api/user.js', line: 2, snippet: "app.get('/u', (req, res) => {", category: 'Config', severity: 'low', score: 3, exploitability: 3, impact: 3, confidence: 'low', explainSimple: 'x', explainTechnical: 'x', chain: [], cutAt: 0, afterFix: 'x', howToFix: [], cia: {} }
];
function mockGemini(script) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body), text = body.contents[0].parts[0].text, model = url.match(/models\/([^:]+):/)[1];
    calls.push({ model, text, key: init.headers['x-goog-api-key'] });
    const r = script(text, model, calls.length);
    if (r && r.httpStatus) return new Response(JSON.stringify({ error: { message: 'x' } }), { status: r.httpStatus });
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ thought: true, text: 'thinking…' }, { text: JSON.stringify(r) }] } }] }), { status: 200 });
  };
  return { fetch, calls };
}
const defaultScript = text =>
  /Hard-check this project/.test(text) ? { issues: ISSUES } :
  /second reviewer/.test(text) ? { verdicts: [{ index: 0, verdict: 'confirmed', reason: 'concatenation', score: 9.6 }, { index: 1, verdict: 'confirmed', reason: '' }, { index: 2, verdict: 'false_positive', reason: 'not security' }] } :
  /Verification round/.test(text) ? { ok: false, problems: [{ severity: 'major', text: 'Also covers the admin route' }], revised: { summary: 'Use placeholders', steps: [{ title: 'Use placeholders', detail: 'Pass `req.query.id` as a parameter.\n```js\na\nb\nc\nd\ne\n```' }], pitfalls: [], verify: ['Send 1 OR 1=1'], cutAt: 1, afterFix: 'safe', confidence: 'high' } } :
  /Write fix guidance/.test(text) ? { summary: 'Parameterise', steps: [{ title: 'Use placeholders', detail: 'Use ? placeholders' }], pitfalls: ['Do not escape by hand'], verify: ['Test it'], cutAt: 1, afterFix: 'safe', confidence: 'high' } :
  /Developer asks/.test(text) ? { answer: 'Change line 3.\n```js\n1\n2\n3\n4\n5\n6\n```', followUps: [] } :
  /says they fixed/.test(text) ? { status: 'fixed', evidence: 'uses placeholders', remaining: '' } : {};
function env(over = {}) { const g = mockGemini(over.script || defaultScript); return { e: { GEMINI_API_KEY: 'test-key', DB: d1(':memory:'), fetch: g.fetch, RATE_PER_HOUR: '1000', ...over.env }, calls: g.calls }; }
const call = (e, path, body, headers = {}) => handleApi(new Request('https://sf.test' + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }), e).then(async r => ({ status: r.status, body: await r.json() }));

test('analyze: masks secrets, drops reviewer-rejected and unquotable claims, corrects line numbers', async () => {
  const { e, calls } = env();
  const r = await call(e, '/api/ai/analyze', { consent: true, files: FILES, engine: [{ ruleId: 'sql-injection', title: 'SQL', severity: 'critical', file: 'api/user.js', line: 3 }] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(calls.every(c => !c.text.includes('51Hx9aQ2eZ')), 'secret sent to Gemini');
  assert.equal(r.body.issues.length, 1); const i = r.body.issues[0];
  assert.equal(i.line, 3, 'line corrected from 1 to the line the snippet is really on'); assert.equal(i.review, 'confirmed'); assert.equal(i.score, 9.5);
  assert.deepEqual(r.body.guard, { proposed: 3, rejectedByReviewer: 1, droppedUnlocated: 1, challenged: 3 });
  assert.equal(i.chain[0].observed, true); assert.equal(i.chain[2].observed, false); assert.equal(i.cia.confidentiality, 'high');
  assert.match(i.id, /^ai-[0-9a-f]{10}$/); assert.equal(r.body.passes, 2);
});
test('analysis stream emits real provider and stage events with the completed result', async () => {
  const { e } = env();
  const r = await handleApi(new Request('https://sf.test/api/ai/analyze/stream', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({consent:true,files:FILES,engine:[]}) }), e);
  assert.equal(r.status,200); assert.match(r.headers.get('content-type'),/text\/event-stream/);
  const events=(await r.text()).trim().split(/\n\n/).map(x=>JSON.parse(x.slice(6)));
  assert.ok(events.some(x=>x.type==='provider'&&x.state==='request_sent'));
  assert.ok(events.some(x=>x.type==='provider'&&x.state==='response_validated'));
  assert.ok(events.some(x=>x.type==='stage'&&x.index===7&&x.status==='completed'));
  assert.equal(events.at(-1).type,'done'); assert.equal(events.at(-1).result.passes,2);
});
test('development Gemini diagnostic requires auth, is hidden outside development and validates a real reply', async () => {
  const { e } = env({ env:{DEV_DIAGNOSTICS:'true',TOKEN_ENC_KEY:'x'.repeat(32)}, script:()=>({ok:true,reply:'pong'}) });
  assert.equal((await call(e,'/api/ai/diagnostic',{})).status,401);
  const token=await createSessionToken(e,{uid:'diagnostic-user',email:'diag@example.test'});
  const ok=await call(e,'/api/ai/diagnostic',{}, {authorization:'Bearer '+token});
  assert.equal(ok.status,200,JSON.stringify(ok.body)); assert.equal(ok.body.success,true); assert.equal(ok.body.status,200); assert.ok(ok.body.durationMs>=0);
  const prod=env({env:{TOKEN_ENC_KEY:'x'.repeat(32)}});
  const hidden=await call(prod.e,'/api/ai/diagnostic',{}, {authorization:'Bearer '+token}); assert.equal(hidden.status,404);
});
test('stream preserves provider credential rejection as a categorized error event', async()=>{
  const {e}=env({script:()=>({httpStatus:403}),env:{GEMINI_MODELS:'only-model'}});
  const r=await handleApi(new Request('https://sf.test/api/ai/analyze/stream',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({consent:true,files:FILES,engine:[]})}),e);
  const events=(await r.text()).trim().split(/\n\n/).map(x=>JSON.parse(x.slice(6)));
  assert.ok(events.some(x=>x.type==='provider'&&x.state==='failed'&&x.status===403));
  assert.equal(events.at(-1).type,'error'); assert.equal(events.at(-1).error,'gemini_auth_failed'); assert.equal(events.at(-1).detail,403);
});
test('API rejects missing consent, cross-origin calls and non-JSON', async () => {
  const { e } = env();
  assert.equal((await call(e, '/api/ai/analyze', { files: FILES })).body.error, 'consent_required');
  assert.equal((await call(e, '/api/ai/analyze', { consent: true, files: FILES }, { origin: 'https://evil.example' })).status, 403);
  const r = await handleApi(new Request('https://sf.test/api/ai/ask', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' }), e); assert.equal(r.status, 415);
  const h = await (await handleApi(new Request('https://sf.test/api/health'), e)).json(); assert.equal(h.ai, true); assert.equal(h.memory, true); assert.ok(!JSON.stringify(h).includes('test-key'));
});
test('model fallback: busy and retired models are skipped', async () => {
  const { e, calls } = env({ script: (t, model) => model === 'm1' ? { httpStatus: 503 } : model === 'm2' ? { httpStatus: 404 } : defaultScript(t), env: { GEMINI_MODELS: 'm1,m2,m3' } });
  const r = await call(e, '/api/ai/ask', { consent: true, issue: { title: 'SQL', file: 'api/user.js', line: 3 }, code: FILES[0].code, question: 'where?' });
  assert.equal(r.status, 200); assert.deepEqual(calls.map(c => c.model), ['m1', 'm1', 'm2', 'm3']);
  const { e: e2 } = env({ script: () => ({ httpStatus: 503 }), env: { GEMINI_MODELS: 'm1' } });
  assert.equal((await call(e2, '/api/ai/ask', { consent: true, issue: { title: 'SQL', file: 'a.js', line: 1 }, code: 'x', question: 'q' })).body.error, 'ai_unavailable');
});
test('guidance rounds and answers never include a full code rewrite', async () => {
  const { e } = env(); const issue = { title: 'SQL', file: 'api/user.js', line: 3, severity: 'critical' };
  const r1 = await call(e, '/api/ai/guide', { consent: true, issue, code: FILES[0].code, round: 1 }); assert.equal(r1.body.guidance.summary, 'Parameterise');
  const r2 = await call(e, '/api/ai/guide', { consent: true, issue, code: FILES[0].code, round: 2, draft: r1.body.guidance });
  assert.equal(r2.body.review.ok, false); assert.equal(r2.body.review.problems[0].severity, 'major');
  assert.match(r2.body.guidance.steps[0].detail, /code example removed/); assert.ok(!r2.body.guidance.steps[0].detail.includes('```'));
  const a = await call(e, '/api/ai/ask', { consent: true, issue, code: FILES[0].code, question: 'give me the code' }); assert.match(a.body.answer, /code example removed/);
  const v = await call(e, '/api/ai/verify-fix', { consent: true, issue, code: 'db.query("SELECT * FROM users WHERE id=?", [id]);' }); assert.equal(v.body.status, 'fixed', JSON.stringify(v.body));
});
test('helpers: locate, stripLongCode, similarity', () => {
  const byName = new Map([['a.js', { code: 'x\n  foo(bar);\ny' }]]);
  assert.equal(locate({ file: 'a.js', line: 9, snippet: 'foo(bar);' }, byName), 2); assert.equal(locate({ file: 'a.js', line: 1, snippet: 'nope()' }, byName), null);
  assert.equal(stripLongCode('use ```x```'), 'use `x`');
  const a = Array.from({ length: 64 }, (_, i) => i); assert.equal(similarity(a, a), 1);
});
const sig = (base, changed = 0) => Array.from({ length: 64 }, (_, i) => i < changed ? 4e9 - i : base + i * 7);
test('memory: save, recognise the same and a similar codebase, require possession, forget', async () => {
  const { e } = env(); const S = sig(1000);
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: S })).body.match, null);
  assert.equal((await call(e, '/api/memory/save', { consent: true, sig: S, files: [{ path: 'a.js', hashes: 'aaaaaaaa' }] })).body.error, 'invalid_salt');
  const save = await call(e, '/api/memory/save', { consent: true, sig: S, digest: 'd1', salt: '0123456789abcdef', files: [{ path: 'a.js', hashes: 'aaaaaaaabbbbbbbb' }],
    issues: [{ id: 'ai-0123456789', source: 'ai', title: 'SQL', severity: 'critical', score: 9.5, file: 'a.js', line: 2, anchor: 'bbbbbbbb', ctx: 'aaaaaaaa000000000000000000000000', howto: ['Use placeholders', '```\n1\n2\n3\n4\n5\n```'], status: 'open' }], visit: { score: 80, open: 1, fixed: 0 } });
  assert.equal(save.status, 200, JSON.stringify(save.body)); assert.equal(save.body.created, true);
  const m = await call(e, '/api/memory/match', { consent: true, sig: sig(1000, 10), digest: 'x' }); assert.equal(m.body.match.id, save.body.id); assert.ok(m.body.match.similarity > .8); assert.equal(m.body.match.openIssues, 1);
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: sig(5000) })).body.match, null, 'different codebase');
  // small project, heavily edited: few identical lines but the same files → still recognised; same files but nothing in common → not
  const P = ['0000aaaa', '0000bbbb'];
  const s2 = await call(e, '/api/memory/save', { consent: true, sig: sig(9000), paths: P, salt: 'fedcba9876543210', files: [{ path: 'x.js', hashes: 'aaaaaaaa' }] });
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: sig(9000, 50), paths: P })).body.match.id, s2.body.id, 'edited small project');
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: sig(9000, 60), paths: P })).body.match, null, 'same layout, different code');
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: sig(9000, 50), paths: ['1111cccc'] })).body.match, null, 'different layout');
  assert.equal((await call(e, `/api/memory/${save.body.id}/load`, { consent: true, sig: sig(5000) })).status, 404, 'needs the code to read it');
  const L = await call(e, `/api/memory/${save.body.id}/load`, { consent: true, sig: S }); assert.equal(L.body.salt, '0123456789abcdef'); assert.equal(L.body.issues[0].howto.length, 2); assert.match(L.body.issues[0].howto[1], /removed/);
  assert.ok(!JSON.stringify(L.body).includes('SELECT'), 'no code stored');
  const up = await call(e, '/api/memory/save', { consent: true, id: save.body.id, sig: S, digest: 'd2', files: [{ path: 'a.js', hashes: 'aaaaaaaacccccccc' }], issues: [{ id: 'ai-0123456789', status: 'verified_fixed', title: 'SQL', file: 'a.js', line: 2 }], visit: { score: 10, open: 0, fixed: 1 } });
  assert.equal(up.body.created, false); const L2 = await call(e, `/api/memory/${save.body.id}/load`, { consent: true, sig: S });
  assert.equal(L2.body.issues[0].status, 'verified_fixed'); assert.ok(L2.body.issues[0].fixed_at); assert.equal(L2.body.issues[0].howto.length, 2, 'earlier directions kept'); assert.equal(L2.body.visits.length, 2); assert.equal(L2.body.codebase.visits, 2);
  assert.equal((await call(e, `/api/memory/${save.body.id}/forget`, { consent: true, sig: sig(5000) })).status, 404);
  assert.equal((await call(e, `/api/memory/${save.body.id}/forget`, { consent: true, sig: S })).body.deleted, true);
  assert.equal((await call(e, '/api/memory/match', { consent: true, sig: S })).body.match, null);
});
test('rate limit per network per hour', async () => {
  const { e } = env({ env: { RATE_PER_HOUR: '7' } });
  assert.equal((await call(e, '/api/ai/analyze', { consent: true, files: FILES })).status, 200);
  const r = await call(e, '/api/ai/analyze', { consent: true, files: FILES }); assert.equal(r.status, 429); assert.equal(r.body.error, 'rate_limited');
});
