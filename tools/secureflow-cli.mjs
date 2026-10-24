#!/usr/bin/env node
// SecureFlow CLI: run the same local rules in CI.
//   node tools/secureflow-cli.mjs <dir> [--fail-on=critical|high|medium|low|info|none] [--min-confidence=low|medium|high] [--format=text|json] [--strict]
// Exit codes: 0 = no findings at/above the threshold · 1 = findings at/above the threshold · 2 = usage or read error · 3 = --strict and coverage incomplete
// Reads files only; never executes project code; makes no network requests.
import fs from 'node:fs'; import path from 'node:path'; import { createRequire } from 'node:module'; import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const E = require(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'engine.js'))();

const args = process.argv.slice(2), opt = {}; const pos = [];
for (const a of args) { const m = a.match(/^--([\w-]+)(?:=(.*))?$/); if (m) opt[m[1]] = m[2] === undefined ? true : m[2]; else pos.push(a); }
const SEV = ['critical', 'high', 'medium', 'low', 'info'], CONF = ['high', 'medium', 'low'];
const failOn = opt['fail-on'] || 'high', minConf = opt['min-confidence'] || 'low', format = opt.format || 'text';
if (opt.help || pos.length !== 1 || !(SEV.includes(failOn) || failOn === 'none') || !CONF.includes(minConf) || !['text', 'json'].includes(format)) {
  process.stderr.write('Usage: secureflow <dir> [--fail-on=critical|high|medium|low|info|none] [--min-confidence=low|medium|high] [--format=text|json] [--strict]\n'); process.exit(2);
}
const root = path.resolve(pos[0]);
if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) { process.stderr.write('Not a directory: ' + pos[0] + '\n'); process.exit(2); }

const cands = [], skippedDirs = [];
(function walk(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name), rel = path.relative(root, abs).split(path.sep).join('/');
    if (ent.isSymbolicLink()) continue;                         // never follow links out of the project
    if (ent.isDirectory()) { if (/^(node_modules|\.git|dist|build|\.next|vendor|coverage|__pycache__|\.venv|venv)$/.test(ent.name)) skippedDirs.push({ path: rel + '/', reason: 'excluded-folder-or-lockfile' }); else walk(abs); continue; }
    if (ent.isFile()) cands.push({ path: rel, size: fs.statSync(abs).size, abs });
  }
})(root);
const v = E.validateIncoming(cands);
const files = [], readSkipped = [];
for (const c of v.keep) { const t = fs.readFileSync(cands.find(x => x.path === c.path).abs, 'utf8'); if (E.isBinary(t)) readSkipped.push({ path: c.path, reason: 'binary' }); else files.push({ name: c.path, code: t }); }
const r = E.scanProject(files);
const shown = r.findings.filter(f => CONF.indexOf(f.confidence) <= CONF.indexOf(minConf));
const failing = failOn === 'none' ? [] : shown.filter(f => SEV.indexOf(f.severity) <= SEV.indexOf(failOn));
const skipped = skippedDirs.concat(v.skipped, readSkipped, (r.coverage && r.coverage.skipped) || []);
const out = { tool: 'secureflow', engine: E.VERSION, status: r.status, threshold: { failOn, minConfidence: minConf }, score: E.score(shown), verdict: E.verdict(shown, r.status),
  coverage: r.coverage, skipped, counts: E.counts(shown), failing: failing.length, limitations: E.LIMITATIONS,
  findings: shown.map(f => ({ id: f.id, ruleId: f.ruleId, severity: f.severity, confidence: f.confidence, title: f.title, file: f.file, line: f.line, column: f.column, cwe: f.cwe, evidence: f.code.trim(), fix: f.fix })) };
if (format === 'json') process.stdout.write(JSON.stringify(out, null, 2) + '\n');
else {
  const L = [];
  L.push(`SecureFlow ${E.VERSION}: ${r.status}. ${r.coverage ? r.coverage.analyzed + '/' + r.coverage.imported + ' files analysed' : 'no files analysed'}${skipped.length ? ', ' + skipped.length + ' skipped' : ''}.`);
  for (const f of shown) L.push(`${f.severity.toUpperCase().padEnd(8)} ${f.confidence.padEnd(6)} ${f.file}:${f.line}:${f.column}  ${f.title} [${f.ruleId}]\n           ${f.code.trim().slice(0, 140)}`);
  L.push(`${out.verdict.title}. ${failing.length} finding(s) at or above "${failOn}". Pattern-based check, not a full audit.`);
  process.stdout.write(L.join('\n') + '\n');
}
if (opt.strict && r.status !== 'complete') process.exit(3);
process.exit(r.status === 'failed' ? 2 : failing.length ? 1 : 0);
