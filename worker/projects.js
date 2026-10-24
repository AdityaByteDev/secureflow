import { E, HttpError, json, sha, str } from './core.js';

const te = new TextEncoder(), td = new TextDecoder();
const now = () => new Date().toISOString();
const randomToken = () => {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const equal = (a, b) => {
  a = String(a || ''); b = String(b || '');
  if (!a || a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};
const projectId = () => 'prj_' + [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');

export function getProjectStorage(env) {
  if (env.PROJECTS) return env.PROJECTS;
  if (!env.DB) return null;
  return {
    async put(key, value, opts = {}) {
      const ct = (opts.httpMetadata && opts.httpMetadata.contentType) || 'application/octet-stream';
      let bytes;
      if (typeof value === 'string') {
        bytes = te.encode(value);
      } else if (value instanceof Uint8Array) {
        bytes = value;
      } else if (value && value.buffer) {
        bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      } else {
        bytes = new Uint8Array(await value.arrayBuffer());
      }
      await env.DB.prepare(`
        INSERT INTO storage_objects (key, data, content_type, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET data = excluded.data, content_type = excluded.content_type, updated_at = excluded.updated_at
      `).bind(key, bytes, ct).run();
    },
    async get(key) {
      const row = await env.DB.prepare('SELECT data, content_type FROM storage_objects WHERE key = ?').bind(key).first();
      if (!row) return null;
      const dataArr = row.data instanceof Uint8Array ? row.data : new Uint8Array(row.data);
      return {
        async text() {
          return td.decode(dataArr);
        },
        async arrayBuffer() {
          return dataArr.buffer.slice(dataArr.byteOffset, dataArr.byteOffset + dataArr.byteLength);
        },
        get body() {
          return new Response(dataArr).body;
        }
      };
    }
  };
}

async function authorize(req, env, project, requireVerified) {
  if (!project) throw new HttpError(404, 'project_not_found');
  const capability = req.headers.get('x-project-session') || '';
  if (project.session_hash && project.expires_at > now() && capability && equal(await sha(capability), project.session_hash)) return { uid: project.uid || null, session: true };
  const user = await requireVerified(req, env);
  if (!project.uid || project.uid !== user.uid) throw new HttpError(404, 'project_not_found');
  return { uid: user.uid, session: false };
}

async function loadProject(env, id) {
  if (!/^prj_[0-9a-f]{32}$/.test(id || '')) return null;
  return env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(id).first();
}

async function readProjectFiles(env, id) {
  const storage = getProjectStorage(env);
  if (!storage) throw new HttpError(503, 'project_storage_not_configured');
  const rows = (await env.DB.prepare('SELECT path, object_key, sha256, size FROM project_files WHERE project_id = ? ORDER BY path').bind(id).all()).results || [];
  const files = [];
  for (const row of rows) {
    const object = await storage.get(row.object_key);
    if (!object) throw new HttpError(503, 'project_file_missing', { path: row.path });
    const code = await object.text();
    if (await sha(code) !== row.sha256 || te.encode(code).length !== row.size) throw new HttpError(503, 'project_file_integrity_error', { path: row.path });
    files.push({ name: row.path, code });
  }
  return files;
}

export async function handleProjectApi(req, env, { requireAuth }) {
  const u = new URL(req.url), path = u.pathname, method = req.method;
  if (!(path === '/api/projects' || /^\/api\/projects\//.test(path))) return null;
  if (!env.DB) throw new HttpError(503, 'database_not_configured');
  const storage = getProjectStorage(env);
  if (!storage) throw new HttpError(503, 'project_storage_not_configured', { message: 'Project storage is not configured. Bind the Cloudflare R2 bucket named secureflow-projects or configure database storage.' });

  if (method === 'POST' && path === '/api/projects') {
    const body = await req.json().catch(() => { throw new HttpError(400, 'invalid_json'); });
    const name = str(body.name, 120).trim();
    const manifest = Array.isArray(body.files) ? body.files : [];
    if (!name || !manifest.length || manifest.length > 300) throw new HttpError(400, 'invalid_project');
    const normalized = [], seen = new Set(); let total = 0;
    for (const f of manifest) {
      const filePath = E.safePath(str(f && f.path, 300));
      const size = Number(f && f.size);
      if (!filePath || !Number.isInteger(size) || size < 1 || size > 400 * 1024 || seen.has(filePath)) throw new HttpError(400, 'invalid_manifest');
      seen.add(filePath); total += size; normalized.push({ path: filePath, size });
    }
    if (total > 20 * 1024 * 1024) throw new HttpError(413, 'project_too_large');
    let uid = null;
    if (req.headers.has('authorization')) uid = (await requireAuth(req, env)).uid;
    const id = projectId(), token = randomToken(), expires = new Date(Date.now() + 24 * 3600 * 1000).toISOString(), stamp = now();
    await env.DB.prepare('INSERT INTO projects (id, uid, session_hash, name, status, expires_at, manifest, file_count, total_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)')
      .bind(id, uid, await sha(token), name, 'uploading', expires, JSON.stringify(normalized), stamp, stamp).run();
    return json({ id, sessionToken: token, expiresAt: expires, uploadCount: normalized.length }, 201);
  }

  const match = path.match(/^\/api\/projects\/(prj_[0-9a-f]{32})(?:\/(files|finalize|claim|scan))?$/);
  if (!match) return null;
  const [, id, action] = match;
  const project = await loadProject(env, id);
  if (!project) throw new HttpError(404, 'project_not_found');

  if (method === 'POST' && action === 'claim') {
    const user = await requireAuth(req, env);
    const body = await req.json().catch(() => ({}));
    if (!project.session_hash || project.expires_at <= now() || !equal(await sha(String(body.sessionToken || '')), project.session_hash)) throw new HttpError(404, 'project_not_found');
    if (project.uid && project.uid !== user.uid) throw new HttpError(404, 'project_not_found');
    await env.DB.prepare('UPDATE projects SET uid = ?, session_hash = NULL, expires_at = NULL, updated_at = ? WHERE id = ? AND session_hash = ?')
      .bind(user.uid, now(), id, project.session_hash).run();
    return json({ ok: true, id });
  }

  if (method === 'POST' && action === 'files') {
    await authorize(req, env, project, requireAuth);
    if (project.status !== 'uploading') throw new HttpError(409, 'project_upload_closed');
    if (!/^text\/(plain|javascript|html|css)|application\/(json|javascript|xml)$/.test(req.headers.get('content-type') || '')) throw new HttpError(415, 'text_file_required');
    const filePath = E.safePath(u.searchParams.get('path') || '');
    const expected = JSON.parse(project.manifest || '[]').find(f => f.path === filePath);
    if (!expected) throw new HttpError(400, 'path_not_in_manifest');
    const code = await req.text(), bytes = te.encode(code);
    if (!code || bytes.length !== expected.size || bytes.length > 400 * 1024 || code.includes('\0')) throw new HttpError(400, 'file_size_or_content_mismatch');
    const hash = await sha(code), key = `${id}/${hash.slice(0, 24)}`;
    await storage.put(key, code, { httpMetadata: { contentType: 'text/plain; charset=utf-8' } });
    await env.DB.prepare('INSERT INTO project_files (project_id, path, object_key, sha256, size, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, path) DO UPDATE SET object_key = excluded.object_key, sha256 = excluded.sha256, size = excluded.size, updated_at = excluded.updated_at')
      .bind(id, filePath, key, hash, bytes.length, now()).run();
    return json({ ok: true, path: filePath, size: bytes.length, sha256: hash });
  }

  if (method === 'POST' && action === 'finalize') {
    await authorize(req, env, project, requireAuth);
    if (project.status !== 'uploading') return json({ ok: true, status: project.status });
    const got = (await env.DB.prepare('SELECT path, size FROM project_files WHERE project_id = ?').bind(id).all()).results || [];
    const want = JSON.parse(project.manifest || '[]');
    if (got.length !== want.length || want.some(f => !got.some(x => x.path === f.path && x.size === f.size))) throw new HttpError(409, 'project_upload_incomplete', { uploaded: got.length, expected: want.length });
    const total = got.reduce((n, f) => n + f.size, 0);
    await env.DB.prepare("UPDATE projects SET status = 'uploaded', file_count = ?, total_bytes = ?, updated_at = ? WHERE id = ?")
      .bind(got.length, total, now(), id).run();
    return json({ ok: true, status: 'uploaded', fileCount: got.length, totalBytes: total });
  }

  if (method === 'POST' && action === 'scan') {
    await authorize(req, env, project, requireAuth);
    if (!['uploaded', 'scanned'].includes(project.status)) throw new HttpError(409, 'project_not_ready');
    const files = await readProjectFiles(env, id);
    const scan = E.scanProject(files);
    if (scan.status === 'failed') throw new HttpError(422, 'project_scan_failed', { error: scan.error || 'no_supported_source_files' });
    const result = { status: scan.status, score: scan.score, verdict: scan.verdict, counts: scan.counts, findings: scan.findings, coverage: scan.coverage };
    const scanId = 'ps_' + [...crypto.getRandomValues(new Uint8Array(12))].map(x => x.toString(16).padStart(2, '0')).join('');
    await env.DB.prepare('INSERT INTO project_scans (id, project_id, result, created_at) VALUES (?, ?, ?, ?)').bind(scanId, id, JSON.stringify(result), now()).run();
    await env.DB.prepare("UPDATE projects SET status = 'scanned', updated_at = ? WHERE id = ?").bind(now(), id).run();
    return json({ scanId, ...result });
  }

  if (method === 'GET' && !action) {
    await authorize(req, env, project, requireAuth);
    const scan = await env.DB.prepare('SELECT id, result, created_at FROM project_scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1').bind(id).first();
    return json({ id, name: project.name, status: project.status, fileCount: project.file_count, totalBytes: project.total_bytes, scan: scan ? { id: scan.id, ...JSON.parse(scan.result), createdAt: scan.created_at } : null });
  }
  if (method === 'GET' && action === 'files') {
    await authorize(req, env, project, requireAuth);
    if (!u.searchParams.has('path')) {
      const rows = (await env.DB.prepare('SELECT path, size, sha256 FROM project_files WHERE project_id = ? ORDER BY path').bind(id).all()).results || [];
      return json({ files: rows });
    }
    const filePath = E.safePath(u.searchParams.get('path') || '');
    const row = await env.DB.prepare('SELECT object_key, sha256, size FROM project_files WHERE project_id = ? AND path = ?').bind(id, filePath).first();
    if (!row) throw new HttpError(404, 'project_file_not_found');
    const object = await storage.get(row.object_key);
    if (!object) throw new HttpError(404, 'project_file_not_found');
    const code = await object.text();
    if (await sha(code) !== row.sha256) throw new HttpError(503, 'project_file_integrity_error');
    return new Response(code, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  }
  return null;
}

const privatePath = p => /(^|\/)(?:\.env(?:\..*)?|id_rsa(?:\.pub)?|id_ed25519(?:\.pub)?|credentials(?:\..*)?|secrets?(?:\..*)?)$/i.test(p) || /\.(?:pem|key|p12|pfx|keystore)$/i.test(p);

export async function runPaidProjectRepair(env, { request, user }) {
  const existing = await env.DB.prepare('SELECT * FROM repair_jobs WHERE request_id = ?').bind(request.id).first();
  if (existing) return { status: existing.status, jobId: existing.id, summary: existing.summary, validation: JSON.parse(existing.validation), manifest: JSON.parse(existing.manifest) };
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ? AND uid = ? AND status = ?').bind(request.project_id, user.uid, 'scanned').first();
  if (!project) throw new HttpError(404, 'project_not_found');
  const snapshot = await env.DB.prepare('SELECT result FROM project_scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1').bind(project.id).first();
  const scan = snapshot ? JSON.parse(snapshot.result) : null;
  const finding = scan && (scan.findings || []).find(f => f.id === request.finding_id);
  if (!finding) throw new HttpError(409, 'repair_finding_not_current');
  const files = await readProjectFiles(env, project.id);
  const proposal = E.proposePatch(finding, files);
  const jobId = 'rj_' + [...crypto.getRandomValues(new Uint8Array(12))].map(x => x.toString(16).padStart(2, '0')).join('');
  const stamp = now();
  if (!proposal.available) {
    const validation = { patchGenerated: false, syntaxChecks: 'not_run', securityRescan: 'not_run', limitation: proposal.reason || 'No safe deterministic patch exists for this finding.' };
    const manifest = { changedFiles: [], excludedSensitiveFiles: files.filter(f => privatePath(f.name)).map(f => f.name) };
    const summary = 'No automatic patch was produced. The finding needs a developer to choose a context-specific fix.';
    await env.DB.prepare('INSERT INTO repair_jobs (id, request_id, uid, project_id, finding_id, status, summary, validation, manifest, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(jobId, request.id, user.uid, project.id, finding.id, 'manual_review', summary, JSON.stringify(validation), JSON.stringify(manifest), stamp, stamp).run();
    return { status: 'manual_review', jobId, summary, validation, manifest };
  }
  const applied = E.applyPatch(files, proposal);
  if (!applied.ok) throw new HttpError(409, 'patch_validation_failed', { detail: applied.error });
  const rescan = E.scanProject(applied.files);
  if (rescan.status === 'failed') throw new HttpError(422, 'repair_rescan_failed');
  const remaining = (rescan.findings || []).some(f => f.ruleId === finding.ruleId && f.file === finding.file);
  if (remaining) throw new HttpError(422, 'repair_validation_failed', { validation: 'The selected finding remains after the follow-up scan.' });

  const output = applied.files.filter(f => !privatePath(f.name));
  const excludedSensitiveFiles = applied.files.filter(f => privatePath(f.name)).map(f => f.name);
  if (!output.length) throw new HttpError(422, 'no_exportable_files');
  const changedFiles = [];
  for (const f of output) {
    const original = files.find(x => x.name === f.name);
    const changed = !original || original.code !== f.code;
    if (changed) changedFiles.push(f.name);
  }
  if (!changedFiles.length) throw new HttpError(422, 'repair_made_no_changes');
  const diffs = changedFiles.map(name => { const before = files.find(f => f.name === name), after = output.find(f => f.name === name); return { file: name, text: E.diffLines(before ? before.code : '', after ? after.code : '', 1) }; });
  const manifest = { changedFiles, excludedSensitiveFiles, fileCount: output.length, diffs };
  const validation = { patchGenerated: true, patchApplied: true, targetLineMatched: true, followUpScan: 'selected rule no longer detected', findingStatus: 'no_longer_detected', syntaxChecks: 'not_run', projectTests: 'not_run', execution: 'uploaded code was not executed' };
  const summary = `Changed ${changedFiles.length} file${changedFiles.length === 1 ? '' : 's'}. The selected pattern no longer appears in the follow-up scan; syntax checks and project tests were not run.`;
  const zipFiles = output.concat([
    { name: 'SECUREFLOW_REPAIR_MANIFEST.json', code: JSON.stringify({ ...manifest, validation, summary }, null, 2) },
    { name: 'SECUREFLOW_REPAIR_SUMMARY.txt', code: `${summary}\n\nValidation: ${JSON.stringify(validation, null, 2)}\n` }
  ]);
  const zipBlob = E.writeZip(zipFiles), zipBytes = new Uint8Array(await zipBlob.arrayBuffer());
  const checked = await E.readZip(zipBytes);
  if (checked.rejected.length || checked.entries.length !== zipFiles.length) throw new HttpError(500, 'repair_zip_validation_failed');
  for (let i = 0; i < zipFiles.length; i++) if (checked.entries[i].path !== zipFiles[i].name || await checked.entries[i].read() !== zipFiles[i].code) throw new HttpError(500, 'repair_zip_validation_failed');
  const zipKey = `${project.id}/${(await sha(jobId + ':zip')).slice(0, 24)}`;
  const storage = getProjectStorage(env);
  if (!storage) throw new HttpError(503, 'project_storage_not_configured');
  await storage.put(zipKey, zipBytes, { httpMetadata: { contentType: 'application/zip' } });
  const rows = [];
  for (const f of output) {
    const fileHash = await sha(f.code), objectKey = `${project.id}/${(await sha(jobId + ':' + f.name + ':' + fileHash)).slice(0, 24)}`;
    await storage.put(objectKey, f.code, { httpMetadata: { contentType: 'text/plain; charset=utf-8' } });
    rows.push(env.DB.prepare('INSERT INTO repair_artifacts (job_id, project_id, path, object_key, sha256, size, changed) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(jobId, project.id, f.name, objectKey, fileHash, te.encode(f.code).length, changedFiles.includes(f.name) ? 1 : 0));
  }
  const st = await env.DB.prepare('INSERT INTO repair_jobs (id, request_id, uid, project_id, finding_id, status, summary, validation, manifest, zip_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(jobId, request.id, user.uid, project.id, finding.id, 'completed_with_limitations', summary, JSON.stringify(validation), JSON.stringify(manifest), zipKey, stamp, stamp);
  await env.DB.batch([...rows, st]);
  return { status: 'completed_with_limitations', jobId, summary, validation, manifest };
}

export async function repairDownload(env, { job, path }) {
  const storage = getProjectStorage(env);
  if (!storage) throw new HttpError(503, 'project_storage_not_configured');
  if (path === null) {
    const object = await storage.get(job.zip_key);
    if (!object) throw new HttpError(404, 'repair_archive_not_found');
    return new Response(object.body || await object.arrayBuffer(), { headers: { 'content-type': 'application/zip', 'content-disposition': `attachment; filename="secureflow-repair-${job.id}.zip"`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  }
  const clean = E.safePath(path);
  if (!clean || privatePath(clean)) throw new HttpError(404, 'repair_file_not_found');
  const row = await env.DB.prepare('SELECT object_key, sha256 FROM repair_artifacts WHERE job_id = ? AND path = ?').bind(job.id, clean).first();
  if (!row) throw new HttpError(404, 'repair_file_not_found');
  const object = await storage.get(row.object_key);
  if (!object) throw new HttpError(404, 'repair_file_not_found');
  const code = await object.text();
  if (await sha(code) !== row.sha256) throw new HttpError(503, 'repair_file_integrity_error');
  return new Response(code, { headers: { 'content-type': 'text/plain; charset=utf-8', 'content-disposition': `attachment; filename="${clean.split('/').pop().replace(/["\\\r\n]/g, '_')}"`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
}
