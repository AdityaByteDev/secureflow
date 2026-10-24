-- Durable uploaded-project sessions and scan snapshots. Source bytes live in R2, not D1.
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  uid TEXT,
  session_hash TEXT,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'uploading',
  expires_at TEXT,
  manifest TEXT NOT NULL DEFAULT '[]',
  file_count INTEGER NOT NULL DEFAULT 0,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS projects_uid ON projects(uid, updated_at);
CREATE TABLE IF NOT EXISTS project_files (
  project_id TEXT NOT NULL,
  path TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(project_id, path)
);
CREATE TABLE IF NOT EXISTS project_scans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS project_scans_project ON project_scans(project_id, created_at);
CREATE TABLE IF NOT EXISTS repair_jobs (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  uid TEXT NOT NULL,
  project_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  validation TEXT NOT NULL,
  manifest TEXT NOT NULL,
  zip_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repair_artifacts (
  job_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  path TEXT NOT NULL,
  object_key TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  changed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(job_id, path)
);
CREATE INDEX IF NOT EXISTS repair_jobs_uid ON repair_jobs(uid, created_at);

-- Link new repair requests to their authenticated owner and durable project. Legacy requests remain readable by token.
ALTER TABLE repair_requests ADD COLUMN uid TEXT;
ALTER TABLE repair_requests ADD COLUMN project_id TEXT;
ALTER TABLE repair_requests ADD COLUMN finding_id TEXT;
ALTER TABLE repair_requests ADD COLUMN scope TEXT;
CREATE INDEX IF NOT EXISTS repair_requests_uid ON repair_requests(uid, created_at);
