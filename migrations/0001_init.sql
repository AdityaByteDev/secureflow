-- SecureFlow codebase memory. No source code is stored: only per-line fingerprints (8 hex chars per line),
-- file paths, a 64-value MinHash signature, and finding metadata (title, severity, location, short fix directions).
CREATE TABLE IF NOT EXISTS codebases (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  minhash TEXT NOT NULL, paths TEXT, digest TEXT, salt TEXT, file_count INTEGER, line_count INTEGER, visits INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS bands (key TEXT NOT NULL, cid TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS bands_key ON bands(key);
CREATE INDEX IF NOT EXISTS bands_cid ON bands(cid);
CREATE TABLE IF NOT EXISTS files (cid TEXT NOT NULL, path TEXT NOT NULL, hashes TEXT NOT NULL, PRIMARY KEY (cid, path));
CREATE TABLE IF NOT EXISTS issues (
  cid TEXT NOT NULL, id TEXT NOT NULL, source TEXT, rule_id TEXT, title TEXT, severity TEXT, score REAL, category TEXT,
  file TEXT, line INTEGER, anchor TEXT, ctx TEXT, howto TEXT, status TEXT, first_seen TEXT, updated_at TEXT, fixed_at TEXT, note TEXT,
  PRIMARY KEY (cid, id)
);
CREATE TABLE IF NOT EXISTS visits (cid TEXT NOT NULL, at TEXT NOT NULL, score INTEGER, open_count INTEGER, fixed_count INTEGER);
CREATE INDEX IF NOT EXISTS visits_cid ON visits(cid);
CREATE TABLE IF NOT EXISTS rate (k TEXT PRIMARY KEY, n INTEGER NOT NULL);
