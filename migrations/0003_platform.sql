-- SecureFlow platform: customers (Firebase UID), GitHub connections, monitored repositories, scan jobs, findings, history,
-- AI patch proposals, pushes, CI test results, webhook deliveries, deployments, subscriptions (Cashfree), usage, alerts, audit.
-- No full source code is stored. Findings keep only masked evidence lines; scans keep salted 8-hex line fingerprints.
-- GitHub tokens are stored AES-GCM encrypted (key: TOKEN_ENC_KEY secret), never in plaintext.
CREATE TABLE IF NOT EXISTS customers (
  uid TEXT PRIMARY KEY, email TEXT, name TEXT, email_verified INTEGER NOT NULL DEFAULT 0,
  alerts_enabled INTEGER NOT NULL DEFAULT 1, alert_min_severity TEXT NOT NULL DEFAULT 'high',
  alert_types TEXT NOT NULL DEFAULT '["new_high","regression","scan_failed","monitoring","billing"]',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS github_connections (
  uid TEXT PRIMARY KEY, gh_user_id INTEGER NOT NULL, login TEXT NOT NULL, avatar_url TEXT, scopes TEXT,
  token_enc TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, uid TEXT NOT NULL, scope TEXT, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS repos (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, gh_repo_id INTEGER NOT NULL, full_name TEXT NOT NULL, private INTEGER NOT NULL DEFAULT 0,
  default_branch TEXT, branch TEXT NOT NULL, monitoring TEXT NOT NULL DEFAULT 'off', hook_id INTEGER, salt TEXT NOT NULL,
  last_sha TEXT, last_scan_id TEXT, status TEXT NOT NULL DEFAULT 'active', status_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (uid, gh_repo_id)
);
CREATE INDEX IF NOT EXISTS repos_gh ON repos (gh_repo_id);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, repo_id TEXT NOT NULL, commit_sha TEXT NOT NULL, ref TEXT, trigger TEXT NOT NULL,
  status TEXT NOT NULL, error TEXT, coverage TEXT, counts TEXT, compare TEXT, parent_scan_id TEXT, patch_id TEXT,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS scans_repo ON scans (repo_id, created_at);
CREATE TABLE IF NOT EXISTS scan_files (scan_id TEXT NOT NULL, path TEXT NOT NULL, hashes TEXT NOT NULL, PRIMARY KEY (scan_id, path));
CREATE TABLE IF NOT EXISTS findings (
  scan_id TEXT NOT NULL, id TEXT NOT NULL, key TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT, severity TEXT, confidence TEXT, category TEXT, cwe TEXT,
  file TEXT, line INTEGER, evidence TEXT, why TEXT, fix TEXT, tests TEXT, PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS finding_history (
  repo_id TEXT NOT NULL, key TEXT NOT NULL, rule_id TEXT, title TEXT, severity TEXT, file TEXT, first_scan TEXT, last_scan TEXT,
  status TEXT NOT NULL, reappeared INTEGER NOT NULL DEFAULT 0, test_check TEXT, PRIMARY KEY (repo_id, key)
);
CREATE TABLE IF NOT EXISTS patches (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, repo_id TEXT NOT NULL, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, finding_key TEXT, base_sha TEXT NOT NULL,
  file TEXT NOT NULL, status TEXT NOT NULL, proposal TEXT, edits TEXT, checks TEXT, diff TEXT, model TEXT, invalid_reason TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS push_ops (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, repo_id TEXT NOT NULL, patch_id TEXT NOT NULL, mode TEXT NOT NULL, target_branch TEXT NOT NULL,
  fix_branch TEXT, base_head TEXT, commit_sha TEXT, commit_url TEXT, pr_url TEXT, pr_number INTEGER, status TEXT NOT NULL, error TEXT,
  rescan_scan_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS push_ops_patch ON push_ops (patch_id);
CREATE TABLE IF NOT EXISTS test_results (
  repo_id TEXT NOT NULL, commit_sha TEXT NOT NULL, name TEXT NOT NULL, status TEXT, conclusion TEXT, url TEXT, source TEXT, updated_at TEXT,
  PRIMARY KEY (repo_id, commit_sha, name)
);
CREATE TABLE IF NOT EXISTS gh_events (id TEXT PRIMARY KEY, type TEXT, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deployments (
  repo_id TEXT NOT NULL, gh_deployment_id INTEGER NOT NULL, environment TEXT, state TEXT NOT NULL, sha TEXT, url TEXT, at TEXT NOT NULL,
  PRIMARY KEY (repo_id, gh_deployment_id, state)
);
CREATE TABLE IF NOT EXISTS subscriptions (
  uid TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL, period_start TEXT, period_end TEXT, canceled_at TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS billing_orders (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, plan TEXT NOT NULL, amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL,
  cf_order_id TEXT, payment_id TEXT, applied INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL, paid_at TEXT
);
CREATE INDEX IF NOT EXISTS billing_orders_uid ON billing_orders (uid);
CREATE TABLE IF NOT EXISTS usage (uid TEXT NOT NULL, period TEXT NOT NULL, ai_fixes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, period));
CREATE TABLE IF NOT EXISTS email_log (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, type TEXT NOT NULL, subject TEXT, status TEXT NOT NULL, provider_id TEXT, error TEXT, at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS email_log_uid ON email_log (uid, at);
CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, uid TEXT, action TEXT NOT NULL, detail TEXT, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_uid ON audit (uid, at);
