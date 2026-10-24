-- D1 fallback for project file storage when R2 bucket is not provisioned
CREATE TABLE IF NOT EXISTS storage_objects (
  key TEXT PRIMARY KEY,
  data BLOB NOT NULL,
  content_type TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
