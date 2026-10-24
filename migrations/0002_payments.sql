-- Paid repair requests (Cashfree). No card or UPI details are ever seen or stored by SecureFlow; Cashfree hosts the payment.
CREATE TABLE IF NOT EXISTS repair_requests (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, offer_id TEXT NOT NULL, status TEXT NOT NULL,
  finding TEXT NOT NULL, evidence TEXT, order_id TEXT UNIQUE, cf_order_id TEXT, payment_id TEXT,
  last_error TEXT, events TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, fulfilled_at TEXT
);
CREATE TABLE IF NOT EXISTS payment_events (id TEXT PRIMARY KEY, at TEXT NOT NULL, type TEXT);
