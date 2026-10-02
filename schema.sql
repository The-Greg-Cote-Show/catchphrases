-- Greg Cote Top 75 Catchphrase Countdown: database schema.
-- Paste this whole file into the D1 console once. Safe to run again (IF NOT EXISTS / OR IGNORE).

CREATE TABLE IF NOT EXISTS submissions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  exercise   TEXT    NOT NULL CHECK (exercise IN ('top10', 'number1', 'rearrange')),
  ip_hash    TEXT    NOT NULL,
  payload    TEXT    NOT NULL,              -- JSON array of catchphrase ids, never text
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  country    TEXT,
  UNIQUE (ip_hash, exercise)                -- one per connection per exercise; also indexes the status lookup
);

CREATE INDEX IF NOT EXISTS idx_submissions_exercise ON submissions (exercise, id);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('voting_open', '0');
INSERT OR IGNORE INTO settings (key, value) VALUES ('results_public', '0');

CREATE TABLE IF NOT EXISTS snapshots (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  data       TEXT NOT NULL                  -- JSON computed in the admin browser: ids and numbers only
);
