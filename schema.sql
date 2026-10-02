-- Greg Cote Top 75 Catchphrase Countdown: database schema.
-- Paste this whole file into the D1 console once. Safe to run again (IF NOT EXISTS / OR IGNORE).

CREATE TABLE IF NOT EXISTS submissions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  exercise    TEXT    NOT NULL CHECK (exercise IN ('top10', 'number1', 'rearrange', 'omissions')),
  ip_hash     TEXT    NOT NULL,             -- scrambled connection (HMAC of the IP), never the IP itself
  device_hash TEXT    NOT NULL,             -- scrambled random device id from the browser
  payload     TEXT    NOT NULL,             -- JSON array: catchphrase ids, or for omissions the typed answers
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  country     TEXT,
  UNIQUE (device_hash, exercise)            -- one vote per device per exercise; also indexes the status lookup
);

CREATE INDEX IF NOT EXISTS idx_submissions_ip ON submissions (ip_hash, exercise);
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
