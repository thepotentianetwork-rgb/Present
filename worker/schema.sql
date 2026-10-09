-- Present per-user data (D1). Every row that belongs to a person carries user_id,
-- and every query in worker.js filters on it. Deleting a user cascades to everything.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name           TEXT NOT NULL,
  pw_hash        TEXT NOT NULL,          -- PBKDF2-SHA256, base64url
  pw_salt        TEXT NOT NULL,          -- 16 random bytes, base64url
  pw_iter        INTEGER NOT NULL,
  memory_enabled INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,           -- SHA-256 of the cookie token; the token itself is never stored
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS prefs (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, key)
);

CREATE TABLE IF NOT EXISTS conversations (
  id                 TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title              TEXT NOT NULL DEFAULT '',
  mode               TEXT,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  message_count      INTEGER NOT NULL DEFAULT 0,
  last_extracted_id  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS conv_user ON conversations(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role            TEXT NOT NULL CHECK (role IN ('user','assistant')),
  content         TEXT NOT NULL,
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS msg_conv ON messages(conversation_id, id);
CREATE INDEX IF NOT EXISTS msg_user ON messages(user_id);

CREATE TABLE IF NOT EXISTS memories (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text            TEXT NOT NULL,
  category        TEXT,
  source          TEXT NOT NULL,         -- 'chat' (extracted) or 'you' (typed on the Memory page)
  conversation_id TEXT,                  -- informational only; deleting the chat does not delete the memory
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mem_user ON memories(user_id, created_at);
