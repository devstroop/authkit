CREATE TABLE one_time_token_new (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES user_account(id),
  purpose     TEXT NOT NULL CHECK (purpose IN ('password_reset','email_verification','magic_auth','org_selection')),
  token_hash  TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at  INTEGER NOT NULL
);
INSERT INTO one_time_token_new (id, user_id, purpose, token_hash, expires_at, consumed_at, created_at)
  SELECT id, user_id, purpose, token_hash, expires_at, consumed_at, created_at FROM one_time_token;
DROP TABLE one_time_token;
ALTER TABLE one_time_token_new RENAME TO one_time_token;
CREATE UNIQUE INDEX one_time_token_hash_uq ON one_time_token (token_hash);
CREATE INDEX one_time_token_user_idx ON one_time_token (user_id, purpose, created_at);
