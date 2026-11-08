CREATE TABLE one_time_token (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES user_account(id),
  purpose     TEXT NOT NULL CHECK (purpose IN ('password_reset','email_verification')),
  token_hash  TEXT NOT NULL,
  expires_at  BIGINT NOT NULL,
  consumed_at BIGINT,
  created_at  BIGINT NOT NULL
);
CREATE UNIQUE INDEX one_time_token_hash_uq ON one_time_token (token_hash);
CREATE INDEX one_time_token_user_idx ON one_time_token (user_id, purpose, created_at);
