CREATE TABLE passkey (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES user_account(id),
  credential_id   TEXT NOT NULL UNIQUE,
  passkey_json    TEXT NOT NULL,
  created_at      INTEGER NOT NULL
);
CREATE INDEX passkey_user_idx ON passkey (user_id, created_at);
