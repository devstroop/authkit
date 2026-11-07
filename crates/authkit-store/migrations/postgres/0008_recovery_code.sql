CREATE TABLE recovery_code (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user_account (id),
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    version INTEGER NOT NULL
);
CREATE INDEX recovery_code_user_idx ON recovery_code (user_id);
