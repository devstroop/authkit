ALTER TABLE authorization_code ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authorization_code ADD COLUMN session_id TEXT REFERENCES session (id) ON DELETE SET NULL;
