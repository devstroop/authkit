ALTER TABLE authorization_code ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0;
ALTER TABLE authorization_code ADD COLUMN session_id TEXT REFERENCES session (id) ON DELETE SET NULL;
