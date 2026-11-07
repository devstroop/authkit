CREATE TABLE rate_limit_bucket (
    key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX rate_limit_bucket_expires_idx ON rate_limit_bucket (expires_at);
