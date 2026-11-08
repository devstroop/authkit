ALTER TABLE audit_event ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_event ADD COLUMN hash TEXT;
CREATE INDEX audit_event_hash_idx ON audit_event (hash);
