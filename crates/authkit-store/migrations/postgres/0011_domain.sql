CREATE TABLE domain (
  id                 TEXT PRIMARY KEY,
  application_id    TEXT NOT NULL REFERENCES application(id),
  domain             TEXT NOT NULL UNIQUE,
  verification_token TEXT NOT NULL,
  verified_at        BIGINT,
  created_at         BIGINT NOT NULL,
  updated_at         BIGINT NOT NULL,
  version            BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX domain_application_idx ON domain (application_id, created_at);
