CREATE TABLE domain (
  id                 TEXT PRIMARY KEY,
  organization_id    TEXT NOT NULL REFERENCES organization(id),
  domain             TEXT NOT NULL UNIQUE,
  verification_token TEXT NOT NULL,
  verified_at        INTEGER,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  version            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX domain_org_idx ON domain (organization_id, created_at);
