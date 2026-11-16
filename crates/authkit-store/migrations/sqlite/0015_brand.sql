CREATE TABLE brand (
  id          TEXT PRIMARY KEY,
  org_id      TEXT REFERENCES organization(id),
  domain      TEXT,
  title       TEXT NOT NULL,
  logo_url    TEXT,
  favicon_url TEXT,
  custom_css  TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  version     INTEGER NOT NULL
);
CREATE INDEX brand_domain_idx ON brand (domain);
CREATE INDEX brand_org_idx ON brand (org_id);