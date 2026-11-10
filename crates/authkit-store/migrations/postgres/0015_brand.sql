CREATE TABLE brand (
  id          TEXT PRIMARY KEY,
  application_id      TEXT REFERENCES application(id),
  domain      TEXT,
  title       TEXT NOT NULL,
  logo_url    TEXT,
  favicon_url TEXT,
  custom_css  TEXT,
  created_at  BIGINT NOT NULL,
  updated_at  BIGINT NOT NULL,
  version     BIGINT NOT NULL
);
CREATE INDEX brand_domain_idx ON brand (domain);
CREATE INDEX brand_application_idx ON brand (application_id);