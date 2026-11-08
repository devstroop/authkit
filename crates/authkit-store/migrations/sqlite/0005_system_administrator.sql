CREATE TABLE system_administrator (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES user_account (id),
    created_by  TEXT REFERENCES user_account (id),
    status      TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    version     INTEGER NOT NULL
);
CREATE UNIQUE INDEX system_administrator_user_idx ON system_administrator (user_id);
