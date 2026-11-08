CREATE TABLE user_account (
    id                TEXT PRIMARY KEY,
    email             TEXT NOT NULL,
    email_verified_at BIGINT,
    display_name      TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at        BIGINT NOT NULL,
    updated_at        BIGINT NOT NULL,
    version           BIGINT NOT NULL
);
CREATE UNIQUE INDEX user_account_email_uq ON user_account (email);

CREATE TABLE organization (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    version    BIGINT NOT NULL
);
CREATE UNIQUE INDEX organization_slug_uq ON organization (slug);

CREATE TABLE application (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organization (id),
    slug        TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('web', 'admin', 'native', 'service', 'cli')),
    first_party BIGINT NOT NULL CHECK (first_party IN (0, 1)),
    status      TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    version     BIGINT NOT NULL,
    UNIQUE (org_id, slug)
);

CREATE TABLE membership (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organization (id),
    user_id    TEXT NOT NULL REFERENCES user_account (id),
    status     TEXT NOT NULL CHECK (status IN ('invited', 'active', 'suspended', 'removed')),
    invited_by TEXT REFERENCES user_account (id),
    joined_at  BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    version    BIGINT NOT NULL,
    UNIQUE (org_id, user_id)
);

CREATE TABLE role (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organization (id),
    application_id TEXT REFERENCES application (id),
    scope_key      TEXT NOT NULL,
    slug           TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    kind           TEXT NOT NULL CHECK (kind IN ('owner', 'admin', 'member', 'custom')),
    created_at     BIGINT NOT NULL,
    updated_at     BIGINT NOT NULL,
    version        BIGINT NOT NULL,
    UNIQUE (org_id, scope_key, slug)
);

CREATE TABLE role_permission (
    role_id    TEXT NOT NULL REFERENCES role (id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    position   BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE role_binding (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organization (id),
    application_id TEXT REFERENCES application (id),
    scope_key      TEXT NOT NULL,
    role_id        TEXT NOT NULL REFERENCES role (id),
    user_id        TEXT NOT NULL REFERENCES user_account (id),
    created_at     BIGINT NOT NULL,
    UNIQUE (org_id, scope_key, role_id, user_id)
);

CREATE TABLE invitation (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organization (id),
    email      TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    invited_by TEXT NOT NULL REFERENCES user_account (id),
    status     TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
    expires_at BIGINT NOT NULL,
    accepted_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    version    BIGINT NOT NULL
);
CREATE UNIQUE INDEX invitation_token_hash_uq ON invitation (token_hash);

CREATE TABLE invitation_role (
    invitation_id TEXT NOT NULL REFERENCES invitation (id) ON DELETE CASCADE,
    role_id       TEXT NOT NULL REFERENCES role (id),
    position      BIGINT NOT NULL,
    PRIMARY KEY (invitation_id, role_id)
);

CREATE TABLE oauth_client (
    id                          TEXT PRIMARY KEY,
    application_id              TEXT NOT NULL REFERENCES application (id),
    client_id                   TEXT NOT NULL,
    name                        TEXT NOT NULL,
    client_type                 TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
    token_endpoint_auth_method  TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    secret_hash                 TEXT,
    require_pkce                BIGINT NOT NULL CHECK (require_pkce IN (0, 1)),
    status                      TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at                  BIGINT NOT NULL,
    updated_at                  BIGINT NOT NULL,
    version                     BIGINT NOT NULL
);
CREATE UNIQUE INDEX oauth_client_client_id_uq ON oauth_client (client_id);

CREATE TABLE oauth_client_redirect_uri (
    client_row_id TEXT NOT NULL REFERENCES oauth_client (id) ON DELETE CASCADE,
    uri           TEXT NOT NULL,
    position      BIGINT NOT NULL,
    PRIMARY KEY (client_row_id, uri)
);

CREATE TABLE oauth_client_post_logout_redirect_uri (
    client_row_id TEXT NOT NULL REFERENCES oauth_client (id) ON DELETE CASCADE,
    uri           TEXT NOT NULL,
    position      BIGINT NOT NULL,
    PRIMARY KEY (client_row_id, uri)
);

CREATE TABLE oauth_client_scope (
    client_row_id TEXT NOT NULL REFERENCES oauth_client (id) ON DELETE CASCADE,
    scope         TEXT NOT NULL,
    position      BIGINT NOT NULL,
    PRIMARY KEY (client_row_id, scope)
);

CREATE TABLE oauth_client_grant_type (
    client_row_id TEXT NOT NULL REFERENCES oauth_client (id) ON DELETE CASCADE,
    grant_type    TEXT NOT NULL CHECK (grant_type IN ('authorization_code', 'refresh_token', 'client_credentials')),
    position      BIGINT NOT NULL,
    PRIMARY KEY (client_row_id, grant_type)
);

CREATE TABLE credential (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL REFERENCES user_account (id),
    kind                      TEXT NOT NULL CHECK (kind IN ('password', 'passkey', 'totp')),
    password_verifier         TEXT,
    webauthn_credential_id    BYTEA,
    webauthn_public_key       BYTEA,
    webauthn_aaguid           BYTEA,
    webauthn_sign_count       BIGINT,
    webauthn_transports       TEXT,
    webauthn_discoverable     BIGINT CHECK (webauthn_discoverable IN (0, 1)),
    webauthn_backup_eligible  BIGINT CHECK (webauthn_backup_eligible IN (0, 1)),
    webauthn_backup_state     BIGINT CHECK (webauthn_backup_state IN (0, 1)),
    totp_ciphertext           BYTEA,
    totp_key_id               TEXT,
    totp_nonce                BYTEA,
    totp_algorithm            TEXT CHECK (totp_algorithm IN ('sha1', 'sha256', 'sha512')),
    totp_digits               BIGINT,
    totp_period               BIGINT,
    totp_last_accepted_step   BIGINT,
    status                    TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
    created_at                BIGINT NOT NULL,
    updated_at                BIGINT NOT NULL,
    last_used_at              BIGINT,
    version                   BIGINT NOT NULL
);
CREATE UNIQUE INDEX credential_passkey_id_uq ON credential (webauthn_credential_id)
    WHERE webauthn_credential_id IS NOT NULL;
CREATE INDEX credential_user_idx ON credential (user_id);

CREATE TABLE session (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES user_account (id),
    organization_id     TEXT REFERENCES organization (id),
    audience            TEXT NOT NULL CHECK (audience IN ('account', 'admin')),
    token_hash          TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at          BIGINT NOT NULL,
    last_seen_at        BIGINT NOT NULL,
    idle_expires_at     BIGINT NOT NULL,
    absolute_expires_at BIGINT NOT NULL,
    revoked_at          BIGINT,
    rotated_from        TEXT REFERENCES session (id),
    version             BIGINT NOT NULL
);
CREATE UNIQUE INDEX session_token_hash_uq ON session (token_hash);
CREATE INDEX session_user_idx ON session (user_id, status, absolute_expires_at);

CREATE TABLE authorization_code (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organization (id),
    application_id TEXT NOT NULL REFERENCES application (id),
    client_id      TEXT NOT NULL REFERENCES oauth_client (id),
    user_id        TEXT NOT NULL REFERENCES user_account (id),
    code_hash      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    nonce          TEXT,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    consumed_at    BIGINT,
    version        BIGINT NOT NULL
);
CREATE UNIQUE INDEX authorization_code_hash_uq ON authorization_code (code_hash);

CREATE TABLE authorization_code_scope (
    code_id  TEXT NOT NULL REFERENCES authorization_code (id) ON DELETE CASCADE,
    scope    TEXT NOT NULL,
    position BIGINT NOT NULL,
    PRIMARY KEY (code_id, scope)
);

CREATE TABLE consent (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organization (id),
    user_id    TEXT NOT NULL REFERENCES user_account (id),
    client_id  TEXT NOT NULL REFERENCES oauth_client (id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    revoked_at BIGINT,
    version    BIGINT NOT NULL,
    UNIQUE (org_id, user_id, client_id)
);

CREATE TABLE consent_scope (
    consent_id TEXT NOT NULL REFERENCES consent (id) ON DELETE CASCADE,
    scope      TEXT NOT NULL,
    position   BIGINT NOT NULL,
    PRIMARY KEY (consent_id, scope)
);

CREATE TABLE refresh_family (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES organization (id),
    client_id           TEXT NOT NULL REFERENCES oauth_client (id),
    user_id             TEXT NOT NULL REFERENCES user_account (id),
    created_at          BIGINT NOT NULL,
    absolute_expires_at BIGINT NOT NULL,
    revoked_at          BIGINT,
    version             BIGINT NOT NULL
);
CREATE INDEX refresh_family_client_user_idx ON refresh_family (client_id, user_id);

CREATE TABLE refresh_token (
    id          TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL REFERENCES refresh_family (id),
    token_hash  TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    consumed_at BIGINT,
    version     BIGINT NOT NULL
);
CREATE UNIQUE INDEX refresh_token_hash_uq ON refresh_token (token_hash);
CREATE INDEX refresh_token_family_idx ON refresh_token (family_id);

CREATE TABLE audit_event (
    id          TEXT PRIMARY KEY,
    org_id      TEXT REFERENCES organization (id),
    actor_type  TEXT NOT NULL CHECK (actor_type IN ('user', 'client', 'system', 'anonymous')),
    actor_id    TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    occurred_at BIGINT NOT NULL,
    attributes  TEXT NOT NULL
);
CREATE INDEX audit_event_org_time_idx ON audit_event (org_id, occurred_at);
CREATE INDEX audit_event_actor_time_idx ON audit_event (actor_id, occurred_at);
CREATE INDEX audit_event_action_time_idx ON audit_event (action, occurred_at);
