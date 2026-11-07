//! OAuth 2.0 and OpenID Connect token issuance, validation, and revocation.

use std::sync::Arc;

use authkit_core::domain::audit::{
    AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget,
};
use authkit_core::domain::grant::{RefreshFamily, RefreshToken};
use authkit_core::domain::id::{
    AuditEventEntity, Id, OrganizationEntity, RefreshFamilyEntity, RefreshTokenEntity,
    SessionEntity, UserEntity,
};
use authkit_core::domain::oauth_client::{ClientType, GrantType, OAuthClient};
use authkit_core::domain::scope::ScopeSet;
use authkit_core::domain::secret::SecretHash;
use authkit_core::domain::tenant::TenantContext;
use authkit_core::domain::time::Timestamp;
use authkit_core::domain::user::User;
use authkit_core::domain::{ClientId, DomainError};
use authkit_core::ports::{
    Clock, IdGenerator, MembershipRepository, RefreshFamilyRepository, RefreshTokenRepository,
    SessionRepository, UserRepository, write::UnitOfWork, write::WriteBatch, write::WriteCommand,
};
use authkit_store::SqlStore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use p256::pkcs8::EncodePrivateKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::authorization::{AuthorizationService, ClientContext, RedeemCode, RedeemError};
use crate::config::{Issuer, TokenConfig};
use crate::http::error::{OAuthError, OAuthErrorCode};
use crate::session::{SecureIdGenerator, SessionService, SessionToken};
use crate::signing::KeyRing;

/// The JWT `typ` header required for access tokens.
pub const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// The namespaced claim carrying the tenant identifier.
pub const ORGANIZATION_CLAIM: &str = "https://authkit.dev/org";

const CLIENT_SECRET_DOMAIN: &[u8] = b"authkit.client_secret.v1";
const REFRESH_TOKEN_DOMAIN: &[u8] = b"authkit.refresh_token.v1";
const REFRESH_TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    client_id: String,
    scope: String,
    #[serde(rename = "https://authkit.dev/org")]
    organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    auth_time: u64,
    azp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

/// A successful token-endpoint response.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    /// The signed access token.
    pub access_token: String,
    /// The token type, always `Bearer`.
    pub token_type: &'static str,
    /// The access-token lifetime in seconds.
    pub expires_in: u64,
    /// The rotating refresh token, when one was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The signed ID token, when OpenID Connect scopes were granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The granted scopes, space-delimited.
    pub scope: String,
}

/// An authorization-code exchange request.
#[derive(Debug, Clone)]
pub struct CodeExchange {
    /// The plaintext authorization code.
    pub code: String,
    /// The exact redirect URI used at authorization.
    pub redirect_uri: String,
    /// The PKCE verifier.
    pub code_verifier: String,
    /// The request identifier used for audit correlation.
    pub request_id: String,
}

/// A refresh-token exchange request.
#[derive(Debug, Clone)]
pub struct RefreshExchange {
    /// The plaintext refresh token.
    pub refresh_token: String,
    /// An optional narrowed scope set.
    pub scope: Option<ScopeSet>,
}

/// A client-credentials request.
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    /// The optional requested scope set.
    pub scope: Option<ScopeSet>,
}

/// An RP-initiated logout request.
#[derive(Debug)]
pub struct LogoutRequest {
    /// A previously issued ID token identifying the client and session.
    pub id_token_hint: Option<String>,
    /// The client identifier when no ID token hint is available.
    pub client_id: Option<ClientId>,
    /// The exact registered post-logout redirect URI.
    pub post_logout_redirect_uri: Option<String>,
    /// An opaque value returned to the client.
    pub state: Option<String>,
    /// The current account-session cookie token, if present.
    pub session_token: Option<SessionToken>,
}

/// The outcome of an RP-initiated logout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutOutcome {
    /// The validated redirect target, when one may be used.
    pub redirect: Option<String>,
    /// Whether the browser session cookie must be cleared.
    pub clear_cookie: bool,
}

/// A userinfo validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInfoError {
    /// The bearer token is missing, malformed, expired, or not an access token.
    InvalidToken,
    /// The access token does not carry the required scope.
    InsufficientScope,
    /// Token storage could not be reached.
    Unavailable,
}

/// Issues and validates AuthKit tokens.
#[derive(Clone)]
pub struct TokenService {
    store: Arc<SqlStore>,
    issuer: Issuer,
    clock: Arc<dyn Clock + Send + Sync>,
    keys: Arc<KeyRing>,
    ids: SecureIdGenerator,
    sessions: Arc<SessionService>,
    authorization: Arc<AuthorizationService>,
    policy: TokenConfig,
    secret_pepper: Zeroizing<Vec<u8>>,
}

impl TokenService {
    /// Creates a token service.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<SqlStore>,
        issuer: Issuer,
        clock: Arc<dyn Clock + Send + Sync>,
        keys: Arc<KeyRing>,
        sessions: Arc<SessionService>,
        authorization: Arc<AuthorizationService>,
        policy: TokenConfig,
        secret_pepper: Vec<u8>,
    ) -> Self {
        Self {
            store,
            issuer,
            clock,
            keys,
            ids: SecureIdGenerator,
            sessions,
            authorization,
            policy,
            secret_pepper: Zeroizing::new(secret_pepper),
        }
    }

    /// Returns the session service used for logout.
    pub fn sessions(&self) -> &Arc<SessionService> {
        &self.sessions
    }

    /// Returns the authorization service used to resolve clients.
    pub fn authorization(&self) -> &Arc<AuthorizationService> {
        &self.authorization
    }

    /// Verifies a client secret against a stored verifier.
    pub(crate) fn client_secret_matches(&self, stored: &SecretHash, supplied: &str) -> bool {
        verify_client_secret(&self.secret_pepper, stored, supplied)
    }

    /// Exchanges a one-time authorization code for tokens.
    pub async fn exchange_code(
        &self,
        context: &ClientContext,
        request: CodeExchange,
    ) -> Result<TokenResponse, OAuthError> {
        let client = context.client();
        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(unauthorized_client());
        }

        let code = self
            .authorization
            .redeem_code(RedeemCode {
                client_id: client.client_id().clone(),
                code: request.code,
                redirect_uri: parse_redirect_uri(&request.redirect_uri)?,
                code_verifier: request.code_verifier,
                request_id: request.request_id,
            })
            .await
            .map_err(|error| match error {
                RedeemError::InvalidGrant => invalid_grant(),
                RedeemError::Unavailable => temporarily_unavailable(),
            })?;

        if code.organization_id() != context.organization().id() || code.client_id() != client.id()
        {
            return Err(invalid_grant());
        }

        let now = self.clock.now();
        let user = self.load_active_user(code.user_id(), context).await?;
        let scopes = code.scopes().clone();
        let session_id = code.session_id().cloned();
        let auth_time = code.auth_time();
        let organization_id = code.organization_id().clone();

        let access = self.sign_access(
            context,
            code.user_id().as_str(),
            &organization_id,
            &scopes,
            session_id.as_ref(),
            Some(auth_time),
        )?;
        let id_token = self.maybe_id_token(
            client,
            &user,
            &scopes,
            session_id.as_ref(),
            Some(auth_time),
            code.nonce().map(|nonce| nonce.as_str()),
        )?;

        let mut response = TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: self.policy.access_ttl_secs(),
            refresh_token: None,
            id_token,
            scope: scope_string(&scopes),
        };

        if client.allows_grant(GrantType::RefreshToken)
            && (has_scope(&scopes, "offline_access") || !has_scope(&scopes, "openid"))
        {
            let (family, refresh_token, plaintext) = self.prepare_refresh_family(
                context,
                code.user_id(),
                &organization_id,
                &scopes,
                session_id.as_ref(),
                auth_time,
                now,
            )?;
            let event = self.audit_event(
                Some(organization_id),
                AuditActor::User(code.user_id().clone()),
                "token.issue",
                client.client_id().as_str(),
                now,
                &[
                    ("client_id", client.client_id().as_str()),
                    ("grant_type", "authorization_code"),
                    ("scope", &scope_string(&scopes)),
                ],
            )?;
            let batch = WriteBatch::new()
                .with(WriteCommand::InsertRefreshFamily {
                    tenant: context.tenant().clone(),
                    family,
                })
                .with(WriteCommand::InsertRefreshToken {
                    tenant: context.tenant().clone(),
                    token: refresh_token,
                })
                .with(WriteCommand::AppendAudit {
                    tenant: context.tenant().clone(),
                    event,
                });
            let store = self.store.clone();
            blocking(move || store.commit(&batch)).await?;
            response.refresh_token = Some(plaintext);
        } else {
            self.append_audit(
                context.tenant().clone(),
                self.audit_event(
                    Some(organization_id),
                    AuditActor::User(code.user_id().clone()),
                    "token.issue",
                    client.client_id().as_str(),
                    now,
                    &[
                        ("client_id", client.client_id().as_str()),
                        ("grant_type", "authorization_code"),
                        ("scope", &scope_string(&scopes)),
                    ],
                )?,
            )
            .await?;
        }

        Ok(response)
    }

    /// Rotates a refresh token and issues a fresh token set.
    pub async fn refresh(
        &self,
        context: &ClientContext,
        request: RefreshExchange,
    ) -> Result<TokenResponse, OAuthError> {
        let client = context.client();
        if !client.allows_grant(GrantType::RefreshToken) {
            return Err(unauthorized_client());
        }

        let now = self.clock.now();
        let hash = hash_secret(
            &self.secret_pepper,
            REFRESH_TOKEN_DOMAIN,
            &request.refresh_token,
        );
        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let Some(mut token) =
            blocking(move || RefreshTokenRepository::find_by_hash(&*store, &tenant, &hash)).await?
        else {
            return Err(invalid_grant());
        };

        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let family_id = token.family_id().clone();
        let Some(mut family) =
            blocking(move || RefreshFamilyRepository::find_by_id(&*store, &tenant, &family_id))
                .await?
        else {
            return Err(invalid_grant());
        };

        if family.client_id() != client.id() || !family.is_active(now) {
            return Err(invalid_grant());
        }

        if let Some(session_id) = family.session_id() {
            let store = self.store.clone();
            let session_id = session_id.clone();
            let session =
                blocking(move || SessionRepository::find_by_id(&*store, &session_id)).await?;
            let invalid = session.map(|value| !value.is_valid(now)).unwrap_or(true);
            if invalid {
                self.revoke_replayed_family(context, &family, now).await?;
                return Err(invalid_grant());
            }
        }

        if token.consumed_at().is_some() {
            self.revoke_replayed_family(context, &family, now).await?;
            return Err(invalid_grant());
        }
        if !token.is_usable(now) {
            return Err(invalid_grant());
        }

        let user = self.load_active_user(family.user_id(), context).await?;
        let granted = match request.scope {
            Some(scope) => {
                if scope
                    .as_slice()
                    .iter()
                    .any(|scope| !family.scopes().contains(scope))
                {
                    return Err(invalid_scope());
                }
                scope
            }
            None => family.scopes().clone(),
        };
        if granted.is_empty() {
            return Err(invalid_scope());
        }

        let family_version = family.version();
        let narrows = granted.as_slice() != family.scopes().as_slice();
        if narrows {
            family
                .narrow_scopes(granted.clone())
                .map_err(|_| invalid_scope())?;
        }

        let old_version = token.version();
        token.consume(now).map_err(|_| invalid_grant())?;
        let plaintext = random_token(REFRESH_TOKEN_BYTES);
        let token_hash = plaintext_hash(&plaintext, &self.secret_pepper)?;
        let new_token =
            self.build_refresh_token(family.id(), token_hash, now, family.absolute_expires_at())?;

        let mut batch = WriteBatch::new()
            .with(WriteCommand::UpdateRefreshToken {
                tenant: context.tenant().clone(),
                token,
                expected_version: old_version,
            })
            .with(WriteCommand::InsertRefreshToken {
                tenant: context.tenant().clone(),
                token: new_token,
            })
            .with(WriteCommand::AppendAudit {
                tenant: context.tenant().clone(),
                event: self.audit_event(
                    Some(family.organization_id().clone()),
                    AuditActor::User(family.user_id().clone()),
                    "token.refresh",
                    family.id().as_str(),
                    now,
                    &[
                        ("client_id", client.client_id().as_str()),
                        ("scope", &scope_string(&granted)),
                    ],
                )?,
            });
        if narrows {
            batch = batch.with(WriteCommand::UpdateRefreshFamily {
                tenant: context.tenant().clone(),
                family: family.clone(),
                expected_version: family_version,
            });
        }

        let store = self.store.clone();
        match blocking(move || store.commit(&batch)).await {
            Ok(outcome) if outcome.is_applied() => {}
            Ok(_) => {
                self.revoke_replayed_family(context, &family, now).await?;
                return Err(invalid_grant());
            }
            Err(error) => return Err(error),
        }

        let access = self.sign_access(
            context,
            family.user_id().as_str(),
            family.organization_id(),
            &granted,
            family.session_id(),
            Some(family.auth_time()),
        )?;
        let id_token = self.maybe_id_token(
            client,
            &user,
            &granted,
            family.session_id(),
            Some(family.auth_time()),
            None,
        )?;

        Ok(TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: self.policy.access_ttl_secs(),
            refresh_token: Some(plaintext),
            id_token,
            scope: scope_string(&granted),
        })
    }

    /// Issues an access token for a confidential client acting on its own behalf.
    pub async fn client_credentials(
        &self,
        context: &ClientContext,
        request: ClientCredentials,
    ) -> Result<TokenResponse, OAuthError> {
        let client = context.client();
        if client.client_type() != ClientType::Confidential
            || !client.allows_grant(GrantType::ClientCredentials)
        {
            return Err(unauthorized_client());
        }

        let scopes = match request.scope {
            Some(scopes) => {
                if scopes
                    .as_slice()
                    .iter()
                    .any(|scope| !client.allows_scope(scope))
                {
                    return Err(invalid_scope());
                }
                scopes
            }
            None => client.allowed_scopes().clone(),
        };
        if scopes.is_empty() {
            return Err(invalid_scope());
        }

        let now = self.clock.now();
        let organization_id = context.organization().id().clone();
        let client_id = client.client_id().as_str().to_owned();
        let access = self.sign_access(
            context,
            client_id.as_str(),
            &organization_id,
            &scopes,
            None,
            None,
        )?;
        self.append_audit(
            context.tenant().clone(),
            self.audit_event(
                Some(organization_id),
                AuditActor::Client(client.id().clone()),
                "token.issue",
                &client_id,
                now,
                &[
                    ("client_id", &client_id),
                    ("grant_type", "client_credentials"),
                    ("scope", &scope_string(&scopes)),
                ],
            )?,
        )
        .await?;

        Ok(TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: self.policy.access_ttl_secs(),
            refresh_token: None,
            id_token: None,
            scope: scope_string(&scopes),
        })
    }

    /// Validates an access token and returns scope-gated OpenID Connect claims.
    pub async fn userinfo(&self, token: &str) -> Result<Value, UserInfoError> {
        let claims = self.decode_access_token(token)?;
        if !scope_string_has(&claims.scope, "openid") {
            return Err(UserInfoError::InsufficientScope);
        }

        let user_id =
            Id::<UserEntity>::parse(&claims.sub).map_err(|_| UserInfoError::InvalidToken)?;
        let store = self.store.clone();
        let user = blocking(move || UserRepository::find_by_id(&*store, &user_id))
            .await
            .map_err(|_| UserInfoError::Unavailable)?
            .ok_or(UserInfoError::InvalidToken)?;
        if !user.is_active() {
            return Err(UserInfoError::InvalidToken);
        }

        let mut response = json!({"sub": user.id().as_str()});
        if scope_string_has(&claims.scope, "profile") {
            response["name"] = json!(user.display_name().as_str());
        }
        if scope_string_has(&claims.scope, "email") {
            response["email"] = json!(user.email().as_str());
            response["email_verified"] = json!(user.is_email_verified());
        }
        Ok(response)
    }

    /// Revokes a refresh-token family owned by the authenticated client.
    ///
    /// Access tokens are self-contained and cannot be revoked before expiry; the
    /// endpoint still returns success for them, as RFC 7009 permits.
    pub async fn revoke(
        &self,
        context: &ClientContext,
        token: &str,
        _token_type_hint: Option<&str>,
    ) -> Result<(), OAuthError> {
        let hash = hash_secret(&self.secret_pepper, REFRESH_TOKEN_DOMAIN, token);
        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let Some(token) =
            blocking(move || RefreshTokenRepository::find_by_hash(&*store, &tenant, &hash)).await?
        else {
            return Ok(());
        };

        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let family_id = token.family_id().clone();
        let Some(mut family) =
            blocking(move || RefreshFamilyRepository::find_by_id(&*store, &tenant, &family_id))
                .await?
        else {
            return Ok(());
        };
        if family.client_id() != context.client().id() || family.revoked_at().is_some() {
            return Ok(());
        }

        let now = self.clock.now();
        let version = family.version();
        family.revoke(now);
        let event = self.audit_event(
            Some(family.organization_id().clone()),
            AuditActor::Client(context.client().id().clone()),
            "token.revoke",
            family.id().as_str(),
            now,
            &[
                ("client_id", context.client().client_id().as_str()),
                ("token_type", "refresh_token"),
            ],
        )?;
        let batch = WriteBatch::new()
            .with(WriteCommand::UpdateRefreshFamily {
                tenant: context.tenant().clone(),
                family,
                expected_version: version,
            })
            .with(WriteCommand::AppendAudit {
                tenant: context.tenant().clone(),
                event,
            });
        let store = self.store.clone();
        blocking(move || store.commit(&batch)).await?;
        Ok(())
    }

    /// Ends the browser session and validates an RP logout redirect.
    pub async fn logout(&self, request: LogoutRequest) -> Result<LogoutOutcome, OAuthError> {
        let now = self.clock.now();
        let hint = request
            .id_token_hint
            .as_deref()
            .and_then(|token| self.decode_id_token(token).ok());

        let client = match hint.as_ref() {
            Some(claims) => match ClientId::parse(claims.aud.as_str()) {
                Ok(client_id) => self
                    .authorization
                    .resolve_client(&client_id)
                    .await
                    .ok()
                    .flatten(),
                Err(_) => None,
            },
            None => match request.client_id.as_ref() {
                Some(client_id) => self
                    .authorization
                    .resolve_client(client_id)
                    .await
                    .ok()
                    .flatten(),
                None => None,
            },
        };

        let redirect = match request.post_logout_redirect_uri.as_deref() {
            Some(uri) => match client.as_ref() {
                Some(client) => match authkit_core::domain::RedirectUri::parse(uri) {
                    Ok(uri) if client.client().allows_post_logout_redirect_uri(&uri) => {
                        append_state(uri.as_str(), request.state.as_deref())
                    }
                    _ => None,
                },
                None => None,
            },
            None => None,
        };

        let had_cookie = request.session_token.is_some();
        let mut ended_user = None;
        if let Some(token) = request.session_token
            && let Ok(Some(session)) = self.sessions.load(&token, now).await
        {
            let user_id = session.user_id().clone();
            if session.is_valid(now)
                && hint
                    .as_ref()
                    .is_none_or(|claims| claims.sub == user_id.as_str())
                && self.sessions.revoke(session, now).await.is_ok()
            {
                ended_user = Some(user_id);
            }
        }

        if let (Some(user_id), Some(client)) = (ended_user, client.as_ref()) {
            self.append_audit(
                client.tenant().clone(),
                self.audit_event(
                    Some(client.organization().id().clone()),
                    AuditActor::User(user_id),
                    "session.logout",
                    request
                        .post_logout_redirect_uri
                        .as_deref()
                        .unwrap_or("logout"),
                    now,
                    &[("client_id", client.client().client_id().as_str())],
                )?,
            )
            .await?;
        }

        Ok(LogoutOutcome {
            redirect,
            clear_cookie: had_cookie,
        })
    }

    async fn load_active_user(
        &self,
        user_id: &Id<UserEntity>,
        context: &ClientContext,
    ) -> Result<User, OAuthError> {
        let store = self.store.clone();
        let user_id = user_id.clone();
        let user = blocking(move || UserRepository::find_by_id(&*store, &user_id)).await?;
        let Some(user) = user else {
            return Err(invalid_grant());
        };
        if !user.is_active() {
            return Err(invalid_grant());
        }
        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let membership_user_id = user.id().clone();
        let membership = blocking(move || {
            MembershipRepository::find_by_user(&*store, &tenant, &membership_user_id)
        })
        .await?;
        if !membership.is_some_and(|membership| membership.is_active()) {
            return Err(invalid_grant());
        }
        Ok(user)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_access(
        &self,
        context: &ClientContext,
        subject: &str,
        organization_id: &Id<OrganizationEntity>,
        scopes: &ScopeSet,
        session_id: Option<&Id<SessionEntity>>,
        auth_time: Option<Timestamp>,
    ) -> Result<String, OAuthError> {
        let now = self.clock.now();
        let issued_at = now.as_millis() / 1_000;
        let expiry = issued_at.saturating_add(self.policy.access_ttl_secs());
        let claims = AccessClaims {
            iss: self.issuer.as_str().to_owned(),
            sub: subject.to_owned(),
            aud: context.client().client_id().as_str().to_owned(),
            exp: expiry,
            iat: issued_at,
            nbf: issued_at,
            jti: random_token(16),
            client_id: context.client().client_id().as_str().to_owned(),
            scope: scope_string(scopes),
            organization_id: organization_id.as_str().to_owned(),
            sid: session_id.map(|session| session.as_str().to_owned()),
            auth_time: auth_time.map(|time| time.as_millis() / 1_000),
        };
        self.sign_jwt(ACCESS_TOKEN_TYPE, &claims)
    }

    fn maybe_id_token(
        &self,
        client: &OAuthClient,
        user: &User,
        scopes: &ScopeSet,
        session_id: Option<&Id<SessionEntity>>,
        auth_time: Option<Timestamp>,
        nonce: Option<&str>,
    ) -> Result<Option<String>, OAuthError> {
        if !has_scope(scopes, "openid") {
            return Ok(None);
        }
        let now = self.clock.now();
        let issued_at = now.as_millis() / 1_000;
        let claims = IdTokenClaims {
            iss: self.issuer.as_str().to_owned(),
            sub: user.id().as_str().to_owned(),
            aud: client.client_id().as_str().to_owned(),
            exp: issued_at.saturating_add(self.policy.id_ttl_secs()),
            iat: issued_at,
            auth_time: auth_time.unwrap_or(now).as_millis().saturating_div(1_000),
            azp: client.client_id().as_str().to_owned(),
            sid: session_id.map(|session| session.as_str().to_owned()),
            nonce: nonce.map(str::to_owned),
            name: has_scope(scopes, "profile").then(|| user.display_name().as_str().to_owned()),
            email: has_scope(scopes, "email").then(|| user.email().as_str().to_owned()),
            email_verified: has_scope(scopes, "email").then(|| user.is_email_verified()),
        };
        self.sign_jwt("JWT", &claims).map(Some)
    }

    fn sign_jwt(&self, typ: &str, claims: &impl Serialize) -> Result<String, OAuthError> {
        let key = self.keys.active();
        let secret = key.secret().ok_or_else(server_error)?;
        let der = secret.to_pkcs8_der().map_err(|_| server_error())?;
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.to_owned());
        header.kid = Some(key.kid().to_owned());
        encode(&header, claims, &EncodingKey::from_ec_der(der.as_bytes()))
            .map_err(|_| server_error())
    }

    fn decode_access_token(&self, token: &str) -> Result<AccessClaims, UserInfoError> {
        let claims: AccessClaims = self
            .decode_jwt(token, ACCESS_TOKEN_TYPE)
            .map_err(|_| UserInfoError::InvalidToken)?;
        if claims.iss != self.issuer.as_str()
            || !self.claims_are_current(claims.exp, claims.iat, Some(claims.nbf), 0)
        {
            return Err(UserInfoError::InvalidToken);
        }
        Ok(claims)
    }

    fn decode_id_token(&self, token: &str) -> Result<IdTokenClaims, OAuthError> {
        let claims: IdTokenClaims = self.decode_jwt(token, "JWT")?;
        if claims.iss != self.issuer.as_str()
            || !self.claims_are_current(claims.exp, claims.iat, None, 300)
        {
            return Err(invalid_request());
        }
        Ok(claims)
    }

    fn claims_are_current(&self, exp: u64, iat: u64, nbf: Option<u64>, grace: u64) -> bool {
        let now = self.clock.now().as_millis() / 1_000;
        let leeway = self.policy.clock_skew_secs().saturating_add(grace);
        now <= exp.saturating_add(leeway)
            && iat <= now.saturating_add(leeway)
            && nbf.is_none_or(|nbf| nbf <= now.saturating_add(leeway))
    }

    fn decode_jwt<T>(&self, token: &str, expected_type: &str) -> Result<T, OAuthError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let header = decode_header(token).map_err(|_| invalid_token())?;
        if header.alg != Algorithm::ES256
            || header.typ.as_deref() != Some(expected_type)
            || header.kid.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid_token());
        }
        let kid = header.kid.as_deref().unwrap_or_default();
        let now_secs = self.clock.now().as_millis() / 1_000;
        let jwk = self
            .keys
            .verification_key(kid, now_secs)
            .ok_or_else(invalid_token)?;
        let decoding =
            DecodingKey::from_ec_components(&jwk.x, &jwk.y).map_err(|_| server_error())?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let data = decode::<T>(token, &decoding, &validation).map_err(|_| invalid_token())?;
        Ok(data.claims)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_refresh_family(
        &self,
        context: &ClientContext,
        user_id: &Id<UserEntity>,
        organization_id: &Id<OrganizationEntity>,
        scopes: &ScopeSet,
        session_id: Option<&Id<SessionEntity>>,
        auth_time: Timestamp,
        now: Timestamp,
    ) -> Result<(RefreshFamily, RefreshToken, String), OAuthError> {
        let family_id = self
            .ids
            .generate::<RefreshFamilyEntity>()
            .map_err(|_| server_error())?;
        let expiry = Timestamp::from_millis(
            now.as_millis()
                .saturating_add(self.policy.refresh_family_ttl_secs().saturating_mul(1_000)),
        );
        let family = RefreshFamily::new(
            family_id.clone(),
            organization_id.clone(),
            context.client().id().clone(),
            user_id.clone(),
            scopes.clone(),
            session_id.cloned(),
            auth_time,
            now,
            expiry,
        )
        .map_err(|error| OAuthError::from_domain(&error))?;
        let plaintext = random_token(REFRESH_TOKEN_BYTES);
        let hash = plaintext_hash(&plaintext, &self.secret_pepper)?;
        let token = self.build_refresh_token(&family_id, hash, now, expiry)?;
        Ok((family, token, plaintext))
    }

    fn build_refresh_token(
        &self,
        family_id: &Id<RefreshFamilyEntity>,
        hash: SecretHash,
        now: Timestamp,
        family_expiry: Timestamp,
    ) -> Result<RefreshToken, OAuthError> {
        let id = self
            .ids
            .generate::<RefreshTokenEntity>()
            .map_err(|_| server_error())?;
        let ttl_expiry = Timestamp::from_millis(
            now.as_millis()
                .saturating_add(self.policy.refresh_ttl_secs().saturating_mul(1_000)),
        );
        let expires_at = if ttl_expiry.is_before(family_expiry) {
            ttl_expiry
        } else {
            family_expiry
        };
        RefreshToken::new(id, family_id.clone(), hash, now, expires_at)
            .map_err(|error| OAuthError::from_domain(&error))
    }

    async fn revoke_replayed_family(
        &self,
        context: &ClientContext,
        family: &RefreshFamily,
        now: Timestamp,
    ) -> Result<(), OAuthError> {
        let store = self.store.clone();
        let tenant = context.tenant().clone();
        let family_id = family.id().clone();
        let Some(mut latest) =
            blocking(move || RefreshFamilyRepository::find_by_id(&*store, &tenant, &family_id))
                .await?
        else {
            return Ok(());
        };
        if latest.revoked_at().is_some() {
            return Ok(());
        }
        let version = latest.version();
        latest.revoke(now);
        let event = self.audit_event(
            Some(latest.organization_id().clone()),
            AuditActor::User(latest.user_id().clone()),
            "token.refresh.reuse",
            latest.id().as_str(),
            now,
            &[("client_id", context.client().client_id().as_str())],
        )?;
        let batch = WriteBatch::new()
            .with(WriteCommand::UpdateRefreshFamily {
                tenant: context.tenant().clone(),
                family: latest,
                expected_version: version,
            })
            .with(WriteCommand::AppendAudit {
                tenant: context.tenant().clone(),
                event,
            });
        let store = self.store.clone();
        blocking(move || store.commit(&batch)).await.map(|_| ())
    }

    fn audit_event(
        &self,
        organization_id: Option<Id<OrganizationEntity>>,
        actor: AuditActor,
        action: &str,
        target: &str,
        now: Timestamp,
        attributes: &[(&str, &str)],
    ) -> Result<AuditEvent, OAuthError> {
        let id = self
            .ids
            .generate::<AuditEventEntity>()
            .map_err(|_| server_error())?;
        let mut values = Vec::with_capacity(attributes.len());
        for (key, value) in attributes {
            values.push(
                AuditAttribute::new(*key, *value)
                    .map_err(|error| OAuthError::from_domain(&error.into()))?,
            );
        }
        AuditEvent::new(
            id,
            organization_id,
            actor,
            AuditAction::parse(action).map_err(|error| OAuthError::from_domain(&error.into()))?,
            Some(
                AuditTarget::parse(target)
                    .map_err(|error| OAuthError::from_domain(&error.into()))?,
            ),
            now,
            values,
        )
        .map_err(|error| OAuthError::from_domain(&error))
    }

    async fn append_audit(
        &self,
        tenant: TenantContext,
        event: AuditEvent,
    ) -> Result<(), OAuthError> {
        let store = self.store.clone();
        blocking(move || {
            let batch = WriteBatch::new().with(WriteCommand::AppendAudit { tenant, event });
            store.commit(&batch)
        })
        .await?;
        Ok(())
    }
}

/// Hashes a client secret with the deployment pepper.
pub fn hash_client_secret(pepper: &[u8], secret: &str) -> Result<SecretHash, DomainError> {
    Ok(hash_secret(pepper, CLIENT_SECRET_DOMAIN, secret))
}

/// Verifies a supplied client secret in constant time.
pub fn verify_client_secret(pepper: &[u8], stored: &SecretHash, supplied: &str) -> bool {
    let Some(encoded) = stored.as_str().strip_prefix("hmac-sha256:") else {
        return false;
    };
    let Ok(expected) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(pepper) else {
        return false;
    };
    mac.update(CLIENT_SECRET_DOMAIN);
    mac.update(supplied.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

fn hash_secret(pepper: &[u8], domain: &[u8], value: &str) -> SecretHash {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(value.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    SecretHash::parse(format!("hmac-sha256:{encoded}")).expect("HMAC output is a valid secret hash")
}

fn plaintext_hash(plaintext: &str, pepper: &[u8]) -> Result<SecretHash, OAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).map_err(|_| server_error())?;
    mac.update(REFRESH_TOKEN_DOMAIN);
    mac.update(plaintext.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    SecretHash::parse(format!("hmac-sha256:{encoded}")).map_err(|_| server_error())
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn scope_string(scopes: &ScopeSet) -> String {
    scopes
        .as_slice()
        .iter()
        .map(authkit_core::domain::Scope::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

fn has_scope(scopes: &ScopeSet, name: &str) -> bool {
    scopes.as_slice().iter().any(|scope| scope.as_str() == name)
}

fn scope_string_has(scopes: &str, name: &str) -> bool {
    scopes.split_ascii_whitespace().any(|scope| scope == name)
}

fn parse_redirect_uri(value: &str) -> Result<authkit_core::domain::RedirectUri, OAuthError> {
    authkit_core::domain::RedirectUri::parse(value).map_err(|_| invalid_request())
}

fn append_state(uri: &str, state: Option<&str>) -> Option<String> {
    let mut url = url::Url::parse(uri).ok()?;
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Some(url.to_string())
}

async fn blocking<T>(
    operation: impl FnOnce() -> Result<T, DomainError> + Send + 'static,
) -> Result<T, OAuthError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| temporarily_unavailable())?
        .map_err(|error| OAuthError::from_domain(&error))
}

const fn invalid_request() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidRequest,
        "the request is malformed or missing a required parameter",
    )
}

const fn invalid_grant() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidGrant,
        "the grant or token is invalid, expired, or already consumed",
    )
}

const fn invalid_scope() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidScope,
        "the requested scope is invalid or exceeds the granted scope",
    )
}

const fn unauthorized_client() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::UnauthorizedClient,
        "the client is not allowed to use this grant type",
    )
}

const fn invalid_token() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidGrant,
        "the token is invalid, expired, or not an access token",
    )
}

const fn server_error() -> OAuthError {
    OAuthError::new(OAuthErrorCode::ServerError, "an internal error occurred")
}

const fn temporarily_unavailable() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::TemporarilyUnavailable,
        "the service is temporarily unavailable",
    )
}
