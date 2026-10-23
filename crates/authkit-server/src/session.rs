//! Server-side browser session lifecycle.
//!
//! Session tokens are random opaque values. Storage only receives an HMAC-SHA256 verifier
//! keyed by the deployment pepper, so a database leak does not expose usable cookies. The
//! same pepper derives the session-bound CSRF token.

use std::fmt;
use std::sync::Arc;

use authkit_core::domain::audit::{
    AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget,
};
use authkit_core::domain::id::{
    AuditEventEntity, Id, OrganizationEntity, SessionEntity, UserEntity,
};
use authkit_core::domain::{
    DomainError, ErrorCode, IdError, SecretHash, Session, SessionAudience, Timestamp, ValueError,
    WriteOutcome,
};
use authkit_core::ports::write::{WriteBatch, WriteCommand};
use authkit_core::ports::{Clock, IdGenerator, SessionRepository, UnitOfWork};
use authkit_store::SqlStore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use hmac::{Hmac, Mac as _};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::task;
use zeroize::Zeroizing;

use crate::config::{Environment, SessionConfig, SessionLifetime};

/// Number of random bytes in a session token.
pub const SESSION_TOKEN_BYTES: usize = 32;

/// Number of random bytes in a session identifier suffix.
const SESSION_ID_BYTES: usize = 16;

/// Minimum interval between activity writes for an active session.
const TOUCH_INTERVAL_MS: u64 = 60_000;

/// Development and test account-session cookie name.
pub const DEVELOPMENT_ACCOUNT_COOKIE: &str = "authkit_session";

/// Development and test administrator-session cookie name.
pub const DEVELOPMENT_ADMIN_COOKIE: &str = "authkit_admin_session";

/// Production account-session cookie name.
pub const PRODUCTION_ACCOUNT_COOKIE: &str = "__Host-authkit_session";

/// Production administrator-session cookie name.
pub const PRODUCTION_ADMIN_COOKIE: &str = "__Host-authkit_admin_session";

/// A random, opaque session token.
///
/// The token is zeroized on drop and redacted from `Debug`. Only the derived verifier is
/// persisted.
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// Generates a new 256-bit session token.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SESSION_TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Parses a canonical token received from a cookie.
    ///
    /// Returns `None` for malformed, non-canonical, or incorrectly sized values.
    pub fn from_cookie(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > 128 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        if bytes.len() != SESSION_TOKEN_BYTES {
            return None;
        }
        Some(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))))
    }

    /// Returns the encoded token.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn digest(&self, pepper: &[u8]) -> Result<SecretHash, DomainError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
            .map_err(|_| DomainError::new(ErrorCode::Internal, "session pepper is invalid"))?;
        mac.update(b"authkit.session.v1\0");
        mac.update(self.0.as_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        SecretHash::parse(format!("hmac-sha256:{encoded}"))
            .map_err(|_| DomainError::new(ErrorCode::Internal, "session token verifier is invalid"))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([redacted])")
    }
}

/// A newly created or rotated session and its plaintext token.
pub struct NewSession {
    session: Session,
    token: SessionToken,
}

impl NewSession {
    /// Returns the persisted session.
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Returns the plaintext token for the browser cookie.
    pub const fn token(&self) -> &SessionToken {
        &self.token
    }
}

/// A session lifecycle failure.
#[derive(Debug)]
pub enum SessionError {
    /// A domain or storage operation failed.
    Domain(DomainError),
    /// A blocking database task failed.
    Blocking(task::JoinError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => write!(formatter, "{error}"),
            Self::Blocking(error) => write!(formatter, "session storage task failed: {error}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<DomainError> for SessionError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<IdError> for SessionError {
    fn from(error: IdError) -> Self {
        Self::Domain(error.into())
    }
}

impl From<ValueError> for SessionError {
    fn from(error: ValueError) -> Self {
        Self::Domain(error.into())
    }
}

impl From<task::JoinError> for SessionError {
    fn from(error: task::JoinError) -> Self {
        Self::Blocking(error)
    }
}

/// A session service bound to storage, policy, and the deployment pepper.
#[derive(Clone)]
pub struct SessionService {
    store: Arc<SqlStore>,
    config: SessionConfig,
    environment: Environment,
    clock: Arc<dyn Clock + Send + Sync>,
    ids: SecureIdGenerator,
}

impl SessionService {
    /// Creates a session service.
    pub fn new(
        store: Arc<SqlStore>,
        config: SessionConfig,
        environment: Environment,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            store,
            config,
            environment,
            clock,
            ids: SecureIdGenerator,
        }
    }

    /// Returns the configured clock.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Returns the cookie name for an audience.
    pub const fn cookie_name(&self, audience: SessionAudience) -> &'static str {
        match (self.environment, audience) {
            (Environment::Production, SessionAudience::Account) => PRODUCTION_ACCOUNT_COOKIE,
            (Environment::Production, SessionAudience::Admin) => PRODUCTION_ADMIN_COOKIE,
            (_, SessionAudience::Account) => DEVELOPMENT_ACCOUNT_COOKIE,
            (_, SessionAudience::Admin) => DEVELOPMENT_ADMIN_COOKIE,
        }
    }

    fn lifetime(&self, audience: SessionAudience) -> SessionLifetime {
        match audience {
            SessionAudience::Account => self.config.account(),
            SessionAudience::Admin => self.config.admin(),
        }
    }

    /// Creates a new active session for a user.
    pub async fn create(
        &self,
        user_id: Id<UserEntity>,
        organization_id: Option<Id<OrganizationEntity>>,
        audience: SessionAudience,
        now: Timestamp,
    ) -> Result<NewSession, SessionError> {
        self.create_inner(user_id, organization_id, audience, now, None)
            .await
    }

    async fn create_inner(
        &self,
        user_id: Id<UserEntity>,
        organization_id: Option<Id<OrganizationEntity>>,
        audience: SessionAudience,
        now: Timestamp,
        rotated_from: Option<Id<SessionEntity>>,
    ) -> Result<NewSession, SessionError> {
        let token = SessionToken::generate();
        let token_hash = token.digest(self.config.pepper())?;
        let id = self.ids.generate::<SessionEntity>()?;
        let lifetime = self.lifetime(audience);
        let idle_expires_at = expiry(now, lifetime.idle_secs());
        let absolute_expires_at = expiry(now, lifetime.absolute_secs());
        let session = Session::new(
            id,
            user_id,
            organization_id,
            audience,
            token_hash,
            now,
            idle_expires_at,
            absolute_expires_at,
            rotated_from,
        )?;

        let store = self.store.clone();
        let to_insert = session.clone();
        let outcome = task::spawn_blocking(move || store.insert(&to_insert)).await??;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("session identifier already exists").into());
        }

        Ok(NewSession { session, token })
    }

    /// Loads the session for a token without validating its current status.
    ///
    /// Callers must check [`Session::is_valid`] and must treat storage failures as a
    /// fail-closed authentication error.
    pub async fn load(
        &self,
        token: &SessionToken,
        _now: Timestamp,
    ) -> Result<Option<Session>, SessionError> {
        let token_hash = token.digest(self.config.pepper())?;
        let store = self.store.clone();
        let session = task::spawn_blocking(move || store.find_by_token_hash(&token_hash)).await??;
        Ok(session)
    }

    /// Records activity and extends the idle expiry when needed.
    pub async fn touch(&self, session: Session, now: Timestamp) -> Result<Session, SessionError> {
        if !session.is_valid(now) {
            return Err(DomainError::unauthenticated("session is not active").into());
        }
        let idle_remaining = session
            .idle_expires_at()
            .as_millis()
            .saturating_sub(now.as_millis());
        if now
            .as_millis()
            .saturating_sub(session.last_seen_at().as_millis())
            < TOUCH_INTERVAL_MS
            && idle_remaining > TOUCH_INTERVAL_MS
        {
            return Ok(session);
        }

        let lifetime = self.lifetime(session.audience());
        let idle_expires_at = expiry(now, lifetime.idle_secs());
        let idle_expires_at = if idle_expires_at > session.absolute_expires_at() {
            session.absolute_expires_at()
        } else {
            idle_expires_at
        };
        if !now.is_before(idle_expires_at) {
            return Err(DomainError::unauthenticated("session is not active").into());
        }

        let expected_version = session.version();
        let mut touched = session;
        touched.touch(now, idle_expires_at)?;

        let store = self.store.clone();
        let to_update = touched.clone();
        let outcome =
            task::spawn_blocking(move || store.update(&to_update, expected_version)).await??;
        match outcome {
            WriteOutcome::Applied => Ok(touched),
            WriteOutcome::Conflict | WriteOutcome::NotFound => {
                let id = touched.id().clone();
                let store = self.store.clone();
                let fresh = task::spawn_blocking(move || store.find_by_id(&id)).await??;
                match fresh {
                    Some(fresh) if fresh.is_valid(now) => Ok(fresh),
                    _ => Err(DomainError::unauthenticated("session is not active").into()),
                }
            }
        }
    }

    /// Revokes a session. Repeated revocation is idempotent.
    pub async fn revoke(
        &self,
        mut session: Session,
        now: Timestamp,
    ) -> Result<Session, SessionError> {
        let expected_version = session.version();
        session.revoke(now);
        if session.version() == expected_version {
            return Ok(session);
        }

        let store = self.store.clone();
        let to_update = session.clone();
        let outcome =
            task::spawn_blocking(move || store.update(&to_update, expected_version)).await??;
        match outcome {
            WriteOutcome::Applied => Ok(session),
            WriteOutcome::Conflict | WriteOutcome::NotFound => {
                let id = session.id().clone();
                let store = self.store.clone();
                let fresh = task::spawn_blocking(move || store.find_by_id(&id)).await??;
                fresh.ok_or_else(|| DomainError::unauthenticated("session not found").into())
            }
        }
    }

    /// Atomically revokes `current` and creates its replacement.
    pub async fn rotate(
        &self,
        current: Session,
        now: Timestamp,
    ) -> Result<NewSession, SessionError> {
        if !current.is_valid(now) {
            return Err(DomainError::unauthenticated("session is not active").into());
        }

        let expected_version = current.version();
        let mut revoked = current.clone();
        revoked.revoke(now);

        let token = SessionToken::generate();
        let token_hash = token.digest(self.config.pepper())?;
        let id = self.ids.generate::<SessionEntity>()?;
        let lifetime = self.lifetime(current.audience());
        let replacement = Session::new(
            id,
            current.user_id().clone(),
            current.organization_id().cloned(),
            current.audience(),
            token_hash,
            now,
            expiry(now, lifetime.idle_secs()),
            expiry(now, lifetime.absolute_secs()),
            Some(current.id().clone()),
        )?;

        let batch = WriteBatch::new()
            .with(WriteCommand::UpdateSession {
                session: revoked,
                expected_version,
            })
            .with(WriteCommand::InsertSession(replacement.clone()));

        let store = self.store.clone();
        let outcome = task::spawn_blocking(move || store.commit(&batch)).await??;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("session rotation lost a race").into());
        }

        Ok(NewSession {
            session: replacement,
            token,
        })
    }

    /// Records a rejected CSRF request in the audit log.
    ///
    /// Security audit writes are deployment-global when the session has no organization.
    pub async fn audit_csrf_rejection(
        &self,
        session: &Session,
        request_id: &str,
        method: &str,
        path: &str,
        reason: &str,
    ) -> Result<(), SessionError> {
        let event = AuditEvent::new(
            self.ids.generate::<AuditEventEntity>()?,
            session.organization_id().cloned(),
            AuditActor::User(session.user_id().clone()),
            AuditAction::parse("security.csrf_rejected")?,
            Some(AuditTarget::parse(session.id().as_str())?),
            self.clock.now(),
            vec![
                AuditAttribute::new("request_id", truncate(request_id, 128))?,
                AuditAttribute::new("method", truncate(method, 16))?,
                AuditAttribute::new("path", truncate(path, 512))?,
                AuditAttribute::new("reason", truncate(reason, 64))?,
            ],
        )?;

        let store = self.store.clone();
        let outcome = task::spawn_blocking(move || store.append_security_audit(&event)).await??;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("security audit event was not appended").into());
        }
        Ok(())
    }

    /// Derives the session-bound CSRF token.
    pub fn csrf_token(&self, session: &Session) -> String {
        URL_SAFE_NO_PAD.encode(self.csrf_mac(session).finalize().into_bytes())
    }

    /// Verifies a supplied CSRF token in constant time.
    pub fn csrf_matches(&self, session: &Session, supplied: &str) -> bool {
        if supplied.is_empty() || supplied.len() > 128 {
            return false;
        }
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(supplied) else {
            return false;
        };
        self.csrf_mac(session).verify_slice(&bytes).is_ok()
    }

    fn csrf_mac(&self, session: &Session) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.config.pepper())
            .expect("a 32-byte pepper is a valid HMAC key");
        mac.update(b"authkit.csrf.v1\0");
        mac.update(session.id().as_str().as_bytes());
        mac
    }

    const fn secure_cookies(&self) -> bool {
        matches!(self.environment, Environment::Production) || self.config.cookie_secure()
    }

    /// Builds the `Set-Cookie` value for a session.
    pub fn set_cookie(&self, session: &Session, token: &SessionToken, now: Timestamp) -> String {
        let expires_at = if session.idle_expires_at() < session.absolute_expires_at() {
            session.idle_expires_at()
        } else {
            session.absolute_expires_at()
        };
        let remaining_ms = expires_at.as_millis().saturating_sub(now.as_millis());
        let max_age = (remaining_ms / 1_000).max(1);
        let max_age = i64::try_from(max_age).unwrap_or(i64::MAX);

        let builder = Cookie::build((self.cookie_name(session.audience()), token.as_str()))
            .path("/")
            .secure(self.secure_cookies())
            .http_only(true)
            .same_site(match session.audience() {
                SessionAudience::Account => SameSite::Lax,
                SessionAudience::Admin => SameSite::Strict,
            })
            .max_age(Duration::seconds(max_age));
        builder.build().to_string()
    }

    /// Builds a `Set-Cookie` value that removes the cookie for an audience.
    pub fn clear_cookie(&self, audience: SessionAudience) -> String {
        Cookie::build((self.cookie_name(audience), ""))
            .path("/")
            .secure(self.secure_cookies())
            .http_only(true)
            .same_site(match audience {
                SessionAudience::Account => SameSite::Lax,
                SessionAudience::Admin => SameSite::Strict,
            })
            .removal()
            .build()
            .to_string()
    }
}

fn expiry(now: Timestamp, seconds: u64) -> Timestamp {
    Timestamp::from_millis(
        now.as_millis()
            .saturating_add(seconds.saturating_mul(1_000)),
    )
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

/// The production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_millis(crate::signing::unix_now())
    }
}

/// A cryptographically secure identifier generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureIdGenerator;

impl IdGenerator for SecureIdGenerator {
    fn generate<E: authkit_core::domain::Entity>(
        &self,
    ) -> Result<Id<E>, authkit_core::domain::IdError> {
        use std::fmt::Write as _;

        let mut bytes = [0_u8; SESSION_ID_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let mut suffix = String::with_capacity(SESSION_ID_BYTES * 2);
        for byte in bytes {
            write!(suffix, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Id::from_suffix(&suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkit_core::domain::id::{OrganizationEntity, UserEntity};
    use authkit_core::domain::{DisplayName, Email, Organization, SessionStatus, Slug, User};
    use authkit_core::ports::{IdGenerator, OrganizationRepository, UserRepository};

    fn service(environment: Environment) -> SessionService {
        let config = SessionConfig::new(
            vec![7_u8; 32],
            true,
            SessionLifetime::new(1_800, 43_200),
            SessionLifetime::new(900, 28_800),
        );
        let store = SqlStore::sqlite_in_memory().expect("in-memory store");
        store.migrate().expect("migrated store");
        let epoch = Timestamp::from_millis(1);
        let user = User::new(
            user_id(),
            Email::parse("session-test@example.com").expect("valid email"),
            DisplayName::parse("Session Test").expect("valid display name"),
            epoch,
        );
        UserRepository::insert(&store, &user).expect("inserted user");
        let organization = Organization::new(
            organization_id(),
            Slug::parse("session-test").expect("valid slug"),
            DisplayName::parse("Session Test").expect("valid display name"),
            epoch,
        );
        OrganizationRepository::insert(&store, &organization).expect("inserted organization");
        SessionService::new(Arc::new(store), config, environment, Arc::new(SystemClock))
    }

    fn user_id() -> Id<UserEntity> {
        Id::from_suffix("0123456789abcdef").expect("valid user id")
    }

    fn organization_id() -> Id<OrganizationEntity> {
        Id::from_suffix("fedcba9876543210").expect("valid organization id")
    }

    #[test]
    fn tokens_are_opaque_and_canonical() {
        let token = SessionToken::generate();
        assert_eq!(token.as_str().len(), 43);
        assert_eq!(format!("{token:?}"), "SessionToken([redacted])");
        assert!(SessionToken::from_cookie(token.as_str()).is_some());
        assert!(SessionToken::from_cookie("not-a-token").is_none());
        assert!(SessionToken::from_cookie(&"a".repeat(200)).is_none());
    }

    #[test]
    fn csrf_rejection_audit_future_is_send() {
        fn assert_send<F: std::future::Future + Send>(_: F) {}
        let service = service(Environment::Test);
        let now = Timestamp::from_millis(1_000_000);
        let session = Session::new(
            service.ids.generate::<SessionEntity>().expect("id"),
            user_id(),
            None,
            SessionAudience::Account,
            SecretHash::parse("hmac-sha256:0123456789abcdef").expect("hash"),
            now,
            Timestamp::from_millis(2_000_000),
            Timestamp::from_millis(3_000_000),
            None,
        )
        .expect("session");
        assert_send(service.audit_csrf_rejection(
            &session,
            "request-id",
            "POST",
            "/secure",
            "invalid_csrf",
        ));
    }

    #[test]
    fn csrf_tokens_are_session_bound() {
        let service = service(Environment::Test);
        let now = Timestamp::from_millis(1_000_000);
        let first = service.ids.generate::<SessionEntity>().expect("id");
        let second = service.ids.generate::<SessionEntity>().expect("id");
        let hash = SecretHash::parse("hmac-sha256:0123456789abcdef").expect("hash");
        let session = Session::new(
            first,
            user_id(),
            None,
            SessionAudience::Account,
            hash.clone(),
            now,
            Timestamp::from_millis(2_000_000),
            Timestamp::from_millis(3_000_000),
            None,
        )
        .expect("session");
        let other = Session::new(
            second,
            user_id(),
            None,
            SessionAudience::Account,
            hash,
            now,
            Timestamp::from_millis(2_000_000),
            Timestamp::from_millis(3_000_000),
            None,
        )
        .expect("session");
        let token = service.csrf_token(&session);
        assert!(service.csrf_matches(&session, &token));
        assert!(!service.csrf_matches(&other, &token));
        assert!(!service.csrf_matches(&session, "bad"));
    }

    #[test]
    fn cookies_are_host_only_and_audience_specific() {
        let now = Timestamp::from_millis(1_000_000);
        let service = service(Environment::Production);
        let session = Session::new(
            service.ids.generate::<SessionEntity>().expect("id"),
            user_id(),
            None,
            SessionAudience::Admin,
            SecretHash::parse("hmac-sha256:0123456789abcdef").expect("hash"),
            now,
            Timestamp::from_millis(1_900_000),
            Timestamp::from_millis(2_000_000),
            None,
        )
        .expect("session");
        let token = SessionToken::generate();
        let cookie = service.set_cookie(&session, &token, now);
        assert!(cookie.starts_with(PRODUCTION_ADMIN_COOKIE));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Domain="));
        assert!(
            service
                .clear_cookie(SessionAudience::Admin)
                .contains("Max-Age=0")
        );
    }

    #[test]
    fn production_always_marks_cookies_secure() {
        let config = SessionConfig::new(
            vec![7_u8; 32],
            false,
            SessionLifetime::new(1_800, 43_200),
            SessionLifetime::new(900, 28_800),
        );
        let store = SqlStore::sqlite_in_memory().expect("in-memory store");
        store.migrate().expect("migrated store");
        let service = SessionService::new(
            Arc::new(store),
            config,
            Environment::Production,
            Arc::new(SystemClock),
        );
        let session = Session::new(
            service.ids.generate::<SessionEntity>().expect("id"),
            user_id(),
            None,
            SessionAudience::Account,
            SecretHash::parse("hmac-sha256:0123456789abcdef").expect("hash"),
            Timestamp::from_millis(1_000_000),
            Timestamp::from_millis(1_900_000),
            Timestamp::from_millis(2_000_000),
            None,
        )
        .expect("session");
        let cookie = service.set_cookie(
            &session,
            &SessionToken::generate(),
            Timestamp::from_millis(1_000_000),
        );
        assert!(cookie.contains("Secure"));
        assert!(cookie.starts_with(PRODUCTION_ACCOUNT_COOKIE));
    }

    #[test]
    fn production_and_development_cookie_names_differ() {
        let production = service(Environment::Production);
        let development = service(Environment::Development);
        assert_eq!(
            production.cookie_name(SessionAudience::Account),
            PRODUCTION_ACCOUNT_COOKIE
        );
        assert_eq!(
            development.cookie_name(SessionAudience::Account),
            DEVELOPMENT_ACCOUNT_COOKIE
        );
    }

    #[test]
    fn create_load_touch_and_revoke_round_trip() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let service = service(Environment::Test);
        runtime.block_on(async {
            let now = Timestamp::from_millis(1_000_000);
            let created = service
                .create(user_id(), None, SessionAudience::Account, now)
                .await
                .expect("created session");
            let loaded = service
                .load(created.token(), now)
                .await
                .expect("load")
                .expect("session");
            assert_eq!(loaded.id(), created.session().id());
            assert!(loaded.is_valid(now));

            let later = Timestamp::from_millis(1_100_000);
            let touched = service.touch(loaded, later).await.expect("touch");
            assert_eq!(touched.last_seen_at(), later);
            assert!(touched.idle_expires_at() > created.session().idle_expires_at());

            let revoked = service.revoke(touched, later).await.expect("revoke");
            assert_eq!(revoked.status(), SessionStatus::Revoked);
            let loaded = service
                .load(created.token(), later)
                .await
                .expect("load")
                .expect("session");
            assert!(!loaded.is_valid(later));
        });
    }

    #[test]
    fn touch_refreshes_when_the_idle_deadline_is_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let config = SessionConfig::new(
            vec![7_u8; 32],
            true,
            SessionLifetime::new(60, 300),
            SessionLifetime::new(60, 300),
        );
        let store = SqlStore::sqlite_in_memory().expect("in-memory store");
        store.migrate().expect("migrated store");
        let user = User::new(
            user_id(),
            Email::parse("session-test@example.com").expect("valid email"),
            DisplayName::parse("Session Test").expect("valid display name"),
            Timestamp::from_millis(0),
        );
        UserRepository::insert(&store, &user).expect("inserted user");
        let service = SessionService::new(
            Arc::new(store),
            config,
            Environment::Test,
            Arc::new(SystemClock),
        );
        runtime.block_on(async {
            let created = service
                .create(
                    user_id(),
                    None,
                    SessionAudience::Account,
                    Timestamp::from_millis(0),
                )
                .await
                .expect("created session");
            let touched = service
                .touch(created.session().clone(), Timestamp::from_millis(59_000))
                .await
                .expect("first touch");
            assert_eq!(touched.last_seen_at(), Timestamp::from_millis(59_000));
            let touched = service
                .touch(touched, Timestamp::from_millis(118_000))
                .await
                .expect("second touch");
            assert_eq!(touched.last_seen_at(), Timestamp::from_millis(118_000));
        });
    }

    #[test]
    fn rotation_replaces_the_token_and_revokes_the_old_session() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let service = service(Environment::Test);
        runtime.block_on(async {
            let now = Timestamp::from_millis(1_000_000);
            let created = service
                .create(user_id(), None, SessionAudience::Account, now)
                .await
                .expect("created session");
            let loaded = service
                .load(created.token(), now)
                .await
                .expect("load")
                .expect("session");
            let rotated = service
                .rotate(loaded, Timestamp::from_millis(1_001_000))
                .await
                .expect("rotate");
            assert_ne!(created.token().as_str(), rotated.token().as_str());
            assert_eq!(
                rotated.session().rotated_from(),
                Some(created.session().id())
            );
            let old = service
                .load(created.token(), Timestamp::from_millis(1_001_000))
                .await
                .expect("load")
                .expect("old session");
            assert_eq!(old.status(), SessionStatus::Revoked);
            let new = service
                .load(rotated.token(), Timestamp::from_millis(1_001_000))
                .await
                .expect("load")
                .expect("new session");
            assert!(new.is_valid(Timestamp::from_millis(1_001_000)));
        });
    }

    #[test]
    fn organization_ids_round_trip() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let service = service(Environment::Test);
        runtime.block_on(async {
            let org = organization_id();
            let created = service
                .create(
                    user_id(),
                    Some(org.clone()),
                    SessionAudience::Account,
                    Timestamp::from_millis(1_000_000),
                )
                .await
                .expect("created session");
            let loaded = service
                .load(created.token(), Timestamp::from_millis(1_000_000))
                .await
                .expect("load")
                .expect("session");
            assert_eq!(loaded.organization_id(), Some(&org));
        });
    }
}
