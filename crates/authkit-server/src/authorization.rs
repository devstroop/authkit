//! Authorization-code issuance, consent persistence, and redemption checks.

use std::sync::Arc;

use authkit_core::domain::audit::{
    AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget,
};
use authkit_core::domain::grant::{AuthorizationCode, Consent};
use authkit_core::domain::id::{
    AuditEventEntity, AuthorizationCodeEntity, ConsentEntity, Id, OrganizationEntity,
    SessionEntity, UserEntity,
};
use authkit_core::domain::oauth_client::OAuthClient;
use authkit_core::domain::pkce::PkceChallenge;
use authkit_core::domain::redirect_uri::RedirectUri;
use authkit_core::domain::scope::{Scope, ScopeSet};
use authkit_core::domain::tenant::TenantContext;
use authkit_core::domain::time::Timestamp;
use authkit_core::domain::{
    Application, DomainError, ErrorCode, Membership, Nonce, Organization, SecretHash,
};
use authkit_core::ports::write::{WriteBatch, WriteCommand};
use authkit_core::ports::{
    Clock, ConsentRepository, IdGenerator, MembershipRepository, OAuthClientRepository,
    OrganizationRepository, UnitOfWork,
};
use authkit_store::SqlStore;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::task;
use tracing::warn;
use zeroize::Zeroizing;

use crate::config::Issuer;
use crate::session::SecureIdGenerator;

/// Authorization-code lifetime in seconds.
pub const AUTHORIZATION_CODE_TTL_SECS: u64 = 60;

const AUTHORIZATION_CODE_BYTES: usize = 32;
const MIN_VERIFIER_LEN: usize = 43;
const MAX_VERIFIER_LEN: usize = 128;

/// A resolved OAuth client, its application, and the owning tenant.
#[derive(Clone)]
pub struct ClientContext {
    client: OAuthClient,
    application: Application,
    organization: Organization,
    tenant: TenantContext,
}

impl ClientContext {
    /// Returns the OAuth client.
    pub const fn client(&self) -> &OAuthClient {
        &self.client
    }

    /// Returns the owning application.
    pub const fn application(&self) -> &Application {
        &self.application
    }

    /// Returns the owning organization.
    pub const fn organization(&self) -> &Organization {
        &self.organization
    }

    /// Returns the tenant context.
    pub const fn tenant(&self) -> &TenantContext {
        &self.tenant
    }
}

/// The input required to issue an authorization code.
pub struct IssueCode {
    /// The resolved client context.
    pub context: ClientContext,
    /// The authenticated user.
    pub user_id: Id<UserEntity>,
    /// The browser session that authorized the code.
    pub session_id: Id<SessionEntity>,
    /// The authentication time to bind into the code.
    pub auth_time: Timestamp,
    /// The exact validated redirect URI.
    pub redirect_uri: RedirectUri,
    /// The requested scopes.
    pub scopes: ScopeSet,
    /// The OIDC nonce, when requested.
    pub nonce: Option<Nonce>,
    /// The validated S256 PKCE challenge.
    pub pkce_challenge: PkceChallenge,
    /// The request identifier used for correlation.
    pub request_id: String,
    /// How consent was established for this issuance.
    pub consent_mode: ConsentMode,
}

/// How consent was established for an authorization code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentMode {
    /// Consent was granted automatically for a first-party application.
    Automatic,
    /// The user explicitly approved the consent form.
    Explicit,
    /// An existing active consent already covered the request.
    Reuse,
}

/// The input required to redeem an authorization code.
pub struct RedeemCode {
    /// The public client identifier.
    pub client_id: authkit_core::domain::ClientId,
    /// The plaintext authorization code.
    pub code: String,
    /// The redirect URI supplied at token exchange.
    pub redirect_uri: RedirectUri,
    /// The PKCE verifier supplied at token exchange.
    pub code_verifier: String,
    /// The request identifier used for correlation.
    pub request_id: String,
}

/// A redemption failure that is safe to map to `invalid_grant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// The code, client, redirect URI, verifier, or lifecycle is invalid.
    InvalidGrant,
    /// Storage could not be reached.
    Unavailable,
}

/// A service for the authorization-code and consent protocol state.
#[derive(Clone)]
pub struct AuthorizationService {
    store: Arc<SqlStore>,
    issuer: Issuer,
    clock: Arc<dyn Clock + Send + Sync>,
    ids: SecureIdGenerator,
}

impl AuthorizationService {
    /// Creates an authorization service.
    pub fn new(store: Arc<SqlStore>, issuer: Issuer, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self {
            store,
            issuer,
            clock,
            ids: SecureIdGenerator,
        }
    }

    /// Returns the issuer used for audit correlation.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Returns the current service time.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Resolves an active client and its active application.
    pub async fn resolve_client(
        &self,
        client_id: &authkit_core::domain::ClientId,
    ) -> Result<Option<ClientContext>, DomainError> {
        let store = self.store.clone();
        let client_id = client_id.clone();
        blocking(move || {
            let Some(client) = OAuthClientRepository::find_by_client_id(&*store, &client_id)?
            else {
                return Ok(None);
            };
            if !client.is_active() {
                return Ok(None);
            }
            let Some(application) =
                store.find_application_by_id_unscoped(client.application_id())?
            else {
                return Ok(None);
            };
            if !application.is_active() {
                return Ok(None);
            }
            let Some(organization) =
                OrganizationRepository::find_by_id(&*store, application.organization_id())?
            else {
                return Ok(None);
            };
            if !organization.is_active() {
                return Ok(None);
            }
            let tenant = TenantContext::new(organization.id().clone());
            Ok(Some(ClientContext {
                client,
                application,
                organization,
                tenant,
            }))
        })
        .await
    }

    /// Finds the active membership for a user in the client's tenant.
    pub async fn membership(
        &self,
        context: &ClientContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Membership>, DomainError> {
        let store = self.store.clone();
        let tenant = context.tenant.clone();
        let user_id = user_id.clone();
        blocking(move || MembershipRepository::find_by_user(&*store, &tenant, &user_id)).await
    }

    /// Finds the user's consent for the client.
    pub async fn consent(
        &self,
        context: &ClientContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Consent>, DomainError> {
        let store = self.store.clone();
        let tenant = context.tenant.clone();
        let client_id = context.client.id().clone();
        let user_id = user_id.clone();
        blocking(move || {
            ConsentRepository::find_for_client_user(&*store, &tenant, &client_id, &user_id)
        })
        .await
    }

    /// Issues a one-time authorization code and records consent.
    pub async fn issue_code(&self, request: IssueCode) -> Result<String, DomainError> {
        if request.consent_mode == ConsentMode::Automatic
            && !request.context.application.is_first_party()
        {
            return Err(DomainError::forbidden(
                "automatic consent is limited to first-party applications",
            ));
        }
        if !request
            .context
            .client
            .allows_grant(authkit_core::domain::oauth_client::GrantType::AuthorizationCode)
        {
            return Err(DomainError::forbidden(
                "the client may not use the authorization code grant",
            ));
        }
        if !request
            .context
            .client
            .redirect_uris()
            .iter()
            .any(|registered| registered.matches(&request.redirect_uri))
        {
            return Err(DomainError::invalid(
                "the authorization redirect URI is not registered",
            ));
        }
        if request.scopes.as_slice().is_empty()
            || !request
                .scopes
                .as_slice()
                .iter()
                .all(|scope| request.context.client.allowed_scopes().contains(scope))
        {
            return Err(DomainError::invalid(
                "the requested scopes are not allowed for this client",
            ));
        }
        let now = self.clock.now();
        let auth_time = request.auth_time.min(now);
        let token = AuthorizationCodeToken::generate();
        let code_hash = token.digest()?;
        let code_id = self.ids.generate::<AuthorizationCodeEntity>()?;
        let expires_at = Timestamp::from_millis(
            now.as_millis()
                .saturating_add(AUTHORIZATION_CODE_TTL_SECS.saturating_mul(1_000)),
        );
        let code = AuthorizationCode::new(
            code_id.clone(),
            request.context.tenant.organization_id().clone(),
            request.context.application.id().clone(),
            request.context.client.id().clone(),
            request.user_id.clone(),
            code_hash,
            request.redirect_uri,
            request.scopes.clone(),
            request.pkce_challenge,
            request.nonce,
            auth_time,
            Some(request.session_id),
            now,
            expires_at,
        )?;

        let store = self.store.clone();
        let tenant = request.context.tenant.clone();
        let organization_id = tenant.organization_id().clone();
        let client_row_id = request.context.client.id().clone();
        let client_public_id = request.context.client.client_id().as_str().to_owned();
        let user_id = request.user_id.clone();
        let request_id = truncate(&request.request_id, 128);
        let scopes = code.scopes().clone();
        let code_id_for_audit = code.id().clone();
        let consent_mode = request.consent_mode;
        let consent_id = self.ids.generate::<ConsentEntity>()?;
        let consent_audit_id = self.ids.generate::<AuditEventEntity>()?;
        let code_audit_id = self.ids.generate::<AuditEventEntity>()?;
        let code_event = AuditEvent::new(
            code_audit_id,
            Some(organization_id.clone()),
            AuditActor::User(user_id.clone()),
            AuditAction::parse("authorization.code.issue")?,
            Some(AuditTarget::parse(code_id_for_audit.as_str())?),
            now,
            vec![
                AuditAttribute::new("client_id", client_public_id.clone())?,
                AuditAttribute::new("request_id", request_id.clone())?,
            ],
        )?;

        blocking(move || {
            let membership = MembershipRepository::find_by_user(&*store, &tenant, &user_id)?;
            if !membership.is_some_and(|membership| membership.is_active()) {
                return Err(DomainError::forbidden(
                    "the user is not an active member of the organization",
                ));
            }
            let existing = ConsentRepository::find_for_client_user(
                &*store,
                &tenant,
                &client_row_id,
                &user_id,
            )?;
            let mut batch = WriteBatch::new();

            match existing {
                Some(consent)
                    if consent.is_active()
                        && consent.covers(&scopes)
                        && !matches!(consent_mode, ConsentMode::Explicit) => {}
                Some(_) if consent_mode == ConsentMode::Reuse => {
                    return Err(DomainError::invalid(
                        "consent reuse requires an active grant covering the request",
                    ));
                }
                Some(mut consent) => {
                    let updated_scopes = if consent.is_active() {
                        merge_scopes(consent.scopes(), &scopes)
                    } else {
                        scopes.clone()
                    };
                    let expected_version = consent.version();
                    consent.grant(updated_scopes, now);
                    let event = AuditEvent::new(
                        consent_audit_id,
                        Some(organization_id.clone()),
                        AuditActor::User(user_id.clone()),
                        AuditAction::parse("authorization.consent.grant")?,
                        Some(AuditTarget::parse(consent.id().as_str())?),
                        now,
                        vec![
                            AuditAttribute::new("client_id", client_public_id.clone())?,
                            AuditAttribute::new("request_id", request_id.clone())?,
                            AuditAttribute::new("consent", consent_mode.as_str())?,
                        ],
                    )?;
                    batch = batch
                        .with(WriteCommand::UpdateConsent {
                            tenant: tenant.clone(),
                            consent,
                            expected_version,
                        })
                        .with(WriteCommand::AppendAudit {
                            tenant: tenant.clone(),
                            event,
                        });
                }
                None if consent_mode == ConsentMode::Reuse => {
                    return Err(DomainError::invalid(
                        "consent reuse requires an existing consent",
                    ));
                }
                None => {
                    let consent = Consent::new(
                        consent_id,
                        organization_id.clone(),
                        user_id.clone(),
                        client_row_id,
                        scopes.clone(),
                        now,
                    );
                    let event = AuditEvent::new(
                        consent_audit_id,
                        Some(organization_id.clone()),
                        AuditActor::User(user_id.clone()),
                        AuditAction::parse("authorization.consent.grant")?,
                        Some(AuditTarget::parse(consent.id().as_str())?),
                        now,
                        vec![
                            AuditAttribute::new("client_id", client_public_id.clone())?,
                            AuditAttribute::new("request_id", request_id.clone())?,
                            AuditAttribute::new("consent", consent_mode.as_str())?,
                        ],
                    )?;
                    batch = batch
                        .with(WriteCommand::InsertConsent {
                            tenant: tenant.clone(),
                            consent,
                        })
                        .with(WriteCommand::AppendAudit {
                            tenant: tenant.clone(),
                            event,
                        });
                }
            }

            batch = batch
                .with(WriteCommand::InsertAuthorizationCode {
                    tenant: tenant.clone(),
                    code,
                })
                .with(WriteCommand::AppendAudit {
                    tenant,
                    event: code_event,
                });

            let outcome = store.commit(&batch)?;
            if !outcome.is_applied() {
                return Err(DomainError::conflict(
                    "authorization code issuance lost a concurrency race",
                ));
            }
            Ok(())
        })
        .await?;

        Ok(token.expose())
    }

    /// Records an explicit consent denial.
    pub async fn record_denial(
        &self,
        context: &ClientContext,
        user_id: &Id<UserEntity>,
        request_id: &str,
    ) -> Result<(), DomainError> {
        let event = self.event(
            Some(context.tenant.organization_id().clone()),
            AuditActor::User(user_id.clone()),
            "authorization.consent.deny",
            Some(context.client.id().as_str()),
            request_id,
        )?;
        self.append_security_event(event).await
    }

    /// Records a rejected authorization request.
    pub async fn record_rejection(
        &self,
        tenant: Option<Id<OrganizationEntity>>,
        actor: AuditActor,
        target: Option<&str>,
        request_id: &str,
        reason: &'static str,
    ) -> Result<(), DomainError> {
        let event = AuditEvent::new(
            self.ids.generate::<AuditEventEntity>()?,
            tenant,
            actor,
            AuditAction::parse("authorization.request.reject")?,
            target.map(AuditTarget::parse).transpose()?,
            self.clock.now(),
            vec![
                AuditAttribute::new("request_id", truncate(request_id, 128))?,
                AuditAttribute::new("reason", reason)?,
            ],
        )?;
        self.append_security_event(event).await
    }

    /// Redemptions validate the code binding, consume it, and audit failures.
    pub async fn redeem_code(&self, request: RedeemCode) -> Result<AuthorizationCode, RedeemError> {
        let Some(context) = self
            .resolve_client(&request.client_id)
            .await
            .map_err(|_| RedeemError::Unavailable)?
        else {
            self.reject(None, None, &request, "unknown_client").await;
            return Err(RedeemError::InvalidGrant);
        };

        let token = AuthorizationCodeToken::from_existing(&request.code);
        let hash = token.digest().map_err(|_| RedeemError::Unavailable)?;
        let store = self.store.clone();
        let tenant = context.tenant.clone();
        let found = blocking(move || {
            authkit_core::ports::AuthorizationCodeRepository::find_by_hash(&*store, &tenant, &hash)
        })
        .await
        .map_err(|_| RedeemError::Unavailable)?;

        let Some(code) = found else {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "code_not_found",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        };

        if code.client_id() != context.client.id() {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "wrong_client",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }
        if code.redirect_uri() != &request.redirect_uri {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "wrong_redirect_uri",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }
        let now = self.clock.now();
        if code.consumed_at().is_some() {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "code_replay",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }
        if !code.is_usable(now) {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "code_expired",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }
        if !verifier_matches(code.pkce_challenge(), &request.code_verifier) {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "pkce_mismatch",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }

        let expected_version = code.version();
        let mut consumed = code;
        consumed
            .consume(now)
            .map_err(|_| RedeemError::InvalidGrant)?;
        let audit = AuditEvent::new(
            self.ids
                .generate::<AuditEventEntity>()
                .map_err(|_| RedeemError::Unavailable)?,
            Some(context.tenant.organization_id().clone()),
            AuditActor::User(consumed.user_id().clone()),
            AuditAction::parse("authorization.code.consume")
                .map_err(|_| RedeemError::Unavailable)?,
            Some(AuditTarget::parse(consumed.id().as_str()).map_err(|_| RedeemError::Unavailable)?),
            now,
            vec![
                AuditAttribute::new("request_id", truncate(&request.request_id, 128))
                    .map_err(|_| RedeemError::Unavailable)?,
            ],
        )
        .map_err(|_| RedeemError::Unavailable)?;
        let store = self.store.clone();
        let tenant = context.tenant.clone();
        let to_update = consumed.clone();
        let outcome = blocking(move || {
            store.commit(
                &WriteBatch::new()
                    .with(WriteCommand::UpdateAuthorizationCode {
                        tenant: tenant.clone(),
                        code: to_update,
                        expected_version,
                    })
                    .with(WriteCommand::AppendAudit {
                        tenant,
                        event: audit,
                    }),
            )
        })
        .await
        .map_err(|_| RedeemError::Unavailable)?;
        if !outcome.is_applied() {
            self.reject(
                Some(context.tenant.organization_id().clone()),
                Some(&context),
                &request,
                "code_replay",
            )
            .await;
            return Err(RedeemError::InvalidGrant);
        }
        Ok(consumed)
    }

    fn event(
        &self,
        tenant: Option<Id<OrganizationEntity>>,
        actor: AuditActor,
        action: &str,
        target: Option<&str>,
        request_id: &str,
    ) -> Result<AuditEvent, DomainError> {
        AuditEvent::new(
            self.ids.generate::<AuditEventEntity>()?,
            tenant,
            actor,
            AuditAction::parse(action)?,
            target.map(AuditTarget::parse).transpose()?,
            self.clock.now(),
            vec![AuditAttribute::new(
                "request_id",
                truncate(request_id, 128),
            )?],
        )
    }

    async fn append_security_event(&self, event: AuditEvent) -> Result<(), DomainError> {
        let store = self.store.clone();
        blocking(move || store.append_security_audit(&event)).await?;
        Ok(())
    }

    async fn reject(
        &self,
        tenant: Option<Id<OrganizationEntity>>,
        context: Option<&ClientContext>,
        request: &RedeemCode,
        reason: &'static str,
    ) {
        let target = context
            .map(|context| context.client.id().as_str())
            .or_else(|| Some(request.client_id.as_str()));
        let actor = AuditActor::Anonymous;
        if let Err(error) = self
            .record_rejection(tenant, actor, target, &request.request_id, reason)
            .await
        {
            warn!(
                event = "authorization.audit_failed",
                request_id = %request.request_id,
                error = %error,
                "could not append authorization rejection audit event"
            );
        }
    }
}

/// A random, opaque authorization code.
struct AuthorizationCodeToken(Zeroizing<String>);

impl AuthorizationCodeToken {
    fn generate() -> Self {
        let mut bytes = [0_u8; AUTHORIZATION_CODE_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes)))
    }

    fn from_existing(value: &str) -> Self {
        Self(Zeroizing::new(value.to_owned()))
    }

    fn digest(&self) -> Result<SecretHash, DomainError> {
        let digest = Sha256::digest(self.0.as_bytes());
        SecretHash::parse(format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))).map_err(|_| {
            DomainError::new(ErrorCode::Internal, "authorization code hash is invalid")
        })
    }

    fn expose(self) -> String {
        self.0.to_string()
    }
}

fn verifier_matches(challenge: &PkceChallenge, verifier: &str) -> bool {
    if !(MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&verifier.len()) {
        return false;
    }
    if !verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == challenge.as_str()
}

fn merge_scopes(existing: &ScopeSet, requested: &ScopeSet) -> ScopeSet {
    let mut scopes: Vec<Scope> = existing.as_slice().to_vec();
    for scope in requested.as_slice() {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    ScopeSet::new(scopes)
}

impl ConsentMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Explicit => "explicit",
            Self::Reuse => "reuse",
        }
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

async fn blocking<T>(
    operation: impl FnOnce() -> Result<T, DomainError> + Send + 'static,
) -> Result<T, DomainError>
where
    T: Send + 'static,
{
    task::spawn_blocking(operation).await.map_err(|_| {
        DomainError::new(ErrorCode::Unavailable, "authorization storage task failed")
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_matches_s256_challenge() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = PkceChallenge::parse(URL_SAFE_NO_PAD.encode(digest)).expect("challenge");
        assert!(verifier_matches(&challenge, verifier));
        assert!(!verifier_matches(&challenge, &format!("{verifier}x")));
        assert!(!verifier_matches(&challenge, "short"));
    }

    #[test]
    fn merge_scopes_preserves_order_and_deduplicates() {
        let existing = ScopeSet::new([
            Scope::parse("openid").expect("scope"),
            Scope::parse("profile").expect("scope"),
        ]);
        let requested = ScopeSet::new([
            Scope::parse("profile").expect("scope"),
            Scope::parse("email").expect("scope"),
        ]);
        let merged = merge_scopes(&existing, &requested);
        assert_eq!(merged.as_slice().len(), 3);
        assert!(merged.contains(&Scope::parse("email").expect("scope")));
    }
}
