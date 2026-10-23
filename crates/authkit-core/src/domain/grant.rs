use crate::domain::DomainError;
use crate::domain::id::{
    ApplicationEntity, AuthorizationCodeEntity, ConsentEntity, Id, OAuthClientEntity,
    OrganizationEntity, RefreshFamilyEntity, RefreshTokenEntity, SessionEntity, UserEntity,
};
use crate::domain::pkce::{Nonce, PkceChallenge};
use crate::domain::redirect_uri::RedirectUri;
use crate::domain::scope::ScopeSet;
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

/// A one-time authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    id: Id<AuthorizationCodeEntity>,
    organization_id: Id<OrganizationEntity>,
    application_id: Id<ApplicationEntity>,
    client_id: Id<OAuthClientEntity>,
    user_id: Id<UserEntity>,
    code_hash: SecretHash,
    redirect_uri: RedirectUri,
    scopes: ScopeSet,
    pkce_challenge: PkceChallenge,
    nonce: Option<Nonce>,
    auth_time: Timestamp,
    session_id: Option<Id<SessionEntity>>,
    created_at: Timestamp,
    expires_at: Timestamp,
    consumed_at: Option<Timestamp>,
    version: u64,
}

impl AuthorizationCode {
    /// Creates a single-use authorization code.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<AuthorizationCodeEntity>,
        organization_id: Id<OrganizationEntity>,
        application_id: Id<ApplicationEntity>,
        client_id: Id<OAuthClientEntity>,
        user_id: Id<UserEntity>,
        code_hash: SecretHash,
        redirect_uri: RedirectUri,
        scopes: ScopeSet,
        pkce_challenge: PkceChallenge,
        nonce: Option<Nonce>,
        auth_time: Timestamp,
        session_id: Option<Id<SessionEntity>>,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if !now.is_before(expires_at) {
            return Err(DomainError::invalid(
                "authorization code expiry must be after creation",
            ));
        }
        if auth_time > now {
            return Err(DomainError::invalid(
                "authorization code auth_time must not be after creation",
            ));
        }

        Ok(Self {
            id,
            organization_id,
            application_id,
            client_id,
            user_id,
            code_hash,
            redirect_uri,
            scopes,
            pkce_challenge,
            nonce,
            auth_time,
            session_id,
            created_at: now,
            expires_at,
            consumed_at: None,
            version: 0,
        })
    }

    /// Reconstructs an authorization code from persisted state.
    ///
    /// Storage adapters use this; normal callers create codes through
    /// [`AuthorizationCode::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<AuthorizationCodeEntity>,
        organization_id: Id<OrganizationEntity>,
        application_id: Id<ApplicationEntity>,
        client_id: Id<OAuthClientEntity>,
        user_id: Id<UserEntity>,
        code_hash: SecretHash,
        redirect_uri: RedirectUri,
        scopes: ScopeSet,
        pkce_challenge: PkceChallenge,
        nonce: Option<Nonce>,
        auth_time: Timestamp,
        session_id: Option<Id<SessionEntity>>,
        created_at: Timestamp,
        expires_at: Timestamp,
        consumed_at: Option<Timestamp>,
        version: u64,
    ) -> Result<Self, DomainError> {
        let mut code = Self::new(
            id,
            organization_id,
            application_id,
            client_id,
            user_id,
            code_hash,
            redirect_uri,
            scopes,
            pkce_challenge,
            nonce,
            auth_time,
            session_id,
            created_at,
            expires_at,
        )?;
        if let Some(consumed_at) = consumed_at {
            if consumed_at < created_at || !consumed_at.is_before(expires_at) {
                return Err(DomainError::invalid(
                    "authorization code consumption is outside the code lifetime",
                ));
            }
            code.consumed_at = Some(consumed_at);
        }
        code.version = version;
        Ok(code)
    }

    /// Returns the code identifier.
    pub const fn id(&self) -> &Id<AuthorizationCodeEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the application.
    pub const fn application_id(&self) -> &Id<ApplicationEntity> {
        &self.application_id
    }

    /// Returns the client that requested the code.
    pub const fn client_id(&self) -> &Id<OAuthClientEntity> {
        &self.client_id
    }

    /// Returns the authenticated user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the encoded code verifier. Callers must not log this value.
    pub const fn code_hash(&self) -> &SecretHash {
        &self.code_hash
    }

    /// Returns the redirect URI bound to the code.
    pub const fn redirect_uri(&self) -> &RedirectUri {
        &self.redirect_uri
    }

    /// Returns the granted scopes.
    pub const fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }

    /// Returns the PKCE challenge.
    pub const fn pkce_challenge(&self) -> &PkceChallenge {
        &self.pkce_challenge
    }

    /// Returns the OIDC nonce, if supplied.
    pub const fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }

    /// Returns the authentication time bound to the code.
    pub const fn auth_time(&self) -> Timestamp {
        self.auth_time
    }

    /// Returns the browser session that authorized the code, when known.
    pub const fn session_id(&self) -> Option<&Id<SessionEntity>> {
        self.session_id.as_ref()
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns the consumption time, if used.
    pub const fn consumed_at(&self) -> Option<Timestamp> {
        self.consumed_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the code is unused and not expired.
    pub fn is_usable(&self, now: Timestamp) -> bool {
        self.consumed_at.is_none() && now.is_before(self.expires_at)
    }

    /// Consumes the code exactly once.
    pub fn consume(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.consumed_at.is_some() {
            return Err(DomainError::conflict(
                "authorization code has already been used",
            ));
        }
        if !now.is_before(self.expires_at) {
            return Err(DomainError::conflict("authorization code has expired"));
        }
        self.consumed_at = Some(now);
        self.version = self.version.saturating_add(1);
        Ok(())
    }
}

/// A user's consent to an OAuth client and scope set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    id: Id<ConsentEntity>,
    organization_id: Id<OrganizationEntity>,
    user_id: Id<UserEntity>,
    client_id: Id<OAuthClientEntity>,
    scopes: ScopeSet,
    created_at: Timestamp,
    updated_at: Timestamp,
    revoked_at: Option<Timestamp>,
    version: u64,
}

impl Consent {
    /// Creates an active consent.
    pub fn new(
        id: Id<ConsentEntity>,
        organization_id: Id<OrganizationEntity>,
        user_id: Id<UserEntity>,
        client_id: Id<OAuthClientEntity>,
        scopes: ScopeSet,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            user_id,
            client_id,
            scopes,
            created_at: now,
            updated_at: now,
            revoked_at: None,
            version: 0,
        }
    }

    /// Reconstructs a consent from persisted state.
    ///
    /// Storage adapters use this; normal callers create consent through
    /// [`Consent::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<ConsentEntity>,
        organization_id: Id<OrganizationEntity>,
        user_id: Id<UserEntity>,
        client_id: Id<OAuthClientEntity>,
        scopes: ScopeSet,
        created_at: Timestamp,
        updated_at: Timestamp,
        revoked_at: Option<Timestamp>,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "consent updated_at must not precede created_at",
            ));
        }
        if let Some(revoked_at) = revoked_at
            && (revoked_at < created_at || revoked_at > updated_at)
        {
            return Err(DomainError::invalid(
                "consent revoked_at is outside the consent lifetime",
            ));
        }

        Ok(Self {
            id,
            organization_id,
            user_id,
            client_id,
            scopes,
            created_at,
            updated_at,
            revoked_at,
            version,
        })
    }

    /// Returns the consent identifier.
    pub const fn id(&self) -> &Id<ConsentEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the consenting user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the client.
    pub const fn client_id(&self) -> &Id<OAuthClientEntity> {
        &self.client_id
    }

    /// Returns the consented scopes.
    pub const fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the last mutation time.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Returns the revocation time, if revoked.
    pub const fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the consent is active.
    pub const fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Returns `true` when every requested scope is covered.
    pub fn covers(&self, requested: &ScopeSet) -> bool {
        requested
            .as_slice()
            .iter()
            .all(|scope| self.scopes.contains(scope))
    }

    /// Replaces the consented scopes.
    pub fn replace_scopes(&mut self, scopes: ScopeSet, now: Timestamp) {
        self.scopes = scopes;
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }

    /// Grants an updated scope set, reactivating a previously revoked consent.
    pub fn grant(&mut self, scopes: ScopeSet, now: Timestamp) {
        self.scopes = scopes;
        self.revoked_at = None;
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }

    /// Revokes the consent. Repeated calls are idempotent.
    pub fn revoke(&mut self, now: Timestamp) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(now);
            self.updated_at = now;
            self.version = self.version.saturating_add(1);
        }
    }
}

/// A refresh-token family bounded by an absolute lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamily {
    id: Id<RefreshFamilyEntity>,
    organization_id: Id<OrganizationEntity>,
    client_id: Id<OAuthClientEntity>,
    user_id: Id<UserEntity>,
    created_at: Timestamp,
    absolute_expires_at: Timestamp,
    revoked_at: Option<Timestamp>,
    version: u64,
}

impl RefreshFamily {
    /// Creates an active refresh family.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<RefreshFamilyEntity>,
        organization_id: Id<OrganizationEntity>,
        client_id: Id<OAuthClientEntity>,
        user_id: Id<UserEntity>,
        now: Timestamp,
        absolute_expires_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if !now.is_before(absolute_expires_at) {
            return Err(DomainError::invalid(
                "refresh family expiry must be after creation",
            ));
        }

        Ok(Self {
            id,
            organization_id,
            client_id,
            user_id,
            created_at: now,
            absolute_expires_at,
            revoked_at: None,
            version: 0,
        })
    }

    /// Reconstructs a refresh family from persisted state.
    ///
    /// Storage adapters use this; normal callers create families through
    /// [`RefreshFamily::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<RefreshFamilyEntity>,
        organization_id: Id<OrganizationEntity>,
        client_id: Id<OAuthClientEntity>,
        user_id: Id<UserEntity>,
        created_at: Timestamp,
        absolute_expires_at: Timestamp,
        revoked_at: Option<Timestamp>,
        version: u64,
    ) -> Result<Self, DomainError> {
        let mut family = Self::new(
            id,
            organization_id,
            client_id,
            user_id,
            created_at,
            absolute_expires_at,
        )?;
        if let Some(revoked_at) = revoked_at {
            if revoked_at < created_at {
                return Err(DomainError::invalid(
                    "refresh family revoked_at must not precede creation",
                ));
            }
            family.revoked_at = Some(revoked_at);
        }
        family.version = version;
        Ok(family)
    }

    /// Returns the family identifier.
    pub const fn id(&self) -> &Id<RefreshFamilyEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the client.
    pub const fn client_id(&self) -> &Id<OAuthClientEntity> {
        &self.client_id
    }

    /// Returns the user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the absolute expiry.
    pub const fn absolute_expires_at(&self) -> Timestamp {
        self.absolute_expires_at
    }

    /// Returns the revocation time, if revoked.
    pub const fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the family is active and not expired.
    pub fn is_active(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && now.is_before(self.absolute_expires_at)
    }

    /// Revokes the family. Repeated calls are idempotent.
    pub fn revoke(&mut self, now: Timestamp) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(now);
            self.version = self.version.saturating_add(1);
        }
    }
}

/// A rotating refresh token within a family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    id: Id<RefreshTokenEntity>,
    family_id: Id<RefreshFamilyEntity>,
    token_hash: SecretHash,
    created_at: Timestamp,
    expires_at: Timestamp,
    consumed_at: Option<Timestamp>,
    version: u64,
}

impl RefreshToken {
    /// Creates an unused refresh token.
    pub fn new(
        id: Id<RefreshTokenEntity>,
        family_id: Id<RefreshFamilyEntity>,
        token_hash: SecretHash,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if !now.is_before(expires_at) {
            return Err(DomainError::invalid(
                "refresh token expiry must be after creation",
            ));
        }

        Ok(Self {
            id,
            family_id,
            token_hash,
            created_at: now,
            expires_at,
            consumed_at: None,
            version: 0,
        })
    }

    /// Reconstructs a refresh token from persisted state.
    ///
    /// Storage adapters use this; normal callers create tokens through
    /// [`RefreshToken::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<RefreshTokenEntity>,
        family_id: Id<RefreshFamilyEntity>,
        token_hash: SecretHash,
        created_at: Timestamp,
        expires_at: Timestamp,
        consumed_at: Option<Timestamp>,
        version: u64,
    ) -> Result<Self, DomainError> {
        let mut token = Self::new(id, family_id, token_hash, created_at, expires_at)?;
        if let Some(consumed_at) = consumed_at {
            if consumed_at < created_at || !consumed_at.is_before(expires_at) {
                return Err(DomainError::invalid(
                    "refresh token consumption is outside the token lifetime",
                ));
            }
            token.consumed_at = Some(consumed_at);
        }
        token.version = version;
        Ok(token)
    }

    /// Returns the token identifier.
    pub const fn id(&self) -> &Id<RefreshTokenEntity> {
        &self.id
    }

    /// Returns the family.
    pub const fn family_id(&self) -> &Id<RefreshFamilyEntity> {
        &self.family_id
    }

    /// Returns the encoded token verifier. Callers must not log this value.
    pub const fn token_hash(&self) -> &SecretHash {
        &self.token_hash
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns the consumption time, if used.
    pub const fn consumed_at(&self) -> Option<Timestamp> {
        self.consumed_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the token is unused and not expired.
    pub fn is_usable(&self, now: Timestamp) -> bool {
        self.consumed_at.is_none() && now.is_before(self.expires_at)
    }

    /// Consumes the token exactly once.
    pub fn consume(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.consumed_at.is_some() {
            return Err(DomainError::conflict("refresh token has already been used"));
        }
        if !now.is_before(self.expires_at) {
            return Err(DomainError::conflict("refresh token has expired"));
        }
        self.consumed_at = Some(now);
        self.version = self.version.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::scope::Scope;

    fn organization_id() -> Id<OrganizationEntity> {
        Id::<OrganizationEntity>::from_suffix("0123456789abcdef").expect("valid id")
    }

    fn application_id() -> Id<ApplicationEntity> {
        Id::<ApplicationEntity>::from_suffix("fedcba9876543210").expect("valid id")
    }

    fn client_id() -> Id<OAuthClientEntity> {
        Id::<OAuthClientEntity>::from_suffix("0011223344556677").expect("valid id")
    }

    fn user_id() -> Id<UserEntity> {
        Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id")
    }

    fn secret() -> SecretHash {
        SecretHash::parse("sha256:0123456789abcdef").expect("valid hash")
    }

    fn scopes() -> ScopeSet {
        ScopeSet::new([
            Scope::parse("openid").expect("valid"),
            Scope::parse("profile").expect("valid"),
        ])
    }

    fn code() -> AuthorizationCode {
        AuthorizationCode::new(
            Id::<AuthorizationCodeEntity>::from_suffix("1122334455667788").expect("valid id"),
            organization_id(),
            application_id(),
            client_id(),
            user_id(),
            secret(),
            RedirectUri::parse("https://app.example.com/callback").expect("valid uri"),
            scopes(),
            PkceChallenge::parse("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
                .expect("valid challenge"),
            Some(Nonce::parse("nonce").expect("valid nonce")),
            Timestamp::from_millis(900),
            None,
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(2_000),
        )
        .expect("valid code")
    }

    #[test]
    fn authorization_codes_are_single_use() {
        let mut code = code();
        assert!(code.is_usable(Timestamp::from_millis(1_500)));
        code.consume(Timestamp::from_millis(1_500))
            .expect("first use");
        assert!(!code.is_usable(Timestamp::from_millis(1_600)));
        assert!(code.consume(Timestamp::from_millis(1_600)).is_err());
    }

    #[test]
    fn expired_codes_cannot_be_consumed() {
        let mut code = code();
        assert!(code.consume(Timestamp::from_millis(2_000)).is_err());
    }

    #[test]
    fn consent_covers_only_granted_scopes() {
        let consent = Consent::new(
            Id::<ConsentEntity>::from_suffix("2233445566778899").expect("valid id"),
            organization_id(),
            user_id(),
            client_id(),
            ScopeSet::new([Scope::parse("openid").expect("valid")]),
            Timestamp::from_millis(1_000),
        );
        assert!(consent.covers(&ScopeSet::new([Scope::parse("openid").expect("valid")])));
        assert!(!consent.covers(&scopes()));
    }

    #[test]
    fn consent_grant_reactivates_and_replaces_scopes() {
        let mut consent = Consent::new(
            Id::<ConsentEntity>::from_suffix("2233445566778899").expect("valid id"),
            organization_id(),
            user_id(),
            client_id(),
            ScopeSet::new([Scope::parse("openid").expect("valid")]),
            Timestamp::from_millis(1_000),
        );
        consent.revoke(Timestamp::from_millis(2_000));
        assert!(!consent.is_active());
        consent.grant(
            ScopeSet::new([
                Scope::parse("openid").expect("valid"),
                Scope::parse("profile").expect("valid"),
            ]),
            Timestamp::from_millis(3_000),
        );
        assert!(consent.is_active());
        assert_eq!(consent.revoked_at(), None);
        assert_eq!(consent.updated_at(), Timestamp::from_millis(3_000));
        assert!(consent.covers(&ScopeSet::new([
            Scope::parse("openid").expect("valid"),
            Scope::parse("profile").expect("valid"),
        ])));
    }

    #[test]
    fn refresh_families_revoke_idempotently() {
        let mut family = RefreshFamily::new(
            Id::<RefreshFamilyEntity>::from_suffix("33445566778899aa").expect("valid id"),
            organization_id(),
            client_id(),
            user_id(),
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(10_000),
        )
        .expect("valid family");
        assert!(family.is_active(Timestamp::from_millis(2_000)));
        family.revoke(Timestamp::from_millis(2_000));
        family.revoke(Timestamp::from_millis(3_000));
        assert!(!family.is_active(Timestamp::from_millis(4_000)));
        assert_eq!(family.version(), 1);
    }

    #[test]
    fn refresh_tokens_are_single_use() {
        let mut token = RefreshToken::new(
            Id::<RefreshTokenEntity>::from_suffix("445566778899aabb").expect("valid id"),
            Id::<RefreshFamilyEntity>::from_suffix("33445566778899aa").expect("valid id"),
            secret(),
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(2_000),
        )
        .expect("valid token");
        token
            .consume(Timestamp::from_millis(1_500))
            .expect("first use");
        assert!(token.consume(Timestamp::from_millis(1_600)).is_err());
    }
}
