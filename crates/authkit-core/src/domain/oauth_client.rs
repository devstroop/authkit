use crate::domain::DomainError;
use crate::domain::client_id::ClientId;
use crate::domain::id::{ApplicationEntity, Id, OAuthClientEntity};
use crate::domain::name::DisplayName;
use crate::domain::redirect_uri::RedirectUri;
use crate::domain::scope::{Scope, ScopeSet};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

/// How a client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic with the client ID and secret.
    ClientSecretBasic,
    /// Client credentials in the request body.
    ClientSecretPost,
    /// No client authentication; only valid for public clients.
    None,
}

/// The OAuth client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    /// A client that can keep a secret, such as a BFF or service.
    Confidential,
    /// A client that cannot keep a secret, such as a native or CLI app.
    Public,
}

/// A supported OAuth grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantType {
    /// Authorization code with PKCE.
    AuthorizationCode,
    /// Rotating refresh tokens.
    RefreshToken,
    /// Service-to-service client credentials.
    ClientCredentials,
}

/// The lifecycle state of an OAuth client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    /// The client may authorize and exchange tokens.
    Active,
    /// The client is blocked from new authorizations and token exchanges.
    Disabled,
}

/// The values required to register an OAuth client.
#[derive(Debug, Clone)]
pub struct OAuthClientSpec {
    /// The owning application.
    pub application_id: Id<ApplicationEntity>,
    /// The public client identifier.
    pub client_id: ClientId,
    /// The human-readable client name.
    pub name: DisplayName,
    /// Confidential or public.
    pub client_type: ClientType,
    /// Token-endpoint authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Encoded client-secret verifier for confidential clients.
    pub secret_hash: Option<SecretHash>,
    /// Whether PKCE is mandatory.
    pub require_pkce: bool,
    /// Exact registered redirect URIs.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact registered post-logout redirect URIs.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// Scopes the client may request.
    pub allowed_scopes: ScopeSet,
    /// Grants the client may use.
    pub allowed_grant_types: Vec<GrantType>,
}

/// An OAuth client registered under an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    id: Id<OAuthClientEntity>,
    application_id: Id<ApplicationEntity>,
    client_id: ClientId,
    name: DisplayName,
    client_type: ClientType,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    secret_hash: Option<SecretHash>,
    require_pkce: bool,
    redirect_uris: Vec<RedirectUri>,
    post_logout_redirect_uris: Vec<RedirectUri>,
    allowed_scopes: ScopeSet,
    allowed_grant_types: Vec<GrantType>,
    status: ClientStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl OAuthClient {
    /// Registers a client after validating the type, secret, redirect, and grant rules.
    pub fn new(
        id: Id<OAuthClientEntity>,
        spec: OAuthClientSpec,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        ensure_unique(&spec.redirect_uris, "redirect URIs")?;
        ensure_unique(&spec.post_logout_redirect_uris, "post-logout redirect URIs")?;
        ensure_unique(&spec.allowed_grant_types, "grant types")?;

        if spec.allowed_grant_types.is_empty() {
            return Err(DomainError::invalid(
                "a client must allow at least one grant type",
            ));
        }
        if spec
            .allowed_grant_types
            .contains(&GrantType::AuthorizationCode)
            && spec.redirect_uris.is_empty()
        {
            return Err(DomainError::invalid(
                "a client using the authorization code grant must register a redirect URI",
            ));
        }
        if spec.allowed_grant_types.contains(&GrantType::RefreshToken)
            && !spec
                .allowed_grant_types
                .contains(&GrantType::AuthorizationCode)
        {
            return Err(DomainError::invalid(
                "a client using refresh tokens must also allow the authorization code grant",
            ));
        }
        if spec
            .allowed_grant_types
            .contains(&GrantType::ClientCredentials)
            && spec.client_type != ClientType::Confidential
        {
            return Err(DomainError::invalid(
                "the client credentials grant requires a confidential client",
            ));
        }

        if spec
            .allowed_grant_types
            .contains(&GrantType::AuthorizationCode)
            && !spec.require_pkce
        {
            return Err(DomainError::invalid(
                "every authorization-code client must require PKCE",
            ));
        }

        match spec.client_type {
            ClientType::Public => {
                if spec.token_endpoint_auth_method != TokenEndpointAuthMethod::None {
                    return Err(DomainError::invalid(
                        "a public client must not use token-endpoint authentication",
                    ));
                }
                if spec.secret_hash.is_some() {
                    return Err(DomainError::invalid(
                        "a public client must not have a client secret",
                    ));
                }
            }
            ClientType::Confidential => {
                if spec.token_endpoint_auth_method == TokenEndpointAuthMethod::None {
                    return Err(DomainError::invalid(
                        "a confidential client must use a token-endpoint authentication method",
                    ));
                }
                if spec.secret_hash.is_none() {
                    return Err(DomainError::invalid(
                        "a confidential client must have a client secret",
                    ));
                }
            }
        }

        Ok(Self {
            id,
            application_id: spec.application_id,
            client_id: spec.client_id,
            name: spec.name,
            client_type: spec.client_type,
            token_endpoint_auth_method: spec.token_endpoint_auth_method,
            secret_hash: spec.secret_hash,
            require_pkce: spec.require_pkce,
            redirect_uris: spec.redirect_uris,
            post_logout_redirect_uris: spec.post_logout_redirect_uris,
            allowed_scopes: spec.allowed_scopes,
            allowed_grant_types: spec.allowed_grant_types,
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
            version: 0,
        })
    }

    /// Reconstructs an OAuth client from persisted state.
    ///
    /// Storage adapters use this; normal callers register clients through
    /// [`OAuthClient::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<OAuthClientEntity>,
        application_id: Id<ApplicationEntity>,
        client_id: ClientId,
        name: DisplayName,
        client_type: ClientType,
        token_endpoint_auth_method: TokenEndpointAuthMethod,
        secret_hash: Option<SecretHash>,
        require_pkce: bool,
        redirect_uris: Vec<RedirectUri>,
        post_logout_redirect_uris: Vec<RedirectUri>,
        allowed_scopes: ScopeSet,
        allowed_grant_types: Vec<GrantType>,
        status: ClientStatus,
        created_at: Timestamp,
        updated_at: Timestamp,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "OAuth client updated_at must not precede created_at",
            ));
        }
        let mut client = Self::new(
            id,
            OAuthClientSpec {
                application_id,
                client_id,
                name,
                client_type,
                token_endpoint_auth_method,
                secret_hash,
                require_pkce,
                redirect_uris,
                post_logout_redirect_uris,
                allowed_scopes,
                allowed_grant_types,
            },
            created_at,
        )?;
        client.status = status;
        client.updated_at = updated_at;
        client.version = version;
        Ok(client)
    }

    /// Returns the internal row identifier.
    pub const fn id(&self) -> &Id<OAuthClientEntity> {
        &self.id
    }

    /// Returns the owning application.
    pub const fn application_id(&self) -> &Id<ApplicationEntity> {
        &self.application_id
    }

    /// Returns the public client identifier.
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the display name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// Returns the client type.
    pub const fn client_type(&self) -> ClientType {
        self.client_type
    }

    /// Returns the token-endpoint authentication method.
    pub const fn token_endpoint_auth_method(&self) -> TokenEndpointAuthMethod {
        self.token_endpoint_auth_method
    }

    /// Returns the encoded client-secret verifier, if any. Callers must not log this value.
    pub const fn secret_hash(&self) -> Option<&SecretHash> {
        self.secret_hash.as_ref()
    }

    /// Returns whether PKCE is mandatory.
    pub const fn require_pkce(&self) -> bool {
        self.require_pkce
    }

    /// Returns the registered redirect URIs.
    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }

    /// Returns the registered post-logout redirect URIs.
    pub fn post_logout_redirect_uris(&self) -> &[RedirectUri] {
        &self.post_logout_redirect_uris
    }

    /// Returns the allowed scopes.
    pub const fn allowed_scopes(&self) -> &ScopeSet {
        &self.allowed_scopes
    }

    /// Returns the allowed grant types.
    pub fn allowed_grant_types(&self) -> &[GrantType] {
        &self.allowed_grant_types
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> ClientStatus {
        self.status
    }

    /// Returns `true` when the client may authorize and exchange tokens.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ClientStatus::Active)
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the last mutation time.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the URI exactly matches a registered redirect URI.
    pub fn allows_redirect_uri(&self, uri: &RedirectUri) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered.matches(uri))
    }

    /// Returns `true` when the URI exactly matches a registered post-logout URI.
    pub fn allows_post_logout_redirect_uri(&self, uri: &RedirectUri) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|registered| registered.matches(uri))
    }

    /// Returns `true` when the scope is allowed.
    pub fn allows_scope(&self, scope: &Scope) -> bool {
        self.allowed_scopes.contains(scope)
    }

    /// Returns `true` when the grant type is allowed.
    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.allowed_grant_types.contains(&grant)
    }

    /// Adds a redirect URI.
    pub fn add_redirect_uri(
        &mut self,
        uri: RedirectUri,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        if self.allows_redirect_uri(&uri) {
            return Err(DomainError::conflict("redirect URI is already registered"));
        }
        self.redirect_uris.push(uri);
        self.touch(now);
        Ok(())
    }

    /// Removes a redirect URI, preserving the authorization-code invariant.
    pub fn remove_redirect_uri(
        &mut self,
        uri: &RedirectUri,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let Some(index) = self
            .redirect_uris
            .iter()
            .position(|registered| registered.matches(uri))
        else {
            return Err(DomainError::not_found("redirect URI is not registered"));
        };
        if self.allows_grant(GrantType::AuthorizationCode) && self.redirect_uris.len() == 1 {
            return Err(DomainError::conflict(
                "an authorization code client must keep at least one redirect URI",
            ));
        }
        self.redirect_uris.remove(index);
        self.touch(now);
        Ok(())
    }

    /// Replaces the allowed scope set.
    pub fn replace_scopes(&mut self, scopes: ScopeSet, now: Timestamp) {
        self.allowed_scopes = scopes;
        self.touch(now);
    }

    /// Replaces the client secret for a confidential client.
    pub fn rotate_secret(
        &mut self,
        secret_hash: SecretHash,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        if self.client_type != ClientType::Confidential {
            return Err(DomainError::conflict(
                "a public client does not have a client secret",
            ));
        }
        self.secret_hash = Some(secret_hash);
        self.touch(now);
        Ok(())
    }

    /// Disables the client.
    pub fn disable(&mut self, now: Timestamp) {
        if self.status == ClientStatus::Active {
            self.status = ClientStatus::Disabled;
            self.touch(now);
        }
    }

    /// Enables a disabled client.
    pub fn enable(&mut self, now: Timestamp) {
        if self.status == ClientStatus::Disabled {
            self.status = ClientStatus::Active;
            self.touch(now);
        }
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

fn ensure_unique<T: PartialEq>(values: &[T], field: &'static str) -> Result<(), DomainError> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(DomainError::invalid(format!("{field} must be unique")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> OAuthClientSpec {
        OAuthClientSpec {
            application_id: Id::<ApplicationEntity>::from_suffix("0123456789abcdef")
                .expect("valid id"),
            client_id: ClientId::parse("client0123456789abcdef").expect("valid client id"),
            name: DisplayName::parse("Console").expect("valid name"),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            secret_hash: Some(SecretHash::parse("sha256:0123456789abcdef").expect("valid hash")),
            require_pkce: true,
            redirect_uris: vec![
                RedirectUri::parse("https://app.example.com/callback").expect("valid uri"),
            ],
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: ScopeSet::new([
                Scope::parse("openid").expect("valid scope"),
                Scope::parse("profile").expect("valid scope"),
            ]),
            allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        }
    }

    fn client(spec: OAuthClientSpec) -> Result<OAuthClient, DomainError> {
        OAuthClient::new(
            Id::<OAuthClientEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            spec,
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn registers_a_confidential_client() {
        let client = client(spec()).expect("valid client");
        assert!(client.is_active());
        assert!(client.require_pkce());
        assert!(client.allows_grant(GrantType::AuthorizationCode));
        assert!(client.allows_scope(&Scope::parse("openid").expect("valid")));
    }

    #[test]
    fn public_clients_require_pkce_and_no_secret() {
        let mut spec = spec();
        spec.client_type = ClientType::Public;
        spec.token_endpoint_auth_method = TokenEndpointAuthMethod::None;
        spec.secret_hash = None;
        spec.require_pkce = true;
        assert!(client(spec.clone()).is_ok());

        spec.require_pkce = false;
        assert!(client(spec.clone()).is_err());

        spec.require_pkce = true;
        spec.secret_hash = Some(SecretHash::parse("sha256:0123456789abcdef").expect("valid"));
        assert!(client(spec).is_err());
    }

    #[test]
    fn every_client_requires_pkce() {
        let mut spec = spec();
        spec.require_pkce = false;
        assert!(client(spec).is_err());
    }

    #[test]
    fn confidential_clients_require_a_secret() {
        let mut spec = spec();
        spec.secret_hash = None;
        assert!(client(spec).is_err());
    }

    #[test]
    fn client_credentials_require_a_confidential_client() {
        let mut spec = spec();
        spec.allowed_grant_types = vec![GrantType::ClientCredentials];
        spec.redirect_uris.clear();
        assert!(client(spec.clone()).is_ok());

        spec.client_type = ClientType::Public;
        spec.token_endpoint_auth_method = TokenEndpointAuthMethod::None;
        spec.secret_hash = None;
        spec.require_pkce = true;
        assert!(client(spec).is_err());
    }

    #[test]
    fn code_clients_need_a_redirect_uri() {
        let mut spec = spec();
        spec.redirect_uris.clear();
        assert!(client(spec).is_err());
    }

    #[test]
    fn redirect_matching_is_exact() {
        let client = client(spec()).expect("valid client");
        let registered = RedirectUri::parse("https://app.example.com/callback").expect("valid uri");
        let different = RedirectUri::parse("https://app.example.com/callback/").expect("valid uri");
        assert!(client.allows_redirect_uri(&registered));
        assert!(!client.allows_redirect_uri(&different));
    }

    #[test]
    fn cannot_remove_the_last_code_redirect_uri() {
        let mut client = client(spec()).expect("valid client");
        let uri = client.redirect_uris()[0].clone();
        assert!(
            client
                .remove_redirect_uri(&uri, Timestamp::from_millis(2_000))
                .is_err()
        );
    }

    #[test]
    fn public_clients_cannot_rotate_a_secret() {
        let mut spec = spec();
        spec.client_type = ClientType::Public;
        spec.token_endpoint_auth_method = TokenEndpointAuthMethod::None;
        spec.secret_hash = None;
        let mut client = client(spec).expect("valid client");
        assert!(
            client
                .rotate_secret(
                    SecretHash::parse("sha256:fedcba9876543210").expect("valid"),
                    Timestamp::from_millis(2_000),
                )
                .is_err()
        );
    }
}
