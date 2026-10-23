//! Ports implemented by storage, cryptography, email, and runtime adapters.
//!
//! Ports are shaped around domain types. The core never imports a concrete adapter.

pub mod write;

pub use write::{EntityKind, OrganizationProvisioning, UnitOfWork, WriteBatch, WriteCommand};

use crate::domain::DomainError;
use crate::domain::Timestamp;
use crate::domain::application::Application;
use crate::domain::audit::AuditEvent;
use crate::domain::credential::Credential;
use crate::domain::email::Email;
use crate::domain::grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
use crate::domain::id::{
    ApplicationEntity, AuthorizationCodeEntity, ConsentEntity, Entity, Id, IdError,
    InvitationEntity, MembershipEntity, OAuthClientEntity, OrganizationEntity, RefreshFamilyEntity,
    RefreshTokenEntity, RoleBindingEntity, RoleEntity, SessionEntity, UserEntity,
};
use crate::domain::invitation::Invitation;
use crate::domain::membership::Membership;
use crate::domain::oauth_client::OAuthClient;
use crate::domain::organization::Organization;
use crate::domain::role::{Role, RoleBinding};
use crate::domain::secret::SecretHash;
use crate::domain::session::Session;
use crate::domain::slug::Slug;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::domain::write::WriteOutcome;

/// Supplies the current time to domain and application code.
pub trait Clock {
    /// Returns the current UTC time.
    fn now(&self) -> Timestamp;
}

/// Generates new typed entity identifiers.
///
/// Implementations must use a cryptographically secure random source and return a suffix
/// that satisfies [`Id::from_suffix`]. An unavailable or exhausted source returns an error
/// rather than a weak or duplicate identifier.
pub trait IdGenerator {
    /// Generates a new identifier for the requested entity kind.
    fn generate<E: Entity>(&self) -> Result<Id<E>, IdError>;
}

/// Read and write access to deployment-global users.
pub trait UserRepository {
    /// Finds a user by identifier.
    fn find_by_id(&self, id: &Id<UserEntity>) -> Result<Option<User>, DomainError>;

    /// Finds a user by normalized email.
    fn find_by_email(&self, email: &Email) -> Result<Option<User>, DomainError>;

    /// Inserts a new user.
    fn insert(&self, user: &User) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing user using optimistic concurrency.
    fn update(&self, user: &User, expected_version: u64) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to tenant-owned organizations.
pub trait OrganizationRepository {
    /// Finds an organization by identifier.
    fn find_by_id(&self, id: &Id<OrganizationEntity>) -> Result<Option<Organization>, DomainError>;

    /// Finds an organization by slug.
    fn find_by_slug(&self, slug: &Slug) -> Result<Option<Organization>, DomainError>;

    /// Inserts a new organization.
    fn insert(&self, organization: &Organization) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing organization using optimistic concurrency.
    fn update(
        &self,
        organization: &Organization,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to tenant-owned memberships.
pub trait MembershipRepository {
    /// Finds a membership by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<MembershipEntity>,
    ) -> Result<Option<Membership>, DomainError>;

    /// Finds the membership for a user in a tenant.
    fn find_by_user(
        &self,
        tenant: &TenantContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Membership>, DomainError>;

    /// Inserts a new membership.
    fn insert(
        &self,
        tenant: &TenantContext,
        membership: &Membership,
    ) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing membership using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        membership: &Membership,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to tenant-owned invitations.
pub trait InvitationRepository {
    /// Finds an invitation by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<InvitationEntity>,
    ) -> Result<Option<Invitation>, DomainError>;

    /// Inserts a new invitation.
    fn insert(
        &self,
        tenant: &TenantContext,
        invitation: &Invitation,
    ) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing invitation using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        invitation: &Invitation,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to tenant-owned applications.
pub trait ApplicationRepository {
    /// Finds an application by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<ApplicationEntity>,
    ) -> Result<Option<Application>, DomainError>;

    /// Finds an application by slug within a tenant.
    fn find_by_slug(
        &self,
        tenant: &TenantContext,
        slug: &crate::domain::slug::Slug,
    ) -> Result<Option<Application>, DomainError>;

    /// Inserts a new application.
    fn insert(
        &self,
        tenant: &TenantContext,
        application: &Application,
    ) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing application using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        application: &Application,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to OAuth clients.
pub trait OAuthClientRepository {
    /// Finds a client by internal identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<OAuthClientEntity>,
    ) -> Result<Option<OAuthClient>, DomainError>;

    /// Finds a client by its public client identifier.
    fn find_by_client_id(
        &self,
        client_id: &crate::domain::client_id::ClientId,
    ) -> Result<Option<OAuthClient>, DomainError>;

    /// Inserts a new client.
    fn insert(
        &self,
        tenant: &TenantContext,
        client: &OAuthClient,
    ) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing client using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        client: &OAuthClient,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to credentials.
///
/// Adapters persist the type-specific credential payload in the columns for its kind and
/// must reject a row whose stored type does not match the domain value. Secret material is
/// already encrypted or hashed by the adapter before it reaches this port; the core never
/// receives plaintext passwords or TOTP secrets.
pub trait CredentialRepository {
    /// Finds a credential by identifier.
    fn find_by_id(
        &self,
        id: &Id<crate::domain::id::CredentialEntity>,
    ) -> Result<Option<Credential>, DomainError>;

    /// Lists credentials for a user.
    fn list_for_user(&self, user_id: &Id<UserEntity>) -> Result<Vec<Credential>, DomainError>;

    /// Inserts a new credential.
    fn insert(&self, credential: &Credential) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing credential using optimistic concurrency.
    fn update(
        &self,
        credential: &Credential,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to sessions.
pub trait SessionRepository {
    /// Finds a session by identifier.
    fn find_by_id(&self, id: &Id<SessionEntity>) -> Result<Option<Session>, DomainError>;

    /// Finds a session by token hash.
    fn find_by_token_hash(&self, token_hash: &SecretHash) -> Result<Option<Session>, DomainError>;

    /// Inserts a new session.
    fn insert(&self, session: &Session) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing session using optimistic concurrency.
    fn update(&self, session: &Session, expected_version: u64)
    -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to roles.
pub trait RoleRepository {
    /// Finds a role by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RoleEntity>,
    ) -> Result<Option<Role>, DomainError>;

    /// Lists roles for a tenant.
    fn list(&self, tenant: &TenantContext) -> Result<Vec<Role>, DomainError>;

    /// Inserts a new role.
    fn insert(&self, tenant: &TenantContext, role: &Role) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing role using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        role: &Role,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to role bindings.
pub trait RoleBindingRepository {
    /// Finds bindings for a user in a tenant.
    fn list_for_user(
        &self,
        tenant: &TenantContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Vec<RoleBinding>, DomainError>;

    /// Inserts a new binding.
    fn insert(
        &self,
        tenant: &TenantContext,
        binding: &RoleBinding,
    ) -> Result<WriteOutcome, DomainError>;

    /// Deletes a binding.
    fn delete(
        &self,
        tenant: &TenantContext,
        binding_id: &Id<RoleBindingEntity>,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to one-time authorization codes.
pub trait AuthorizationCodeRepository {
    /// Finds a code by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<AuthorizationCodeEntity>,
    ) -> Result<Option<AuthorizationCode>, DomainError>;

    /// Finds a code by its hashed verifier.
    fn find_by_hash(
        &self,
        tenant: &TenantContext,
        hash: &SecretHash,
    ) -> Result<Option<AuthorizationCode>, DomainError>;

    /// Inserts a new code.
    fn insert(
        &self,
        tenant: &TenantContext,
        code: &AuthorizationCode,
    ) -> Result<WriteOutcome, DomainError>;

    /// Consumes or otherwise updates a code using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        code: &AuthorizationCode,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to user consent records.
pub trait ConsentRepository {
    /// Finds a consent by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<ConsentEntity>,
    ) -> Result<Option<Consent>, DomainError>;

    /// Finds the consent for a client and user, if one exists.
    fn find_for_client_user(
        &self,
        tenant: &TenantContext,
        client_id: &Id<OAuthClientEntity>,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Consent>, DomainError>;

    /// Inserts a new consent.
    fn insert(
        &self,
        tenant: &TenantContext,
        consent: &Consent,
    ) -> Result<WriteOutcome, DomainError>;

    /// Updates an existing consent using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        consent: &Consent,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to refresh-token families.
pub trait RefreshFamilyRepository {
    /// Finds a family by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RefreshFamilyEntity>,
    ) -> Result<Option<RefreshFamily>, DomainError>;

    /// Inserts a new family.
    fn insert(
        &self,
        tenant: &TenantContext,
        family: &RefreshFamily,
    ) -> Result<WriteOutcome, DomainError>;

    /// Revokes or otherwise updates a family using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        family: &RefreshFamily,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to refresh tokens.
pub trait RefreshTokenRepository {
    /// Finds a token by identifier.
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RefreshTokenEntity>,
    ) -> Result<Option<RefreshToken>, DomainError>;

    /// Finds a token by its hashed verifier.
    fn find_by_hash(
        &self,
        tenant: &TenantContext,
        hash: &SecretHash,
    ) -> Result<Option<RefreshToken>, DomainError>;

    /// Inserts a new token.
    fn insert(
        &self,
        tenant: &TenantContext,
        token: &RefreshToken,
    ) -> Result<WriteOutcome, DomainError>;

    /// Consumes or rotates a token using optimistic concurrency.
    fn update(
        &self,
        tenant: &TenantContext,
        token: &RefreshToken,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access to tenant-owned audit events.
pub trait AuditRepository {
    /// Appends an audit event. Audit writes are append-only.
    fn append(
        &self,
        tenant: &TenantContext,
        event: &AuditEvent,
    ) -> Result<WriteOutcome, DomainError>;
}

/// A repository bundle available to use cases.
pub trait Repositories:
    UserRepository
    + OrganizationRepository
    + MembershipRepository
    + InvitationRepository
    + ApplicationRepository
    + OAuthClientRepository
    + CredentialRepository
    + SessionRepository
    + RoleRepository
    + RoleBindingRepository
    + AuthorizationCodeRepository
    + ConsentRepository
    + RefreshFamilyRepository
    + RefreshTokenRepository
    + AuditRepository
    + write::UnitOfWork
{
}
