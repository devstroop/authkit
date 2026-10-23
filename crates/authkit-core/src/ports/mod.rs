//! Ports implemented by storage, cryptography, email, and runtime adapters.
//!
//! Ports are shaped around domain types. The core never imports a concrete adapter.

use crate::domain::DomainError;
use crate::domain::Timestamp;
use crate::domain::audit::AuditEvent;
use crate::domain::email::Email;
use crate::domain::organization::Organization;
use crate::domain::slug::Slug;
use crate::domain::user::User;
use crate::domain::id::{Entity, Id, IdError, OrganizationEntity, UserEntity};
use crate::domain::tenant::TenantContext;
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

/// Read and write access to tenant-owned audit events.
pub trait AuditRepository {
    /// Appends an audit event. Audit writes are append-only.
    fn append(&self, tenant: &TenantContext, event: &AuditEvent) -> Result<WriteOutcome, DomainError>;
}

/// A repository bundle available to use cases.
pub trait Repositories: UserRepository + OrganizationRepository + AuditRepository {}
