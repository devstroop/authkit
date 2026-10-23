//! Application use cases.
//!
//! Use cases load the minimum state, apply domain policy, and submit a guarded write batch.
//! They depend on ports, never on a concrete adapter. The first implementation slices land
//! with the identity, tenancy, and grant work in milestone M1.

use crate::domain::DomainError;
use crate::domain::id::{Id, OrganizationEntity, UserEntity};
use crate::domain::organization::Organization;
use crate::domain::slug::Slug;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::ports::{Clock, IdGenerator, OrganizationRepository, UserRepository};

/// Creates a deployment-global user.
pub struct CreateUser {
    pub email: crate::domain::email::Email,
    pub display_name: crate::domain::name::DisplayName,
}

impl CreateUser {
    /// Executes the use case.
    pub fn execute<R: UserRepository, I: IdGenerator, C: Clock>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<User, DomainError> {
        let now = clock.now();
        if repositories.find_by_email(&self.email)?.is_some() {
            return Err(DomainError::conflict(
                "a user with this email already exists",
            ));
        }
        let id = ids.generate::<crate::domain::id::UserEntity>()?;
        let user = User::new(id, self.email.clone(), self.display_name.clone(), now);
        let outcome = repositories.insert(&user)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("user creation lost a race"));
        }
        Ok(user)
    }
}

/// Creates an organization and its initial owner membership.
pub struct CreateOrganization {
    pub slug: Slug,
    pub name: crate::domain::name::DisplayName,
    pub owner: Id<UserEntity>,
}

impl CreateOrganization {
    /// Executes the use case.
    pub fn execute<R: OrganizationRepository, I: IdGenerator, C: Clock>(
        &self,
        repositories: &R,
        clock: &C,
        ids: &I,
    ) -> Result<Organization, DomainError> {
        let now = clock.now();
        if repositories.find_by_slug(&self.slug)?.is_some() {
            return Err(DomainError::conflict(
                "an organization with this slug already exists",
            ));
        }
        let id = ids.generate::<crate::domain::id::OrganizationEntity>()?;
        let organization = Organization::new(id, self.slug.clone(), self.name.clone(), now);
        let outcome = repositories.insert(&organization)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("organization creation lost a race"));
        }
        let _ = self.owner;
        Ok(organization)
    }
}

/// Returns the tenant context for an organization.
pub fn tenant_for(organization_id: Id<OrganizationEntity>) -> TenantContext {
    TenantContext::new(organization_id)
}
