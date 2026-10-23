//! Application use cases.
//!
//! Use cases load the minimum state, apply domain policy, and submit a guarded write batch.
//! They depend on ports, never on a concrete adapter. The first implementation slices land
//! with the identity, tenancy, and grant work in milestone M1.

use crate::domain::DomainError;
use crate::domain::application::Application;
use crate::domain::application::ApplicationKind;
use crate::domain::email::Email;
use crate::domain::id::{ApplicationEntity, Id, OrganizationEntity, UserEntity};
use crate::domain::membership::Membership;
use crate::domain::name::DisplayName;
use crate::domain::organization::Organization;
use crate::domain::slug::Slug;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::ports::{Clock, IdGenerator, OrganizationRepository, UserRepository};

/// Creates a deployment-global user.
pub struct CreateUser {
    pub email: Email,
    pub display_name: DisplayName,
}

impl CreateUser {
    /// Executes the use case.
    pub fn execute<R, I, C>(
        &self,
        repositories: &R,
        clock: &C,
        ids: &I,
    ) -> Result<User, DomainError>
    where
        R: UserRepository,
        I: IdGenerator,
        C: Clock,
    {
        let now = clock.now();
        if repositories.find_by_email(&self.email)?.is_some() {
            return Err(DomainError::conflict(
                "a user with this email already exists",
            ));
        }
        let id = ids.generate::<UserEntity>()?;
        let user = User::new(id, self.email.clone(), self.display_name.clone(), now);
        let outcome = repositories.insert(&user)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("user creation lost a race"));
        }
        Ok(user)
    }
}

/// Creates an organization.
pub struct CreateOrganization {
    pub slug: Slug,
    pub name: DisplayName,
}

impl CreateOrganization {
    /// Executes the use case.
    pub fn execute<R, I, C>(
        &self,
        repositories: &R,
        clock: &C,
        ids: &I,
    ) -> Result<Organization, DomainError>
    where
        R: OrganizationRepository,
        I: IdGenerator,
        C: Clock,
    {
        let now = clock.now();
        if repositories.find_by_slug(&self.slug)?.is_some() {
            return Err(DomainError::conflict(
                "an organization with this slug already exists",
            ));
        }
        let id = ids.generate::<OrganizationEntity>()?;
        let organization = Organization::new(id, self.slug.clone(), self.name.clone(), now);
        let outcome = repositories.insert(&organization)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("organization creation lost a race"));
        }
        Ok(organization)
    }
}

/// Creates an application inside a tenant.
pub struct CreateApplication {
    pub tenant: TenantContext,
    pub slug: Slug,
    pub name: DisplayName,
    pub kind: ApplicationKind,
    pub first_party: bool,
}

impl CreateApplication {
    /// Executes the use case.
    pub fn execute<R, I, C>(
        &self,
        repositories: &R,
        clock: &C,
        ids: &I,
    ) -> Result<Application, DomainError>
    where
        R: crate::ports::ApplicationRepository,
        I: IdGenerator,
        C: Clock,
    {
        let now = clock.now();
        if repositories
            .find_by_slug(&self.tenant, &self.slug)?
            .is_some()
        {
            return Err(DomainError::conflict(
                "an application with this slug already exists in the organization",
            ));
        }
        let id = ids.generate::<ApplicationEntity>()?;
        let application = Application::new(
            id,
            self.tenant.organization_id().clone(),
            self.slug.clone(),
            self.name.clone(),
            self.kind,
            self.first_party,
            now,
        );
        let outcome = repositories.insert(&self.tenant, &application)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("application creation lost a race"));
        }
        Ok(application)
    }
}

/// Adds an active membership for a user in a tenant.
pub struct AddMembership {
    pub tenant: TenantContext,
    pub user_id: Id<UserEntity>,
}

impl AddMembership {
    /// Executes the use case.
    pub fn execute<R, I, C>(
        &self,
        repositories: &R,
        clock: &C,
        ids: &I,
    ) -> Result<Membership, DomainError>
    where
        R: crate::ports::MembershipRepository,
        I: IdGenerator,
        C: Clock,
    {
        let now = clock.now();
        if repositories
            .find_by_user(&self.tenant, &self.user_id)?
            .is_some()
        {
            return Err(DomainError::conflict(
                "user already has a membership in this organization",
            ));
        }
        let id = ids.generate::<crate::domain::id::MembershipEntity>()?;
        let membership = Membership::active(
            id,
            self.tenant.organization_id().clone(),
            self.user_id.clone(),
            now,
        );
        let outcome = repositories.insert(&self.tenant, &membership)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("membership creation lost a race"));
        }
        Ok(membership)
    }
}

/// Returns the tenant context for an organization.
pub fn tenant_for(organization_id: Id<OrganizationEntity>) -> TenantContext {
    TenantContext::new(organization_id)
}
