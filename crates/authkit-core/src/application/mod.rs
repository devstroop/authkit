//! Application use cases.
//!
//! Use cases load the minimum state, apply domain policy, and submit a guarded write batch.
//! They depend on ports, never on a concrete adapter. The first implementation slices land
//! with the identity, tenancy, and grant work in milestone M1.

use crate::domain::DomainError;
use crate::domain::application::Application;
use crate::domain::application::ApplicationKind;
use crate::domain::audit::{AuditAction, AuditActor, AuditEvent, AuditTarget};
use crate::domain::email::Email;
use crate::domain::id::{
    ApplicationEntity, AuditEventEntity, Id, MembershipEntity, OrganizationEntity,
    RoleBindingEntity, RoleEntity, UserEntity,
};
use crate::domain::membership::Membership;
use crate::domain::name::DisplayName;
use crate::domain::organization::Organization;
use crate::domain::role::{Role, RoleBinding};
use crate::domain::slug::Slug;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::ports::{
    Clock, IdGenerator, OrganizationProvisioning, OrganizationRepository, UserRepository,
    WriteBatch, WriteCommand,
};

/// Creates a deployment-global user.
pub struct CreateUser {
    pub email: Email,
    pub display_name: DisplayName,
}

impl CreateUser {
    /// Executes the use case.
    pub fn execute<R, I>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<User, DomainError>
    where
        R: UserRepository,
        I: IdGenerator,
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

/// Creates an organization together with its initial owner.
///
/// The organization, the owner's active membership, the built-in owner role, the owner role
/// binding, and the creation audit event are committed as one atomic batch. An organization
/// therefore never exists without an authorized owner, and a failed write leaves no partial
/// organization behind.
pub struct CreateOrganization {
    pub slug: Slug,
    pub name: DisplayName,
    pub owner_id: Id<UserEntity>,
}

impl CreateOrganization {
    /// Executes the use case.
    pub fn execute<R, I>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<Organization, DomainError>
    where
        R: OrganizationProvisioning,
        I: IdGenerator,
    {
        let now = clock.now();

        let owner = UserRepository::find_by_id(repositories, &self.owner_id)?
            .ok_or_else(|| DomainError::not_found("owner user does not exist"))?;
        if !owner.is_active() {
            return Err(DomainError::forbidden("owner user is not active"));
        }

        if OrganizationRepository::find_by_slug(repositories, &self.slug)?.is_some() {
            return Err(DomainError::conflict(
                "an organization with this slug already exists",
            ));
        }

        let organization_id = ids.generate::<OrganizationEntity>()?;
        let membership_id = ids.generate::<MembershipEntity>()?;
        let role_id = ids.generate::<RoleEntity>()?;
        let binding_id = ids.generate::<RoleBindingEntity>()?;
        let audit_id = ids.generate::<AuditEventEntity>()?;

        let organization = Organization::new(
            organization_id.clone(),
            self.slug.clone(),
            self.name.clone(),
            now,
        );
        let membership = Membership::active(
            membership_id,
            organization_id.clone(),
            self.owner_id.clone(),
            now,
        );
        let owner_role = Role::owner(role_id.clone(), organization_id.clone(), now)?;
        let owner_binding = RoleBinding::organization(
            binding_id,
            organization_id.clone(),
            role_id,
            self.owner_id.clone(),
            now,
        );
        let audit = AuditEvent::new(
            audit_id,
            Some(organization_id.clone()),
            AuditActor::User(self.owner_id.clone()),
            AuditAction::parse("organization.create")?,
            Some(AuditTarget::parse(organization_id.as_str())?),
            now,
            Vec::new(),
        )?;

        let tenant = tenant_for(organization_id);
        let batch = WriteBatch::new()
            .with(WriteCommand::InsertOrganization(organization.clone()))
            .with(WriteCommand::InsertMembership {
                tenant: tenant.clone(),
                membership,
            })
            .with(WriteCommand::InsertRole {
                tenant: tenant.clone(),
                role: owner_role,
            })
            .with(WriteCommand::InsertRoleBinding {
                tenant: tenant.clone(),
                binding: owner_binding,
            })
            .with(WriteCommand::AppendAudit {
                tenant,
                event: audit,
            });

        let outcome = repositories.commit(&batch)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict(
                "organization creation lost a race on the slug or owner provisioning",
            ));
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
    pub fn execute<R, I>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<Application, DomainError>
    where
        R: crate::ports::ApplicationRepository,
        I: IdGenerator,
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
    pub fn execute<R, I>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<Membership, DomainError>
    where
        R: crate::ports::MembershipRepository,
        I: IdGenerator,
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
