//! Application use cases.
//!
//! Use cases load the minimum state, apply domain policy, and submit a guarded write batch.
//! They depend on ports, never on a concrete adapter. The first implementation slices land
//! with the identity, tenancy, and grant work in milestone M1.

use crate::domain::ClientId;
use crate::domain::DomainError;
use crate::domain::application::Application;
use crate::domain::application::ApplicationKind;
use crate::domain::audit::{AuditAction, AuditActor, AuditEvent, AuditTarget};
use crate::domain::email::Email;
use crate::domain::id::{
    ApplicationEntity, AuditEventEntity, Id, MembershipEntity, OAuthClientEntity,
    RoleBindingEntity, RoleEntity, UserEntity,
};
use crate::domain::invitation::Invitation;
use crate::domain::membership::Membership;
use crate::domain::name::DisplayName;
use crate::domain::oauth_client::GrantType;
use crate::domain::oauth_client::{
    ClientType, OAuthClient, OAuthClientSpec, TokenEndpointAuthMethod,
};
use crate::domain::organization::Organization;
use crate::domain::redirect_uri::RedirectUri;
use crate::domain::role::{Role, RoleBinding};
use crate::domain::scope::ScopeSet;
use crate::domain::secret::SecretHash;
use crate::domain::slug::Slug;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::ports::{
    Clock, IdGenerator, InvitationRepository, MembershipRepository, OrganizationProvisioning,
    OrganizationRepository, RoleBindingRepository, UnitOfWork, UserRepository, WriteBatch,
    WriteCommand,
};

/// Creates a user scoped to one application.
pub struct CreateUser {
    pub application_id: Option<Id<ApplicationEntity>>,
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
        if repositories
            .find_by_email(self.application_id.as_ref(), &self.email)?
            .is_some()
        {
            return Err(DomainError::conflict(
                "a user with this email already exists",
            ));
        }
        let id = ids.generate::<UserEntity>()?;
        let user = User::new(
            id,
            self.application_id.clone(),
            self.email.clone(),
            self.display_name.clone(),
            now,
        );
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
/// Optional first OAuth client provisioned atomically with an application.
#[derive(Clone)]
pub struct CreateApplicationClient {
    pub name: DisplayName,
    pub client_type: ClientType,
    pub client_id: ClientId,
    pub secret_hash: Option<SecretHash>,
    pub redirect_uris: Vec<RedirectUri>,
    pub allowed_scopes: ScopeSet,
}

pub struct CreateApplication {
    pub slug: Slug,
    pub name: DisplayName,
    pub primary_domain: String,
    pub owner_id: Id<UserEntity>,
    pub client: Option<CreateApplicationClient>,
}

impl CreateApplication {
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

        let primary_domain = self.primary_domain.trim().to_ascii_lowercase();
        let valid = !primary_domain.is_empty()
            && primary_domain.len() <= 253
            && primary_domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !valid {
            return Err(DomainError::invalid(
                "primary domain must be a valid hostname",
            ));
        }

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

        let application_id = ids.generate::<ApplicationEntity>()?;
        let membership_id = ids.generate::<MembershipEntity>()?;
        let role_id = ids.generate::<RoleEntity>()?;
        let binding_id = ids.generate::<RoleBindingEntity>()?;
        let audit_id = ids.generate::<AuditEventEntity>()?;

        let organization = Application::new(
            application_id.clone(),
            self.slug.clone(),
            self.name.clone(),
            ApplicationKind::Web,
            false,
            primary_domain.clone(),
            now,
        );
        let membership = Membership::active(
            membership_id,
            application_id.clone(),
            self.owner_id.clone(),
            now,
        );
        let owner_role = Role::owner(role_id.clone(), application_id.clone(), now)?;
        let owner_binding = RoleBinding::organization(
            binding_id,
            application_id.clone(),
            role_id,
            self.owner_id.clone(),
            now,
        );
        let audit = AuditEvent::new(
            audit_id,
            Some(application_id.clone()),
            AuditActor::User(self.owner_id.clone()),
            AuditAction::parse("organization.create")?,
            Some(AuditTarget::parse(application_id.as_str())?),
            now,
            Vec::new(),
        )?;

        let tenant = tenant_for(application_id.clone());
        let mut batch = WriteBatch::new()
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
                tenant: tenant.clone(),
                event: audit,
            });

        if let Some(client) = self.client.clone() {
            let token_endpoint_auth_method = if client.client_type == ClientType::Confidential {
                TokenEndpointAuthMethod::ClientSecretPost
            } else {
                TokenEndpointAuthMethod::None
            };
            let spec = OAuthClientSpec {
                application_id: application_id.clone(),
                client_id: client.client_id,
                name: client.name,
                client_type: client.client_type,
                token_endpoint_auth_method,
                secret_hash: client.secret_hash,
                require_pkce: true,
                redirect_uris: client.redirect_uris,
                post_logout_redirect_uris: Vec::new(),
                allowed_scopes: client.allowed_scopes,
                allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            };
            let oauth_client = OAuthClient::new(ids.generate::<OAuthClientEntity>()?, spec, now)?;
            batch = batch.with(WriteCommand::InsertOAuthClient {
                tenant: tenant.clone(),
                client: oauth_client,
            });
        }

        let outcome = repositories.commit(&batch)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict(
                "organization creation lost a race on the slug or owner provisioning",
            ));
        }

        Ok(organization)
    }
}

/// Creates an application surface inside a tenant.
pub struct CreateApplicationSurface {
    pub tenant: TenantContext,
    pub slug: Slug,
    pub name: DisplayName,
    pub kind: ApplicationKind,
    pub first_party: bool,
}

impl CreateApplicationSurface {
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
            self.slug.clone(),
            self.name.clone(),
            self.kind,
            self.first_party,
            String::new(),
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
            self.tenant.application_id().clone(),
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

/// Accepts a pending invitation for the given user.
///
/// The invitation is loaded by its hashed token. The accepting user must match the
/// invited email address. A membership is created when the user is not already a
/// member, the invitation's roles are bound to the user, and the invitation is
/// marked accepted, all in one atomic batch.
pub struct AcceptInvitation {
    /// The hashed invitation token presented by the accepting user.
    pub token_hash: SecretHash,
    /// The user accepting the invitation.
    pub user_id: Id<UserEntity>,
}

impl AcceptInvitation {
    /// Executes the use case.
    pub fn execute<R, I>(
        &self,
        repositories: &R,
        clock: &dyn Clock,
        ids: &I,
    ) -> Result<Invitation, DomainError>
    where
        R: UserRepository
            + InvitationRepository
            + MembershipRepository
            + RoleBindingRepository
            + UnitOfWork,
        I: IdGenerator,
    {
        let now = clock.now();

        let invitation = InvitationRepository::find_by_token_hash(repositories, &self.token_hash)?
            .ok_or_else(|| DomainError::not_found("invitation not found"))?;

        let user = UserRepository::find_by_id(repositories, &self.user_id)?
            .ok_or_else(|| DomainError::not_found("user not found"))?;

        if user.email().as_str() != invitation.email().as_str() {
            return Err(DomainError::forbidden(
                "invitation email does not match the accepting user",
            ));
        }
        if !invitation.is_usable(now) {
            return Err(DomainError::conflict("invitation is not usable"));
        }

        let application_id = invitation.application_id().clone();
        let tenant = TenantContext::new(application_id.clone());
        let role_ids = invitation.role_ids().to_vec();
        let original_version = invitation.version();

        // Create membership if the user is not already a member.
        let need_membership =
            MembershipRepository::find_by_user(repositories, &tenant, &self.user_id)?.is_none();
        let mut batch = WriteBatch::new();
        if need_membership {
            let membership = Membership::active(
                ids.generate::<MembershipEntity>()?,
                application_id.clone(),
                self.user_id.clone(),
                now,
            );
            batch = batch.with(WriteCommand::InsertMembership {
                tenant: tenant.clone(),
                membership,
            });
        }

        // Bind the invitation's roles to the user.
        for role_id in &role_ids {
            let binding = RoleBinding::organization(
                ids.generate::<RoleBindingEntity>()?,
                application_id.clone(),
                role_id.clone(),
                self.user_id.clone(),
                now,
            );
            batch = batch.with(WriteCommand::InsertRoleBinding {
                tenant: tenant.clone(),
                binding,
            });
        }

        // Mark the invitation accepted.
        let mut accepted = invitation.clone();
        accepted.accept(now)?;
        batch = batch.with(WriteCommand::UpdateInvitation {
            tenant: tenant.clone(),
            invitation: accepted.clone(),
            expected_version: original_version,
        });

        let outcome = repositories.commit(&batch)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("invitation acceptance lost a race"));
        }

        Ok(accepted)
    }
}

/// Suspends an active user.
pub struct SuspendUser {
    pub user_id: Id<UserEntity>,
}

impl SuspendUser {
    pub fn execute<R>(&self, repositories: &R, clock: &dyn Clock) -> Result<User, DomainError>
    where
        R: UserRepository + UnitOfWork,
    {
        let now = clock.now();
        let mut user = UserRepository::find_by_id(repositories, &self.user_id)?
            .ok_or_else(|| DomainError::not_found("user not found"))?;
        let expected = user.version();
        user.suspend(now)?;
        let outcome = repositories.update(&user, expected)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("user suspension lost a race"));
        }
        Ok(user)
    }
}

/// Marks a user as deleted.
pub struct DeleteUser {
    pub user_id: Id<UserEntity>,
}

impl DeleteUser {
    pub fn execute<R>(&self, repositories: &R, clock: &dyn Clock) -> Result<User, DomainError>
    where
        R: UserRepository + UnitOfWork,
    {
        let now = clock.now();
        let mut user = UserRepository::find_by_id(repositories, &self.user_id)?
            .ok_or_else(|| DomainError::not_found("user not found"))?;
        let expected = user.version();
        user.mark_deleted(now);
        let outcome = repositories.update(&user, expected)?;
        if !outcome.is_applied() {
            return Err(DomainError::conflict("user deletion lost a race"));
        }
        Ok(user)
    }
}

/// Returns the tenant context for an organization.
pub fn tenant_for(application_id: Id<ApplicationEntity>) -> TenantContext {
    TenantContext::new(application_id)
}
