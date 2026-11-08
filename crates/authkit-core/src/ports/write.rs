//! Storage-independent atomic unit-of-work contract.
//!
//! A use case loads state through read repositories, evaluates domain policy, and submits
//! every related mutation as one [`WriteBatch`]. Adapters execute the batch atomically: if
//! any command fails a guard or the storage reports an error, none of the commands persist.
//!
//! The contract deliberately contains no interactive transaction handle. A use case must
//! precompute all values, including generated identifiers, before submitting the batch.
//! Native adapters execute the batch inside one SQL transaction; a D1 adapter executes one
//! `batch()` call with the same ordered statements and guards. This keeps the core
//! portable and prevents read-after-write dependencies inside a transaction.

use crate::domain::DomainError;
use crate::domain::application::Application;
use crate::domain::audit::AuditEvent;
use crate::domain::credential::Credential;
use crate::domain::grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
use crate::domain::id::{Id, RoleBindingEntity};
use crate::domain::invitation::Invitation;
use crate::domain::membership::Membership;
use crate::domain::oauth_client::OAuthClient;
use crate::domain::organization::Organization;
use crate::domain::role::{Role, RoleBinding};
use crate::domain::session::Session;
use crate::domain::tenant::TenantContext;
use crate::domain::user::User;
use crate::domain::write::WriteOutcome;

/// A guarded mutation that participates in an atomic write batch.
///
/// Update commands carry the version the caller read. An adapter must apply the update only
/// when the stored version matches; otherwise the guard fails and the whole batch is
/// rejected with [`WriteOutcome::Conflict`] or [`WriteOutcome::NotFound`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCommand {
    /// Inserts a deployment-global user.
    InsertUser(User),
    /// Updates a user using optimistic concurrency.
    UpdateUser {
        /// The new aggregate state.
        user: User,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts an organization.
    InsertOrganization(Organization),
    /// Updates an organization using optimistic concurrency.
    UpdateOrganization {
        /// The new aggregate state.
        organization: Organization,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned membership.
    InsertMembership {
        /// The tenant that owns the membership.
        tenant: TenantContext,
        /// The membership to insert.
        membership: Membership,
    },
    /// Updates a tenant-owned membership using optimistic concurrency.
    UpdateMembership {
        /// The tenant that owns the membership.
        tenant: TenantContext,
        /// The new aggregate state.
        membership: Membership,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned invitation.
    InsertInvitation {
        /// The tenant that owns the invitation.
        tenant: TenantContext,
        /// The invitation to insert.
        invitation: Invitation,
    },
    /// Updates a tenant-owned invitation using optimistic concurrency.
    UpdateInvitation {
        /// The tenant that owns the invitation.
        tenant: TenantContext,
        /// The new aggregate state.
        invitation: Invitation,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned application.
    InsertApplication {
        /// The tenant that owns the application.
        tenant: TenantContext,
        /// The application to insert.
        application: Application,
    },
    /// Updates a tenant-owned application using optimistic concurrency.
    UpdateApplication {
        /// The tenant that owns the application.
        tenant: TenantContext,
        /// The new aggregate state.
        application: Application,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned OAuth client.
    InsertOAuthClient {
        /// The tenant that owns the client.
        tenant: TenantContext,
        /// The client to insert.
        client: OAuthClient,
    },
    /// Updates a tenant-owned OAuth client using optimistic concurrency.
    UpdateOAuthClient {
        /// The tenant that owns the client.
        tenant: TenantContext,
        /// The new aggregate state.
        client: OAuthClient,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a credential.
    InsertCredential(Credential),
    /// Updates a credential using optimistic concurrency.
    UpdateCredential {
        /// The new aggregate state.
        credential: Credential,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a session.
    InsertSession(Session),
    /// Updates a session using optimistic concurrency.
    UpdateSession {
        /// The new aggregate state.
        session: Session,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned role.
    InsertRole {
        /// The tenant that owns the role.
        tenant: TenantContext,
        /// The role to insert.
        role: Role,
    },
    /// Updates a tenant-owned role using optimistic concurrency.
    UpdateRole {
        /// The tenant that owns the role.
        tenant: TenantContext,
        /// The new aggregate state.
        role: Role,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a tenant-owned role binding.
    InsertRoleBinding {
        /// The tenant that owns the binding.
        tenant: TenantContext,
        /// The binding to insert.
        binding: RoleBinding,
    },
    /// Deletes a tenant-owned role binding.
    DeleteRoleBinding {
        /// The tenant that owns the binding.
        tenant: TenantContext,
        /// The binding to delete.
        binding_id: Id<RoleBindingEntity>,
    },
    /// Inserts a one-time authorization code.
    InsertAuthorizationCode {
        /// The tenant that owns the code.
        tenant: TenantContext,
        /// The code to insert.
        code: AuthorizationCode,
    },
    /// Consumes or otherwise updates an authorization code with an optimistic guard.
    UpdateAuthorizationCode {
        /// The tenant that owns the code.
        tenant: TenantContext,
        /// The new aggregate state.
        code: AuthorizationCode,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a consent record.
    InsertConsent {
        /// The tenant that owns the consent.
        tenant: TenantContext,
        /// The consent to insert.
        consent: Consent,
    },
    /// Updates a consent record using optimistic concurrency.
    UpdateConsent {
        /// The tenant that owns the consent.
        tenant: TenantContext,
        /// The new aggregate state.
        consent: Consent,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a refresh-token family.
    InsertRefreshFamily {
        /// The tenant that owns the family.
        tenant: TenantContext,
        /// The family to insert.
        family: RefreshFamily,
    },
    /// Revokes or otherwise updates a refresh-token family.
    UpdateRefreshFamily {
        /// The tenant that owns the family.
        tenant: TenantContext,
        /// The new aggregate state.
        family: RefreshFamily,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Inserts a refresh token within a family.
    InsertRefreshToken {
        /// The tenant that owns the token.
        tenant: TenantContext,
        /// The token to insert.
        token: RefreshToken,
    },
    /// Consumes a refresh token with an optimistic guard.
    UpdateRefreshToken {
        /// The tenant that owns the token.
        tenant: TenantContext,
        /// The new aggregate state.
        token: RefreshToken,
        /// The version the caller read before deciding.
        expected_version: u64,
    },
    /// Appends a tenant-scoped audit event in the same atomic batch as the state change.
    AppendAudit {
        /// The tenant that owns the event.
        tenant: TenantContext,
        /// The event to append.
        event: AuditEvent,
    },
}

impl WriteCommand {
    /// Returns the tenant scope when the command is tenant-owned.
    pub const fn tenant(&self) -> Option<&TenantContext> {
        match self {
            Self::InsertOrganization(_)
            | Self::UpdateOrganization { .. }
            | Self::InsertUser(_)
            | Self::UpdateUser { .. }
            | Self::InsertCredential(_)
            | Self::UpdateCredential { .. }
            | Self::InsertSession(_)
            | Self::UpdateSession { .. } => None,
            Self::InsertMembership { tenant, .. }
            | Self::UpdateMembership { tenant, .. }
            | Self::InsertInvitation { tenant, .. }
            | Self::UpdateInvitation { tenant, .. }
            | Self::InsertApplication { tenant, .. }
            | Self::UpdateApplication { tenant, .. }
            | Self::InsertOAuthClient { tenant, .. }
            | Self::UpdateOAuthClient { tenant, .. }
            | Self::InsertRole { tenant, .. }
            | Self::UpdateRole { tenant, .. }
            | Self::InsertRoleBinding { tenant, .. }
            | Self::DeleteRoleBinding { tenant, .. }
            | Self::InsertAuthorizationCode { tenant, .. }
            | Self::UpdateAuthorizationCode { tenant, .. }
            | Self::InsertConsent { tenant, .. }
            | Self::UpdateConsent { tenant, .. }
            | Self::InsertRefreshFamily { tenant, .. }
            | Self::UpdateRefreshFamily { tenant, .. }
            | Self::InsertRefreshToken { tenant, .. }
            | Self::UpdateRefreshToken { tenant, .. }
            | Self::AppendAudit { tenant, .. } => Some(tenant),
        }
    }

    /// Returns the entity kind affected by the command, for adapter diagnostics.
    pub const fn entity_kind(&self) -> EntityKind {
        match self {
            Self::InsertUser(_) | Self::UpdateUser { .. } => EntityKind::User,
            Self::InsertOrganization(_) | Self::UpdateOrganization { .. } => {
                EntityKind::Organization
            }
            Self::InsertMembership { .. } | Self::UpdateMembership { .. } => EntityKind::Membership,
            Self::InsertInvitation { .. } | Self::UpdateInvitation { .. } => EntityKind::Invitation,
            Self::InsertApplication { .. } | Self::UpdateApplication { .. } => {
                EntityKind::Application
            }
            Self::InsertOAuthClient { .. } | Self::UpdateOAuthClient { .. } => {
                EntityKind::OAuthClient
            }
            Self::InsertCredential(_) | Self::UpdateCredential { .. } => EntityKind::Credential,
            Self::InsertSession(_) | Self::UpdateSession { .. } => EntityKind::Session,
            Self::InsertRole { .. } | Self::UpdateRole { .. } => EntityKind::Role,
            Self::InsertRoleBinding { .. } | Self::DeleteRoleBinding { .. } => {
                EntityKind::RoleBinding
            }
            Self::InsertAuthorizationCode { .. } | Self::UpdateAuthorizationCode { .. } => {
                EntityKind::AuthorizationCode
            }
            Self::InsertConsent { .. } | Self::UpdateConsent { .. } => EntityKind::Consent,
            Self::InsertRefreshFamily { .. } | Self::UpdateRefreshFamily { .. } => {
                EntityKind::RefreshFamily
            }
            Self::InsertRefreshToken { .. } | Self::UpdateRefreshToken { .. } => {
                EntityKind::RefreshToken
            }
            Self::AppendAudit { .. } => EntityKind::AuditEvent,
        }
    }
}

/// The aggregate affected by a [`WriteCommand`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    /// A user identity.
    User,
    /// An organization.
    Organization,
    /// A membership.
    Membership,
    /// An invitation.
    Invitation,
    /// An application.
    Application,
    /// An OAuth client.
    OAuthClient,
    /// A credential.
    Credential,
    /// A session.
    Session,
    /// A role.
    Role,
    /// A role binding.
    RoleBinding,
    /// A one-time authorization code.
    AuthorizationCode,
    /// A consent record.
    Consent,
    /// A refresh-token family.
    RefreshFamily,
    /// A refresh token.
    RefreshToken,
    /// An audit event.
    AuditEvent,
}

/// An ordered, precomputed set of mutations committed as one atomic unit.
///
/// The order is significant for audit rows and for adapters that translate the batch into
/// statements. A batch is all-or-nothing: a guard failure or storage error rolls back every
/// command in the batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBatch {
    commands: Vec<WriteCommand>,
}

impl WriteBatch {
    /// Creates an empty batch.
    pub const fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    /// Appends a command and returns the batch for chaining.
    pub fn push(&mut self, command: WriteCommand) -> &mut Self {
        self.commands.push(command);
        self
    }

    /// Appends a command and returns the owned batch for chaining.
    pub fn with(mut self, command: WriteCommand) -> Self {
        self.commands.push(command);
        self
    }

    /// Returns the commands in submission order.
    pub fn commands(&self) -> &[WriteCommand] {
        &self.commands
    }

    /// Returns `true` when the batch contains no commands.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Returns the number of commands in the batch.
    pub fn len(&self) -> usize {
        self.commands.len()
    }
}

/// Executes a [`WriteBatch`] atomically.
///
/// Implementations must map the batch to one storage transaction or one D1 `batch()` call.
/// They must never partially apply a batch. A guard that does not match returns
/// [`WriteOutcome::Conflict`] or [`WriteOutcome::NotFound`] and leaves storage unchanged.
pub trait UnitOfWork {
    /// Commits every command in the batch or none of them.
    fn commit(&self, batch: &WriteBatch) -> Result<WriteOutcome, DomainError>;
}

/// Read and write access needed to provision an organization and its initial owner.
pub trait OrganizationProvisioning:
    crate::ports::UserRepository
    + crate::ports::OrganizationRepository
    + crate::ports::MembershipRepository
    + crate::ports::RoleRepository
    + crate::ports::RoleBindingRepository
    + UnitOfWork
{
}

impl<T> OrganizationProvisioning for T where
    T: crate::ports::UserRepository
        + crate::ports::OrganizationRepository
        + crate::ports::MembershipRepository
        + crate::ports::RoleRepository
        + crate::ports::RoleBindingRepository
        + UnitOfWork
{
}
