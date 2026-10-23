use crate::domain::DomainError;
use crate::domain::email::Email;
use crate::domain::id::{Id, InvitationEntity, OrganizationEntity, RoleEntity, UserEntity};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

/// The lifecycle state of an organization invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationStatus {
    /// The invitation may still be accepted.
    Pending,
    /// The invitation has been accepted.
    Accepted,
    /// The invitation was revoked by an administrator.
    Revoked,
}

/// A pending invitation to join an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    id: Id<InvitationEntity>,
    organization_id: Id<OrganizationEntity>,
    email: Email,
    token_hash: SecretHash,
    role_ids: Vec<Id<RoleEntity>>,
    invited_by: Id<UserEntity>,
    status: InvitationStatus,
    expires_at: Timestamp,
    accepted_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Invitation {
    /// Creates a pending invitation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<InvitationEntity>,
        organization_id: Id<OrganizationEntity>,
        email: Email,
        token_hash: SecretHash,
        role_ids: Vec<Id<RoleEntity>>,
        invited_by: Id<UserEntity>,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if role_ids.is_empty() {
            return Err(DomainError::invalid(
                "an invitation must include at least one role",
            ));
        }
        if !now.is_before(expires_at) {
            return Err(DomainError::invalid(
                "invitation expiry must be after creation",
            ));
        }

        let mut unique_roles: Vec<Id<RoleEntity>> = Vec::with_capacity(role_ids.len());
        for role_id in role_ids {
            if !unique_roles.contains(&role_id) {
                unique_roles.push(role_id);
            }
        }

        Ok(Self {
            id,
            organization_id,
            email,
            token_hash,
            role_ids: unique_roles,
            invited_by,
            status: InvitationStatus::Pending,
            expires_at,
            accepted_at: None,
            created_at: now,
            updated_at: now,
            version: 0,
        })
    }

    /// Returns the invitation identifier.
    pub const fn id(&self) -> &Id<InvitationEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the invited email address.
    pub const fn email(&self) -> &Email {
        &self.email
    }

    /// Returns the encoded invitation-token verifier. Callers must not log this value.
    pub const fn token_hash(&self) -> &SecretHash {
        &self.token_hash
    }

    /// Returns the roles granted on acceptance.
    pub fn role_ids(&self) -> &[Id<RoleEntity>] {
        &self.role_ids
    }

    /// Returns the inviter.
    pub const fn invited_by(&self) -> &Id<UserEntity> {
        &self.invited_by
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> InvitationStatus {
        self.status
    }

    /// Returns the expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns the acceptance time, if accepted.
    pub const fn accepted_at(&self) -> Option<Timestamp> {
        self.accepted_at
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

    /// Returns `true` when the invitation is pending and not expired.
    pub fn is_usable(&self, now: Timestamp) -> bool {
        matches!(self.status, InvitationStatus::Pending) && now.is_before(self.expires_at)
    }

    /// Accepts the invitation.
    pub fn accept(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.status != InvitationStatus::Pending {
            return Err(DomainError::conflict("invitation is not pending"));
        }
        if !now.is_before(self.expires_at) {
            return Err(DomainError::conflict("invitation has expired"));
        }
        self.status = InvitationStatus::Accepted;
        self.accepted_at = Some(now);
        self.touch(now);
        Ok(())
    }

    /// Revokes a pending invitation.
    pub fn revoke(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.status != InvitationStatus::Pending {
            return Err(DomainError::conflict("invitation is not pending"));
        }
        self.status = InvitationStatus::Revoked;
        self.touch(now);
        Ok(())
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitation(now: Timestamp, expires_at: Timestamp) -> Invitation {
        Invitation::new(
            Id::<InvitationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Email::parse("alice@example.com").expect("valid email"),
            SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
            vec![Id::<RoleEntity>::from_suffix("0011223344556677").expect("valid id")],
            Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id"),
            now,
            expires_at,
        )
        .expect("valid invitation")
    }

    #[test]
    fn requires_a_future_expiry_and_roles() {
        let now = Timestamp::from_millis(1_000);
        assert!(
            Invitation::new(
                Id::<InvitationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
                Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
                Email::parse("alice@example.com").expect("valid email"),
                SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
                Vec::new(),
                Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id"),
                now,
                Timestamp::from_millis(2_000),
            )
            .is_err()
        );
        assert!(
            Invitation::new(
                Id::<InvitationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
                Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
                Email::parse("alice@example.com").expect("valid email"),
                SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
                vec![Id::<RoleEntity>::from_suffix("0011223344556677").expect("valid id")],
                Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id"),
                now,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_only_before_expiry() {
        let mut invitation =
            invitation(Timestamp::from_millis(1_000), Timestamp::from_millis(2_000));
        assert!(invitation.is_usable(Timestamp::from_millis(1_500)));
        assert!(invitation.accept(Timestamp::from_millis(2_000)).is_err());
        invitation
            .accept(Timestamp::from_millis(1_500))
            .expect("valid acceptance");
        assert_eq!(invitation.status(), InvitationStatus::Accepted);
        assert_eq!(
            invitation.accepted_at(),
            Some(Timestamp::from_millis(1_500))
        );
    }

    #[test]
    fn duplicate_roles_are_removed() {
        let role = Id::<RoleEntity>::from_suffix("0011223344556677").expect("valid id");
        let invitation = Invitation::new(
            Id::<InvitationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Email::parse("alice@example.com").expect("valid email"),
            SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
            vec![role.clone(), role.clone()],
            Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id"),
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(2_000),
        )
        .expect("valid invitation");
        assert_eq!(invitation.role_ids().len(), 1);
    }
}
