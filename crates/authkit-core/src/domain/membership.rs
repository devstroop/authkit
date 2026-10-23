use crate::domain::DomainError;
use crate::domain::id::{Id, MembershipEntity, OrganizationEntity, UserEntity};
use crate::domain::time::Timestamp;

/// The lifecycle state of a membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    /// The invitation has not been accepted.
    Invited,
    /// The member may exercise organization permissions.
    Active,
    /// The member is temporarily blocked.
    Suspended,
    /// The membership has been removed.
    Removed,
}

/// A user's membership in an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    id: Id<MembershipEntity>,
    organization_id: Id<OrganizationEntity>,
    user_id: Id<UserEntity>,
    status: MembershipStatus,
    invited_by: Option<Id<UserEntity>>,
    joined_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Membership {
    /// Creates an unaccepted invitation state.
    pub fn invited(
        id: Id<MembershipEntity>,
        organization_id: Id<OrganizationEntity>,
        user_id: Id<UserEntity>,
        invited_by: Option<Id<UserEntity>>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            user_id,
            status: MembershipStatus::Invited,
            invited_by,
            joined_at: None,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// Creates an active membership.
    pub fn active(
        id: Id<MembershipEntity>,
        organization_id: Id<OrganizationEntity>,
        user_id: Id<UserEntity>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            user_id,
            status: MembershipStatus::Active,
            invited_by: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// Returns the membership identifier.
    pub const fn id(&self) -> &Id<MembershipEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the member.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> MembershipStatus {
        self.status
    }

    /// Returns `true` when the membership grants organization permissions.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, MembershipStatus::Active)
    }

    /// Returns who invited the user, when known.
    pub const fn invited_by(&self) -> Option<&Id<UserEntity>> {
        self.invited_by.as_ref()
    }

    /// Returns when the user joined, if ever.
    pub const fn joined_at(&self) -> Option<Timestamp> {
        self.joined_at
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

    /// Accepts an invitation or reactivates a suspended membership.
    pub fn activate(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            MembershipStatus::Active => Ok(()),
            MembershipStatus::Invited | MembershipStatus::Suspended => {
                self.status = MembershipStatus::Active;
                if self.joined_at.is_none() {
                    self.joined_at = Some(now);
                }
                self.touch(now);
                Ok(())
            }
            MembershipStatus::Removed => Err(DomainError::conflict(
                "a removed membership cannot be reactivated",
            )),
        }
    }

    /// Suspends an active membership.
    pub fn suspend(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            MembershipStatus::Active => {
                self.status = MembershipStatus::Suspended;
                self.touch(now);
                Ok(())
            }
            MembershipStatus::Suspended => Ok(()),
            MembershipStatus::Invited | MembershipStatus::Removed => Err(DomainError::conflict(
                "only an active membership can be suspended",
            )),
        }
    }

    /// Removes the membership. This is a one-way state transition.
    pub fn remove(&mut self, now: Timestamp) {
        if self.status != MembershipStatus::Removed {
            self.status = MembershipStatus::Removed;
            self.touch(now);
        }
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

/// Guards the last-owner invariant.
///
/// The caller supplies the number of active owners in the organization and whether the
/// target is one of them. The check is a domain rule; the storage adapter must make the
/// count and the write atomic with a guarded batch.
pub fn ensure_owner_remains(
    active_owner_count: u64,
    target_is_active_owner: bool,
) -> Result<(), DomainError> {
    if target_is_active_owner && active_owner_count <= 1 {
        return Err(DomainError::conflict(
            "the last active owner cannot be removed or demoted",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership() -> Membership {
        Membership::active(
            Id::<MembershipEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Id::<UserEntity>::from_suffix("0011223344556677").expect("valid id"),
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn invited_members_are_not_active() {
        let membership = Membership::invited(
            Id::<MembershipEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Id::<UserEntity>::from_suffix("0011223344556677").expect("valid id"),
            None,
            Timestamp::from_millis(1_000),
        );
        assert!(!membership.is_active());
        assert!(membership.joined_at().is_none());
    }

    #[test]
    fn activation_records_join_time_once() {
        let mut membership = Membership::invited(
            Id::<MembershipEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Id::<UserEntity>::from_suffix("0011223344556677").expect("valid id"),
            None,
            Timestamp::from_millis(1_000),
        );
        membership
            .activate(Timestamp::from_millis(2_000))
            .expect("valid activation");
        membership
            .activate(Timestamp::from_millis(3_000))
            .expect("idempotent activation");
        assert_eq!(membership.joined_at(), Some(Timestamp::from_millis(2_000)));
    }

    #[test]
    fn removed_memberships_cannot_return() {
        let mut membership = membership();
        membership.remove(Timestamp::from_millis(2_000));
        assert!(membership.activate(Timestamp::from_millis(3_000)).is_err());
        assert!(membership.suspend(Timestamp::from_millis(3_000)).is_err());
    }

    #[test]
    fn last_owner_cannot_be_removed() {
        assert!(ensure_owner_remains(1, true).is_err());
        assert!(ensure_owner_remains(2, true).is_ok());
        assert!(ensure_owner_remains(1, false).is_ok());
    }
}
