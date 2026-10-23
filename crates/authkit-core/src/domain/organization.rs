use crate::domain::DomainError;
use crate::domain::id::{Id, OrganizationEntity};
use crate::domain::name::DisplayName;
use crate::domain::slug::Slug;
use crate::domain::time::Timestamp;

/// The lifecycle state of an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationStatus {
    /// The tenant may authorize users and accept administrative changes.
    Active,
    /// The tenant is blocked from new authorizations and changes.
    Suspended,
    /// The tenant is retained for audit and deletion processing.
    Deleted,
}

/// An organization, the tenant boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    id: Id<OrganizationEntity>,
    slug: Slug,
    name: DisplayName,
    status: OrganizationStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Organization {
    /// Creates an active organization.
    pub fn new(id: Id<OrganizationEntity>, slug: Slug, name: DisplayName, now: Timestamp) -> Self {
        Self {
            id,
            slug,
            name,
            status: OrganizationStatus::Active,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// Returns the organization identifier.
    pub const fn id(&self) -> &Id<OrganizationEntity> {
        &self.id
    }

    /// Returns the public slug.
    pub const fn slug(&self) -> &Slug {
        &self.slug
    }

    /// Returns the display name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Returns `true` when the tenant is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, OrganizationStatus::Active)
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

    /// Renames the organization.
    pub fn rename(&mut self, name: DisplayName, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        self.name = name;
        self.touch(now);
        Ok(())
    }

    /// Changes the public slug.
    pub fn change_slug(&mut self, slug: Slug, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        self.slug = slug;
        self.touch(now);
        Ok(())
    }

    /// Suspends an active organization.
    pub fn suspend(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            OrganizationStatus::Active => {
                self.status = OrganizationStatus::Suspended;
                self.touch(now);
                Ok(())
            }
            OrganizationStatus::Suspended => Ok(()),
            OrganizationStatus::Deleted => Err(DomainError::conflict(
                "a deleted organization cannot be suspended",
            )),
        }
    }

    /// Returns a suspended organization to active use.
    pub fn activate(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            OrganizationStatus::Suspended => {
                self.status = OrganizationStatus::Active;
                self.touch(now);
                Ok(())
            }
            OrganizationStatus::Active => Ok(()),
            OrganizationStatus::Deleted => Err(DomainError::conflict(
                "a deleted organization cannot be reactivated",
            )),
        }
    }

    /// Marks the organization as deleted. This is a one-way state transition.
    pub fn mark_deleted(&mut self, now: Timestamp) {
        if self.status != OrganizationStatus::Deleted {
            self.status = OrganizationStatus::Deleted;
            self.touch(now);
        }
    }

    fn ensure_mutable(&self) -> Result<(), DomainError> {
        if self.status == OrganizationStatus::Deleted {
            return Err(DomainError::conflict(
                "a deleted organization cannot be modified",
            ));
        }
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

    fn organization() -> Organization {
        Organization::new(
            Id::<OrganizationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Slug::parse("acme").expect("valid slug"),
            DisplayName::parse("Acme").expect("valid name"),
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn starts_active() {
        let organization = organization();
        assert!(organization.is_active());
        assert_eq!(organization.version(), 0);
    }

    #[test]
    fn deleted_organizations_cannot_return_to_active_use() {
        let mut organization = organization();
        organization.mark_deleted(Timestamp::from_millis(2_000));
        assert_eq!(organization.status(), OrganizationStatus::Deleted);
        assert!(
            organization
                .activate(Timestamp::from_millis(3_000))
                .is_err()
        );
        assert!(organization.suspend(Timestamp::from_millis(3_000)).is_err());
    }

    #[test]
    fn mutations_bump_the_version() {
        let mut organization = organization();
        organization
            .rename(
                DisplayName::parse("Acme Platform").expect("valid name"),
                Timestamp::from_millis(2_000),
            )
            .expect("mutable organization");
        assert_eq!(organization.version(), 1);
        assert_eq!(organization.updated_at(), Timestamp::from_millis(2_000));
    }
}
