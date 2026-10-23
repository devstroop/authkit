use crate::domain::DomainError;
use crate::domain::id::{ApplicationEntity, Id, OrganizationEntity};
use crate::domain::name::DisplayName;
use crate::domain::slug::Slug;
use crate::domain::time::Timestamp;

/// The kind of product surface an application represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationKind {
    /// A browser-facing application.
    Web,
    /// An administrative console.
    Admin,
    /// A native desktop or mobile application.
    Native,
    /// A service-to-service integration.
    Service,
    /// A command-line client.
    Cli,
}

/// The lifecycle state of an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationStatus {
    /// The application may authorize and exchange tokens.
    Active,
    /// The application is blocked from new authorizations.
    Disabled,
}

/// A product surface owned by one organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    id: Id<ApplicationEntity>,
    organization_id: Id<OrganizationEntity>,
    slug: Slug,
    name: DisplayName,
    kind: ApplicationKind,
    first_party: bool,
    status: ApplicationStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Application {
    /// Creates an active application.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<ApplicationEntity>,
        organization_id: Id<OrganizationEntity>,
        slug: Slug,
        name: DisplayName,
        kind: ApplicationKind,
        first_party: bool,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            slug,
            name,
            kind,
            first_party,
            status: ApplicationStatus::Active,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// Returns the application identifier.
    pub const fn id(&self) -> &Id<ApplicationEntity> {
        &self.id
    }

    /// Returns the owning tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the slug unique within the organization.
    pub const fn slug(&self) -> &Slug {
        &self.slug
    }

    /// Returns the display name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// Returns the application kind.
    pub const fn kind(&self) -> ApplicationKind {
        self.kind
    }

    /// Returns `true` when the application is marked first-party.
    pub const fn is_first_party(&self) -> bool {
        self.first_party
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> ApplicationStatus {
        self.status
    }

    /// Returns `true` when the application may authorize new sessions.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ApplicationStatus::Active)
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

    /// Renames the application.
    pub fn rename(&mut self, name: DisplayName, now: Timestamp) {
        self.name = name;
        self.touch(now);
    }

    /// Changes the slug unique within the organization.
    pub fn change_slug(&mut self, slug: Slug, now: Timestamp) {
        self.slug = slug;
        self.touch(now);
    }

    /// Sets the first-party marker. This is a system-administration action.
    pub fn set_first_party(&mut self, first_party: bool, now: Timestamp) {
        if self.first_party != first_party {
            self.first_party = first_party;
            self.touch(now);
        }
    }

    /// Disables the application.
    pub fn disable(&mut self, now: Timestamp) {
        if self.status == ApplicationStatus::Active {
            self.status = ApplicationStatus::Disabled;
            self.touch(now);
        }
    }

    /// Enables a disabled application.
    pub fn enable(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.status == ApplicationStatus::Disabled {
            self.status = ApplicationStatus::Active;
            self.touch(now);
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

    fn application() -> Application {
        Application::new(
            Id::<ApplicationEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<OrganizationEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            Slug::parse("console").expect("valid slug"),
            DisplayName::parse("Console").expect("valid name"),
            ApplicationKind::Web,
            true,
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn starts_active_and_first_party() {
        let application = application();
        assert!(application.is_active());
        assert!(application.is_first_party());
        assert_eq!(application.version(), 0);
    }

    #[test]
    fn disable_and_enable_are_idempotent() {
        let mut application = application();
        application.disable(Timestamp::from_millis(2_000));
        application.disable(Timestamp::from_millis(3_000));
        assert_eq!(application.status(), ApplicationStatus::Disabled);
        assert_eq!(application.version(), 1);
        application
            .enable(Timestamp::from_millis(4_000))
            .expect("valid enable");
        assert!(application.is_active());
    }
}
