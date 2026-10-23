use crate::domain::DomainError;
use crate::domain::email::Email;
use crate::domain::id::{Id, UserEntity};
use crate::domain::name::DisplayName;
use crate::domain::time::Timestamp;

/// The lifecycle state of a user identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// The user may authenticate and use active memberships.
    Active,
    /// The user may not authenticate; existing sessions are revoked by the application.
    Suspended,
    /// The user is retained for audit and deletion processing but cannot return to active use.
    Deleted,
}

/// A deployment-global user identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    id: Id<UserEntity>,
    email: Email,
    email_verified_at: Option<Timestamp>,
    display_name: DisplayName,
    status: UserStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl User {
    /// Creates an active, unverified user.
    pub fn new(
        id: Id<UserEntity>,
        email: Email,
        display_name: DisplayName,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            email,
            email_verified_at: None,
            display_name,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    /// Reconstructs a user from persisted state.
    ///
    /// Storage adapters use this; normal callers create users through [`User::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<UserEntity>,
        email: Email,
        email_verified_at: Option<Timestamp>,
        display_name: DisplayName,
        status: UserStatus,
        created_at: Timestamp,
        updated_at: Timestamp,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "user updated_at must not precede created_at",
            ));
        }
        if let Some(verified_at) = email_verified_at
            && verified_at < created_at
        {
            return Err(DomainError::invalid(
                "user verification must not precede creation",
            ));
        }

        Ok(Self {
            id,
            email,
            email_verified_at,
            display_name,
            status,
            created_at,
            updated_at,
            version,
        })
    }

    /// Returns the user identifier.
    pub const fn id(&self) -> &Id<UserEntity> {
        &self.id
    }

    /// Returns the normalized email address.
    pub const fn email(&self) -> &Email {
        &self.email
    }

    /// Returns when the current email was verified, if ever.
    pub const fn email_verified_at(&self) -> Option<Timestamp> {
        self.email_verified_at
    }

    /// Returns `true` when the current email has been verified.
    pub const fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    /// Returns the display name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> UserStatus {
        self.status
    }

    /// Returns `true` when the user may authenticate.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active)
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

    /// Marks the current email as verified.
    ///
    /// Returns `true` when verification was recorded and `false` when it was already
    /// present. The timestamp records the first successful verification.
    pub fn verify_email(&mut self, now: Timestamp) -> Result<bool, DomainError> {
        self.ensure_mutable()?;
        if self.email_verified_at.is_some() {
            return Ok(false);
        }
        self.email_verified_at = Some(now);
        self.touch(now);
        Ok(true)
    }

    /// Changes the email address and clears verification.
    pub fn change_email(&mut self, email: Email, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        self.email = email;
        self.email_verified_at = None;
        self.touch(now);
        Ok(())
    }

    /// Renames the user.
    pub fn rename(&mut self, display_name: DisplayName, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        self.display_name = display_name;
        self.touch(now);
        Ok(())
    }

    /// Suspends an active user.
    pub fn suspend(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            UserStatus::Active => {
                self.status = UserStatus::Suspended;
                self.touch(now);
                Ok(())
            }
            UserStatus::Suspended => Ok(()),
            UserStatus::Deleted => Err(DomainError::conflict("a deleted user cannot be suspended")),
        }
    }

    /// Returns a suspended user to active use.
    pub fn activate(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            UserStatus::Suspended => {
                self.status = UserStatus::Active;
                self.touch(now);
                Ok(())
            }
            UserStatus::Active => Ok(()),
            UserStatus::Deleted => Err(DomainError::conflict(
                "a deleted user cannot be reactivated",
            )),
        }
    }

    /// Marks the user as deleted. This is a one-way state transition.
    pub fn mark_deleted(&mut self, now: Timestamp) {
        if self.status != UserStatus::Deleted {
            self.status = UserStatus::Deleted;
            self.touch(now);
        }
    }

    fn ensure_mutable(&self) -> Result<(), DomainError> {
        if self.status == UserStatus::Deleted {
            return Err(DomainError::conflict("a deleted user cannot be modified"));
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

    fn user() -> User {
        User::new(
            Id::<UserEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Email::parse("alice@example.com").expect("valid email"),
            DisplayName::parse("Alice").expect("valid name"),
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn new_user_is_active_and_unverified() {
        let user = user();
        assert!(user.is_active());
        assert!(!user.is_email_verified());
        assert_eq!(user.version(), 0);
    }

    #[test]
    fn verification_is_recorded_once() {
        let mut user = user();
        assert!(
            user.verify_email(Timestamp::from_millis(2_000))
                .expect("mutable user")
        );
        assert!(
            !user
                .verify_email(Timestamp::from_millis(3_000))
                .expect("mutable user")
        );
        assert_eq!(
            user.email_verified_at(),
            Some(Timestamp::from_millis(2_000))
        );
        assert_eq!(user.version(), 1);
    }

    #[test]
    fn changing_email_clears_verification() {
        let mut user = user();
        user.verify_email(Timestamp::from_millis(2_000))
            .expect("mutable user");
        user.change_email(
            Email::parse("bob@example.com").expect("valid email"),
            Timestamp::from_millis(3_000),
        )
        .expect("mutable user");
        assert_eq!(user.email().as_str(), "bob@example.com");
        assert!(!user.is_email_verified());
        assert_eq!(user.version(), 2);
    }

    #[test]
    fn deleted_users_cannot_return_to_active_use() {
        let mut user = user();
        user.mark_deleted(Timestamp::from_millis(2_000));
        assert_eq!(user.status(), UserStatus::Deleted);
        assert!(user.activate(Timestamp::from_millis(3_000)).is_err());
        assert!(user.suspend(Timestamp::from_millis(3_000)).is_err());
        assert!(user.verify_email(Timestamp::from_millis(3_000)).is_err());
        assert!(
            user.rename(
                DisplayName::parse("Deleted").expect("valid name"),
                Timestamp::from_millis(3_000),
            )
            .is_err()
        );
    }
}
