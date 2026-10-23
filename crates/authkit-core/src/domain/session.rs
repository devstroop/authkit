use crate::domain::DomainError;
use crate::domain::id::{Id, OrganizationEntity, SessionEntity, UserEntity};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

/// The audience a session may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAudience {
    /// The account UI and ordinary browser flows.
    Account,
    /// The system-administration plane.
    Admin,
}

/// The lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// The session may be used until its idle or absolute expiry.
    Active,
    /// The session has been explicitly revoked.
    Revoked,
}

/// A revocable authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    id: Id<SessionEntity>,
    user_id: Id<UserEntity>,
    organization_id: Option<Id<OrganizationEntity>>,
    audience: SessionAudience,
    token_hash: SecretHash,
    status: SessionStatus,
    created_at: Timestamp,
    last_seen_at: Timestamp,
    idle_expires_at: Timestamp,
    absolute_expires_at: Timestamp,
    revoked_at: Option<Timestamp>,
    rotated_from: Option<Id<SessionEntity>>,
    version: u64,
}

impl Session {
    /// Creates an active session with explicit idle and absolute expiries.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<SessionEntity>,
        user_id: Id<UserEntity>,
        organization_id: Option<Id<OrganizationEntity>>,
        audience: SessionAudience,
        token_hash: SecretHash,
        now: Timestamp,
        idle_expires_at: Timestamp,
        absolute_expires_at: Timestamp,
        rotated_from: Option<Id<SessionEntity>>,
    ) -> Result<Self, DomainError> {
        if !now.is_before(idle_expires_at) {
            return Err(DomainError::invalid(
                "session idle expiry must be after creation",
            ));
        }
        if idle_expires_at > absolute_expires_at {
            return Err(DomainError::invalid(
                "session idle expiry must not exceed absolute expiry",
            ));
        }

        Ok(Self {
            id,
            user_id,
            organization_id,
            audience,
            token_hash,
            status: SessionStatus::Active,
            created_at: now,
            last_seen_at: now,
            idle_expires_at,
            absolute_expires_at,
            revoked_at: None,
            rotated_from,
            version: 0,
        })
    }

    /// Returns the session identifier.
    pub const fn id(&self) -> &Id<SessionEntity> {
        &self.id
    }

    /// Returns the authenticated user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the optional organization scope.
    pub const fn organization_id(&self) -> Option<&Id<OrganizationEntity>> {
        self.organization_id.as_ref()
    }

    /// Returns the session audience.
    pub const fn audience(&self) -> SessionAudience {
        self.audience
    }

    /// Returns the encoded session-token verifier. Callers must not log this value.
    pub const fn token_hash(&self) -> &SecretHash {
        &self.token_hash
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> SessionStatus {
        self.status
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the last activity time.
    pub const fn last_seen_at(&self) -> Timestamp {
        self.last_seen_at
    }

    /// Returns the idle expiry.
    pub const fn idle_expires_at(&self) -> Timestamp {
        self.idle_expires_at
    }

    /// Returns the absolute expiry.
    pub const fn absolute_expires_at(&self) -> Timestamp {
        self.absolute_expires_at
    }

    /// Returns the revocation time, if revoked.
    pub const fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    /// Returns the session this one replaced during rotation, if any.
    pub const fn rotated_from(&self) -> Option<&Id<SessionEntity>> {
        self.rotated_from.as_ref()
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns `true` when the session is active and not expired at `now`.
    pub fn is_valid(&self, now: Timestamp) -> bool {
        matches!(self.status, SessionStatus::Active)
            && now.is_before(self.idle_expires_at)
            && now.is_before(self.absolute_expires_at)
    }

    /// Records activity and extends the idle expiry.
    pub fn touch(&mut self, now: Timestamp, idle_expires_at: Timestamp) -> Result<(), DomainError> {
        if !self.is_valid(now) {
            return Err(DomainError::unauthenticated("session is not active"));
        }
        if !now.is_before(idle_expires_at) {
            return Err(DomainError::invalid(
                "session idle expiry must be after the current time",
            ));
        }
        if idle_expires_at > self.absolute_expires_at {
            return Err(DomainError::invalid(
                "session idle expiry must not exceed absolute expiry",
            ));
        }

        self.last_seen_at = now;
        self.idle_expires_at = idle_expires_at;
        self.touch_version();
        Ok(())
    }

    /// Revokes the session. Repeated calls are idempotent.
    pub fn revoke(&mut self, now: Timestamp) {
        if self.status == SessionStatus::Active {
            self.status = SessionStatus::Revoked;
            self.revoked_at = Some(now);
            self.touch_version();
        }
    }

    fn touch_version(&mut self) {
        self.version = self.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new(
            Id::<SessionEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<UserEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            None,
            SessionAudience::Account,
            SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(2_000),
            Timestamp::from_millis(10_000),
            None,
        )
        .expect("valid session")
    }

    #[test]
    fn validates_expiry_order() {
        let result = Session::new(
            Id::<SessionEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<UserEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            None,
            SessionAudience::Account,
            SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
            Timestamp::from_millis(1_000),
            Timestamp::from_millis(500),
            Timestamp::from_millis(10_000),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn expires_at_idle_and_absolute_boundaries() {
        let session = session();
        assert!(session.is_valid(Timestamp::from_millis(1_999)));
        assert!(!session.is_valid(Timestamp::from_millis(2_000)));
    }

    #[test]
    fn touch_extends_idle_expiry_within_absolute_limit() {
        let mut session = session();
        session
            .touch(Timestamp::from_millis(1_500), Timestamp::from_millis(3_000))
            .expect("valid touch");
        assert_eq!(session.last_seen_at(), Timestamp::from_millis(1_500));
        assert_eq!(session.idle_expires_at(), Timestamp::from_millis(3_000));
        assert!(
            session
                .touch(
                    Timestamp::from_millis(1_600),
                    Timestamp::from_millis(11_000)
                )
                .is_err()
        );
    }

    #[test]
    fn revocation_is_idempotent() {
        let mut session = session();
        session.revoke(Timestamp::from_millis(1_500));
        session.revoke(Timestamp::from_millis(1_600));
        assert_eq!(session.status(), SessionStatus::Revoked);
        assert_eq!(session.version(), 1);
        assert!(!session.is_valid(Timestamp::from_millis(1_700)));
    }
}
