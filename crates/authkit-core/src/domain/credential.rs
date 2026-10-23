use crate::domain::DomainError;
use crate::domain::id::{CredentialEntity, Id, UserEntity};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

/// The type of an authentication credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// An Argon2id password verifier.
    Password,
    /// A WebAuthn/passkey credential.
    Passkey,
    /// A TOTP shared-secret verifier.
    Totp,
}

/// The lifecycle state of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential may be used to authenticate.
    Active,
    /// The credential is temporarily disabled.
    Disabled,
    /// The credential is permanently revoked.
    Revoked,
}

/// A credential belonging to a user.
///
/// Plaintext secrets never enter the domain. The stored value is an opaque encoded verifier
/// produced by an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    id: Id<CredentialEntity>,
    user_id: Id<UserEntity>,
    kind: CredentialKind,
    secret_hash: SecretHash,
    status: CredentialStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    last_used_at: Option<Timestamp>,
    version: u64,
}

impl Credential {
    /// Creates an active credential.
    pub fn new(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        kind: CredentialKind,
        secret_hash: SecretHash,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            user_id,
            kind,
            secret_hash,
            status: CredentialStatus::Active,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            version: 0,
        }
    }

    /// Returns the credential identifier.
    pub const fn id(&self) -> &Id<CredentialEntity> {
        &self.id
    }

    /// Returns the owning user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the credential kind.
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// Returns the encoded verifier. Callers must not log this value.
    pub const fn secret_hash(&self) -> &SecretHash {
        &self.secret_hash
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> CredentialStatus {
        self.status
    }

    /// Returns `true` when the credential may authenticate.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, CredentialStatus::Active)
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the last mutation time.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Returns the last successful use time.
    pub const fn last_used_at(&self) -> Option<Timestamp> {
        self.last_used_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Records a successful authentication with this credential.
    pub fn record_use(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden("credential is not active"));
        }
        self.last_used_at = Some(now);
        self.touch(now);
        Ok(())
    }

    /// Replaces the encoded verifier.
    pub fn rotate_secret(
        &mut self,
        secret_hash: SecretHash,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        if matches!(self.status, CredentialStatus::Revoked) {
            return Err(DomainError::conflict(
                "a revoked credential cannot be rotated",
            ));
        }
        self.secret_hash = secret_hash;
        self.touch(now);
        Ok(())
    }

    /// Temporarily disables the credential.
    pub fn disable(&mut self, now: Timestamp) {
        if self.status == CredentialStatus::Active {
            self.status = CredentialStatus::Disabled;
            self.touch(now);
        }
    }

    /// Permanently revokes the credential.
    pub fn revoke(&mut self, now: Timestamp) {
        if self.status != CredentialStatus::Revoked {
            self.status = CredentialStatus::Revoked;
            self.touch(now);
        }
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Credential {
        Credential::new(
            Id::<CredentialEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            Id::<UserEntity>::from_suffix("fedcba9876543210").expect("valid id"),
            CredentialKind::Password,
            SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn records_use_only_while_active() {
        let mut credential = credential();
        credential
            .record_use(Timestamp::from_millis(2_000))
            .expect("active credential");
        assert_eq!(
            credential.last_used_at(),
            Some(Timestamp::from_millis(2_000))
        );
        credential.disable(Timestamp::from_millis(3_000));
        assert!(
            credential
                .record_use(Timestamp::from_millis(4_000))
                .is_err()
        );
    }

    #[test]
    fn revocation_is_terminal() {
        let mut credential = credential();
        credential.revoke(Timestamp::from_millis(2_000));
        credential.revoke(Timestamp::from_millis(3_000));
        assert_eq!(credential.status(), CredentialStatus::Revoked);
        assert_eq!(credential.version(), 1);
        assert!(
            credential
                .rotate_secret(
                    SecretHash::parse("sha256:fedcba9876543210").expect("valid hash"),
                    Timestamp::from_millis(4_000),
                )
                .is_err()
        );
    }
}
