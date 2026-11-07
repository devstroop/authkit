use crate::domain::DomainError;
use crate::domain::id::{Id, OneTimeTokenEntity, UserEntity};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneTimeTokenPurpose {
    PasswordReset,
    EmailVerification,
}

impl OneTimeTokenPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::EmailVerification => "email_verification",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "password_reset" => Ok(Self::PasswordReset),
            "email_verification" => Ok(Self::EmailVerification),
            _ => Err(DomainError::invalid("unknown one-time token purpose")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OneTimeToken {
    id: Id<OneTimeTokenEntity>,
    user_id: Id<UserEntity>,
    purpose: OneTimeTokenPurpose,
    token_hash: SecretHash,
    expires_at: Timestamp,
    consumed_at: Option<Timestamp>,
    created_at: Timestamp,
}

impl OneTimeToken {
    pub fn new(
        id: Id<OneTimeTokenEntity>,
        user_id: Id<UserEntity>,
        purpose: OneTimeTokenPurpose,
        token_hash: SecretHash,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if !created_at.is_before(expires_at) {
            return Err(DomainError::invalid("expiry must be after creation"));
        }
        Ok(Self {
            id,
            user_id,
            purpose,
            token_hash,
            expires_at,
            consumed_at: None,
            created_at,
        })
    }

    pub fn id(&self) -> &Id<OneTimeTokenEntity> {
        &self.id
    }
    pub fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }
    pub fn purpose(&self) -> OneTimeTokenPurpose {
        self.purpose
    }
    pub fn token_hash(&self) -> &SecretHash {
        &self.token_hash
    }
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    pub fn consumed_at(&self) -> Option<Timestamp> {
        self.consumed_at
    }
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub fn is_usable(&self, now: Timestamp) -> bool {
        self.consumed_at.is_none() && now.is_before(self.expires_at)
    }
    pub fn consume(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.consumed_at.is_some() {
            return Err(DomainError::conflict("token already consumed"));
        }
        self.consumed_at = Some(now);
        Ok(())
    }
    pub fn version(&self) -> u64 {
        1
    }
}
