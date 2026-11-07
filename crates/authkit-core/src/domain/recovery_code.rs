use crate::domain::DomainError;
use crate::domain::id::{Id, RecoveryCodeEntity, UserEntity};
use crate::domain::secret::SecretHash;
use crate::domain::time::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    id: Id<RecoveryCodeEntity>,
    user_id: Id<UserEntity>,
    code_hash: SecretHash,
    used_at: Option<Timestamp>,
    created_at: Timestamp,
    version: u64,
}

impl RecoveryCode {
    pub fn new(id: Id<RecoveryCodeEntity>, user_id: Id<UserEntity>, code_hash: SecretHash, now: Timestamp) -> Self {
        Self { id, user_id, code_hash, used_at: None, created_at: now, version: 0 }
    }
    pub fn restore(id: Id<RecoveryCodeEntity>, user_id: Id<UserEntity>, code_hash: SecretHash, used_at: Option<Timestamp>, created_at: Timestamp, version: u64) -> Result<Self, DomainError> {
        if let Some(used_at) = used_at && used_at < created_at {
            return Err(DomainError::invalid("recovery code used_at must not precede creation"));
        }
        Ok(Self { id, user_id, code_hash, used_at, created_at, version })
    }
    pub const fn id(&self) -> &Id<RecoveryCodeEntity> { &self.id }
    pub const fn user_id(&self) -> &Id<UserEntity> { &self.user_id }
    pub const fn code_hash(&self) -> &SecretHash { &self.code_hash }
    pub const fn used_at(&self) -> Option<Timestamp> { self.used_at }
    pub const fn created_at(&self) -> Timestamp { self.created_at }
    pub const fn version(&self) -> u64 { self.version }
    pub const fn is_used(&self) -> bool { self.used_at.is_some() }
    pub fn mark_used(&mut self, now: Timestamp) {
        if self.used_at.is_none() {
            self.used_at = Some(now);
            self.version = self.version.saturating_add(1);
        }
    }
}
