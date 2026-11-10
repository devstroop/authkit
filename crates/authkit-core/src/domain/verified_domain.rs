use crate::domain::DomainError;
use crate::domain::id::{ApplicationEntity, DomainEntity, Id};
use crate::domain::time::Timestamp;

/// A verified (or pending) email domain belonging to an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    id: Id<DomainEntity>,
    application_id: Id<ApplicationEntity>,
    domain: String,
    verification_token: String,
    verified_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

#[allow(clippy::too_many_arguments)]
impl Domain {
    pub fn new(
        id: Id<DomainEntity>,
        application_id: Id<ApplicationEntity>,
        domain: String,
        verification_token: String,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        if domain.is_empty() {
            return Err(DomainError::invalid("domain must not be empty"));
        }
        Ok(Self {
            id,
            application_id,
            domain,
            verification_token,
            verified_at: None,
            created_at: now,
            updated_at: now,
            version: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<DomainEntity>,
        application_id: Id<ApplicationEntity>,
        domain: String,
        verification_token: String,
        verified_at: Option<Timestamp>,
        created_at: Timestamp,
        updated_at: Timestamp,
        version: u64,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id,
            application_id,
            domain,
            verification_token,
            verified_at,
            created_at,
            updated_at,
            version,
        })
    }

    pub const fn id(&self) -> &Id<DomainEntity> {
        &self.id
    }
    pub const fn application_id(&self) -> &Id<ApplicationEntity> {
        &self.application_id
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn verification_token(&self) -> &str {
        &self.verification_token
    }
    pub const fn verified_at(&self) -> Option<Timestamp> {
        self.verified_at
    }
    pub const fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
    pub const fn version(&self) -> u64 {
        self.version
    }

    pub fn mark_verified(&mut self, now: Timestamp) {
        if self.verified_at.is_none() {
            self.verified_at = Some(now);
            self.updated_at = now;
            self.version = self.version.saturating_add(1);
        }
    }

    pub fn revoke(&mut self, now: Timestamp) {
        self.verified_at = None;
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_domain_unverified() {
        let d = Domain::new(
            Id::<DomainEntity>::from_suffix("0123456789abcdef").unwrap(),
            Id::<ApplicationEntity>::from_suffix("0123456789abcdef").unwrap(),
            "example.com".to_owned(),
            "token".to_owned(),
            Timestamp::from_millis(1000),
        )
        .unwrap();
        assert!(!d.is_verified());
    }
}
