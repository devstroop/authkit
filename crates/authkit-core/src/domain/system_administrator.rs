use crate::domain::DomainError;
use crate::domain::id::{Id, SystemAdministratorEntity, UserEntity};
use crate::domain::time::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemAdministratorStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemAdministratorRole {
    SuperAdmin,
    Auditor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemAdministrator {
    id: Id<SystemAdministratorEntity>,
    user_id: Id<UserEntity>,
    created_by: Option<Id<UserEntity>>,
    status: SystemAdministratorStatus,
    role: SystemAdministratorRole,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl SystemAdministrator {
    pub fn new(
        id: Id<SystemAdministratorEntity>,
        user_id: Id<UserEntity>,
        created_by: Option<Id<UserEntity>>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            user_id,
            created_by,
            status: SystemAdministratorStatus::Active,
            role: SystemAdministratorRole::SuperAdmin,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    pub fn restore(
        id: Id<SystemAdministratorEntity>,
        user_id: Id<UserEntity>,
        created_by: Option<Id<UserEntity>>,
        status: SystemAdministratorStatus,
        role: SystemAdministratorRole,
        created_at: Timestamp,
        updated_at: Timestamp,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "system administrator updated_at must not precede created_at",
            ));
        }
        Ok(Self {
            id,
            user_id,
            created_by,
            status,
            role,
            created_at,
            updated_at,
            version,
        })
    }

    pub const fn id(&self) -> &Id<SystemAdministratorEntity> {
        &self.id
    }
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }
    pub const fn created_by(&self) -> Option<&Id<UserEntity>> {
        self.created_by.as_ref()
    }
    pub const fn status(&self) -> SystemAdministratorStatus {
        self.status
    }
    pub const fn role(&self) -> SystemAdministratorRole {
        self.role
    }
    pub const fn is_super_admin(&self) -> bool {
        matches!(self.role, SystemAdministratorRole::SuperAdmin)
    }
    pub const fn is_active(&self) -> bool {
        matches!(self.status, SystemAdministratorStatus::Active)
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

    pub fn disable(&mut self, now: Timestamp) {
        if self.status != SystemAdministratorStatus::Disabled {
            self.status = SystemAdministratorStatus::Disabled;
            self.updated_at = now;
            self.version = self.version.saturating_add(1);
        }
    }

    pub fn enable(&mut self, now: Timestamp) {
        if self.status != SystemAdministratorStatus::Active {
            self.status = SystemAdministratorStatus::Active;
            self.updated_at = now;
            self.version = self.version.saturating_add(1);
        }
    }
}

pub fn ensure_system_admin_remains(
    active_count: u64,
    target_is_active: bool,
) -> Result<(), DomainError> {
    if target_is_active && active_count <= 1 {
        return Err(DomainError::conflict(
            "the last active system administrator cannot be disabled",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_bumps_version() {
        let mut admin = SystemAdministrator::new(
            Id::<SystemAdministratorEntity>::from_suffix("0123456789abcdef").expect("id"),
            Id::<UserEntity>::from_suffix("fedcba9876543210").expect("id"),
            None,
            Timestamp::from_millis(1),
        );
        admin.disable(Timestamp::from_millis(2));
        assert!(!admin.is_active());
        assert_eq!(admin.version(), 1);
    }
}
