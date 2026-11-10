use crate::domain::id::{ApplicationEntity, Id};

/// The organization scope for a tenant-scoped operation.
///
/// Repository methods that touch tenant-owned data require this value. There is no ambient
/// "current organization"; callers must obtain and pass the context explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    application_id: Id<ApplicationEntity>,
}

impl TenantContext {
    /// Creates a tenant context for an organization.
    pub const fn new(application_id: Id<ApplicationEntity>) -> Self {
        Self { application_id }
    }

    /// Returns the organization that owns the operation.
    pub const fn application_id(&self) -> &Id<ApplicationEntity> {
        &self.application_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_application_id() {
        let application_id = Id::<ApplicationEntity>::from_suffix("0123456789abcdef")
            .expect("valid organization id");
        let context = TenantContext::new(application_id.clone());
        assert_eq!(context.application_id(), &application_id);
    }
}
