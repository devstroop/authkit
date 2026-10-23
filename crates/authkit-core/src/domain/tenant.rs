use crate::domain::id::{Id, OrganizationEntity};

/// The organization scope for a tenant-scoped operation.
///
/// Repository methods that touch tenant-owned data require this value. There is no ambient
/// "current organization"; callers must obtain and pass the context explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    organization_id: Id<OrganizationEntity>,
}

impl TenantContext {
    /// Creates a tenant context for an organization.
    pub const fn new(organization_id: Id<OrganizationEntity>) -> Self {
        Self { organization_id }
    }

    /// Returns the organization that owns the operation.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_organization_id() {
        let organization_id = Id::<OrganizationEntity>::from_suffix("0123456789abcdef")
            .expect("valid organization id");
        let context = TenantContext::new(organization_id.clone());
        assert_eq!(context.organization_id(), &organization_id);
    }
}
