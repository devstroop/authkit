use crate::domain::DomainError;
use crate::domain::id::{
    ApplicationEntity, Id, OrganizationEntity, RoleBindingEntity, RoleEntity, UserEntity,
};
use crate::domain::name::DisplayName;
use crate::domain::permission::{Permission, PermissionSet};
use crate::domain::slug::Slug;
use crate::domain::time::Timestamp;
use crate::domain::value::ValueError;

const MAX_DESCRIPTION_LEN: usize = 512;

const ORGANIZATION_READ: &str = "org.read";
const ORGANIZATION_MANAGE: &str = "org.manage";
const ORGANIZATION_DELETE: &str = "org.delete";
const MEMBER_READ: &str = "org.member.read";
const MEMBER_MANAGE: &str = "org.member.manage";
const ROLE_READ: &str = "org.role.read";
const ROLE_MANAGE: &str = "org.role.manage";
const APPLICATION_READ: &str = "org.application.read";
const APPLICATION_MANAGE: &str = "org.application.manage";
const CLIENT_MANAGE: &str = "org.client.manage";
const SESSION_MANAGE: &str = "org.session.manage";
const AUDIT_READ: &str = "org.audit.read";

/// The built-in role family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    /// Full control of the organization, including deletion and ownership changes.
    Owner,
    /// Administrative control except organization deletion.
    Admin,
    /// Read-only organization membership and application access.
    Member,
    /// A role defined by an organization administrator.
    Custom,
}

/// The scope in which a role is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScope {
    /// Applies across the organization.
    Organization,
    /// Applies only within one application.
    Application,
}

/// A named set of permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    id: Id<RoleEntity>,
    organization_id: Id<OrganizationEntity>,
    application_id: Option<Id<ApplicationEntity>>,
    slug: Slug,
    name: DisplayName,
    description: Option<String>,
    kind: RoleKind,
    permissions: PermissionSet,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Role {
    /// Creates a role after validating its scope and built-in rules.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id<RoleEntity>,
        organization_id: Id<OrganizationEntity>,
        application_id: Option<Id<ApplicationEntity>>,
        slug: Slug,
        name: DisplayName,
        description: Option<String>,
        kind: RoleKind,
        permissions: PermissionSet,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        if kind != RoleKind::Custom && application_id.is_some() {
            return Err(DomainError::invalid(
                "built-in roles must be scoped to the organization",
            ));
        }

        let description = validate_description(description)?;

        Ok(Self {
            id,
            organization_id,
            application_id,
            slug,
            name,
            description,
            kind,
            permissions,
            created_at: now,
            updated_at: now,
            version: 0,
        })
    }

    /// Creates a custom organization or application role.
    #[allow(clippy::too_many_arguments)]
    pub fn custom(
        id: Id<RoleEntity>,
        organization_id: Id<OrganizationEntity>,
        application_id: Option<Id<ApplicationEntity>>,
        slug: Slug,
        name: DisplayName,
        description: Option<String>,
        permissions: PermissionSet,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(
            id,
            organization_id,
            application_id,
            slug,
            name,
            description,
            RoleKind::Custom,
            permissions,
            now,
        )
    }

    /// Creates the built-in owner role.
    pub fn owner(
        id: Id<RoleEntity>,
        organization_id: Id<OrganizationEntity>,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(
            id,
            organization_id,
            None,
            Slug::parse("owner")?,
            DisplayName::parse("Owner")?,
            Some("Full control of the organization.".to_owned()),
            RoleKind::Owner,
            permission_set(&[
                ORGANIZATION_READ,
                ORGANIZATION_MANAGE,
                ORGANIZATION_DELETE,
                MEMBER_READ,
                MEMBER_MANAGE,
                ROLE_READ,
                ROLE_MANAGE,
                APPLICATION_READ,
                APPLICATION_MANAGE,
                CLIENT_MANAGE,
                SESSION_MANAGE,
                AUDIT_READ,
            ])?,
            now,
        )
    }

    /// Creates the built-in administrator role.
    pub fn admin(
        id: Id<RoleEntity>,
        organization_id: Id<OrganizationEntity>,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(
            id,
            organization_id,
            None,
            Slug::parse("admin")?,
            DisplayName::parse("Administrator")?,
            Some("Manage members, applications, and security settings.".to_owned()),
            RoleKind::Admin,
            permission_set(&[
                ORGANIZATION_READ,
                ORGANIZATION_MANAGE,
                MEMBER_READ,
                MEMBER_MANAGE,
                ROLE_READ,
                ROLE_MANAGE,
                APPLICATION_READ,
                APPLICATION_MANAGE,
                CLIENT_MANAGE,
                SESSION_MANAGE,
                AUDIT_READ,
            ])?,
            now,
        )
    }

    /// Creates the built-in member role.
    pub fn member(
        id: Id<RoleEntity>,
        organization_id: Id<OrganizationEntity>,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(
            id,
            organization_id,
            None,
            Slug::parse("member")?,
            DisplayName::parse("Member")?,
            Some("Read access to the organization and its applications.".to_owned()),
            RoleKind::Member,
            permission_set(&[ORGANIZATION_READ, APPLICATION_READ])?,
            now,
        )
    }

    /// Returns the role identifier.
    pub const fn id(&self) -> &Id<RoleEntity> {
        &self.id
    }

    /// Returns the owning organization.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the application scope, if the role is application-scoped.
    pub const fn application_id(&self) -> Option<&Id<ApplicationEntity>> {
        self.application_id.as_ref()
    }

    /// Returns the role scope.
    pub const fn scope(&self) -> RoleScope {
        if self.application_id.is_some() {
            RoleScope::Application
        } else {
            RoleScope::Organization
        }
    }

    /// Returns the slug.
    pub const fn slug(&self) -> &Slug {
        &self.slug
    }

    /// Returns the display name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// Returns the optional description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the built-in kind or `Custom`.
    pub const fn kind(&self) -> RoleKind {
        self.kind
    }

    /// Returns `true` when the role is built in and not administrator-defined.
    pub const fn is_builtin(&self) -> bool {
        !matches!(self.kind, RoleKind::Custom)
    }

    /// Returns the role permissions.
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
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

    /// Returns `true` when the role grants the permission.
    pub fn grants(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Renames a custom role.
    pub fn rename(&mut self, name: DisplayName, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_custom()?;
        self.name = name;
        self.touch(now);
        Ok(())
    }

    /// Replaces the description of a custom role.
    pub fn set_description(
        &mut self,
        description: Option<String>,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_custom()?;
        self.description = validate_description(description)?;
        self.touch(now);
        Ok(())
    }

    /// Adds a permission to a custom role.
    pub fn add_permission(
        &mut self,
        permission: Permission,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_custom()?;
        if self.permissions.contains(&permission) {
            return Err(DomainError::conflict("permission is already granted"));
        }
        let mut permissions = self.permissions.as_slice().to_vec();
        permissions.push(permission);
        self.permissions = PermissionSet::new(permissions);
        self.touch(now);
        Ok(())
    }

    /// Removes a permission from a custom role.
    pub fn remove_permission(
        &mut self,
        permission: &Permission,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_custom()?;
        if !self.permissions.contains(permission) {
            return Err(DomainError::not_found("permission is not granted"));
        }
        let permissions: Vec<Permission> = self
            .permissions
            .as_slice()
            .iter()
            .filter(|candidate| *candidate != permission)
            .cloned()
            .collect();
        self.permissions = PermissionSet::new(permissions);
        self.touch(now);
        Ok(())
    }

    fn ensure_custom(&self) -> Result<(), DomainError> {
        if self.is_builtin() {
            return Err(DomainError::conflict("built-in roles cannot be modified"));
        }
        Ok(())
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

fn permission_set(values: &[&str]) -> Result<PermissionSet, DomainError> {
    values
        .iter()
        .map(|value| Permission::parse(*value))
        .collect::<Result<PermissionSet, ValueError>>()
        .map_err(Into::into)
}

fn validate_description(description: Option<String>) -> Result<Option<String>, DomainError> {
    let Some(description) = description else {
        return Ok(None);
    };
    let description = description.trim().to_owned();
    if description.is_empty() {
        return Ok(None);
    }
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(ValueError::TooLong {
            field: "description",
            max: MAX_DESCRIPTION_LEN,
            actual: description.chars().count(),
        }
        .into());
    }
    if description.chars().any(char::is_control) {
        return Err(ValueError::InvalidFormat {
            field: "description",
            reason: "must not contain control characters",
        }
        .into());
    }
    Ok(Some(description))
}

/// A role granted to a user in an organization or application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBinding {
    id: Id<RoleBindingEntity>,
    organization_id: Id<OrganizationEntity>,
    application_id: Option<Id<ApplicationEntity>>,
    role_id: Id<RoleEntity>,
    user_id: Id<UserEntity>,
    created_at: Timestamp,
}

impl RoleBinding {
    /// Creates an organization-scoped binding.
    pub fn organization(
        id: Id<RoleBindingEntity>,
        organization_id: Id<OrganizationEntity>,
        role_id: Id<RoleEntity>,
        user_id: Id<UserEntity>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            application_id: None,
            role_id,
            user_id,
            created_at: now,
        }
    }

    /// Creates an application-scoped binding.
    #[allow(clippy::too_many_arguments)]
    pub fn application(
        id: Id<RoleBindingEntity>,
        organization_id: Id<OrganizationEntity>,
        application_id: Id<ApplicationEntity>,
        role_id: Id<RoleEntity>,
        user_id: Id<UserEntity>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            organization_id,
            application_id: Some(application_id),
            role_id,
            user_id,
            created_at: now,
        }
    }

    /// Returns the binding identifier.
    pub const fn id(&self) -> &Id<RoleBindingEntity> {
        &self.id
    }

    /// Returns the tenant.
    pub const fn organization_id(&self) -> &Id<OrganizationEntity> {
        &self.organization_id
    }

    /// Returns the application scope, if any.
    pub const fn application_id(&self) -> Option<&Id<ApplicationEntity>> {
        self.application_id.as_ref()
    }

    /// Returns the granted role.
    pub const fn role_id(&self) -> &Id<RoleEntity> {
        &self.role_id
    }

    /// Returns the user receiving the role.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization_id() -> Id<OrganizationEntity> {
        Id::<OrganizationEntity>::from_suffix("0123456789abcdef").expect("valid id")
    }

    fn role_id() -> Id<RoleEntity> {
        Id::<RoleEntity>::from_suffix("fedcba9876543210").expect("valid id")
    }

    #[test]
    fn built_in_owner_has_full_control() {
        let role = Role::owner(role_id(), organization_id(), Timestamp::from_millis(1_000))
            .expect("valid owner role");
        assert!(role.is_builtin());
        assert_eq!(role.scope(), RoleScope::Organization);
        assert!(role.grants(&Permission::parse("org.delete").expect("valid")));
        assert!(role.grants(&Permission::parse("org.audit.read").expect("valid")));
    }

    #[test]
    fn built_in_roles_cannot_be_modified() {
        let mut role = Role::admin(role_id(), organization_id(), Timestamp::from_millis(1_000))
            .expect("valid admin role");
        assert!(
            role.rename(
                DisplayName::parse("Super Admin").expect("valid"),
                Timestamp::from_millis(2_000),
            )
            .is_err()
        );
        assert!(
            role.add_permission(
                Permission::parse("org.delete").expect("valid"),
                Timestamp::from_millis(2_000),
            )
            .is_err()
        );
    }

    #[test]
    fn custom_roles_can_change_permissions() {
        let mut role = Role::custom(
            role_id(),
            organization_id(),
            None,
            Slug::parse("support").expect("valid slug"),
            DisplayName::parse("Support").expect("valid name"),
            None,
            PermissionSet::default(),
            Timestamp::from_millis(1_000),
        )
        .expect("valid custom role");
        let permission = Permission::parse("org.member.read").expect("valid");
        role.add_permission(permission.clone(), Timestamp::from_millis(2_000))
            .expect("add permission");
        assert!(role.grants(&permission));
        role.remove_permission(&permission, Timestamp::from_millis(3_000))
            .expect("remove permission");
        assert!(!role.grants(&permission));
    }

    #[test]
    fn application_roles_require_an_application() {
        let application_id =
            Id::<ApplicationEntity>::from_suffix("0011223344556677").expect("valid id");
        let role = Role::custom(
            role_id(),
            organization_id(),
            Some(application_id.clone()),
            Slug::parse("app-reader").expect("valid slug"),
            DisplayName::parse("App Reader").expect("valid name"),
            None,
            PermissionSet::default(),
            Timestamp::from_millis(1_000),
        )
        .expect("valid custom role");
        assert_eq!(role.scope(), RoleScope::Application);
        assert_eq!(role.application_id(), Some(&application_id));
    }

    #[test]
    fn bindings_record_their_scope() {
        let user_id = Id::<UserEntity>::from_suffix("8899aabbccddeeff").expect("valid id");
        let binding = RoleBinding::organization(
            Id::<RoleBindingEntity>::from_suffix("1122334455667788").expect("valid id"),
            organization_id(),
            role_id(),
            user_id,
            Timestamp::from_millis(1_000),
        );
        assert!(binding.application_id().is_none());
    }
}
