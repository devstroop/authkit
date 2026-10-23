use core::fmt;

use crate::domain::value::ValueError;

const MAX_PERMISSION_LEN: usize = 128;
const MAX_SEGMENT_LEN: usize = 32;

/// A granular authorization permission.
///
/// Permissions use a dotted namespace such as `organization.members.read`. They are stable
/// strings: renaming one is a migration, not a display change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Permission(String);

impl Permission {
    /// Parses a permission name.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "permission",
            });
        }
        if value.len() > MAX_PERMISSION_LEN {
            return Err(ValueError::TooLong {
                field: "permission",
                max: MAX_PERMISSION_LEN,
                actual: value.len(),
            });
        }
        if !value.is_ascii() {
            return Err(ValueError::InvalidFormat {
                field: "permission",
                reason: "must use ASCII characters",
            });
        }

        let segments: Vec<&str> = value.split('.').collect();
        if segments.len() < 2 {
            return Err(ValueError::InvalidFormat {
                field: "permission",
                reason: "must have at least two dot-separated segments",
            });
        }

        for segment in segments {
            if segment.is_empty() {
                return Err(ValueError::InvalidFormat {
                    field: "permission",
                    reason: "must not contain empty segments",
                });
            }
            if segment.len() > MAX_SEGMENT_LEN {
                return Err(ValueError::InvalidFormat {
                    field: "permission",
                    reason: "segments must be at most 32 characters",
                });
            }
            let mut bytes = segment.bytes();
            let first = bytes.next().unwrap_or_default();
            if !first.is_ascii_lowercase() {
                return Err(ValueError::InvalidFormat {
                    field: "permission",
                    reason: "segments must start with a lowercase letter",
                });
            }
            if !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            }) {
                return Err(ValueError::InvalidFormat {
                    field: "permission",
                    reason: "segments may contain only lowercase letters, digits, _ and -",
                });
            }
        }

        Ok(Self(value))
    }

    /// Returns the permission name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Permission {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A de-duplicated, order-preserving set of permissions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionSet(Vec<Permission>);

impl PermissionSet {
    /// Creates a set, dropping duplicates while preserving first-seen order.
    pub fn new(permissions: impl IntoIterator<Item = Permission>) -> Self {
        let mut values: Vec<Permission> = Vec::new();
        for permission in permissions {
            if !values.contains(&permission) {
                values.push(permission);
            }
        }
        Self(values)
    }

    /// Returns `true` when the permission is present.
    pub fn contains(&self, permission: &Permission) -> bool {
        self.0.contains(permission)
    }

    /// Returns the permissions in insertion order.
    pub fn as_slice(&self) -> &[Permission] {
        &self.0
    }

    /// Returns `true` when no permissions are present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of permissions.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<Permission> for PermissionSet {
    fn from_iter<T: IntoIterator<Item = Permission>>(iter: T) -> Self {
        Self::new(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_permission_names() {
        for value in [
            "organization.read",
            "organization.members.manage",
            "gateway.admin.console",
        ] {
            assert!(
                Permission::parse(value).is_ok(),
                "{value:?} should be accepted"
            );
        }
        for value in [
            "",
            "organization",
            "Organization.read",
            "organization..read",
            "organization.Read",
            ".organization",
            "organization.read.",
        ] {
            assert!(
                Permission::parse(value).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn permission_set_deduplicates() {
        let read = Permission::parse("organization.read").expect("valid");
        let manage = Permission::parse("organization.manage").expect("valid");
        let set = PermissionSet::new([read.clone(), manage.clone(), read.clone()]);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&read));
        assert_eq!(set.as_slice(), [read, manage]);
    }
}
