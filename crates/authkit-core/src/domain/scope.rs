use core::fmt;

use crate::domain::value::ValueError;

const MAX_SCOPE_LEN: usize = 64;

/// An OAuth scope name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope(String);

impl Scope {
    /// Parses a scope name.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty { field: "scope" });
        }
        if value.len() > MAX_SCOPE_LEN {
            return Err(ValueError::TooLong {
                field: "scope",
                max: MAX_SCOPE_LEN,
                actual: value.len(),
            });
        }
        if !value.is_ascii() {
            return Err(ValueError::InvalidFormat {
                field: "scope",
                reason: "must use ASCII characters",
            });
        }
        let mut bytes = value.bytes();
        let first = bytes.next().unwrap_or_default();
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(ValueError::InvalidFormat {
                field: "scope",
                reason: "must start with a lowercase letter or digit",
            });
        }
        if !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b':' | b'.' | b'_' | b'-')
        }) {
            return Err(ValueError::InvalidFormat {
                field: "scope",
                reason: "may contain only lowercase letters, digits, and : . _ -",
            });
        }

        Ok(Self(value))
    }

    /// Returns the scope name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A de-duplicated, order-preserving set of scopes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    /// Creates a set, dropping duplicate scopes while preserving first-seen order.
    pub fn new(scopes: impl IntoIterator<Item = Scope>) -> Self {
        let mut values: Vec<Scope> = Vec::new();
        for scope in scopes {
            if !values.contains(&scope) {
                values.push(scope);
            }
        }
        Self(values)
    }

    /// Returns `true` when the scope is present.
    pub fn contains(&self, scope: &Scope) -> bool {
        self.0.contains(scope)
    }

    /// Returns the scopes in insertion order.
    pub fn as_slice(&self) -> &[Scope] {
        &self.0
    }

    /// Returns `true` when no scopes are present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of scopes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<T: IntoIterator<Item = Scope>>(iter: T) -> Self {
        Self::new(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_scope_names() {
        for value in [
            "openid",
            "profile",
            "offline_access",
            "gateway.admin.console",
        ] {
            assert!(Scope::parse(value).is_ok(), "{value:?} should be accepted");
        }
        for value in ["", "OpenID", "open id", "openid!", "-openid"] {
            assert!(Scope::parse(value).is_err(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn scope_set_preserves_order_and_deduplicates() {
        let openid = Scope::parse("openid").expect("valid");
        let email = Scope::parse("email").expect("valid");
        let set = ScopeSet::new([openid.clone(), email.clone(), openid.clone()]);
        assert_eq!(set.len(), 2);
        assert_eq!(set.as_slice(), [openid, email]);
    }
}
