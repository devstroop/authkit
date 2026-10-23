use core::fmt;
use core::marker::PhantomData;

/// Minimum suffix length for a generated identifier.
pub const MIN_SUFFIX_LEN: usize = 16;

/// Maximum suffix length for a generated identifier.
pub const MAX_SUFFIX_LEN: usize = 64;

/// A domain entity kind with a stable identifier prefix.
///
/// Implementations are marker types. The prefix is part of every persisted identifier and
/// must not be changed without a migration.
pub trait Entity {
    /// Stable lowercase prefix, for example `usr` or `org`.
    const PREFIX: &'static str;
}

macro_rules! entity {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;

        impl Entity for $name {
            const PREFIX: &'static str = $prefix;
        }
    };
}

entity!(
    /// A deployment-global user identity.
    UserEntity,
    "usr"
);
entity!(
    /// An organization, the tenant boundary.
    OrganizationEntity,
    "org"
);
entity!(
    /// A product surface owned by one organization.
    ApplicationEntity,
    "app"
);
entity!(
    /// An OAuth client registered under an application.
    OAuthClientEntity,
    "cli"
);
entity!(
    /// A user's membership in an organization.
    MembershipEntity,
    "mem"
);
entity!(
    /// A pending organization invitation.
    InvitationEntity,
    "inv"
);
entity!(
    /// A role definition.
    RoleEntity,
    "rol"
);
entity!(
    /// A binding of a role to a user within an organization or application.
    RoleBindingEntity,
    "rbd"
);
entity!(
    /// A permission definition.
    PermissionEntity,
    "perm"
);
entity!(
    /// An authenticated browser or API session.
    SessionEntity,
    "ses"
);
entity!(
    /// A one-time authorization code.
    AuthorizationCodeEntity,
    "ac"
);
entity!(
    /// A refresh-token family.
    RefreshFamilyEntity,
    "rf"
);
entity!(
    /// A refresh token within a family.
    RefreshTokenEntity,
    "rt"
);
entity!(
    /// An append-only audit event.
    AuditEventEntity,
    "aud"
);
entity!(
    /// A signing-key record.
    SigningKeyEntity,
    "key"
);
entity!(
    /// A deployment-level system administrator record.
    SystemAdministratorEntity,
    "sysadm"
);
entity!(
    /// A password, passkey, or other authentication credential.
    CredentialEntity,
    "cred"
);
entity!(
    /// A user's consent to an OAuth client and scope set.
    ConsentEntity,
    "cns"
);

/// A typed, prefix-validated entity identifier.
///
/// The in-memory representation is `<prefix>_<suffix>`. The suffix must be 16 to 64
/// lowercase ASCII alphanumeric characters. Generation is a port responsibility; this type
/// only validates and carries the value.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id<E: Entity> {
    value: String,
    _marker: PhantomData<fn() -> E>,
}

impl<E: Entity> Id<E> {
    /// Parses and validates a full identifier for the given entity kind.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        let (actual_prefix, suffix) = value.split_once('_').ok_or(IdError::MissingSeparator)?;

        if actual_prefix != E::PREFIX {
            return Err(IdError::WrongPrefix {
                expected: E::PREFIX,
                actual: actual_prefix.to_owned(),
            });
        }

        validate_suffix(suffix)?;

        Ok(Self {
            value,
            _marker: PhantomData,
        })
    }

    /// Builds an identifier from a validated suffix.
    pub fn from_suffix(suffix: &str) -> Result<Self, IdError> {
        validate_suffix(suffix)?;
        Ok(Self {
            value: format!("{}_{suffix}", E::PREFIX),
            _marker: PhantomData,
        })
    }

    /// Returns the full `<prefix>_<suffix>` representation.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns the suffix without the entity prefix.
    pub fn suffix(&self) -> &str {
        &self.value[E::PREFIX.len() + 1..]
    }

    /// Returns the entity prefix.
    pub const fn prefix() -> &'static str {
        E::PREFIX
    }
}

fn validate_suffix(suffix: &str) -> Result<(), IdError> {
    if !(MIN_SUFFIX_LEN..=MAX_SUFFIX_LEN).contains(&suffix.len()) {
        return Err(IdError::InvalidLength {
            actual: suffix.len(),
        });
    }

    if !suffix
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(IdError::InvalidCharacter);
    }

    Ok(())
}

impl<E: Entity> fmt::Debug for Id<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Id").field(&self.value).finish()
    }
}

impl<E: Entity> fmt::Display for Id<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl<E: Entity> AsRef<str> for Id<E> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// An identifier validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The value has no `_` separator.
    MissingSeparator,
    /// The prefix does not match the expected entity kind.
    WrongPrefix {
        /// The prefix required by the entity type.
        expected: &'static str,
        /// The prefix found in the input.
        actual: String,
    },
    /// The suffix length is outside the supported range.
    InvalidLength {
        /// The observed suffix length.
        actual: usize,
    },
    /// The suffix contains a character outside lowercase ASCII alphanumerics.
    InvalidCharacter,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => formatter.write_str("identifier has no prefix separator"),
            Self::WrongPrefix { expected, actual } => {
                write!(formatter, "expected prefix {expected:?}, found {actual:?}")
            }
            Self::InvalidLength { actual } => write!(
                formatter,
                "identifier suffix must be {MIN_SUFFIX_LEN} to {MAX_SUFFIX_LEN} characters, found {actual}"
            ),
            Self::InvalidCharacter => {
                formatter.write_str("identifier suffix must be lowercase ASCII alphanumeric")
            }
        }
    }
}

impl std::error::Error for IdError {}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SUFFIX: &str = "0123456789abcdef";

    #[test]
    fn parses_a_valid_typed_id() {
        let id = Id::<UserEntity>::parse(format!("usr_{VALID_SUFFIX}")).expect("valid id");
        assert_eq!(id.as_str(), "usr_0123456789abcdef");
        assert_eq!(id.suffix(), VALID_SUFFIX);
        assert_eq!(Id::<UserEntity>::prefix(), "usr");
    }

    #[test]
    fn rejects_the_wrong_prefix() {
        let error =
            Id::<UserEntity>::parse(format!("org_{VALID_SUFFIX}")).expect_err("wrong prefix");
        assert_eq!(
            error,
            IdError::WrongPrefix {
                expected: "usr",
                actual: "org".to_owned()
            }
        );
    }

    #[test]
    fn rejects_a_missing_separator() {
        assert_eq!(
            Id::<UserEntity>::parse("usrabc").expect_err("missing separator"),
            IdError::MissingSeparator
        );
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(
            Id::<UserEntity>::parse("usr_abc").expect_err("short suffix"),
            IdError::InvalidLength { actual: 3 }
        );
    }

    #[test]
    fn rejects_uppercase_and_punctuation() {
        assert_eq!(
            Id::<UserEntity>::parse("usr_0123456789ABCDEF").expect_err("uppercase"),
            IdError::InvalidCharacter
        );
        assert_eq!(
            Id::<UserEntity>::parse("usr_0123456789abc-def").expect_err("punctuation"),
            IdError::InvalidCharacter
        );
    }

    #[test]
    fn builds_from_a_suffix() {
        let id = Id::<OrganizationEntity>::from_suffix(VALID_SUFFIX).expect("valid suffix");
        assert_eq!(id.as_str(), "org_0123456789abcdef");
    }
}
