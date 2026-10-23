use core::fmt;

use crate::domain::DomainError;
use crate::domain::id::{AuditEventEntity, Id, OAuthClientEntity, OrganizationEntity, UserEntity};
use crate::domain::time::Timestamp;
use crate::domain::value::ValueError;

const MAX_ACTION_LEN: usize = 128;
const MAX_TARGET_LEN: usize = 128;
const MAX_ATTRIBUTE_KEY_LEN: usize = 64;
const MAX_ATTRIBUTE_VALUE_LEN: usize = 1024;
const MAX_ATTRIBUTES: usize = 32;

/// A stable audit action name such as `session.revoke` or `client.secret.rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuditAction(String);

impl AuditAction {
    /// Parses an audit action.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "audit action",
            });
        }
        if value.len() > MAX_ACTION_LEN {
            return Err(ValueError::TooLong {
                field: "audit action",
                max: MAX_ACTION_LEN,
                actual: value.len(),
            });
        }
        if !value.is_ascii() {
            return Err(ValueError::InvalidFormat {
                field: "audit action",
                reason: "must use ASCII characters",
            });
        }

        for segment in value.split('.') {
            if segment.is_empty() || segment.len() > 32 {
                return Err(ValueError::InvalidFormat {
                    field: "audit action",
                    reason: "segments must be 1 to 32 characters",
                });
            }
            let mut bytes = segment.bytes();
            let first = bytes.next().unwrap_or_default();
            if !first.is_ascii_lowercase() {
                return Err(ValueError::InvalidFormat {
                    field: "audit action",
                    reason: "segments must start with a lowercase letter",
                });
            }
            if !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            }) {
                return Err(ValueError::InvalidFormat {
                    field: "audit action",
                    reason: "segments may contain only lowercase letters, digits, _ and -",
                });
            }
        }

        Ok(Self(value))
    }

    /// Returns the action name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The principal that caused an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditActor {
    /// A human user.
    User(Id<UserEntity>),
    /// An OAuth client acting on its own behalf.
    Client(Id<OAuthClientEntity>),
    /// A scheduled or internal system operation.
    System,
    /// An unauthenticated request.
    Anonymous,
}

/// A non-sensitive reference to the affected object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditTarget(String);

impl AuditTarget {
    /// Parses an entity identifier or stable object name.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "audit target",
            });
        }
        if value.len() > MAX_TARGET_LEN {
            return Err(ValueError::TooLong {
                field: "audit target",
                max: MAX_TARGET_LEN,
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ValueError::InvalidFormat {
                field: "audit target",
                reason: "must contain printable ASCII characters only",
            });
        }

        Ok(Self(value))
    }

    /// Returns the target reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A redacted key/value attribute attached to an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAttribute {
    key: String,
    value: String,
}

impl AuditAttribute {
    /// Creates an attribute. Values must already be redacted by the caller.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, ValueError> {
        let key = key.into();
        let value = value.into();

        if key.is_empty() {
            return Err(ValueError::Empty {
                field: "audit attribute key",
            });
        }
        if key.len() > MAX_ATTRIBUTE_KEY_LEN {
            return Err(ValueError::TooLong {
                field: "audit attribute key",
                max: MAX_ATTRIBUTE_KEY_LEN,
                actual: key.len(),
            });
        }
        let mut key_bytes = key.bytes();
        let first = key_bytes.next().unwrap_or_default();
        if !first.is_ascii_lowercase() {
            return Err(ValueError::InvalidFormat {
                field: "audit attribute key",
                reason: "must start with a lowercase letter",
            });
        }
        if !key_bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return Err(ValueError::InvalidFormat {
                field: "audit attribute key",
                reason: "may contain only lowercase letters, digits, ., _ and -",
            });
        }
        if value.chars().count() > MAX_ATTRIBUTE_VALUE_LEN {
            return Err(ValueError::TooLong {
                field: "audit attribute value",
                max: MAX_ATTRIBUTE_VALUE_LEN,
                actual: value.chars().count(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ValueError::InvalidFormat {
                field: "audit attribute value",
                reason: "must not contain control characters",
            });
        }

        Ok(Self { key, value })
    }

    /// Returns the attribute key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the redacted attribute value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// An append-only security audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    id: Id<AuditEventEntity>,
    organization_id: Option<Id<OrganizationEntity>>,
    actor: AuditActor,
    action: AuditAction,
    target: Option<AuditTarget>,
    occurred_at: Timestamp,
    attributes: Vec<AuditAttribute>,
}

impl AuditEvent {
    /// Creates an audit event.
    pub fn new(
        id: Id<AuditEventEntity>,
        organization_id: Option<Id<OrganizationEntity>>,
        actor: AuditActor,
        action: AuditAction,
        target: Option<AuditTarget>,
        occurred_at: Timestamp,
        attributes: Vec<AuditAttribute>,
    ) -> Result<Self, DomainError> {
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(DomainError::invalid("too many audit attributes"));
        }
        for (index, attribute) in attributes.iter().enumerate() {
            if attributes[..index]
                .iter()
                .any(|existing| existing.key == attribute.key)
            {
                return Err(DomainError::invalid("audit attribute keys must be unique"));
            }
        }

        Ok(Self {
            id,
            organization_id,
            actor,
            action,
            target,
            occurred_at,
            attributes,
        })
    }

    /// Returns the event identifier.
    pub const fn id(&self) -> &Id<AuditEventEntity> {
        &self.id
    }

    /// Returns the tenant, when the event is tenant-scoped.
    pub const fn organization_id(&self) -> Option<&Id<OrganizationEntity>> {
        self.organization_id.as_ref()
    }

    /// Returns the actor.
    pub const fn actor(&self) -> &AuditActor {
        &self.actor
    }

    /// Returns the action.
    pub const fn action(&self) -> &AuditAction {
        &self.action
    }

    /// Returns the affected object, if any.
    pub const fn target(&self) -> Option<&AuditTarget> {
        self.target.as_ref()
    }

    /// Returns the event time.
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    /// Returns the redacted attributes.
    pub fn attributes(&self) -> &[AuditAttribute] {
        &self.attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(attributes: Vec<AuditAttribute>) -> Result<AuditEvent, DomainError> {
        AuditEvent::new(
            Id::<AuditEventEntity>::from_suffix("0123456789abcdef").expect("valid id"),
            None,
            AuditActor::System,
            AuditAction::parse("session.revoke").expect("valid action"),
            Some(AuditTarget::parse("ses_0123456789abcdef").expect("valid target")),
            Timestamp::from_millis(1_000),
            attributes,
        )
    }

    #[test]
    fn validates_actions_and_targets() {
        for value in ["login", "session.revoke", "client.secret.rotate"] {
            assert!(
                AuditAction::parse(value).is_ok(),
                "{value:?} should be accepted"
            );
        }
        for value in ["", "Session.Revoke", "session..revoke", "-session"] {
            assert!(
                AuditAction::parse(value).is_err(),
                "{value:?} should be rejected"
            );
        }
        assert!(AuditTarget::parse("usr_0123456789abcdef").is_ok());
        assert!(AuditTarget::parse("bad target").is_err());
    }

    #[test]
    fn rejects_duplicate_attribute_keys() {
        let attribute = AuditAttribute::new("reason", "user_request").expect("valid attribute");
        assert!(event(vec![attribute.clone(), attribute]).is_err());
    }

    #[test]
    fn creates_an_append_only_event() {
        let event = event(vec![
            AuditAttribute::new("reason", "user_request").expect("valid attribute"),
        ])
        .expect("valid event");
        assert_eq!(event.action().as_str(), "session.revoke");
        assert_eq!(event.attributes().len(), 1);
        assert_eq!(event.attributes()[0].key(), "reason");
    }
}
