use authkit_core::domain::{
    AuditAction, AuditTarget, DisplayName, Email, Permission, Scope, Slug,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn email_parse_does_not_panic(value in any::<String>()) {
        let _ = Email::parse(&value);
    }

    #[test]
    fn slug_parse_does_not_panic(value in any::<String>()) {
        let _ = Slug::parse(&value);
    }

    #[test]
    fn display_name_parse_does_not_panic(value in any::<String>()) {
        let _ = DisplayName::parse(&value);
    }

    #[test]
    fn permission_parse_does_not_panic(value in any::<String>()) {
        let _ = Permission::parse(&value);
    }

    #[test]
    fn scope_parse_does_not_panic(value in any::<String>()) {
        let _ = Scope::parse(&value);
    }

    #[test]
    fn audit_action_parse_does_not_panic(value in any::<String>()) {
        let _ = AuditAction::parse(&value);
    }

    #[test]
    fn audit_target_parse_does_not_panic(value in any::<String>()) {
        let _ = AuditTarget::parse(&value);
    }

    #[test]
    fn valid_emails_round_trip(value in "[a-z]{1,8}@[a-z]{1,8}\\.[a-z]{2,4}") {
        let email = Email::parse(&value).expect("valid email");
        let expected = value.to_lowercase();
        prop_assert_eq!(email.as_str(), expected.as_str());
    }

    #[test]
    fn valid_slugs_round_trip(value in "[a-z][a-z0-9-]{0,12}") {
        if let Ok(slug) = Slug::parse(&value) {
            prop_assert_eq!(slug.as_str(), value.as_str());
        }
    }
}
