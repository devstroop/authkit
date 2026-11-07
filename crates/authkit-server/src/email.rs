//! Development email delivery adapter.

use authkit_core::domain::DomainError;
use authkit_core::domain::email::Email;
use authkit_core::ports::EmailSender;

/// Logs email instead of delivering it. Development only.
#[derive(Clone, Copy, Default)]
pub struct DevEmailSender;

impl EmailSender for DevEmailSender {
    fn send(&self, to: &Email, subject: &str, body: &str) -> Result<(), DomainError> {
        tracing::info!(
            target = "authkit.dev.email",
            to = %to.as_str(),
            subject = %subject,
            body = %body,
            "dev-only email"
        );
        Ok(())
    }
}
