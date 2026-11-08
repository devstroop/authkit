//! Internationalization hooks.
//!
//! Templates call `crate::i18n::t(key)` which resolves against the thread-local
//! locale set by handlers via `set_locale`. The catalog currently ships English only.

use std::cell::Cell;

use axum::http::HeaderMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
}

impl Locale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
        }
    }
}

thread_local! {
    static CURRENT: Cell<Locale> = Cell::new(Locale::En);
}

pub fn set_locale(locale: Locale) {
    CURRENT.with(|c| c.set(locale));
}

pub fn current_locale() -> Locale {
    CURRENT.with(|c| c.get())
}

/// Detects a locale from the `Accept-Language` header, falling back to English.
pub fn detect_locale(headers: &HeaderMap) -> Locale {
    if let Some(value) = headers.get(axum::http::header::ACCEPT_LANGUAGE)
        && let Ok(text) = value.to_str()
    {
        let lowered = text.to_lowercase();
        if lowered.starts_with("es") {
            // placeholder for future Spanish support
            return Locale::En;
        }
    }
    Locale::En
}

/// Translates a message key for the current locale. Returns the key itself when missing.
pub fn t(key: &str) -> String {
    let _ = current_locale();
    match key {
        "skip_to_content" => "Skip to content".to_owned(),
        "sign_in" => "Sign in".to_owned(),
        "sign_out" => "Sign out".to_owned(),
        "register" => "Create an account".to_owned(),
        "email" => "Email".to_owned(),
        "password" => "Password".to_owned(),
        "submit" => "Submit".to_owned(),
        _ => key.to_owned(),
    }
}
