//! Internationalization hooks.
//!
//! This module provides locale detection and a translation lookup. Templates may call
//! `crate::i18n::t(key, locale)` once migrated; today the catalog contains only English
//! strings and the default locale is `en`.

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

/// Translates a message key for the given locale. Returns the key itself when missing.
pub fn t(key: &str, _locale: Locale) -> String {
    match key {
        "skip_to_content" => "Skip to content".to_owned(),
        "sign_in" => "Sign in".to_owned(),
        "sign_out" => "Sign out".to_owned(),
        _ => key.to_owned(),
    }
}
