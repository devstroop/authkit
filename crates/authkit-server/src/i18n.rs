//! Internationalization hooks.
//!
//! Templates call `crate::i18n::t(key)` which resolves against the task-local
//! locale set by the locale middleware. The catalog ships English plus a partial
//! Spanish translation; missing keys fall back to English, then to the key.

use std::collections::HashMap;
use std::sync::OnceLock;

use axum::http::HeaderMap;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    En,
    Es,
}

impl Locale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Es => "es",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_ascii_lowercase().as_str() {
            "en" | "en-us" | "en-gb" => Some(Self::En),
            "es" | "es-es" | "es-mx" | "es-419" => Some(Self::Es),
            _ => None,
        }
    }
}

tokio::task_local! {
    static CURRENT: Locale;
}

pub fn set_locale(locale: Locale) {
    let _ = locale;
}

pub fn current_locale() -> Locale {
    match CURRENT.try_get() {
        Ok(l) => l,
        Err(_) => Locale::En,
    }
}

pub fn detect_locale(headers: &HeaderMap) -> Locale {
    if let Some(value) = headers.get(axum::http::header::ACCEPT_LANGUAGE)
        && let Ok(text) = value.to_str()
    {
        let first = text.split(',').next().unwrap_or("").trim();
        let primary = first.split(';').next().unwrap_or("").trim();
        let code = primary.split('-').next().unwrap_or("").trim();
        if let Some(locale) = Locale::from_code(code) {
            return locale;
        }
        if let Some(locale) = Locale::from_code(primary) {
            return locale;
        }
    }
    Locale::En
}

pub async fn scope<F>(locale: Locale, future: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT.scope(locale, future).await
}

pub async fn locale_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut locale = detect_locale(request.headers());
    let mut from_query: Option<Locale> = None;
    if let Some(cookie) = request.headers().get(axum::http::header::COOKIE)
        && let Ok(text) = cookie.to_str()
    {
        for part in text.split(';') {
            let mut kv = part.trim().splitn(2, '=');
            if let (Some("authkit_lang"), Some(val)) = (kv.next(), kv.next())
                && let Some(l) = Locale::from_code(val.trim())
            {
                locale = l;
            }
        }
    }
    if let Some(q) = request.uri().query() {
        for pair in q.split('&') {
            let mut parts = pair.splitn(2, '=');
            if let (Some("lang"), Some(val)) = (parts.next(), parts.next())
                && let Some(l) = Locale::from_code(val)
            {
                locale = l;
                from_query = Some(l);
            }
        }
    }
    let mut response = scope(locale, next.run(request)).await;
    if let Some(l) = from_query {
        let cookie = format!(
            "authkit_lang={}; Path=/; Max-Age=31536000; SameSite=Lax",
            l.as_str()
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

fn catalogs() -> &'static HashMap<Locale, HashMap<String, String>> {
    static CATALOGS: OnceLock<HashMap<Locale, HashMap<String, String>>> = OnceLock::new();
    CATALOGS.get_or_init(|| {
        let mut map = HashMap::new();
        map.insert(Locale::En, load(include_str!("../locales/en.json")));
        map.insert(Locale::Es, load(include_str!("../locales/es.json")));
        map
    })
}

fn load(src: &str) -> HashMap<String, String> {
    serde_json::from_str::<Value>(src)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|obj| {
            obj.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

pub fn t(key: &str) -> String {
    let locale = current_locale();
    if let Some(cat) = catalogs().get(&locale)
        && let Some(val) = cat.get(key)
    {
        return val.clone();
    }
    if locale != Locale::En
        && let Some(cat) = catalogs().get(&Locale::En)
        && let Some(val) = cat.get(key)
    {
        return val.clone();
    }
    key.to_owned()
}
