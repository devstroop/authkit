//! Landing page at the site root.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use askama::Template;

#[derive(askama::Template)]
#[template(path = "pages/public_home.html")]
struct PublicHomeTemplate {
    title: &'static str,
    docs_url: String,
}

pub(crate) async fn home_page() -> Response {
    let mode = std::env::var("AUTHKIT_ROOT_MODE").unwrap_or_else(|_| "landing".to_owned());
    match mode.as_str() {
        "redirect-login" => {
            return (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, "/login")],
            )
                .into_response();
        }
        "redirect-account" => {
            return (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, "/account")],
            )
                .into_response();
        }
        _ => {}
    }
    if let Some(url) = mode.strip_prefix("redirect:") {
        if url.starts_with('/') || url.starts_with("http://") || url.starts_with("https://") {
            return (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, url.to_owned())],
            )
                .into_response();
        }
    }
    let docs_url = std::env::var("AUTHKIT_DOCS_URL")
        .unwrap_or_else(|_| "https://docs.authkit.dev".to_owned());
    let template = PublicHomeTemplate {
        title: "title_home",
        docs_url,
    };
    let body = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}
