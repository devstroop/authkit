use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Extracts a client IP address for rate-limit keys.
///
/// `X-Forwarded-For` is honored only when the direct peer is configured as a
/// trusted proxy. Otherwise the direct peer address is used.
pub fn client_ip(
    headers: &HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    trusted_proxies: &[IpAddr],
) -> String {
    let peer = connect_info.map(|info| info.0.ip());
    if let Some(peer) = peer {
        if !trusted_proxies.is_empty() && trusted_proxies.contains(&peer) {
            if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                if let Some(first) = value.split(',').next() {
                    let candidate = first.trim();
                    if let Ok(ip) = candidate.parse::<IpAddr>() {
                        return ip.to_string();
                    }
                }
            }
        }
        return peer.to_string();
    }

    if trusted_proxies.iter().any(|ip| ip.to_string() == "*") {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let candidate = first.trim();
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    return ip.to_string();
                }
            }
        }
    }

    "unknown".to_owned()
}
