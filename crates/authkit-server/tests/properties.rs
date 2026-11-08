use authkit_server::http::rate_limit::client_ip;
use axum::http::HeaderMap;
use proptest::prelude::*;
use std::net::{IpAddr, SocketAddr};

proptest! {
    #[test]
    fn client_ip_does_not_panic(value in ".*") {
        let mut headers = HeaderMap::new();
        let _ = headers.insert("x-forwarded-for", value.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap()));
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let _ = client_ip(&headers, Some(axum::extract::ConnectInfo(addr)), &[]);
        let _ = client_ip(&headers, None, &[IpAddr::from([127, 0, 0, 1])]);
        let _ = client_ip(&headers, None, &[]);
    }

    #[test]
    fn client_ip_trusted_proxy_handles_random_ips(ip in any::<IpAddr>()) {
        let mut headers = HeaderMap::new();
        let _ = headers.insert("x-forwarded-for", "203.0.113.9, 198.51.100.7".parse().unwrap());
        let addr: SocketAddr = SocketAddr::new(ip, 8080);
        let _ = client_ip(&headers, Some(axum::extract::ConnectInfo(addr)), &[ip]);
    }
}
