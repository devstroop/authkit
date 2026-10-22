//! AuthKit Cloudflare Workers preview entry point.
//!
//! Workers support is a preview profile with explicit feature gates. The runtime adapter,
//! D1 storage, and platform bindings land in milestone M6; this crate exists now so the
//! domain boundary is not coupled to the native server.

#![forbid(unsafe_code)]
