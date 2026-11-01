//! Opt-in HTTPS for AAuth: the one crate in this workspace that opens connections.
//!
//! - [`DiscoveryClient`] fetches metadata and JWKS, and sends server-to-server
//!   requests, through the Signature-Key egress admission of
//!   `aauth-rust-signature-key`: `https` only, globally routable unicast
//!   addresses only, checked after name resolution and pinned for the
//!   connection, same-host redirects only, bounded bodies and deadlines, no
//!   proxy from the environment. Relaxing a rule, such as admitting loopback
//!   for development, is an explicit builder call.
//! - [`KeyResolver`] implements `AgentKeyResolver` by discovery, for the
//!   issuers and roles the host trusts, with the Signature-Key cache rules.
//! - [`RevocationClient`] implements `RevocationDirectory`: installed on a
//!   Person Server, Access Server or Resource, it delivers the revocation
//!   cascade the role computes from its own records.
//!
//! Every call blocks the calling thread. From an async runtime, call it on a
//! blocking thread, such as `tokio::task::spawn_blocking`.
//!
//! ```
//! use aauth_rust_core::{AgentKeyResolver, TokenError};
//! use aauth_rust_discovery::{DiscoveryClient, DiscoveryError, KeyResolver, Refusal, RevocationClient};
//! use aauth_rust_signature_key::DiscoveryFetch;
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), DiscoveryError> {
//! let client = DiscoveryClient::new()?;
//! let keys = KeyResolver::new(client.clone()).trust("https://ap.example", "aauth-agent.json");
//! // Discovery is not trust: an issuer the host did not name is refused
//! // before any request is made.
//! assert_eq!(
//!     keys.key("https://elsewhere.example", "aauth-agent.json", "key-1").unwrap_err(),
//!     TokenError::UntrustedIssuer
//! );
//! // Only https, and only public addresses.
//! let plain = client.get(DiscoveryFetch::Metadata { url: "http://ap.example/.well-known/aauth-agent.json" });
//! assert!(matches!(plain, Err(DiscoveryError::Refused { reason: Refusal::NotHttps, .. })));
//! let local = client.get(DiscoveryFetch::Metadata { url: "https://127.0.0.1/.well-known/aauth-agent.json" });
//! assert!(matches!(local, Err(DiscoveryError::Refused { reason: Refusal::RestrictedAddress(_), .. })));
//! // Pass it to a role's with_revocation_directory.
//! let _revocations = Arc::new(RevocationClient::new(client));
//! # Ok(())
//! # }
//! ```
#![deny(missing_docs)]
mod client;
mod http1;
mod keys;
mod revocation;

pub use client::{
    DEFAULT_TIMEOUT, DiscoveryClient, DiscoveryClientBuilder, DiscoveryError, Exchange, Fetched,
    Metadata, Refusal, Resolve, Transport, TransportError,
};
pub use keys::{DEFAULT_CAPACITY, KeyResolver};
pub use revocation::{Delivery, DeliveryCause, RevocationClient};

// The Rust samples in docs/discovery.md run as doctests of this crate.
#[cfg(doctest)]
mod docs {
    #[doc = include_str!("../../../docs/discovery.md")]
    mod discovery {}
}
