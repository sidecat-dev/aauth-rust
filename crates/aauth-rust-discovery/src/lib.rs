#![doc = include_str!("../README.md")]
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
