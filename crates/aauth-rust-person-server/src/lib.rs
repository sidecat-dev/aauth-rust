//! Person Server identity binding and immediate direct authorization.
//!
//! The host supplies authenticated person policy, admitted issuer keys, an atomic
//! store, Unix-second clock and fresh token IDs. This complete example publishes
//! metadata while refusing person/authorization requests until host policy and
//! issuer trust are configured. Replace the closed policy and resolver with your
//! application integrations; [`MemoryStore`] is volatile, not durable storage.
//!
//! ```
//! use aauth_rust_core::{AgentKeyResolver, TokenError};
//! use aauth_rust_jose::{Jwk, SigningKey};
//! use aauth_rust_person_server::{
//!     AuthorizationRequest, BoxedClock, BoxedPolicy, BoxedTokenIds,
//!     Config, Grant, MemoryStore, Person, PersonRequest,
//!     PersonServer, Policy, PolicyError,
//! };
//! use http::Request;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! struct ClosedPolicy;
//! impl Policy for ClosedPolicy {
//!     fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
//!         Err(PolicyError::Denied)
//!     }
//!     fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
//!         Err(PolicyError::Denied)
//!     }
//! }
//! struct AdmittedIssuers;
//! impl AgentKeyResolver for AdmittedIssuers {
//!     fn key(&self, _: &str, _: &str, _: &str) -> Result<Jwk, TokenError> {
//!         Err(TokenError::UntrustedIssuer)
//!     }
//! }
//! type HostServer = PersonServer<AdmittedIssuers, MemoryStore,
//!     BoxedPolicy, BoxedClock, BoxedTokenIds>;
//! let server: HostServer = PersonServer::new(
//!     Config::new("https://ps.example", "ps-1", SigningKey::generate()),
//!     AdmittedIssuers,
//!     MemoryStore::default(),
//!     Box::new(ClosedPolicy) as BoxedPolicy,
//!     Box::new(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)
//!         as BoxedClock,
//!     Box::new(|| SigningKey::generate().public_jwk().thumbprint().unwrap()) as BoxedTokenIds,
//! )?;
//! let request = Request::builder()
//!     .uri("https://ps.example/.well-known/aauth-person.json")
//!     .body(Vec::new())?;
//! assert_eq!(server.handle(&request).status(), 200);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]
mod policy;
mod server;
mod store;
pub mod storetest;
pub use policy::{
    AuthorizationRequest, BoxedClock, BoxedPolicy, BoxedTokenIds, Grant, Person, PersonRequest,
    Policy, PolicyError, UpstreamContext,
};
pub use server::{Config, ConfigurationError, PersonServer};
pub use store::{
    AgentIdentity, Binding, MemoryStore, Store, StoreError, TokenKind, TokenRecord, TokenReference,
    TokenTie,
};
