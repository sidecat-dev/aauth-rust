//! Person Server identity binding and immediate direct authorization.
#![deny(missing_docs)]
mod policy;
mod server;
mod store;
pub mod storetest;
pub use policy::{
    AuthorizationRequest, Grant, Person, PersonRequest, Policy, PolicyError, UpstreamContext,
};
pub use server::{Config, ConfigurationError, PersonServer};
pub use store::{
    AgentIdentity, Binding, MemoryStore, Store, StoreError, TokenKind, TokenRecord, TokenReference,
    TokenTie,
};
