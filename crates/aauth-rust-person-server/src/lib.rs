//! Person Server identity binding and immediate direct authorization.
#![deny(missing_docs)]
mod store;
pub mod storetest;
pub use store::{
    AgentIdentity, Binding, MemoryStore, Store, StoreError, TokenKind, TokenRecord, TokenReference,
    TokenTie,
};
