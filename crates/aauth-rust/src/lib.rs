//! AAuth for Rust, every crate of the family in one dependency.
//!
//! [AAuth](https://github.com/dickhardt/AAuth) tells an API which software
//! agent is calling it and on whose behalf. The agent signs every HTTP request
//! with its own key, and the API checks that signature and the token sent with
//! it, asking for a token that names the person when it needs one.
//!
//! Each role lives in its own module:
//!
//! - Agent: [`agent`] signs an agent's requests and checks the tokens it receives.
//! - Agent Provider: [`agent_provider`] issues Agent tokens and publishes the provider's keys.
//! - Resource, the API: [`resource`] checks requests before your handler runs.
//! - Person Server: [`person_server`] issues tokens that name the person an
//!   agent acts for; [`person_server_redb`] stores its state in a file, on Unix.
//! - Access Server: [`access_server`] decides access for an API from the API's own rules.
//! - Supervision Server: [`supervision_server`] approves or refuses an agent's
//!   requests for the person.
//!
//! The roles share [`core`] for tokens, [`signature_key`] for HTTP signatures,
//! [`jose`] for keys, and [`r3`] and [`budgets`] for operation lists and
//! spending caps. [`discovery`] is the one module that opens connections: it
//! fetches other servers' keys and delivers revocations over HTTPS.
//!
//! Every module is on by default. Each role module and [`discovery`] has a
//! Cargo feature of the same name, so a service that only checks requests can
//! keep just the Resource:
//!
//! ```toml
//! aauth-rust = { version = "0.1.0-alpha.26", default-features = false, features = ["resource"] }
//! ```
//!
//! The guides are in the repository's
//! [docs](https://gitlab.com/sidecat-dev/aauth-rust/-/tree/main/docs).
#![deny(missing_docs)]

/// Keys, thumbprints and compact JWS.
pub use aauth_rust_jose as jose;

/// Protocol claims, discovery documents and token verification.
pub use aauth_rust_core as core;

/// HTTP request signatures and Signature-Key proofs.
pub use aauth_rust_signature_key as signature_key;

/// R3 vocabularies, documents, grants and proposals.
pub use aauth_rust_r3 as r3;

/// Budget objects, narrowing, metering and usage counters.
pub use aauth_rust_budgets as budgets;

/// The Agent: request signing and checks on the tokens it receives.
#[cfg(feature = "agent")]
pub use aauth_rust_agent as agent;

/// The Agent Provider: Agent token issuance and the provider's published keys.
#[cfg(feature = "agent_provider")]
pub use aauth_rust_agent_provider as agent_provider;

/// The Resource: checks on requests to an API before its handler runs.
#[cfg(feature = "resource")]
pub use aauth_rust_resource as resource;

/// The Person Server: person bindings, consent and the tokens that name the person.
#[cfg(feature = "person_server")]
pub use aauth_rust_person_server as person_server;

/// File-backed storage for a Person Server, on Unix.
#[cfg(feature = "person_server_redb")]
pub use aauth_rust_person_server_redb as person_server_redb;

/// The Access Server: access decisions for an API from the API's own rules.
#[cfg(feature = "access_server")]
pub use aauth_rust_access_server as access_server;

/// The Supervision Server: approvals and refusals of an agent's requests for the person.
#[cfg(feature = "supervision_server")]
pub use aauth_rust_supervision_server as supervision_server;

/// HTTPS fetching of other servers' keys and delivery of revocations.
#[cfg(feature = "discovery")]
pub use aauth_rust_discovery as discovery;
