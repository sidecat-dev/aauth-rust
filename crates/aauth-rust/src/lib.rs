#![doc = include_str!("../README.md")]
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
