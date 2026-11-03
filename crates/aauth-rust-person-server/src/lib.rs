#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
mod federation;
mod mission;
mod policy;
pub use federation::{
    BoxedFederation, Federation, FederationError, FederationFailure, FederationFailureReason,
};
pub use mission::{
    MissionAudit, MissionAuditError, MissionEdit, MissionRecord, MissionState, MissionStore,
    MissionStoreError, MissionUpdateBytes,
};
mod server;
mod store;
pub mod storetest;
pub use policy::{
    AuthorizationRequest, BoxedClock, BoxedPolicy, BoxedTokenIds, Grant, Person, PersonRequest,
    Policy, PolicyError, UpstreamContext,
};
pub use server::{
    AdvanceError, BoxedEgress, BoxedR3Policy, Config, ConfigurationError, ConnectOutcome,
    DeferredConfig, FederationInput, Governance, GovernanceError, InteractionDecision,
    InteractionRelay, InteractionRelayConfig, OpenedInteraction, PendingResourceInteraction,
    PersonAnswer, PersonServer, R3AuthorizationRequest, R3Decision, R3IssuerConfig, R3Policy,
    R3ProposalDecision, R3ProposalRequest, RecordError, RelayChannel, RelayError, RelayUnavailable,
    ResourceInteractionCallback, ResourceInteractionConfig, ResourceInteractionError, Supervision,
    SupervisionConfig, SupervisionExchange, SupervisionHold, SupervisionHostError,
    SupervisionRecord, SupervisionUnavailable, Unconsulted, VerifiedDecision, Waiting,
};
pub use store::{
    AgentIdentity, Binding, MemoryStore, R3IssuanceAudit, Store, StoreError, TokenKind,
    TokenRecord, TokenReference, TokenTie,
};

// Rust samples in docs/ that need the supervision server run as doctests of
// this crate. The others run in aauth-rust-resource.
#[cfg(doctest)]
mod docs {
    #[doc = include_str!("../../../docs/roles/supervision-server.md")]
    mod supervision_server {}
    #[doc = include_str!("../../../docs/features/supervision.md")]
    mod supervision {}
}
