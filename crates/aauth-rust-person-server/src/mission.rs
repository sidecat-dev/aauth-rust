use crate::{AgentIdentity, StoreError, TokenRecord};
use aauth_rust_core::ApprovedMission;

/// Host-retained mission state; termination is permanent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MissionState {
    /// Host independently obtained the accountable person's approval.
    Active,
    /// Opaque retained reason; `expired` is used when expiry is materialized.
    Terminated(String),
}

/// Separately host-approved record. Installing this is not a human-authentication
/// or mission-creation protocol endpoint. The host supplies the authenticated
/// private person, approving PS and complete Agent identity independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionRecord {
    /// Approving PS namespace, authenticated beside the digest.
    pub person_server: String,
    /// Accountable top-level Agent (including its trusted provider).
    pub owner: AgentIdentity,
    /// Host-authenticated private person ID, never copied into a public token.
    pub person_id: String,
    /// Exact approved document, including unknown additive bytes.
    pub document: ApprovedMission,
    /// Current state; termination cannot be reversed by reinstalling a record.
    pub state: MissionState,
}

/// Mission lookup/issuance refusal, distinct from an ordinary missing binding.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MissionStoreError {
    /// Absent mission or different owner. Do not disclose its state.
    #[error("approved mission not found for this Agent and Person Server")]
    NotFound,
    /// Permanently terminated, including materialized expiry.
    #[error("approved mission is terminated ({0})")]
    Terminated(String),
    /// A complete expected snapshot, person or credential binding differs.
    #[error("approved mission or issuance binding changed")]
    Conflict,
    /// Underlying atomic store refusal or operational failure.
    #[error(transparent)]
    Storage(#[from] StoreError),
}

/// Optional mission extension of the SAME [`crate::Store`] atomic boundary.
/// Existing stores default to unsupported. An independent check followed by an
/// ordinary commit is not an implementation of this contract. Operations must
/// enforce active owner/person bindings and materialize expiry permanently.
/// Stores supporting administrative binding replacement must invalidate old
/// approvals even when the replacement has the same person ID.
pub trait MissionStore: Send + Sync {
    /// Return an owned active snapshot for this exact authenticated PS/Agent.
    /// Check ownership before reporting termination. `at` is trusted Unix time.
    fn load_mission(
        &self,
        ps: &str,
        owner: &AgentIdentity,
        s256: &str,
        at: i64,
    ) -> Result<MissionRecord, MissionStoreError>;
    /// Atomically compare every expected field, materialize expiry, check active
    /// binding and retain the complete issuance. The record must have this PS,
    /// owner, private person, mission ceiling and no child/upstream/federation.
    /// Logical refusals leave token/binding/index state unchanged. Operational
    /// failure may leave a complete commit's outcome uncertain, never partial.
    fn commit_mission_token(
        &self,
        expected: &MissionRecord,
        at: i64,
        record: TokenRecord,
        establish_binding: bool,
    ) -> Result<(), MissionStoreError>;
}

impl MissionRecord {
    pub(crate) fn validate(&self) -> Result<(), MissionStoreError> {
        if aauth_rust_core::validate_server_identifier(&self.person_server).is_err()
            || aauth_rust_core::validate_server_identifier(&self.owner.issuer).is_err()
            || aauth_rust_core::validate_agent_identifier(&self.owner.subject).is_err()
            || self.document.agent() != self.owner.subject
            || self.person_id.is_empty()
        {
            return Err(MissionStoreError::Conflict);
        }
        Ok(())
    }
}
