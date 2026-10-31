use crate::{AgentIdentity, StoreError, TokenRecord};
use aauth_rust_core::ApprovedMission;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_AUDIT_JSON: usize = 32 * 1024;
const MAX_UPDATES: usize = 64;

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
    /// the owner as principal, private person, mission ceiling and no child or
    /// federation. Its holder is the owner, except on a chained record (with an
    /// `upstream` tie), which the intermediary holds under the calling Agent's mission.
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

/// Exact JSON bytes of one accepted update or completion summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionUpdateBytes {
    /// Unpadded base64url SHA-256 of the persisted JSON.
    pub s256: String,
    /// Unpadded base64url of the exact persisted JSON.
    pub encoded: String,
}

impl MissionUpdateBytes {
    /// Digest and encode the exact JSON bytes that will be persisted.
    ///
    /// # Errors
    ///
    /// Rejects an empty value or one larger than 32 KiB.
    pub fn from_exact(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.is_empty() || bytes.len() > MAX_AUDIT_JSON {
            return Err(StoreError::InvalidRecord);
        }
        let value = Self {
            s256: URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
            encoded: URL_SAFE_NO_PAD.encode(bytes),
        };
        value.validate()?;
        Ok(value)
    }

    /// Reject bytes whose encoding or digest does not match this value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRecord`] when the pair is not exact.
    pub fn validate(&self) -> Result<(), StoreError> {
        if !bounded_encoding(&self.encoded) {
            return Err(StoreError::InvalidRecord);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.encoded)
            .map_err(|_| StoreError::InvalidRecord)?;
        if bytes.is_empty()
            || bytes.len() > MAX_AUDIT_JSON
            || URL_SAFE_NO_PAD.encode(&bytes) != self.encoded
            || URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)) != self.s256
        {
            return Err(StoreError::InvalidRecord);
        }
        Ok(())
    }
}

/// One change to an approved mission that is already stored.
#[derive(Clone, Debug)]
pub enum MissionEdit {
    /// Append one accepted update. The mission digest stays the same.
    Update(MissionUpdateBytes),
    /// Record the completion summary and terminate with reason `completed`.
    Completion(MissionUpdateBytes),
}

/// Approved mission document and the updates a Person Server has accepted.
/// This is the audit log, not the issuance [`MissionRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionAudit {
    /// Person Server that approved and persists this document.
    pub person_server: String,
    /// Agent provider of the owning agent.
    pub owner_issuer: String,
    /// Agent identifier named by the approved document.
    pub owner_subject: String,
    /// SHA-256 of the exact mission bytes, unpadded base64url.
    pub s256: String,
    /// Unpadded base64url of the exact persisted mission JSON.
    pub encoded: String,
    /// Accepted updates, oldest first, each the exact JSON the server persisted.
    pub updates: Vec<MissionUpdateBytes>,
    /// Completion summary, when the mission was completed through the endpoint.
    pub summary: Option<MissionUpdateBytes>,
    /// Set when the mission is terminated. Completion uses `completed`.
    pub termination_reason: Option<String>,
}

impl MissionAudit {
    /// Reject a row whose digest, owner, or update bytes do not match.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRecord`] when any check fails. At most 64
    /// updates are retained, and each encoded JSON value must fit in 32 KiB.
    pub fn validate(&self) -> Result<(), StoreError> {
        if !bounded_encoding(&self.encoded)
            || self.updates.len() > MAX_UPDATES
            || aauth_rust_core::validate_server_identifier(&self.person_server).is_err()
            || aauth_rust_core::validate_server_identifier(&self.owner_issuer).is_err()
        {
            return Err(StoreError::InvalidRecord);
        }
        let document = ApprovedMission::decode(&self.s256, &self.encoded)
            .map_err(|_| StoreError::InvalidRecord)?;
        if document.agent() != self.owner_subject {
            return Err(StoreError::InvalidRecord);
        }
        for update in &self.updates {
            update.validate()?;
        }
        if let Some(summary) = &self.summary {
            summary.validate()?;
        }
        if self
            .termination_reason
            .as_ref()
            .is_some_and(|reason| reason.is_empty() || reason.len() > 256)
        {
            return Err(StoreError::InvalidRecord);
        }
        Ok(())
    }

    /// Why the mission is terminated at `now`: the recorded reason, or `expired`
    /// once `now` reaches the document's `expires_at`. `None` while it is active.
    pub(crate) fn termination_at(&self, now: i64) -> Result<Option<&str>, StoreError> {
        if let Some(reason) = &self.termination_reason {
            return Ok(Some(reason.as_str()));
        }
        let document = ApprovedMission::decode(&self.s256, &self.encoded)
            .map_err(|_| StoreError::InvalidRecord)?;
        Ok(document
            .expires_at()
            .is_some_and(|expires_at| now >= expires_at)
            .then_some("expired"))
    }

    /// Apply an update or completion. The row is unchanged when this returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`MissionAuditError::Terminated`] when the mission is already
    /// terminated, and [`MissionAuditError::Invalid`] when the bytes or the
    /// 64-update limit fail.
    pub fn apply(&mut self, edit: MissionEdit) -> Result<(), MissionAuditError> {
        self.validate().map_err(|_| MissionAuditError::Invalid)?;
        if let Some(reason) = &self.termination_reason {
            return Err(MissionAuditError::Terminated(reason.clone()));
        }
        match edit {
            MissionEdit::Update(update) => {
                update.validate().map_err(|_| MissionAuditError::Invalid)?;
                if self.updates.len() >= MAX_UPDATES {
                    return Err(MissionAuditError::Invalid);
                }
                self.updates.push(update);
            }
            MissionEdit::Completion(summary) => {
                summary.validate().map_err(|_| MissionAuditError::Invalid)?;
                self.summary = Some(summary);
                self.termination_reason = Some("completed".into());
            }
        }
        self.validate().map_err(|_| MissionAuditError::Invalid)
    }
}

/// Refusal from a mission-audit read or edit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MissionAuditError {
    /// No document for this owner and digest. Do not disclose another owner's row.
    #[error("approved mission not found for this Agent and Person Server")]
    NotFound,
    /// The mission is already terminated, including completion.
    #[error("approved mission is terminated ({0})")]
    Terminated(String),
    /// The stored or submitted bytes failed a digest or size check.
    #[error("invalid mission audit record")]
    Invalid,
    /// The store cannot keep mission audits, or the storage engine failed.
    #[error("Person Server storage is unavailable")]
    Unavailable,
}

fn bounded_encoding(encoded: &str) -> bool {
    !encoded.is_empty() && encoded.len() <= MAX_AUDIT_JSON * 4 / 3 + 4
}
