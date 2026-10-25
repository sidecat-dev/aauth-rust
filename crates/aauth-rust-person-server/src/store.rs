use crate::{MissionRecord, MissionState, MissionStore, MissionStoreError};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Stable Agent identity; a rotated confirmation key does not create a new Agent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Trusted Agent Provider identifier.
    pub issuer: String,
    /// Agent identifier authenticated by that provider.
    pub subject: String,
}

/// Accountable person associated with an Agent in one Person Server namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Host's internal opaque person identifier, never put in a public token.
    pub person_id: String,
    /// A revoked binding cannot be reclaimed through the token endpoints.
    pub revoked: bool,
}

/// Issuer-qualified token identifier; JTI alone is not globally unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenReference {
    /// Actual PS or AS issuer of this retained credential.
    pub issuer: String,
    /// Issuer-local unique token identifier.
    pub jti: String,
}

/// Exact issued credential, preserving lineage across semantically equal JWTs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTie {
    /// Issuer and token identifier.
    pub reference: TokenReference,
    /// Unpadded base64url SHA-256 of the exact compact bytes.
    pub compact_sha256: String,
}

/// Retained credential kind. Person identity alone is never authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    /// PS-issued identity credential for one Resource.
    Person,
    /// PS-issued or PS-retained AS scoped authorization for one Resource.
    Auth,
}

/// State committed before releasing a Person or Auth token.
/// Hosts retain every field until retain_until and return owned snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    /// Authoritative parent of a child holder, verified before issuance. The
    /// principal is this parent; it owns consent and binding revocation. None
    /// preserves older direct/chained records. Never infer this from a name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent: Option<AgentIdentity>,
    /// Explicit PS namespace for a retained AS-issued Auth token. None preserves
    /// local issuance: the credential issuer also owns the binding. Older rows
    /// decode as None. Hosts/adapters must preserve this field on federated records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_server: Option<String>,
    /// Exact issued token reference and compact digest.
    pub token: TokenTie,
    /// Person identity or scoped authorization.
    pub kind: TokenKind,
    /// Resource audience.
    pub resource: String,
    /// Resource-directed public person identifier.
    pub subject: String,
    /// Host's internal person identifier.
    pub person_id: String,
    /// Organization carried by this identity, if any.
    pub tenant: Option<String>,
    /// Agent that holds this token's confirmation key.
    pub agent: AgentIdentity,
    /// Top-level Agent whose person binding authorizes this credential or chain.
    pub principal: AgentIdentity,
    /// JTI of the holder's Agent token used to obtain this credential.
    pub agent_token_jti: String,
    /// Thumbprint of the recipient Agent's confirmation key.
    pub agent_jkt: String,
    /// Trusted issuance time in Unix seconds.
    pub issued_at: i64,
    /// Credential expiration in Unix seconds.
    pub expires_at: i64,
    /// Earliest permitted record removal, including descendant/skew retention.
    pub retain_until: i64,
    /// Exact credential presented to obtain an Auth token.
    pub presented: Option<TokenTie>,
    /// Exact original caller credential required at both chained stages.
    pub upstream: Option<TokenTie>,
}

impl TokenRecord {
    /// Namespace owning this credential's Agent/person binding and directed identity.
    pub fn binding_issuer(&self) -> &str {
        self.person_server
            .as_deref()
            .unwrap_or(&self.token.reference.issuer)
    }
    /// Check the exact retained parent of a federated Auth receipt. Adapters run
    /// this atomically with commit, after exact existing-record comparison.
    ///
    /// # Errors
    /// InvalidRecord on a changed/missing PS namespace, parent, holder or identity.
    pub fn validate_federated_parent(&self, parent: &TokenRecord) -> Result<(), StoreError> {
        if self.person_server.is_none()
            || self.presented.as_ref() != Some(&parent.token)
            || self.binding_issuer() != parent.binding_issuer()
            || self.person_id != parent.person_id
            || self.principal != parent.principal
            || self.agent != parent.agent
            || self.parent_agent != parent.parent_agent
            || self.agent_jkt != parent.agent_jkt
            || self.resource != parent.resource
            || self.subject != parent.subject
            || self.tenant != parent.tenant
            || self.expires_at > parent.expires_at
            || parent.upstream.is_some()
        {
            return Err(StoreError::InvalidRecord);
        }
        Ok(())
    }
    /// Validate complete record shape and whether this issuance may establish a
    /// binding. Storage adapters must still check retained-token equality first,
    /// then validate, and atomically enforce binding and directed identities.
    /// Checks identifier syntax, nonempty token references/digests, and Person
    /// (no presented parent) / Auth (presented parent required) shape. Digest
    /// contents and parent authenticity belong to credential verification.
    /// This performs no lookup or current-time/credential verification.
    ///
    /// # Errors
    /// Returns InvalidRecord for incomplete identity, digest, target or lifetime
    /// fields, or when anything other than a direct or parent-mediated Person
    /// issuance tries to establish its principal's binding.
    pub fn validate_for_commit(&self, establish_binding: bool) -> Result<(), StoreError> {
        let valid_tie = |tie: &TokenTie| {
            !tie.reference.jti.is_empty()
                && !tie.compact_sha256.is_empty()
                && aauth_rust_core::validate_server_identifier(&tie.reference.issuer).is_ok()
        };
        let valid_identity = |identity: &AgentIdentity| {
            aauth_rust_core::validate_server_identifier(&identity.issuer).is_ok()
                && aauth_rust_core::validate_agent_identifier(&identity.subject).is_ok()
        };
        if self.parent_agent.as_ref().is_some_and(|parent| {
            !valid_identity(parent)
                || parent != &self.principal
                || parent == &self.agent
                || parent.issuer != self.agent.issuer
                || self.upstream.is_some()
        }) {
            return Err(StoreError::InvalidRecord);
        }
        if self.person_server.as_ref().is_some_and(|ps| {
            aauth_rust_core::validate_server_identifier(ps).is_err()
                || self.kind != TokenKind::Auth
                || establish_binding
                || self.upstream.is_some()
        }) || !valid_tie(&self.token)
            || !valid_identity(&self.agent)
            || !valid_identity(&self.principal)
            || self.presented.as_ref().is_some_and(|tie| !valid_tie(tie))
            || self.upstream.as_ref().is_some_and(|tie| !valid_tie(tie))
            || (self.kind == TokenKind::Person && self.presented.is_some())
            || (self.kind == TokenKind::Auth && self.presented.is_none())
            || self.person_id.is_empty()
            || self.subject.is_empty()
            || self.agent_jkt.is_empty()
            || self.agent_token_jti.is_empty()
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.retain_until < self.expires_at
            || aauth_rust_core::validate_server_identifier(&self.resource).is_err()
            || (establish_binding
                && (self.kind != TokenKind::Person
                    || (self.agent != self.principal && self.parent_agent.is_none())
                    || self.upstream.is_some()))
        {
            return Err(StoreError::InvalidRecord);
        }
        Ok(())
    }
}

/// Storage failure; operational failures must never release an unretained token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A unique token, binding or directed identity already has different data.
    #[error(
        "retained token, Agent binding or directed person identity conflicts with existing state"
    )]
    Conflict,
    /// The original Agent's binding was revoked.
    #[error("Agent-person binding is revoked; an administrator must establish any replacement")]
    RevokedBinding,
    /// Authorization attempted without an existing original Agent binding.
    #[error("original Agent-person binding is missing")]
    MissingBinding,
    /// Record fields are incomplete/inconsistent, or exceed an adapter's limit.
    #[error(
        "invalid issuance record: check identity, token digest, expiry and the adapter's record-size limit"
    )]
    InvalidRecord,
    /// Storage cannot confirm completion; a whole commit outcome may be unknown.
    #[error("Person Server storage is unavailable")]
    Unavailable,
}

/// Host storage boundary. Operations must be linearizable. Logical refusals
/// (conflict, invalid record, missing/revoked binding) preserve state. An
/// operational Unavailable may leave a whole transaction's outcome uncertain;
/// partial binding/index/token changes must never become visible.
/// Commit is identical-record idempotent, issuer/JTI unique, and atomic
/// with person binding/directed-identity checks. Revocation cannot be undone by a
/// token request. No record may disappear before its retain_until timestamp.
pub trait Store: Send + Sync {
    /// Optional same-store mission boundary. None refuses mission consumption.
    fn missions(&self) -> Option<&dyn MissionStore> {
        None
    }
    /// Read an Agent binding in this PS namespace.
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError>;
    /// Read an owned, complete retained issuance record.
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError>;
    /// Atomically retain a token and consistent directed identity. Only a direct
    /// Person issuance may establish a previously absent binding. Auth/chained
    /// issuance requires the original principal's active binding already exists.
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError>;
    /// Revoke the original Agent's binding, immediately preventing new issuance.
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError>;
}

impl<T: Store + ?Sized> Store for Arc<T> {
    fn missions(&self) -> Option<&dyn MissionStore> {
        (**self).missions()
    }
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        (**self).binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        (**self).token(reference)
    }
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError> {
        (**self).commit(record, establish_binding)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        (**self).revoke_binding(issuer, agent)
    }
}

#[derive(Default)]
struct State {
    missions: BTreeMap<(String, AgentIdentity, String), MissionRecord>,
    bindings: BTreeMap<(String, AgentIdentity), Binding>,
    tokens: BTreeMap<TokenReference, TokenRecord>,
    directed: BTreeMap<(String, String, String), String>,
    subjects: BTreeMap<(String, String, String), String>,
}

/// Volatile reference store with atomic operations. Clones share the same state.
/// It retains records without cleanup and loses all state on process restart;
/// production hosts supply a durable implementation and run the public contract.
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<State>>);
impl MemoryStore {
    /// Install a separately host-approved record and its authenticated person
    /// binding atomically. This administrative fixture boundary is not consent
    /// collection, a login endpoint or a mission proposal API. An exact retry of
    /// the same Active record is idempotent. A record that is not Active is
    /// refused before any binding is written, and a terminated mission cannot
    /// be replaced or reactivated.
    ///
    /// # Errors
    /// Refuses a non-active record, invalid or different records, and
    /// conflicting or revoked bindings.
    pub fn install_approved_mission(&self, record: MissionRecord) -> Result<(), MissionStoreError> {
        record.validate()?;
        if record.state != MissionState::Active {
            return Err(MissionStoreError::Conflict);
        }
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let key = (
            record.person_server.clone(),
            record.owner.clone(),
            record.document.s256().to_owned(),
        );
        if let Some(existing) = state.missions.get(&key) {
            return if existing == &record {
                Ok(())
            } else {
                Err(MissionStoreError::Conflict)
            };
        }
        let binding_key = (record.person_server.clone(), record.owner.clone());
        match state.bindings.get(&binding_key) {
            Some(binding) if binding.revoked => return Err(StoreError::RevokedBinding.into()),
            Some(binding) if binding.person_id != record.person_id => {
                return Err(MissionStoreError::Conflict);
            }
            _ => {}
        }
        state
            .bindings
            .entry(binding_key)
            .or_insert_with(|| Binding {
                person_id: record.person_id.clone(),
                revoked: false,
            });
        state.missions.insert(key, record);
        Ok(())
    }
    /// Permanently terminate an owned mission using a host-supplied reason.
    /// This is host administration, not a protocol mission-management endpoint.
    ///
    /// # Errors
    /// Absent/wrong-owner records are indistinguishable; storage fails closed.
    pub fn terminate_mission(
        &self,
        ps: &str,
        owner: &AgentIdentity,
        s256: &str,
        reason: &str,
    ) -> Result<(), MissionStoreError> {
        // An empty reason is not a termination record. The draft leaves the
        // empty string unspecified; this store refuses it before any write.
        if reason.is_empty() {
            return Err(MissionStoreError::Conflict);
        }
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let record = state
            .missions
            .get_mut(&(ps.into(), owner.clone(), s256.into()))
            .ok_or(MissionStoreError::NotFound)?;
        if record.state == MissionState::Active {
            record.state = MissionState::Terminated(reason.into());
        }
        Ok(())
    }
}
fn active_mission_locked(
    state: &mut State,
    ps: &str,
    owner: &AgentIdentity,
    s256: &str,
    at: i64,
) -> Result<MissionRecord, MissionStoreError> {
    let record = state
        .missions
        .get_mut(&(ps.into(), owner.clone(), s256.into()))
        .ok_or(MissionStoreError::NotFound)?;
    if record.state == MissionState::Active
        && record.document.expires_at().is_some_and(|exp| at >= exp)
    {
        record.state = MissionState::Terminated("expired".into());
    }
    if let MissionState::Terminated(reason) = &record.state {
        return Err(MissionStoreError::Terminated(reason.clone()));
    }
    let binding = state
        .bindings
        .get(&(ps.into(), owner.clone()))
        .ok_or(StoreError::MissingBinding)?;
    if binding.revoked {
        return Err(StoreError::RevokedBinding.into());
    }
    if binding.person_id != record.person_id {
        return Err(MissionStoreError::Conflict);
    }
    Ok(record.clone())
}
impl MissionStore for MemoryStore {
    fn load_mission(
        &self,
        ps: &str,
        owner: &AgentIdentity,
        s256: &str,
        at: i64,
    ) -> Result<MissionRecord, MissionStoreError> {
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        active_mission_locked(&mut state, ps, owner, s256, at)
    }
    fn commit_mission_token(
        &self,
        expected: &MissionRecord,
        at: i64,
        record: TokenRecord,
        establish_binding: bool,
    ) -> Result<(), MissionStoreError> {
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let current = active_mission_locked(
            &mut state,
            &expected.person_server,
            &expected.owner,
            expected.document.s256(),
            at,
        )?;
        if &current != expected
            || record.binding_issuer() != expected.person_server
            || record.person_id != expected.person_id
            || record.principal != expected.owner
            || record.agent != expected.owner
            || record.parent_agent.is_some()
            || record.person_server.is_some()
            || record.upstream.is_some()
            || record.issued_at > at
            || record.expires_at <= at
            || expected
                .document
                .expires_at()
                .is_some_and(|exp| record.expires_at > exp)
        {
            return Err(MissionStoreError::Conflict);
        }
        commit_locked(&mut state, record, establish_binding).map_err(Into::into)
    }
}
impl Store for MemoryStore {
    fn missions(&self) -> Option<&dyn MissionStore> {
        Some(self)
    }
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .bindings
            .get(&(issuer.into(), agent.clone()))
            .cloned())
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .tokens
            .get(reference)
            .cloned())
    }
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError> {
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        commit_locked(&mut state, record, establish_binding)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let binding = state
            .bindings
            .get_mut(&(issuer.into(), agent.clone()))
            .ok_or(StoreError::MissingBinding)?;
        binding.revoked = true;
        Ok(())
    }
}

fn commit_locked(
    state: &mut State,
    record: TokenRecord,
    establish_binding: bool,
) -> Result<(), StoreError> {
    if let Some(existing) = state.tokens.get(&record.token.reference) {
        return if existing == &record {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
    }
    record.validate_for_commit(establish_binding)?;
    if record.person_server.is_some() {
        let reference = &record
            .presented
            .as_ref()
            .ok_or(StoreError::InvalidRecord)?
            .reference;
        let parent = state
            .tokens
            .get(reference)
            .ok_or(StoreError::InvalidRecord)?;
        record.validate_federated_parent(parent)?;
    }
    let issuer = record.binding_issuer();
    let binding_key = (issuer.to_owned(), record.principal.clone());
    match state.bindings.get(&binding_key) {
        Some(binding) if binding.revoked => return Err(StoreError::RevokedBinding),
        Some(binding) if binding.person_id != record.person_id => {
            return Err(StoreError::Conflict);
        }
        None if !establish_binding => return Err(StoreError::MissingBinding),
        _ => {}
    }
    let directed_key = (
        issuer.to_owned(),
        record.person_id.clone(),
        record.resource.clone(),
    );
    let identity = record.subject.clone();
    let subject_key = (
        issuer.to_owned(),
        record.resource.clone(),
        record.subject.clone(),
    );
    if state
        .directed
        .get(&directed_key)
        .is_some_and(|v| v != &identity)
        || state
            .subjects
            .get(&subject_key)
            .is_some_and(|id| id != &record.person_id)
    {
        return Err(StoreError::Conflict);
    }
    state
        .bindings
        .entry(binding_key)
        .or_insert_with(|| Binding {
            person_id: record.person_id.clone(),
            revoked: false,
        });
    state.directed.insert(directed_key, identity);
    state.subjects.insert(subject_key, record.person_id.clone());
    state.tokens.insert(record.token.reference.clone(), record);
    Ok(())
}
