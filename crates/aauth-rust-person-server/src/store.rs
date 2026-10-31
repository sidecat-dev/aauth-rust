use crate::{
    MissionAudit, MissionAuditError, MissionEdit, MissionRecord, MissionState, MissionStore,
    MissionStoreError,
};
use aauth_rust_r3::{IssuanceRecord, Reference, VocabularyUri};
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
    /// How many times [`Store::replace_binding`] replaced this Agent's binding.
    /// The first binding is generation 0; older rows decode as 0. Credentials
    /// carry the generation they were issued under, so a replacement never
    /// revives them, even when it binds the same person again.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: u64,
}

impl Binding {
    /// A first, active binding for `person_id`.
    pub fn new(person_id: &str) -> Self {
        Self {
            person_id: person_id.to_owned(),
            revoked: false,
            generation: 0,
        }
    }
    /// Whether `record` may be committed under this binding. Adapters call
    /// this inside the commit transaction.
    ///
    /// # Errors
    /// [`StoreError::RevokedBinding`] when the binding is revoked or `record`
    /// was issued under an earlier generation, and [`StoreError::Conflict`]
    /// when it names another person.
    pub fn admits(&self, record: &TokenRecord) -> Result<(), StoreError> {
        if self.revoked || self.generation != record.binding_generation {
            return Err(StoreError::RevokedBinding);
        }
        if self.person_id != record.person_id {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
    /// The new binding that replaces this revoked one
    /// (`draft-hardt-oauth-aauth-protocol`, Agent-Person Binding): active,
    /// for `person_id`, one generation later.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] while this binding is still active: revoke it
    /// first. [`StoreError::InvalidRecord`] for an empty `person_id` or a
    /// generation count that cannot grow.
    pub fn replacement(&self, person_id: &str) -> Result<Self, StoreError> {
        if !self.revoked {
            return Err(StoreError::Conflict);
        }
        if person_id.is_empty() {
            return Err(StoreError::InvalidRecord);
        }
        Ok(Self {
            person_id: person_id.to_owned(),
            revoked: false,
            generation: self
                .generation
                .checked_add(1)
                .ok_or(StoreError::InvalidRecord)?,
        })
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
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
    /// [`Binding::generation`] of the principal's binding at issuance. A
    /// replaced binding leaves this credential revoked. Older rows decode as 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub binding_generation: u64,
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
    /// A federated receipt for a chained request keeps the same tie as the
    /// Person token presented for it, so the chain survives the Access Server hop.
    pub upstream: Option<TokenTie>,
    /// R3 audit entry of an Auth token this PS issued for an R3 reference. It
    /// is part of the record, so committing the record writes the entry
    /// atomically with the issuance. Older rows decode as None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r3: Option<R3IssuanceAudit>,
}

/// R3 facts an issuer records with one Auth-token issuance
/// (`draft-hardt-aauth-r3`, Issuer Processing step 4). The issuer, `jti`,
/// Resource and issuance time are the enclosing record's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R3IssuanceAudit {
    /// `r3_uri` of the document or proposal.
    pub r3_uri: String,
    /// `r3_s256` of the document or proposal.
    pub r3_s256: String,
    /// Vocabulary URI selected while parsing that artifact.
    pub vocabulary: String,
    /// `ps` from the Resource token.
    pub person_server: String,
    /// `sub` from the Resource token.
    pub subject: String,
    /// `account` from the Resource token. `Some("")` is present and empty.
    pub account: Option<String>,
    /// `presented_jti` from the Resource token.
    pub presented_jti: String,
    /// `agent_jkt` from the Resource token.
    pub agent_jkt: String,
    /// `sub` of the Agent token the Auth token is bound to.
    pub agent: String,
    /// `sub` of the parent Agent token when a sub-agent token was presented.
    pub parent_agent: Option<String>,
}

impl TokenRecord {
    /// The R3 audit entry with this record's issuer, `jti`, Resource and
    /// issuance time, as the R3 crate's [`IssuanceRecord`]. `None` when the
    /// record carries no R3 facts.
    ///
    /// # Errors
    /// [`StoreError::InvalidRecord`] for a malformed reference or vocabulary.
    pub fn r3_issuance(&self) -> Result<Option<IssuanceRecord>, StoreError> {
        let Some(r3) = &self.r3 else {
            return Ok(None);
        };
        Ok(Some(IssuanceRecord {
            auth_token_issuer: self.token.reference.issuer.clone(),
            auth_token_jti: self.token.reference.jti.clone(),
            resource: self.resource.clone(),
            r3_reference: Reference::new(&r3.r3_uri, &r3.r3_s256)
                .map_err(|_| StoreError::InvalidRecord)?,
            vocabulary: VocabularyUri::parse(&r3.vocabulary)
                .map_err(|_| StoreError::InvalidRecord)?,
            issued_at: self.issued_at,
            person_server: r3.person_server.clone(),
            subject: r3.subject.clone(),
            account: r3.account.clone(),
            presented_jti: r3.presented_jti.clone(),
            agent_jkt: r3.agent_jkt.clone(),
            agent: r3.agent.clone(),
            parent_agent: r3.parent_agent.clone(),
        }))
    }
    /// Namespace owning this credential's Agent/person binding and directed identity.
    pub fn binding_issuer(&self) -> &str {
        self.person_server
            .as_deref()
            .unwrap_or(&self.token.reference.issuer)
    }
    /// Check the exact retained parent of a federated Auth receipt. Adapters run
    /// this atomically with commit, after exact existing-record comparison.
    /// A chained receipt carries its parent's `upstream` tie; any other receipt
    /// has none.
    ///
    /// # Errors
    /// InvalidRecord on a changed/missing PS namespace, parent, holder, identity
    /// or upstream tie.
    pub fn validate_federated_parent(&self, parent: &TokenRecord) -> Result<(), StoreError> {
        if self.person_server.is_none()
            || self.presented.as_ref() != Some(&parent.token)
            || self.binding_issuer() != parent.binding_issuer()
            || self.person_id != parent.person_id
            || self.binding_generation != parent.binding_generation
            || self.principal != parent.principal
            || self.agent != parent.agent
            || self.parent_agent != parent.parent_agent
            || self.agent_jkt != parent.agent_jkt
            || self.resource != parent.resource
            || self.subject != parent.subject
            || self.tenant != parent.tenant
            || self.expires_at > parent.expires_at
            || self.upstream != parent.upstream
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
        if let Some(r3) = &self.r3
            && (self.kind != TokenKind::Auth
                || self.person_server.is_some()
                || r3.person_server != self.token.reference.issuer
                || r3.subject != self.subject
                || r3.agent_jkt != self.agent_jkt
                || r3.agent != self.agent.subject
                || r3.parent_agent.as_ref() != self.parent_agent.as_ref().map(|p| &p.subject)
                || r3.presented_jti.is_empty()
                || self.r3_issuance().is_err())
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
    /// Establish a new binding for an Agent whose binding was revoked, for
    /// example when its person leaves an organization. Apply
    /// [`Binding::replacement`] to the stored binding in one atomic step and
    /// return the new binding. Credentials issued under the revoked binding
    /// stay revoked. This is host administration, never a token request.
    ///
    /// # Errors
    /// [`StoreError::MissingBinding`] when the Agent has no binding, and the
    /// errors of [`Binding::replacement`]. The default refuses with
    /// [`StoreError::Unavailable`], so a store that does not implement it
    /// cannot replace a binding.
    fn replace_binding(
        &self,
        issuer: &str,
        agent: &AgentIdentity,
        person_id: &str,
    ) -> Result<Binding, StoreError> {
        let _ = (issuer, agent, person_id);
        Err(StoreError::Unavailable)
    }
    /// Every retained issuance. The default is empty, so a store that does not
    /// offer a scan cannot drive a revocation cascade. Adapters that retain
    /// tokens override it.
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        Ok(Vec::new())
    }
    /// Persist an approved mission document once per owner and digest.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRecord`] when the document does not match its
    /// digest, [`StoreError::Conflict`] when different bytes are already stored,
    /// and [`StoreError::Unavailable`] when this store does not keep mission
    /// audits or the engine fails. The default refuses the write.
    fn write_mission_audit(&self, audit: &MissionAudit) -> Result<(), StoreError> {
        let _ = audit;
        Err(StoreError::Unavailable)
    }
    /// Read one owner's approved document. `Ok(None)` means this store has no row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the engine fails and
    /// [`StoreError::InvalidRecord`] when a stored row fails its digest checks.
    fn read_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
    ) -> Result<Option<MissionAudit>, StoreError> {
        let _ = (person_server, owner_issuer, owner_subject, s256);
        Ok(None)
    }
    /// Append an update or accept completion on an active stored mission.
    ///
    /// # Errors
    ///
    /// See [`MissionAuditError`]. The default is [`MissionAuditError::Unavailable`].
    fn edit_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
        edit: MissionEdit,
    ) -> Result<MissionAudit, MissionAuditError> {
        let _ = (person_server, owner_issuer, owner_subject, s256, edit);
        Err(MissionAuditError::Unavailable)
    }
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
    fn replace_binding(
        &self,
        issuer: &str,
        agent: &AgentIdentity,
        person_id: &str,
    ) -> Result<Binding, StoreError> {
        (**self).replace_binding(issuer, agent, person_id)
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        (**self).retained()
    }
    fn write_mission_audit(&self, audit: &MissionAudit) -> Result<(), StoreError> {
        (**self).write_mission_audit(audit)
    }
    fn read_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
    ) -> Result<Option<MissionAudit>, StoreError> {
        (**self).read_mission_audit(person_server, owner_issuer, owner_subject, s256)
    }
    fn edit_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
        edit: MissionEdit,
    ) -> Result<MissionAudit, MissionAuditError> {
        (**self).edit_mission_audit(person_server, owner_issuer, owner_subject, s256, edit)
    }
}

#[derive(Default)]
struct State {
    missions: BTreeMap<(String, AgentIdentity, String), MissionRecord>,
    audits: BTreeMap<(String, String, String, String), MissionAudit>,
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
            .or_insert_with(|| Binding::new(&record.person_id));
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
        // A chained record is held by the intermediary; its principal is still
        // the mission's owner, the calling Agent the upstream token names.
        if &current != expected
            || record.binding_issuer() != expected.person_server
            || record.person_id != expected.person_id
            || record.principal != expected.owner
            || (record.agent != expected.owner && record.upstream.is_none())
            || record.parent_agent.is_some()
            || record.person_server.is_some()
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
    fn replace_binding(
        &self,
        issuer: &str,
        agent: &AgentIdentity,
        person_id: &str,
    ) -> Result<Binding, StoreError> {
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let binding = state
            .bindings
            .get_mut(&(issuer.into(), agent.clone()))
            .ok_or(StoreError::MissingBinding)?;
        *binding = binding.replacement(person_id)?;
        Ok(binding.clone())
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .tokens
            .values()
            .cloned()
            .collect())
    }
    fn write_mission_audit(&self, audit: &MissionAudit) -> Result<(), StoreError> {
        audit.validate()?;
        let mut state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let key = audit_key(audit);
        if let Some(existing) = state.audits.get(&key) {
            return if existing == audit {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        state.audits.insert(key, audit.clone());
        Ok(())
    }
    fn read_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
    ) -> Result<Option<MissionAudit>, StoreError> {
        let state = self.0.lock().map_err(|_| StoreError::Unavailable)?;
        let Some(audit) = state
            .audits
            .get(&(
                person_server.into(),
                owner_issuer.into(),
                owner_subject.into(),
                s256.into(),
            ))
            .cloned()
        else {
            return Ok(None);
        };
        audit.validate()?;
        Ok(Some(audit))
    }
    fn edit_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
        edit: MissionEdit,
    ) -> Result<MissionAudit, MissionAuditError> {
        let mut state = self.0.lock().map_err(|_| MissionAuditError::Unavailable)?;
        let key = (
            person_server.into(),
            owner_issuer.into(),
            owner_subject.into(),
            s256.into(),
        );
        let mut audit = state
            .audits
            .get(&key)
            .cloned()
            .ok_or(MissionAuditError::NotFound)?;
        audit.apply(edit)?;
        state.audits.insert(key, audit.clone());
        Ok(audit)
    }
}

fn audit_key(audit: &MissionAudit) -> (String, String, String, String) {
    (
        audit.person_server.clone(),
        audit.owner_issuer.clone(),
        audit.owner_subject.clone(),
        audit.s256.clone(),
    )
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
        Some(binding) => binding.admits(&record)?,
        None if !establish_binding => return Err(StoreError::MissingBinding),
        None if record.binding_generation != 0 => return Err(StoreError::InvalidRecord),
        None => {}
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
        .or_insert_with(|| Binding::new(&record.person_id));
    state.directed.insert(directed_key, identity);
    state.subjects.insert(subject_key, record.person_id.clone());
    state.tokens.insert(record.token.reference.clone(), record);
    Ok(())
}
