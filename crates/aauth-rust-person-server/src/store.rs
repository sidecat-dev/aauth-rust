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
    /// Person Server that issued this retained token.
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
    /// PS-issued scoped authorization credential for one Resource.
    Auth,
}

/// State committed before releasing a Person or Auth token.
/// Hosts retain every field until retain_until and return owned snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
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
    /// Original calling Agent whose person binding authorizes the chain.
    pub principal: AgentIdentity,
    /// JTI of the Agent token used to obtain this credential.
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
    /// Validate complete record shape and whether this issuance may establish a
    /// binding. Storage adapters must still check retained-token equality first,
    /// then validate, and atomically enforce binding and directed identities.
    /// This performs no lookup or current-time/credential verification.
    ///
    /// # Errors
    /// Returns InvalidRecord for incomplete identity, digest, target or lifetime
    /// fields, or when a non-direct Person issuance tries to establish a binding.
    pub fn validate_for_commit(&self, establish_binding: bool) -> Result<(), StoreError> {
        if self.token.reference.jti.is_empty()
            || self.token.compact_sha256.is_empty()
            || self.person_id.is_empty()
            || self.subject.is_empty()
            || self.agent_jkt.is_empty()
            || self.agent_token_jti.is_empty()
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.retain_until < self.expires_at
            || aauth_rust_core::validate_server_identifier(&self.token.reference.issuer).is_err()
            || aauth_rust_core::validate_server_identifier(&self.resource).is_err()
            || (establish_binding
                && (self.kind != TokenKind::Person
                    || self.agent != self.principal
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
    /// Record fields are incomplete or inconsistent.
    #[error("invalid issuance record: retain complete identity, token digest and expiry fields")]
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
impl Store for MemoryStore {
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
        if let Some(existing) = state.tokens.get(&record.token.reference) {
            return if existing == &record {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        record.validate_for_commit(establish_binding)?;
        let issuer = &record.token.reference.issuer;
        let binding_key = (issuer.clone(), record.principal.clone());
        match state.bindings.get(&binding_key) {
            Some(binding) if binding.revoked => return Err(StoreError::RevokedBinding),
            Some(binding) if binding.person_id != record.person_id => {
                return Err(StoreError::Conflict);
            }
            None if !establish_binding => return Err(StoreError::MissingBinding),
            _ => {}
        }
        let directed_key = (
            issuer.clone(),
            record.person_id.clone(),
            record.resource.clone(),
        );
        let identity = record.subject.clone();
        let subject_key = (
            issuer.clone(),
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
