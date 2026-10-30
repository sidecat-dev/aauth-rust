//! Class R3 on a Person-Server Resource.
//!
//! `draft-hardt-aauth-r3` at the pinned revision: Resource Metadata Extensions,
//! Authorization Endpoint Extensions, Content Addressing, R3 Document Access
//! Restriction, Operation Validation and Resource Enforcement. The host selects
//! the authoritative definitions, maps each protected request to at most one
//! operation, and supplies a durable immutable document store. Per-call
//! proposals are opt-in through `with_r3_per_call`. A configured access server
//! is the federated profile: its Auth tokens and document fetches use
//! `aauth-access.json`, and the Resource token audience is that server. With
//! [`PsAuthorizationResource::with_mission_context`] on the direct path, a class
//! document carries the Person token's mission and admits only an Auth token for
//! that mission. Missions with an access server or per-call proposals are refused.
use std::collections::BTreeMap;
use std::sync::Arc;

use aauth_rust_core::{AgentKeyResolver, ResourceClaims, TokenError, VerifiedAuthToken};
use aauth_rust_jose::strict_json;
use aauth_rust_r3::{
    AuthoritativeSnapshot, DefinitionRegistry, Display, Document, DocumentOptions, Operation,
    OperationAccess, OperationSet, Reference, Registry, VocabularyUri, digest,
    validate_document_account, verify_auth_token_claims, verify_budget_auth_token,
};
use aauth_rust_signature_key::{Error, KeyMaterial, PreparedRequest, required_components};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json, value::RawValue};

use super::{
    AuthDecision, ProactiveDecision, PsAuthorizationResource, PsConfigurationError, refusal,
};
use crate::{PolicyOutcome, SignatureFailure};

const PERSON_DOCUMENT: &str = "aauth-person.json";
const ACCESS_DOCUMENT: &str = "aauth-access.json";

#[path = "r3_per_call.rs"]
mod per_call;
pub use per_call::{
    BoxedR3Describe, BoxedR3Present, BoxedR3Release, R3CallDescription, R3CallResult, R3CallStore,
    R3CallToken, R3Claim, R3HeldRequest, R3PendingHeaders, R3PerCallConfig, R3ProposalRecord,
    R3Release,
};

/// A host adapter or store could not answer. Nothing is disclosed or admitted.
#[derive(Debug)]
pub struct R3HostError(Box<dyn std::error::Error + Send + Sync>);
impl R3HostError {
    /// Keep the host cause for logging. It is never sent to the caller.
    pub fn new(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }
}
impl std::fmt::Display for R3HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R3 host adapter: {}", self.0)
    }
}
impl std::error::Error for R3HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Host consent description for one validated operation set.
pub type BoxedR3Display = Box<dyn Fn(&OperationSet) -> Result<Display, R3HostError> + Send + Sync>;

/// Host mapping from one protected request to its R3 operation.
///
/// `Ok(None)` names a Core-only route. The mapping runs only after the
/// credential and HTTP proof verified, and it must not depend on the token.
pub type BoxedR3OperationMapper =
    Box<dyn Fn(&Request<Vec<u8>>) -> Result<Option<Operation>, R3HostError> + Send + Sync>;

/// One advertised vocabulary and the authoritative snapshot the host selected for it.
pub struct R3Vocabulary {
    /// Operations a host-chosen parser derived from the source at its
    /// advertised discovery endpoint. The Resource never refreshes it.
    pub definition: AuthoritativeSnapshot,
    /// Optional resource-asserted consent text placed in each document.
    pub display: Option<BoxedR3Display>,
}

/// Host configuration for immediate class R3 on a direct Person-Server Resource.
pub struct R3Config {
    /// Allowlist used for every request, document and token claim.
    pub registry: Registry,
    /// Parser registrations every snapshot must come from.
    pub definitions: DefinitionRegistry,
    /// Simultaneously advertised vocabularies, at most one per URI.
    pub vocabularies: Vec<R3Vocabulary>,
    /// Durable immutable document custody. The Resource never prunes it.
    pub documents: Arc<dyn R3DocumentStore>,
    /// Request-to-operation mapping for protected routes.
    pub operation_for_request: BoxedR3OperationMapper,
    /// Also require this Resource's Core scopes on R3 routes.
    ///
    /// When set, an `r3_operations` request must name `scope`, and an R3 Auth
    /// token must carry every configured scope as well as the operation.
    pub require_core_scope: bool,
}

/// One exact class document and the entitlement and lineage it was issued for.
///
/// The record is committed before its Resource token is released and is the
/// only source the signed document endpoint serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3DocumentRecord {
    /// `r3_uri` and `r3_s256` of the released Resource token.
    pub reference: Reference,
    /// Exact document bytes. They are served verbatim and never reserialized.
    pub exact_json: Vec<u8>,
    /// `ps` of the Resource token; entitled to fetch with `aauth-person.json`.
    pub person_server: String,
    /// `aud` of the Resource token: the Auth-token issuer entitled to fetch.
    pub auth_token_issuer: String,
    /// Discovery role of that issuer. `aauth-person.json` on the direct path
    /// and `aauth-access.json` when this Resource has an access server.
    pub auth_token_issuer_document: String,
    /// `jti` of the Resource token. It is part of the document URI.
    pub resource_token_jti: String,
    /// Exact compact Resource token that carries this reference.
    pub resource_token: String,
    /// `presented_jti` of the Resource token.
    pub presented_jti: String,
    /// Directed `sub` of the Resource token.
    pub subject: String,
    /// `agent_jkt` of the Resource token.
    pub agent_jkt: String,
    /// `tenant` of the Resource token.
    pub tenant: Option<String>,
    /// `account` of the Resource token and the document.
    pub account: Option<String>,
    /// Core `scope` of the Resource token, when it carried one.
    pub scope: Option<String>,
    /// `iat` of the Resource token.
    pub issued_at: i64,
    /// `exp` of the Resource token.
    pub expires_at: i64,
    /// `mission_s256` of the Resource token, when it carried one.
    pub mission_s256: Option<String>,
}

/// A document record could not be committed or loaded.
#[derive(Debug)]
pub enum R3StoreError {
    /// A different record is already retained at that URI. Nothing changed.
    Conflict,
    /// Storage failed. A commit may or may not have been retained.
    Unavailable(R3HostError),
}

/// Durable, confidential, immutable document custody owned by the host.
///
/// `commit` copies the whole record atomically, accepts an exact repeat, and
/// returns [`R3StoreError::Conflict`] for any different record at the same
/// URI without changing it. Any other failure may have committed. The
/// Resource then withholds the token and does not retry. `load` returns an
/// independent copy by exact URI, `Ok(None)` for a URI never committed, and
/// survives process restart. A volatile map does not satisfy this contract.
pub trait R3DocumentStore: Send + Sync {
    /// Retain `record` before its Resource token becomes observable.
    ///
    /// # Errors
    /// Returns [`R3StoreError`] as described on the trait.
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError>;
    /// Load the record committed at exactly `uri`.
    ///
    /// # Errors
    /// Returns [`R3StoreError::Unavailable`] when storage cannot answer.
    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError>;
}

/// The class grant, or the per-call completion, that admitted a protected R3 request.
#[derive(Clone)]
pub struct R3Grant {
    reference: Reference,
    operation: Operation,
    completion: Option<per_call::R3Completion>,
}
impl std::fmt::Debug for R3Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = self
            .operation
            .json()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        f.debug_struct("R3Grant")
            .field("reference", &self.reference)
            .field("operation", &operation)
            .finish()
    }
}
impl R3Grant {
    /// The signed `r3_uri` and `r3_s256`.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }
    /// The mapped operation found in `r3_granted`.
    pub fn operation(&self) -> &Operation {
        &self.operation
    }
}

pub(super) struct R3Profile {
    registry: Registry,
    vocabularies: BTreeMap<VocabularyUri, R3Vocabulary>,
    documents: Arc<dyn R3DocumentStore>,
    operation_for_request: BoxedR3OperationMapper,
    pub(super) require_core_scope: bool,
    per_call: Option<R3PerCallConfig>,
}

enum Issue {
    Host,
    Retention,
}

impl R3Profile {
    fn new(config: R3Config) -> Result<Self, PsConfigurationError> {
        let invalid = PsConfigurationError::InvalidR3Profile;
        if config.registry.is_empty()
            || config.definitions.is_empty()
            || config.vocabularies.is_empty()
        {
            return Err(invalid);
        }
        let mut vocabularies = BTreeMap::new();
        for vocabulary in config.vocabularies {
            let definition = &vocabulary.definition;
            config
                .definitions
                .validate(definition)
                .map_err(|_| invalid)?;
            config
                .registry
                .validate_operation_set(&definition.operations())
                .map_err(|_| invalid)?;
            let uri = definition.vocabulary().clone();
            if vocabularies.insert(uri, vocabulary).is_some() {
                return Err(invalid);
            }
        }
        Ok(Self {
            registry: config.registry,
            vocabularies,
            documents: config.documents,
            operation_for_request: config.operation_for_request,
            require_core_scope: config.require_core_scope,
            per_call: None,
        })
    }

    fn metadata(&self) -> Value {
        let advertised: BTreeMap<&str, &str> = self
            .vocabularies
            .iter()
            .map(|(uri, vocabulary)| {
                (
                    uri.as_str(),
                    vocabulary.definition.receipt().discovery_endpoint(),
                )
            })
            .collect();
        json!(advertised)
    }

    /// Operation Validation: the set must be defined by the advertised source.
    fn defined(&self, operations: &OperationSet) -> Result<(), ()> {
        self.registry
            .validate_operation_set(operations)
            .map_err(|_| ())?;
        let vocabulary = self.vocabularies.get(operations.vocabulary()).ok_or(())?;
        vocabulary
            .definition
            .validate_defined(operations)
            .map_err(|_| ())
    }

    /// Whether the authoritative definition this Resource advertises annotates
    /// `operation` with `budget: true`, so that running it draws down a budget.
    /// This reads the Resource's own publication about the operation and says
    /// nothing about any caller.
    fn metered(&self, operation: &Operation) -> Result<bool, ()> {
        let vocabulary = self.vocabularies.get(operation.vocabulary()).ok_or(())?;
        let hints = vocabulary.definition.hints_for(operation).map_err(|_| ())?;
        Ok(hints.and_then(|hints| hints.budget()) == Some(true))
    }

    /// Map a verified request. A mapped operation outside the definition is a host error.
    fn route(&self, request: &Request<Vec<u8>>) -> Result<Option<Operation>, ()> {
        match (self.operation_for_request)(request).map_err(|_| ())? {
            None => Ok(None),
            Some(operation) => {
                let set = OperationSet::new(std::slice::from_ref(&operation)).map_err(|_| ())?;
                self.defined(&set)?;
                Ok(Some(operation))
            }
        }
    }

    /// `r3_operations` from an `/authorize` body. `Ok(None)` is a Core request.
    fn requested(&self, body: &[u8]) -> Result<Option<OperationSet>, ()> {
        let value = strict_json(body).map_err(|_| ())?;
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        if !object.contains_key("r3_operations") {
            return Ok(None);
        }
        // Account binding is not this profile. A budget object is judged by
        // the caller, which refuses it when budgets are not enabled.
        if object.contains_key("account") {
            return Err(());
        }
        let members: BTreeMap<String, Box<RawValue>> =
            serde_json::from_slice(body).map_err(|_| ())?;
        let raw = members.get("r3_operations").ok_or(())?;
        let operations = self
            .registry
            .parse_operation_set(raw.get().as_bytes())
            .map_err(|_| ())?;
        self.defined(&operations)?;
        Ok(Some(operations))
    }
}

/// Identity of one class document: its digest, who may fetch it, and the
/// Resource token it was issued for. Distinct issuances never share a URI.
/// `origin` is the canonical signed origin, so the URI is the one fetched.
fn class_document_uri(
    origin: &str,
    document_digest: &str,
    person_server: &str,
    auth_token_issuer: &str,
    resource_token_jti: &str,
) -> String {
    let entitlement = serde_json::to_vec(&json!([
        "aauth-r3-entitlement-v1",
        person_server,
        auth_token_issuer
    ]))
    .unwrap_or_default();
    let lineage = format!("aauth-r3-lineage-v1\0{resource_token_jti}");
    format!(
        "{origin}/r3/c.{document_digest}.{}.{}",
        digest(&entitlement),
        digest(lineage.as_bytes())
    )
}

pub(super) fn carries_r3(extra: &BTreeMap<String, Value>) -> bool {
    ["r3_uri", "r3_s256", "r3_granted", "r3_per_call"]
        .iter()
        .any(|name| extra.contains_key(*name))
}

fn document_response(status: StatusCode, code: &str) -> Response<Vec<u8>> {
    let mut response = refusal(status, code);
    no_store(&mut response);
    response
}

fn no_store(response: &mut Response<Vec<u8>>) {
    let headers = response.headers_mut();
    headers.insert(
        "cache-control",
        "private, no-store, no-transform"
            .parse()
            .expect("static cache control"),
    );
    headers.insert(
        "vary",
        "Signature-Key, Signature-Input, Signature"
            .parse()
            .expect("static vary"),
    );
}

impl<K: AgentKeyResolver, P, O> PsAuthorizationResource<K, P>
where
    P: Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Enable class R3 on this Person-Server Resource.
    ///
    /// Metadata advertises `r3_vocabularies`. `POST /authorize` accepts
    /// `r3_operations`, validates them against the selected definition, commits
    /// the exact document and its fetch entitlement, and only then returns
    /// the Resource token. [`Self::r3_document`] serves those bytes to the
    /// entitled signer. On the direct path the Person Server, signing
    /// `aauth-person.json`, is that issuer. After [`Self::new_federated`] the
    /// access server is the Resource-token audience and signs
    /// `aauth-access.json`; the Person Server remains entitled to fetch with
    /// `aauth-person.json`. A protected request that the host maps to an
    /// operation requires an Auth token from that issuer whose `r3_granted`
    /// covers it. Unmapped routes keep Core scope authorization and refuse R3
    /// Auth tokens. Budgets remain a separate profile via [`Self::with_budgets`].
    ///
    /// # Errors
    /// [`PsConfigurationError::InvalidR3Profile`] for an empty registry,
    /// definition set or vocabulary list, a snapshot from an unregistered
    /// parser or registration, a repeated vocabulary, or mission context on a
    /// Resource with an access server. A mission composition that this profile
    /// does not implement, added afterwards, makes every request a `500`.
    pub fn with_r3(mut self, config: R3Config) -> Result<Self, PsConfigurationError> {
        if self.mission_context && self.access_server.is_some() {
            return Err(PsConfigurationError::InvalidR3Profile);
        }
        self.r3 = Some(Box::new(R3Profile::new(config)?));
        Ok(self)
    }

    /// Mission context with R3 is the direct class profile only. An access
    /// server or per-call proposals in the same Resource refuse it.
    pub(super) fn r3_composition_refused(&self) -> bool {
        self.mission_context
            && self
                .r3
                .as_ref()
                .is_some_and(|profile| self.access_server.is_some() || profile.per_call.is_some())
    }

    /// Discovery document of the Auth-token issuer for this Resource's topology.
    ///
    /// Matches Go `resource`: an access server selects `aauth-access.json`,
    /// and the direct Person-Server path selects `aauth-person.json`.
    pub(super) fn auth_token_issuer_document(&self) -> &'static str {
        if self.access_server.is_some() {
            ACCESS_DOCUMENT
        } else {
            PERSON_DOCUMENT
        }
    }

    pub(super) fn r3_metadata(&self) -> Option<Value> {
        self.r3.as_ref().map(|profile| profile.metadata())
    }

    /// Canonical HTTPS signed origin: every class document URI is issued,
    /// reconstructed, served and admitted under it. JWT `iss`/`aud` keep the
    /// published issuer identity.
    fn document_origin(&self) -> String {
        format!("https://{}", self.authority)
    }

    /// The signed origin when R3 is enabled, for endpoint metadata.
    pub(super) fn r3_document_origin(&self) -> Option<String> {
        self.r3.as_ref().map(|_| self.document_origin())
    }

    /// Serve `GET {signed_origin}/r3/c.…` to a signer entitled to that document.
    ///
    /// The caller signs as a server with `jwks_uri`. Its key is resolved through
    /// the host trust set and the proof verifies before storage is read. Only
    /// the Resource token's `ps` signing with `aauth-person.json`, or its `aud`
    /// signing with the retained issuer role, receives the exact committed
    /// bytes. Any other verified signer, a query, or an unknown URI is `404`.
    /// A store failure or a record that no longer matches its URI is `500`
    /// and discloses no document.
    pub fn r3_document(&self, request: &Request<Vec<u8>>, now: i64) -> Response<Vec<u8>> {
        let Some(profile) = &self.r3 else {
            return document_response(StatusCode::NOT_FOUND, "not_found");
        };
        if self.r3_composition_refused() {
            return document_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
        let path = request.uri().path();
        let id = path.strip_prefix("/r3/").unwrap_or("");
        let proposal = id.starts_with("p.");
        if request.method() != http::Method::GET
            || request.uri().query().is_some()
            || !(id.starts_with("c.") || proposal)
            || id.contains('/')
            || aauth_rust_signature_key::canonical_authority(request.uri())
                .ok()
                .as_deref()
                != Some(self.authority.as_str())
        {
            return document_response(StatusCode::NOT_FOUND, "not_found");
        }
        let exact_uri = format!("{}{path}", self.document_origin());
        let failure = match self.verified_fetcher(request, now) {
            Ok((signer, role)) if proposal => {
                return self.serve_proposal(profile, &exact_uri, &signer, &role);
            }
            Ok((signer, role)) => {
                return self.serve_document(profile, &exact_uri, &signer, &role);
            }
            Err(failure) => failure,
        };
        let mut response = AuthDecision::<()>::SignatureFailure(failure).into_response();
        no_store(&mut response);
        response
    }

    fn verified_fetcher(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<(String, String), SignatureFailure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(|error| match error {
            Error::ClockSkew => SignatureFailure::ClockSkew { server_time: now },
            Error::InvalidInput => SignatureFailure::Input(required_components(request)),
            other => SignatureFailure::Proof(other),
        })?;
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let key = self
            .keys
            .key(id, dwk, kid)
            .map_err(SignatureFailure::Token)?;
        proof.verify(&key).map_err(SignatureFailure::Proof)?;
        Ok((id.clone(), dwk.clone()))
    }

    fn serve_document(
        &self,
        profile: &R3Profile,
        exact_uri: &str,
        signer: &str,
        role: &str,
    ) -> Response<Vec<u8>> {
        let record = match profile.documents.load(exact_uri) {
            Ok(Some(record)) => record,
            Ok(None) => return document_response(StatusCode::NOT_FOUND, "not_found"),
            Err(_) => {
                return document_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        };
        if self.retained_record(profile, &record, exact_uri).is_err() {
            return document_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
        let entitled = (signer == record.person_server && role == PERSON_DOCUMENT)
            || (signer == record.auth_token_issuer && role == record.auth_token_issuer_document);
        if !entitled {
            return document_response(StatusCode::NOT_FOUND, "not_found");
        }
        let mut response = Response::new(record.exact_json);
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            "content-type",
            "application/json".parse().expect("static content type"),
        );
        no_store(&mut response);
        response
    }

    /// The record still names exactly this URI, its entitlement, and valid document bytes.
    fn retained_record(
        &self,
        profile: &R3Profile,
        record: &R3DocumentRecord,
        exact_uri: &str,
    ) -> Result<(), ()> {
        if record.reference.uri() != exact_uri
            || record.person_server.is_empty()
            || record.auth_token_issuer.is_empty()
            || record.auth_token_issuer_document != self.auth_token_issuer_document()
            || class_document_uri(
                &self.document_origin(),
                record.reference.digest(),
                &record.person_server,
                &record.auth_token_issuer,
                &record.resource_token_jti,
            ) != exact_uri
        {
            return Err(());
        }
        let document = profile
            .registry
            .parse_referenced_document(&record.reference, &record.exact_json)
            .map_err(|_| ())?;
        validate_document_account(&document, record.account.as_deref()).map_err(|_| ())
    }

    /// Mint the class Resource token after its exact document is retained.
    fn issue_r3(
        &self,
        profile: &R3Profile,
        claims: &ResourceClaims,
        operations: &OperationSet,
        offer: Option<&aauth_rust_budgets::Budget>,
    ) -> Result<String, Issue> {
        let vocabulary = profile
            .vocabularies
            .get(operations.vocabulary())
            .ok_or(Issue::Host)?;
        let display = match &vocabulary.display {
            Some(describe) => Some(describe(operations).map_err(|_| Issue::Host)?),
            None => None,
        };
        let document = Document::new(
            operations,
            DocumentOptions {
                account: claims.account.as_deref(),
                display: display.as_ref(),
            },
        )
        .map_err(|_| Issue::Host)?;
        // Serialized once; the digest, the record and every fetch use these bytes.
        let exact = serde_json::to_vec(&document).map_err(|_| Issue::Host)?;
        let uri = class_document_uri(
            &self.document_origin(),
            &digest(&exact),
            &claims.ps,
            &claims.aud,
            &claims.jti,
        );
        let (compact, reference) = if let Some(offer) = offer {
            let (compact, reference) = aauth_rust_r3::mint_budget_resource_token(
                &profile.registry,
                &self.config.signing_key,
                &self.config.kid,
                claims,
                &uri,
                &exact,
                offer,
                None,
            )
            .map_err(|_| Issue::Host)?;
            (compact, reference)
        } else {
            aauth_rust_r3::mint_resource_token(
                &profile.registry,
                &self.config.signing_key,
                &self.config.kid,
                claims,
                &uri,
                &exact,
            )
            .map_err(|_| Issue::Host)?
        };
        let record = R3DocumentRecord {
            reference,
            exact_json: exact,
            person_server: claims.ps.clone(),
            auth_token_issuer: claims.aud.clone(),
            auth_token_issuer_document: self.auth_token_issuer_document().into(),
            resource_token_jti: claims.jti.clone(),
            resource_token: compact.clone(),
            presented_jti: claims.presented_jti.clone(),
            subject: claims.sub.clone(),
            agent_jkt: claims.agent_jkt.clone(),
            tenant: claims.tenant.clone(),
            account: claims.account.clone(),
            scope: claims.scope.clone(),
            issued_at: claims.iat,
            expires_at: claims.exp,
            mission_s256: claims.mission_s256.clone(),
        };
        // A conflict or an uncertain commit withholds the token. An uncertain
        // commit may leave a record whose URI was never released.
        profile
            .documents
            .commit(&record)
            .map_err(|_| Issue::Retention)?;
        Ok(compact)
    }

    /// A `budget` object on `/authorize` becomes the resource-token offer when
    /// budgets are enabled. No object leaves the class token unchanged.
    fn r3_budget_offer(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Option<aauth_rust_budgets::Budget>, ProactiveDecision> {
        let value = strict_json(request.body()).map_err(|_| ProactiveDecision::InvalidRequest)?;
        let Some(budget) = value.get("budget") else {
            return Ok(None);
        };
        let Some(gate) = &self.budgets else {
            return Err(ProactiveDecision::InvalidBudget);
        };
        let requested = aauth_rust_budgets::parse_budget(budget)
            .map_err(|_| ProactiveDecision::InvalidBudget)?;
        gate.offer(Some(&requested))
            .map(Some)
            .map_err(|_| ProactiveDecision::InvalidBudget)
    }

    /// `/authorize` with `r3_operations`. `None` continues the Core request unchanged.
    pub(super) fn proactive_r3(
        &self,
        request: &Request<Vec<u8>>,
        challenge: &ResourceClaims,
    ) -> Option<ProactiveDecision> {
        let profile = self.r3.as_ref()?;
        let operations = match profile.requested(request.body()) {
            Ok(Some(operations)) => operations,
            Ok(None) => return None,
            Err(()) => return Some(ProactiveDecision::InvalidRequest),
        };
        let mut claims = challenge.clone();
        let scope_present = strict_json(request.body())
            .ok()
            .is_some_and(|value| value.get("scope").is_some());
        claims.scope = if scope_present {
            match super::requested_scope(request, &self.config.scopes) {
                Ok(scope) => Some(scope),
                Err(decision) => return Some(decision),
            }
        } else if profile.require_core_scope {
            return Some(ProactiveDecision::InvalidScope);
        } else {
            None
        };
        let offer = match self.r3_budget_offer(request) {
            Ok(offer) => offer,
            Err(decision) => return Some(decision),
        };
        Some(
            match self.issue_r3(profile, &claims, &operations, offer.as_ref()) {
                Ok(resource_token) => ProactiveDecision::ResourceToken { resource_token },
                Err(Issue::Host) => ProactiveDecision::InternalError,
                Err(Issue::Retention) => ProactiveDecision::RetentionFailed,
            },
        )
    }

    /// Person challenge on a mapped R3 route: one class document for that operation.
    /// `None` keeps the Core challenge for an unmapped route.
    pub(super) fn r3_challenge(
        &self,
        request: &Request<Vec<u8>>,
        challenge: &ResourceClaims,
    ) -> Option<AuthDecision<O::Context>> {
        let profile = self.r3.as_ref()?;
        let operation = match profile.route(request) {
            Ok(Some(operation)) => operation,
            Ok(None) => return None,
            Err(()) => return Some(AuthDecision::InternalError),
        };
        let Ok(operations) = OperationSet::new(std::slice::from_ref(&operation)) else {
            return Some(AuthDecision::InternalError);
        };
        let mut claims = challenge.clone();
        claims.scope = profile
            .require_core_scope
            .then(|| self.config.scopes.join(" "));
        // A reactive challenge has no R3 budget request. The Core idle offer
        // is not a class-document claim, and the plain mint refuses it.
        claims.extra.remove("budget");
        Some(match self.issue_r3(profile, &claims, &operations, None) {
            Ok(resource_token) => AuthDecision::AuthTokenRequired {
                resource_token,
                budget_reason: None,
                budget_header: None,
            },
            Err(_) => AuthDecision::InternalError,
        })
    }

    /// Resource Enforcement for one verified, proved, non-revoked PS Auth token.
    ///
    /// `Ok(None)` is a Core token on an unmapped route. A Core token on a
    /// mapped route, and an R3 token on an unmapped route, are refused.
    pub(super) fn r3_gate(
        &self,
        token: &VerifiedAuthToken,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> Result<Option<R3Grant>, AuthDecision<O::Context>> {
        let Some(profile) = &self.r3 else {
            return Ok(None);
        };
        let forbidden = || AuthDecision::Forbidden {
            budget_header: None,
        };
        let claims = token.claims();
        // A 202 held invocation completes only at its pending URL, with an R3 token.
        if let Some(id) = request.uri().path().strip_prefix("/r3/pending/") {
            // Method before the id and the token, matching held-poll admission.
            if request.method() != http::Method::GET {
                return Err(AuthDecision::MethodNotAllowed);
            }
            if !carries_r3(&claims.extra) || id.is_empty() || id.contains('/') {
                return Err(forbidden());
            }
            return self
                .per_call_completion(profile, token, request, None, Some(id), now)
                .map(Some);
        }
        let verified = if carries_r3(&claims.extra) {
            // A budget grant is a separate companion. The plain verifier refuses it.
            let verified = if claims.extra.contains_key("budget") {
                verify_budget_auth_token(&profile.registry, token.compact(), &self.keys, now)
                    .map(|(verified, _grant)| verified)
            } else {
                verify_auth_token_claims(&profile.registry, token.compact(), &self.keys, now)
            };
            Some(verified.map_err(|_| {
                AuthDecision::SignatureFailure(SignatureFailure::Token(TokenError::InvalidJwt))
            })?)
        } else {
            None
        };
        let route = profile
            .route(request)
            .map_err(|()| AuthDecision::InternalError)?;
        let (verified, operation) = match (verified, route) {
            (None, None) => return Ok(None),
            (None, Some(_)) | (Some(_), None) => return Err(forbidden()),
            (Some(verified), Some(operation)) => (verified, operation),
        };
        let reference = verified.reference();
        // A per-call Auth token references its proposal; the 401 retry completes it.
        if reference
            .uri()
            .starts_with(&format!("{}/r3/p.", self.document_origin()))
        {
            return self
                .per_call_completion(profile, token, request, Some(&operation), None, now)
                .map(Some);
        }
        if !reference
            .uri()
            .starts_with(&format!("{}/r3/c.", self.document_origin()))
        {
            return Err(forbidden());
        }
        let record = match profile.documents.load(reference.uri()) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(forbidden()),
            Err(_) => return Err(AuthDecision::InternalError),
        };
        self.retained_record(profile, &record, reference.uri())
            .map_err(|()| AuthDecision::InternalError)?;
        let agent_jkt = claims
            .cnf
            .jwk
            .thumbprint()
            .map_err(|_| AuthDecision::InternalError)?;
        // The grant belongs to the Person Server, subject, tenant, mission and
        // agent key the document was issued for, and to no other lineage.
        if &record.reference != reference
            || record.person_server != claims.ps
            || record.auth_token_issuer != claims.iss
            || record.auth_token_issuer_document != claims.dwk
            || record.subject != claims.sub
            || record.tenant != claims.tenant
            || record.mission_s256 != claims.mission_s256
            || record.agent_jkt != agent_jkt
        {
            return Err(forbidden());
        }
        // Account parity, and both claims are disjoint subsets of the exact document.
        if verified
            .prove_against_document(&profile.registry, &record.reference, &record.exact_json)
            .is_err()
        {
            return Err(forbidden());
        }
        match verified.operations().access_for(&operation) {
            Ok(OperationAccess::Granted) => Ok(Some(R3Grant {
                reference: reference.clone(),
                operation,
                completion: None,
            })),
            // Challenged with a retained proposal; refused when per-call is not enabled.
            Ok(OperationAccess::PerCall) => Err(self.per_call_challenge(
                profile,
                token,
                &record.reference,
                request,
                &operation,
                now,
                challenge_jti,
            )),
            Ok(OperationAccess::Denied) => Err(forbidden()),
            Err(_) => Err(AuthDecision::InternalError),
        }
    }
}
