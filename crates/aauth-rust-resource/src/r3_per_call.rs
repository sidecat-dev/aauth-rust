//! Per-call proposals on the direct Person-Server path (`draft-hardt-aauth-r3`,
//! Per-Call Proposals, Flow steps 1, 3 and 4).
//!
//! An operation in the class token's `r3_per_call` is challenged with a
//! Resource token referencing one proposal for this concrete call. The exact
//! proposal bytes and their lineage are committed to the host's
//! [`R3CallStore`] before the challenge is released, either as a `401` retry
//! or as a `202` held invocation. Completion verifies the per-call Auth token
//! against the stored exact bytes, the class lineage and the holder, then
//! claims the proposal once: the first exact token gets a fence to execute,
//! the same token again gets the retained result, and anything uncertain
//! executes nothing. Result-bearing proposals (release gating) are never built.
use std::collections::BTreeMap;
use std::sync::Arc;

use aauth_rust_core::{AgentKeyResolver, ResourceClaims, VerifiedAuthToken};
use aauth_rust_r3::{
    Operation, Parameters, PresentedParameter, Proposal, ProposalDisplay, ProposalOptions,
    Reference, VerifiedR3AuthToken, digest, mint_proposal_resource_token, validate_proposal_account,
    verify_per_call_auth_token,
};
use http::{Request, Response, StatusCode};
use serde_json::json;

use super::{R3Grant, R3HostError, R3Profile, R3StoreError, document_response, no_store};
use crate::PolicyOutcome;
use crate::ps_authorization::{AuthDecision, PsAuthorizationResource, PsConfigurationError, refusal};

const PERSON_DOCUMENT: &str = "aauth-person.json";

/// Host extraction of one call's concrete parameter values.
///
/// It runs only for a verified request already mapped to `operation`. Inline
/// values compare structurally; [`PresentedParameter::Exact`] bytes compare by
/// SHA-256 against a digest parameter. It must be a deterministic function of
/// the request and operation: it runs again on the `401` retry.
pub type BoxedR3Present = Box<
    dyn Fn(&Request<Vec<u8>>, &Operation) -> Result<BTreeMap<String, PresentedParameter>, R3HostError>
        + Send
        + Sync,
>;

/// Host description of one concrete call for the person approving it.
pub type BoxedR3Describe = Box<
    dyn Fn(
            &Operation,
            &BTreeMap<String, PresentedParameter>,
            Option<&str>,
        ) -> Result<R3CallDescription, R3HostError>
        + Send
        + Sync,
>;

/// The Resource's proposal for one concrete call.
pub struct R3CallDescription {
    /// Proposed parameters. They must match the presented values exactly as
    /// completion will check them, or no proposal is published.
    pub parameters: Parameters,
    /// Per-call consent text. The call has not run; this is execution approval.
    pub display: Option<ProposalDisplay>,
}

/// One held request, retained so the `202` completion runs the exact call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3HeldRequest {
    /// Pending identifier in `{signed_origin}/r3/pending/{id}`.
    pub pending_id: String,
    /// Original method.
    pub method: String,
    /// Original absolute request URI.
    pub uri: String,
    /// Original header fields in order, including the signature fields.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Original body bytes.
    pub body: Vec<u8>,
}

/// One immutable proposal and the lineage it was issued for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3ProposalRecord {
    /// `r3_uri` and `r3_s256` of the proposal Resource token.
    pub reference: Reference,
    /// Exact proposal bytes, served verbatim to the entitled PS.
    pub exact_json: Vec<u8>,
    /// `ps` of the proposal Resource token.
    pub person_server: String,
    /// `aud` of the proposal Resource token: the per-call Auth-token issuer.
    pub auth_token_issuer: String,
    /// `jti` of the proposal Resource token; part of the proposal URI.
    pub resource_token_jti: String,
    /// Exact compact proposal Resource token.
    pub resource_token: String,
    /// Reference of the class document whose token left this operation per call.
    pub class_reference: Reference,
    /// `jti` of the class Auth token presented on the challenged call.
    pub presented_jti: String,
    /// Directed `sub`.
    pub subject: String,
    /// `agent_jkt`: the only holder that may complete.
    pub agent_jkt: String,
    /// `tenant`.
    pub tenant: Option<String>,
    /// `account` of the proposal and its token.
    pub account: Option<String>,
    /// Core `scope` carried from the class token.
    pub scope: Option<String>,
    /// `iat` of the proposal Resource token.
    pub issued_at: i64,
    /// `exp` of the proposal Resource token.
    pub expires_at: i64,
    /// The held call under `202`; `None` for the `401` retry.
    pub held: Option<R3HeldRequest>,
}

/// The exact Auth token claiming one proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3CallToken {
    /// Unpadded base64url SHA-256 of the exact compact token.
    pub compact_sha256: String,
    /// Token `jti`.
    pub jti: String,
    /// Token `exp`: the retained result answers that token until then.
    pub retain_until: i64,
}

/// Retained application result of the one execution a proposal authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3CallResult {
    /// HTTP status.
    pub status: u16,
    /// `Content-Type`, when present.
    pub content_type: Option<String>,
    /// Exact response body.
    pub body: Vec<u8>,
}

/// Outcome of claiming a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R3Claim {
    /// First claim by this exact token. Execute once, then retain under `fence`.
    Execute {
        /// Store-issued fence that alone may retain this execution's result.
        fence: String,
    },
    /// Same exact token as the first claim; its retained result.
    Replay(R3CallResult),
    /// Same exact token, but no result was retained. Nothing runs again.
    Unfinished,
    /// The proposal was claimed by a different token.
    DifferentToken,
    /// The retained result is past the claiming token's `exp`.
    Expired,
}

/// Durable, confidential custody of proposals and their single use.
///
/// `commit` creates a record atomically and returns
/// [`R3StoreError::Conflict`] when the URI or pending id already exists, even
/// for identical bytes: each proposal names one invocation. Records are never
/// pruned while a token could reference them. `claim` is linearizable per URI:
/// the first call binds the exact token digest and returns
/// [`R3Claim::Execute`] with a fresh fence; every later call is
/// [`R3Claim::Replay`], [`R3Claim::Unfinished`], [`R3Claim::DifferentToken`]
/// or [`R3Claim::Expired`]. A claim, once bound, never returns `Execute` again,
/// including after restart or an uncertain error. `retain` stores the one
/// result only under the current fence and returns what is stored. Any error
/// other than `Conflict` may have taken effect; the Resource then executes
/// nothing. A volatile map does not satisfy this contract across restart.
pub trait R3CallStore: Send + Sync {
    /// Create the record before its Resource token becomes observable.
    ///
    /// # Errors
    /// Returns [`R3StoreError`] as described on the trait.
    fn commit(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError>;
    /// Load the record committed at exactly `uri`.
    ///
    /// # Errors
    /// Returns [`R3StoreError::Unavailable`] when storage cannot answer.
    fn load(&self, uri: &str) -> Result<Option<R3ProposalRecord>, R3StoreError>;
    /// Load the held record committed under `pending_id`.
    ///
    /// # Errors
    /// Returns [`R3StoreError::Unavailable`] when storage cannot answer.
    fn load_pending(&self, pending_id: &str) -> Result<Option<R3ProposalRecord>, R3StoreError>;
    /// Claim the proposal at `uri` for `token` at trusted time `now`.
    ///
    /// # Errors
    /// Returns [`R3StoreError::Unavailable`] when storage cannot answer.
    fn claim(&self, uri: &str, token: &R3CallToken, now: i64) -> Result<R3Claim, R3StoreError>;
    /// Retain the one result of the execution holding `fence`.
    ///
    /// # Errors
    /// [`R3StoreError::Conflict`] for a stale fence or an existing result;
    /// [`R3StoreError::Unavailable`] when storage cannot answer.
    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> Result<R3CallResult, R3StoreError>;
}

/// Host configuration for per-call proposals.
pub struct R3PerCallConfig {
    /// Concrete parameter values for one mapped request.
    pub present: BoxedR3Present,
    /// Proposal parameters and display for one concrete call.
    pub describe: BoxedR3Describe,
    /// Durable proposal and single-use custody.
    pub calls: Arc<dyn R3CallStore>,
    /// Hold the invocation and answer `202` instead of a `401` retry. The draft
    /// recommends holding when the Resource can.
    pub hold: bool,
}

/// One per-call completion, carried on the [`R3Grant`] the host receives.
#[derive(Clone)]
pub(super) struct R3Completion {
    pub(super) uri: String,
    pub(super) token: R3CallToken,
    pub(super) fence: Option<String>,
    pub(super) held: Option<Request<Vec<u8>>>,
}

fn proposal_uri(
    origin: &str,
    proposal_digest: &str,
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
    let lineage = format!("aauth-r3-proposal-v1\0{resource_token_jti}");
    format!(
        "{origin}/r3/p.{proposal_digest}.{}.{}",
        digest(&entitlement),
        digest(lineage.as_bytes())
    )
}

fn pending_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn snapshot(response: &Response<Vec<u8>>) -> R3CallResult {
    R3CallResult {
        status: response.status().as_u16(),
        content_type: response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: response.body().clone(),
    }
}

fn restore(result: &R3CallResult) -> Response<Vec<u8>> {
    let mut response = Response::new(result.body.clone());
    *response.status_mut() =
        StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Some(content_type) = &result.content_type
        && let Ok(value) = content_type.parse()
    {
        response.headers_mut().insert("content-type", value);
    }
    response
}

fn held_request(request: &Request<Vec<u8>>, pending_id: &str) -> R3HeldRequest {
    R3HeldRequest {
        pending_id: pending_id.to_owned(),
        method: request.method().as_str().to_owned(),
        uri: request.uri().to_string(),
        headers: request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
        body: request.body().clone(),
    }
}

fn rebuild(held: &R3HeldRequest) -> Result<Request<Vec<u8>>, ()> {
    let mut builder = Request::builder()
        .method(held.method.as_str())
        .uri(held.uri.as_str());
    for (name, value) in &held.headers {
        builder = builder.header(name.as_str(), value.as_slice());
    }
    builder.body(held.body.clone()).map_err(|_| ())
}

impl<K: AgentKeyResolver, P, O> PsAuthorizationResource<K, P>
where
    P: Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Challenge operations a class token leaves in `r3_per_call` with a
    /// per-call proposal, and complete them once.
    ///
    /// Requires [`Self::with_r3`]. Without this, a per-call operation is
    /// refused with `403` and never served.
    ///
    /// # Errors
    /// [`PsConfigurationError::InvalidR3Profile`] when class R3 is not enabled.
    pub fn with_r3_per_call(mut self, config: R3PerCallConfig) -> Result<Self, PsConfigurationError> {
        let Some(profile) = self.r3.as_mut() else {
            return Err(PsConfigurationError::InvalidR3Profile);
        };
        profile.per_call = Some(config);
        Ok(self)
    }

    /// Store the result of a per-call execution admitted by `grant` and return
    /// the stored response, which the host sends.
    ///
    /// A class grant needs no retention and `response` is returned unchanged.
    /// A store failure returns `500`; the call is not run again for that token.
    pub fn r3_retain(&self, grant: &R3Grant, response: Response<Vec<u8>>) -> Response<Vec<u8>> {
        let Some(completion) = &grant.completion else {
            return response;
        };
        let (Some(fence), Some(per_call)) = (
            completion.fence.as_deref(),
            self.r3.as_ref().and_then(|profile| profile.per_call.as_ref()),
        ) else {
            return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        match per_call.calls.retain(&completion.uri, fence, &snapshot(&response)) {
            Ok(stored) => restore(&stored),
            Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }

    /// Build, retain and release the proposal challenge for one per-call operation.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn per_call_challenge(
        &self,
        profile: &R3Profile,
        token: &VerifiedAuthToken,
        class_reference: &Reference,
        request: &Request<Vec<u8>>,
        operation: &Operation,
        now: i64,
        challenge_jti: &str,
    ) -> AuthDecision<O::Context> {
        let forbidden = AuthDecision::Forbidden {
            budget_header: None,
        };
        let Some(per_call) = &profile.per_call else {
            return forbidden;
        };
        let c = token.claims();
        if !pending_token(challenge_jti) {
            return AuthDecision::InternalError;
        }
        let Ok(presented) = (per_call.present)(request, operation) else {
            return AuthDecision::InternalError;
        };
        let Ok(description) = (per_call.describe)(operation, &presented, c.account.as_deref())
        else {
            return AuthDecision::InternalError;
        };
        // Publish only what completion will accept for this exact call.
        if !matches!(description.parameters.matches(&presented), Ok(true)) {
            return AuthDecision::InternalError;
        }
        let Ok(proposal) = Proposal::new(
            operation,
            &description.parameters,
            ProposalOptions {
                account: c.account.as_deref(),
                result: None,
                display: description.display.as_ref(),
            },
        ) else {
            return AuthDecision::InternalError;
        };
        let Ok(exact) = serde_json::to_vec(&proposal) else {
            return AuthDecision::InternalError;
        };
        let Ok(agent_jkt) = c.cnf.jwk.thumbprint() else {
            return AuthDecision::InternalError;
        };
        let expires_at = now.saturating_add(300).min(c.exp);
        if expires_at <= now {
            return forbidden;
        }
        let claims = ResourceClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-resource.json".into(),
            aud: c.iss.clone(),
            ps: c.ps.clone(),
            sub: c.sub.clone(),
            jti: challenge_jti.into(),
            presented_jti: c.jti.clone(),
            agent_jkt: agent_jkt.clone(),
            iat: now,
            exp: expires_at,
            scope: c.scope.clone(),
            account: c.account.clone(),
            login_hint: None,
            nbf: None,
            tenant: c.tenant.clone(),
            mission_s256: None,
            extra: BTreeMap::new(),
        };
        let uri = proposal_uri(
            &self.document_origin(),
            &digest(&exact),
            &claims.ps,
            &claims.aud,
            &claims.jti,
        );
        let Ok((compact, reference)) = mint_proposal_resource_token(
            &profile.registry,
            &self.config.signing_key,
            &self.config.kid,
            &claims,
            &uri,
            &exact,
        ) else {
            return AuthDecision::InternalError;
        };
        let held = per_call.hold.then(|| held_request(request, challenge_jti));
        let record = R3ProposalRecord {
            reference,
            exact_json: exact,
            person_server: claims.ps.clone(),
            auth_token_issuer: claims.aud.clone(),
            resource_token_jti: claims.jti.clone(),
            resource_token: compact.clone(),
            class_reference: class_reference.clone(),
            presented_jti: claims.presented_jti.clone(),
            subject: claims.sub.clone(),
            agent_jkt,
            tenant: claims.tenant.clone(),
            account: claims.account.clone(),
            scope: claims.scope.clone(),
            issued_at: claims.iat,
            expires_at: claims.exp,
            held,
        };
        // Committed before the challenge is observable; any failure withholds it.
        if per_call.calls.commit(&record).is_err() {
            return AuthDecision::InternalError;
        }
        if per_call.hold {
            AuthDecision::R3Pending {
                resource_token: compact,
                location: format!("{}/r3/pending/{challenge_jti}", self.document_origin()),
            }
        } else {
            AuthDecision::AuthTokenRequired {
                resource_token: compact,
                budget_reason: None,
                budget_header: None,
            }
        }
    }

    /// The record still names exactly this URI, its entitlement and a valid proposal.
    pub(super) fn retained_proposal(
        &self,
        profile: &R3Profile,
        record: &R3ProposalRecord,
        exact_uri: &str,
    ) -> Result<Proposal, ()> {
        if record.reference.uri() != exact_uri
            || record.person_server.is_empty()
            || record.auth_token_issuer.is_empty()
            || record.presented_jti.is_empty()
            || record.issued_at >= record.expires_at
            || proposal_uri(
                &self.document_origin(),
                record.reference.digest(),
                &record.person_server,
                &record.auth_token_issuer,
                &record.resource_token_jti,
            ) != exact_uri
        {
            return Err(());
        }
        let proposal = profile
            .registry
            .parse_referenced_proposal(&record.reference, &record.exact_json)
            .map_err(|_| ())?;
        if proposal.result().is_some() {
            return Err(());
        }
        validate_proposal_account(&proposal, record.account.as_deref()).map_err(|_| ())?;
        Ok(proposal)
    }

    /// Serve `GET {signed_origin}/r3/p.…` to the entitled PS, as for class documents.
    pub(super) fn serve_proposal(
        &self,
        profile: &R3Profile,
        exact_uri: &str,
        signer: &str,
        role: &str,
    ) -> Response<Vec<u8>> {
        let Some(per_call) = &profile.per_call else {
            return document_response(StatusCode::NOT_FOUND, "not_found");
        };
        let record = match per_call.calls.load(exact_uri) {
            Ok(Some(record)) => record,
            Ok(None) => return document_response(StatusCode::NOT_FOUND, "not_found"),
            Err(_) => {
                return document_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        };
        if self.retained_proposal(profile, &record, exact_uri).is_err() {
            return document_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
        let entitled = (signer == record.person_server || signer == record.auth_token_issuer)
            && role == PERSON_DOCUMENT;
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

    /// Per-call completion: `401` retry at the mapped route, or a `202` poll
    /// at the pending URL. Nothing is claimed here; [`Self::r3_claim`] claims
    /// after host policy admitted the request.
    pub(super) fn per_call_completion(
        &self,
        profile: &R3Profile,
        token: &VerifiedAuthToken,
        request: &Request<Vec<u8>>,
        mapped: Option<&Operation>,
        pending_id: Option<&str>,
        now: i64,
    ) -> Result<R3Grant, AuthDecision<O::Context>> {
        let forbidden = || AuthDecision::Forbidden {
            budget_header: None,
        };
        let per_call = profile.per_call.as_ref().ok_or_else(forbidden)?;
        let record = match pending_id {
            Some(id) => per_call.calls.load_pending(id),
            None => {
                let claimed = aauth_rust_r3::verify_auth_token_claims(
                    &profile.registry,
                    token.compact(),
                    &self.keys,
                    now,
                )
                .map_err(|_| forbidden())?;
                per_call.calls.load(claimed.reference().uri())
            }
        };
        let record = match record {
            Ok(Some(record)) => record,
            Ok(None) => return Err(forbidden()),
            Err(_) => return Err(AuthDecision::InternalError),
        };
        let proposal = self
            .retained_proposal(profile, &record, record.reference.uri())
            .map_err(|()| AuthDecision::InternalError)?;
        // Exactly the stored proposal: same reference, one operation, no r3_per_call, account.
        let (verified, operation): (VerifiedR3AuthToken, Operation) = verify_per_call_auth_token(
            &profile.registry,
            token.compact(),
            &self.keys,
            now,
            &record.reference,
            &record.exact_json,
        )
        .map_err(|_| forbidden())?;
        let claims = verified.claims();
        let holder = claims
            .cnf
            .jwk
            .thumbprint()
            .map_err(|_| AuthDecision::InternalError)?;
        // The approval belongs to this proposal's PS, subject, tenant and holder,
        // and was issued while its proposal Resource token was valid.
        if claims.iss != record.auth_token_issuer
            || claims.dwk != PERSON_DOCUMENT
            || claims.ps != record.person_server
            || claims.sub != record.subject
            || claims.tenant != record.tenant
            || holder != record.agent_jkt
            || claims.iat < record.issued_at
            || claims.iat >= record.expires_at
        {
            return Err(forbidden());
        }
        let held = match (pending_id, &record.held) {
            // 202: the held call runs; there are no parameters to verify.
            (Some(id), Some(held)) if held.pending_id == id => {
                Some(rebuild(held).map_err(|()| AuthDecision::InternalError)?)
            }
            (Some(_), _) => return Err(forbidden()),
            // A held invocation completes only at its pending URL.
            (None, Some(_)) => return Err(forbidden()),
            (None, None) => {
                let mapped = mapped.ok_or_else(forbidden)?;
                if !matches!(operation.equal(mapped), Ok(true)) {
                    return Err(forbidden());
                }
                let presented = (per_call.present)(request, mapped)
                    .map_err(|_| AuthDecision::InternalError)?;
                // Inline structurally, digest parameters byte-exact. Anything else refuses.
                if !matches!(proposal.parameters().matches(&presented), Ok(true)) {
                    return Err(forbidden());
                }
                None
            }
        };
        Ok(R3Grant {
            reference: record.reference.clone(),
            operation,
            completion: Some(R3Completion {
                uri: record.reference.uri().to_owned(),
                token: R3CallToken {
                    compact_sha256: digest(token.compact().as_bytes()),
                    jti: claims.jti.clone(),
                    retain_until: claims.exp,
                },
                fence: None,
                held,
            }),
        })
    }

    /// Claim an admitted per-call completion. A class grant passes through.
    pub(crate) fn r3_claim(
        &self,
        grant: Option<R3Grant>,
        now: i64,
    ) -> Result<Option<R3Grant>, AuthDecision<O::Context>> {
        let Some(mut grant) = grant else {
            return Ok(None);
        };
        let Some(completion) = grant.completion.as_mut() else {
            return Ok(Some(grant));
        };
        let Some(per_call) = self.r3.as_ref().and_then(|profile| profile.per_call.as_ref()) else {
            return Err(AuthDecision::InternalError);
        };
        match per_call.calls.claim(&completion.uri, &completion.token, now) {
            Ok(R3Claim::Execute { fence }) if !fence.is_empty() => {
                completion.fence = Some(fence);
                Ok(Some(grant))
            }
            Ok(R3Claim::Replay(result)) => Err(AuthDecision::Replayed(Box::new(restore(&result)))),
            Ok(R3Claim::DifferentToken | R3Claim::Expired) => Err(AuthDecision::Forbidden {
                budget_header: None,
            }),
            // Unfinished, an empty fence, or an uncertain store: never a second effect.
            Ok(_) | Err(_) => Err(AuthDecision::InternalError),
        }
    }
}

impl R3Grant {
    /// Whether this admission is a per-call completion. The host executes it
    /// once and passes its response through
    /// [`PsAuthorizationResource::r3_retain`].
    pub fn is_per_call(&self) -> bool {
        self.completion.is_some()
    }
    /// The original held request under `202`, which is what the host executes.
    pub fn held_request(&self) -> Option<&Request<Vec<u8>>> {
        self.completion.as_ref()?.held.as_ref()
    }
}
