//! Per-call proposals on a Person-Server Resource (`draft-hardt-aauth-r3`,
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
//! executes nothing. A second poll of a held invocation, while the host still
//! holds that grant and has not retained a result, stays `202`. Dropping the
//! grant without a retained result leaves the next poll `500`.
//!
//! Approving Release Rather Than Execution: under `202` only, a host
//! [`BoxedR3Release`] may run a side-effect-free call before approval. The
//! proposal then carries `result` and a release `display`, and the computed
//! response is committed with the record. Completion releases that stored
//! response once to the first exact per-call token; the host executes nothing.
//! A re-requested held call (for example after the presented class token
//! expired during approval) is proposed again from that custody: the stored
//! proposal bytes and response move to the new challenge, the prior record is
//! retired, and the call does not run again.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use aauth_rust_core::{AgentKeyResolver, ResourceClaims, VerifiedAuthToken};
use aauth_rust_r3::{
    Operation, Parameters, PresentedParameter, Proposal, ProposalDisplay, ProposalOptions,
    ProposalResult, Reference, VerifiedR3AuthToken, digest, mint_proposal_resource_token,
    validate_proposal_account, verify_per_call_auth_token,
};
use http::{Request, Response, StatusCode};
use serde_json::json;

use super::{R3Grant, R3HostError, R3Profile, R3StoreError, document_response, no_store};
use crate::PolicyOutcome;
use crate::ps_authorization::{
    AuthDecision, PsAuthorizationResource, PsConfigurationError, refusal,
};

const PERSON_DOCUMENT: &str = "aauth-person.json";
/// Ceiling on a proposal Resource token's lifetime, and the horizon of a held
/// release-gated response from the challenge that computed it.
const PROPOSAL_LIFETIME: i64 = 300;

/// Host extraction of one call's concrete parameter values.
///
/// It runs only for a verified request already mapped to `operation`. Inline
/// values compare structurally; [`PresentedParameter::Exact`] bytes compare by
/// SHA-256 against a digest parameter. It must be a deterministic function of
/// the request and operation: it runs again on the `401` retry.
pub type BoxedR3Present = Box<
    dyn Fn(
            &Request<Vec<u8>>,
            &Operation,
        ) -> Result<BTreeMap<String, PresentedParameter>, R3HostError>
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
    /// Per-call consent text for execution approval. A release proposal uses
    /// [`R3Release::display`] instead.
    pub display: Option<ProposalDisplay>,
}

/// Host execution of one call before approval (`draft-hardt-aauth-r3`,
/// Approving Release Rather Than Execution).
///
/// It runs only under `202` holding, for a verified call already mapped to
/// `operation` and described, at most once per challenge. `Ok(None)` keeps
/// execution approval. `Ok(Some(_))` means the host has run the call and
/// holds its response for release. Return `Some` only when nothing outside the
/// result changes when the call runs: the draft forbids executing first where
/// execution is audited, metered or billed, or calls another party.
pub type BoxedR3Release = Box<
    dyn Fn(
            &Request<Vec<u8>>,
            &Operation,
            &BTreeMap<String, PresentedParameter>,
            Option<&str>,
        ) -> Result<Option<R3Release>, R3HostError>
        + Send
        + Sync,
>;

/// A response computed before approval and held for release.
pub struct R3Release {
    /// Resource-defined `result` members describing what the response holds,
    /// for the issuer and the Person Server. The response is not carried.
    pub result: ProposalResult,
    /// Consent text. It MUST state that the operation has run and that what is
    /// approved is release of its result; this crate does not judge prose.
    pub display: ProposalDisplay,
    /// The computed response, released once on approval and never otherwise.
    pub response: Response<Vec<u8>>,
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
    /// Release gating: the response computed before approval, present exactly
    /// when the proposal carries `result`. Confidential until released.
    pub released: Option<R3CallResult>,
    /// Release gating: the instant from which the held `released` response may
    /// no longer be proposed or released. Set once, when the response is
    /// computed, to `issued_at` plus the resource's `held_result_lifetime`,
    /// and inherited unchanged by every replacement. `Some` exactly when
    /// `released` is. This is resource policy, not a protocol claim.
    pub release_until: Option<i64>,
    /// URI of the unclaimed held release this record retired, when it was
    /// issued for a re-requested call. Audit lineage only.
    pub supersedes: Option<String>,
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
///
/// Release gating adds `held_releases`, which lists the held responses a
/// re-requested call may be answered from, and `supersede`, which retires one
/// of them and creates its successor in one step. A retired record is never
/// claimed again: every later `claim` on it is [`R3Claim::DifferentToken`].
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
    /// Release-gated records held for `agent_jkt` and `subject` that are
    /// unclaimed, not superseded, and whose `release_until` is after `now`.
    /// Omitting a record only causes a fresh computation; a claimed or
    /// superseded record returned here is refused by `supersede`.
    ///
    /// # Errors
    /// Returns [`R3StoreError::Unavailable`] when storage cannot answer.
    fn held_releases(
        &self,
        agent_jkt: &str,
        subject: &str,
        now: i64,
    ) -> Result<Vec<R3ProposalRecord>, R3StoreError>;
    /// Atomically retire the unclaimed held release at `prior_uri`, so that
    /// every later `claim` on it returns [`R3Claim::DifferentToken`], and
    /// create `record` as `commit` does.
    ///
    /// # Errors
    /// [`R3StoreError::Conflict`], with nothing changed, when the prior record
    /// is absent, holds no release, is claimed, superseded or past its
    /// `release_until` at `now`, or when `record` conflicts as for `commit`.
    /// Any other error may have taken effect; the Resource then releases
    /// nothing for this challenge.
    fn supersede(
        &self,
        prior_uri: &str,
        record: &R3ProposalRecord,
        now: i64,
    ) -> Result<(), R3StoreError>;
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
    /// Execute side-effect-free calls before approval and seek release
    /// instead. Requires `hold`; `None` always seeks execution approval.
    pub release: Option<BoxedR3Release>,
    /// How long, in seconds, a held release result may be proposed again or
    /// released. Resource policy, chosen by the host. It is not extended when
    /// a refreshed class token re-requests the call, and it is not a promise
    /// of the R3 draft. Zero refuses reuse immediately.
    pub held_result_lifetime: i64,
}

/// One per-call completion, carried on the [`R3Grant`] the host receives.
#[derive(Clone)]
pub(super) struct R3Completion {
    pub(super) uri: String,
    pub(super) token: R3CallToken,
    pub(super) fence: Option<String>,
    pub(super) held: Option<Request<Vec<u8>>>,
    /// Pending id when this completion is the held poll. Absent on a `401` retry.
    pub(super) pending_id: Option<String>,
    /// Set only while this process has handed the host a held execution grant.
    pub(super) executing: Option<Arc<ExecutingHold>>,
    /// Release gating: retained and answered at claim; never reaches the host.
    pub(super) released: Option<R3CallResult>,
    /// Held-result horizon copied from the proposal record. Completion refuses
    /// at this instant even when the per-call Auth token is still unexpired.
    pub(super) release_until: Option<i64>,
}

/// Removes one proposal URI from the in-process held-execution set.
///
/// The last clone drops the registration. [`ExecutingHold::finish`] removes it
/// earlier, when retention returns, so a later poll is not still pending.
pub(super) struct ExecutingHold {
    uri: String,
    open: Arc<Mutex<BTreeSet<String>>>,
}

impl ExecutingHold {
    pub(super) fn register(open: &Arc<Mutex<BTreeSet<String>>>, uri: &str) -> Arc<Self> {
        open.lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(uri.to_owned());
        Arc::new(Self {
            uri: uri.to_owned(),
            open: Arc::clone(open),
        })
    }

    pub(super) fn contains(open: &Mutex<BTreeSet<String>>, uri: &str) -> bool {
        open.lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(uri)
    }

    pub(super) fn finish(&self) {
        self.open
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.uri);
    }
}

impl Drop for ExecutingHold {
    fn drop(&mut self) {
        self.finish();
    }
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

/// The lineage of a re-requested call, from its class token and class record.
struct CallerLineage<'a> {
    person_server: &'a str,
    auth_token_issuer: &'a str,
    subject: &'a str,
    tenant: Option<&'a str>,
    agent_jkt: &'a str,
    account: Option<&'a str>,
    scope: Option<&'a str>,
    /// Class document digest. A refreshed class token names a new class URI
    /// for the same document, so the URI is not compared.
    class_digest: &'a str,
    /// `jti` of the class Auth token presented on this call.
    presented_jti: &'a str,
}

/// Whether `prior` is a held release this caller may be answered from at
/// `now`: a computed, held response within its horizon, issued for the same
/// Person Server, issuer, subject, tenant, holder, account, scope and class
/// document. The proposal token must already be expired, and the presented
/// class token must be a different `jti`, so a live challenge is not retired
/// by a same-token duplicate or a second call under that token. The stored
/// proposal is compared separately. After the proposal token has expired, a
/// new class token plus the same operation is not distinguishable on the wire
/// from a fresh intentional call.
fn held_release_matches(prior: &R3ProposalRecord, caller: &CallerLineage<'_>, now: i64) -> bool {
    prior.released.is_some()
        && prior.held.is_some()
        && prior.release_until.is_some_and(|until| now < until)
        && prior.expires_at <= now
        && prior.presented_jti != caller.presented_jti
        && prior.person_server == caller.person_server
        && prior.auth_token_issuer == caller.auth_token_issuer
        && prior.subject == caller.subject
        && prior.tenant.as_deref() == caller.tenant
        && prior.agent_jkt == caller.agent_jkt
        && prior.account.as_deref() == caller.account
        && prior.scope.as_deref() == caller.scope
        && prior.class_reference.digest() == caller.class_digest
}

/// Whether a held release's stored proposal names exactly this call: the same
/// operation, parameters completion would accept, and the token's account.
fn held_proposal_matches(
    proposal: &Proposal,
    operation: &Operation,
    presented: &BTreeMap<String, PresentedParameter>,
    account: Option<&str>,
) -> bool {
    matches!(proposal.operation().equal(operation), Ok(true))
        && matches!(proposal.parameters().matches(presented), Ok(true))
        && validate_proposal_account(proposal, account).is_ok()
}

/// What one challenge publishes: a fresh proposal, or a held release proposed
/// again for a re-requested call.
struct Publication {
    exact: Vec<u8>,
    expires_at: i64,
    released: Option<R3CallResult>,
    release_until: Option<i64>,
    /// The unclaimed held release this challenge retires.
    supersedes: Option<String>,
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
    /// [`PsConfigurationError::InvalidR3Profile`] when class R3 is not enabled,
    /// or when `release` is set without `hold`: release gating holds the
    /// invocation under `202`.
    pub fn with_r3_per_call(
        mut self,
        config: R3PerCallConfig,
    ) -> Result<Self, PsConfigurationError> {
        if config.release.is_some() && !config.hold {
            return Err(PsConfigurationError::InvalidR3Profile);
        }
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
            self.r3
                .as_ref()
                .and_then(|profile| profile.per_call.as_ref()),
        ) else {
            return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        let stored = match per_call
            .calls
            .retain(&completion.uri, fence, &snapshot(&response))
        {
            Ok(stored) => restore(&stored),
            Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        // Retention has returned. A later poll is the stored result, or `500`
        // when nothing was stored. It is not still pending.
        if let Some(hold) = &completion.executing {
            hold.finish();
        }
        stored
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
        let Ok(agent_jkt) = c.cnf.jwk.thumbprint() else {
            return AuthDecision::InternalError;
        };
        // Release gating: a re-requested call whose response is already held
        // is proposed again from custody and never runs again, so the approval
        // covers the bytes that exist. Uncertainty answers nothing; it never
        // falls back to running the call.
        if per_call.hold && per_call.release.is_some() {
            let Ok(held) = per_call.calls.held_releases(&agent_jkt, &c.sub, now) else {
                return AuthDecision::InternalError;
            };
            let caller = CallerLineage {
                person_server: &c.ps,
                auth_token_issuer: &c.iss,
                subject: &c.sub,
                tenant: c.tenant.as_deref(),
                agent_jkt: &agent_jkt,
                account: c.account.as_deref(),
                scope: c.scope.as_deref(),
                class_digest: class_reference.digest(),
                presented_jti: &c.jti,
            };
            for prior in held {
                if !held_release_matches(&prior, &caller, now) {
                    continue;
                }
                let Ok(proposal) = self.retained_proposal(profile, &prior, prior.reference.uri())
                else {
                    return AuthDecision::InternalError;
                };
                if !held_proposal_matches(&proposal, operation, &presented, c.account.as_deref()) {
                    continue;
                }
                let Some(release_until) = prior.release_until else {
                    return AuthDecision::InternalError;
                };
                let publication = Publication {
                    expires_at: now.saturating_add(PROPOSAL_LIFETIME).min(c.exp),
                    supersedes: Some(prior.reference.uri().to_owned()),
                    exact: prior.exact_json,
                    released: prior.released,
                    release_until: Some(release_until),
                };
                return self.publish_proposal(
                    profile,
                    per_call,
                    token,
                    class_reference,
                    request,
                    &agent_jkt,
                    now,
                    challenge_jti,
                    publication,
                );
            }
        }
        let Ok(description) = (per_call.describe)(operation, &presented, c.account.as_deref())
        else {
            return AuthDecision::InternalError;
        };
        // Publish only what completion will accept for this exact call.
        if !matches!(description.parameters.matches(&presented), Ok(true)) {
            return AuthDecision::InternalError;
        }
        // Release gating runs the call now, only under 202; with_r3_per_call
        // refuses release without hold, and this refuses it again.
        let release = match (&per_call.release, per_call.hold) {
            (Some(run), true) => match run(request, operation, &presented, c.account.as_deref()) {
                Ok(release) => release,
                Err(_) => return AuthDecision::InternalError,
            },
            (Some(_), false) => return AuthDecision::InternalError,
            (None, _) => None,
        };
        let Ok(proposal) = Proposal::new(
            operation,
            &description.parameters,
            ProposalOptions {
                account: c.account.as_deref(),
                result: release.as_ref().map(|release| &release.result),
                display: match &release {
                    Some(release) => Some(&release.display),
                    None => description.display.as_ref(),
                },
            },
        ) else {
            return AuthDecision::InternalError;
        };
        let Ok(exact) = serde_json::to_vec(&proposal) else {
            return AuthDecision::InternalError;
        };
        // The held response's horizon starts here and is never extended.
        // It is the host retention policy, not the proposal-token lifetime.
        let horizon = now.saturating_add(per_call.held_result_lifetime.max(0));
        let publication = Publication {
            exact,
            expires_at: now.saturating_add(PROPOSAL_LIFETIME).min(c.exp),
            release_until: release.is_some().then_some(horizon),
            released: release.map(|release| snapshot(&release.response)),
            supersedes: None,
        };
        self.publish_proposal(
            profile,
            per_call,
            token,
            class_reference,
            request,
            &agent_jkt,
            now,
            challenge_jti,
            publication,
        )
    }

    /// Mint, commit and release one proposal challenge. A publication that
    /// supersedes a held release retires it in the same store step.
    #[allow(clippy::too_many_arguments)]
    fn publish_proposal(
        &self,
        profile: &R3Profile,
        per_call: &R3PerCallConfig,
        token: &VerifiedAuthToken,
        class_reference: &Reference,
        request: &Request<Vec<u8>>,
        agent_jkt: &str,
        now: i64,
        challenge_jti: &str,
        publication: Publication,
    ) -> AuthDecision<O::Context> {
        if publication.expires_at <= now {
            return AuthDecision::Forbidden {
                budget_header: None,
            };
        }
        let c = token.claims();
        let claims = ResourceClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-resource.json".into(),
            aud: c.iss.clone(),
            ps: c.ps.clone(),
            sub: c.sub.clone(),
            jti: challenge_jti.into(),
            presented_jti: c.jti.clone(),
            agent_jkt: agent_jkt.to_owned(),
            iat: now,
            exp: publication.expires_at,
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
            &digest(&publication.exact),
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
            &publication.exact,
        ) else {
            return AuthDecision::InternalError;
        };
        let held = per_call.hold.then(|| held_request(request, challenge_jti));
        let record = R3ProposalRecord {
            reference,
            exact_json: publication.exact,
            person_server: claims.ps.clone(),
            auth_token_issuer: claims.aud.clone(),
            resource_token_jti: claims.jti.clone(),
            resource_token: compact.clone(),
            class_reference: class_reference.clone(),
            presented_jti: claims.presented_jti.clone(),
            subject: claims.sub.clone(),
            agent_jkt: claims.agent_jkt.clone(),
            tenant: claims.tenant.clone(),
            account: claims.account.clone(),
            scope: claims.scope.clone(),
            issued_at: claims.iat,
            expires_at: claims.exp,
            held,
            released: publication.released,
            release_until: publication.release_until,
            supersedes: publication.supersedes,
        };
        // Committed before the challenge is observable; any failure withholds it
        // and discards a computed result unreleased. A successor retires its
        // prior in the same store step; a failure there never recomputes.
        let committed = match record.supersedes.as_deref() {
            Some(prior) => per_call.calls.supersede(prior, &record, now),
            None => per_call.calls.commit(&record),
        };
        if committed.is_err() {
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
        // `result` exactly when a computed response is held for a 202 release,
        // and a held response always carries its horizon.
        if proposal.result().is_some() != record.released.is_some()
            || (record.released.is_some() && record.held.is_none())
            || record.release_until.is_some() != record.released.is_some()
        {
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
        let entitled = (signer == record.person_server && role == PERSON_DOCUMENT)
            || (signer == record.auth_token_issuer && role == self.auth_token_issuer_document());
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
    /// at the pending URL. Nothing is claimed here; [`Self::post_callback_admission`] claims
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
            // A pending URL that names no stored invocation is gone. A miss on
            // the mapped completion route stays a refusal of that token.
            Ok(None) if pending_id.is_some() => return Err(AuthDecision::Gone),
            Ok(None) => return Err(forbidden()),
            Err(_) => return Err(AuthDecision::InternalError),
        };
        // The held-result horizon is resource policy. It refuses completion
        // even when the per-call Auth token's own `exp` is still in the future.
        if record.release_until.is_some_and(|until| now >= until) {
            return Err(forbidden());
        }
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
            || claims.dwk != self.auth_token_issuer_document()
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
                let presented =
                    (per_call.present)(request, mapped).map_err(|_| AuthDecision::InternalError)?;
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
                pending_id: pending_id.map(str::to_owned),
                executing: None,
                released: record.released.clone(),
                release_until: record.release_until,
            }),
        })
    }

    /// Shared post-callback verification for every admitted Auth token, Core
    /// or R3: recheck revocation after host policy, then claim a per-call
    /// completion. A Core or class grant needs no claim. A revocation noticed
    /// after a claim never rolls it back, redispatches the operation or
    /// releases a result; the host receives no effect.
    ///
    /// A release-gated completion is retained and answered here as
    /// [`AuthDecision::Replayed`]; the host never executes it.
    pub(crate) fn post_callback_admission(
        &self,
        grant: Option<R3Grant>,
        token: &VerifiedAuthToken,
        now: i64,
    ) -> Result<Option<R3Grant>, AuthDecision<O::Context>> {
        let claims = token.claims();
        // Host policy is a callback: a revocation it completed fences admission.
        if self.presented_revoked(&claims.iss, &claims.jti, now) {
            return Err(AuthDecision::Revoked { auth_token: true });
        }
        let Some(mut grant) = grant else {
            return Ok(None);
        };
        let Some(completion) = grant.completion.as_mut() else {
            return Ok(Some(grant));
        };
        let Some(per_call) = self
            .r3
            .as_ref()
            .and_then(|profile| profile.per_call.as_ref())
        else {
            return Err(AuthDecision::InternalError);
        };
        if completion.token.retain_until <= now
            || completion.release_until.is_some_and(|until| now >= until)
        {
            return Err(AuthDecision::Forbidden {
                budget_header: None,
            });
        }
        let outcome = match per_call
            .calls
            .claim(&completion.uri, &completion.token, now)
        {
            // Release: the claim consumes the proposal and the stored response
            // is retained under the fence; nothing executes.
            Ok(R3Claim::Execute { fence }) if !fence.is_empty() => {
                if let Some(released) = completion.released.take() {
                    // Revoked during the claim callback: the claim stays bound
                    // and nothing is retained, so no later replay can release.
                    if self.presented_revoked(&claims.iss, &claims.jti, now) {
                        return Err(AuthDecision::Revoked { auth_token: true });
                    }
                    match per_call.calls.retain(&completion.uri, &fence, &released) {
                        Ok(stored) => Err(AuthDecision::Replayed(Box::new(restore(&stored)))),
                        Err(_) => Err(AuthDecision::InternalError),
                    }
                } else {
                    completion.fence = Some(fence);
                    if completion.held.is_some() {
                        completion.executing =
                            Some(ExecutingHold::register(&self.executing, &completion.uri));
                    }
                    Ok(Some(grant))
                }
            }
            Ok(R3Claim::Replay(result)) => Err(AuthDecision::Replayed(Box::new(restore(&result)))),
            Ok(R3Claim::DifferentToken | R3Claim::Expired) => Err(AuthDecision::Forbidden {
                budget_header: None,
            }),
            // The host still holds this held grant. The poll stays pending.
            // Nothing runs. A `401` retry, a dropped grant, and an uncertain
            // store stay `500`: there is no second effect.
            Ok(R3Claim::Unfinished) if completion.held.is_some() => {
                match completion.pending_id.as_deref() {
                    Some(id) if ExecutingHold::contains(self.executing.as_ref(), &completion.uri) => {
                        Err(AuthDecision::StillPending {
                            location: format!("{}/r3/pending/{id}", self.document_origin()),
                        })
                    }
                    _ => Err(AuthDecision::InternalError),
                }
            }
            Ok(_) | Err(_) => Err(AuthDecision::InternalError),
        };
        // The store is host code too. A completed revocation during its claim or
        // retain callback fences first execution, first release and replay.
        if self.presented_revoked(&claims.iss, &claims.jti, now) {
            Err(AuthDecision::Revoked { auth_token: true })
        } else {
            outcome
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

#[cfg(test)]
mod tests {
    use super::*;
    use aauth_rust_r3::{McpCodec, Parameter};

    const CLASS: &[u8] = b"class document";

    fn operation(tool: &str) -> Operation {
        let vocabulary = McpCodec::vocabulary().unwrap();
        Operation::new(&vocabulary, format!(r#"{{"tool":"{tool}"}}"#).as_bytes()).unwrap()
    }

    fn presented(record: &str) -> BTreeMap<String, PresentedParameter> {
        BTreeMap::from([(
            "record".to_owned(),
            PresentedParameter::inline(format!(r#""{record}""#).as_bytes()).unwrap(),
        )])
    }

    fn stored_proposal(record: &str, account: Option<&str>) -> Proposal {
        let parameters = Parameters::new([(
            "record".to_owned(),
            Parameter::inline(format!(r#""{record}""#).as_bytes()).unwrap(),
        )])
        .unwrap();
        let result = ProposalResult::new(br#"{"records":1}"#).unwrap();
        Proposal::new(
            &operation("records.query"),
            &parameters,
            ProposalOptions {
                account,
                result: Some(&result),
                display: None,
            },
        )
        .unwrap()
    }

    fn held_release() -> R3ProposalRecord {
        R3ProposalRecord {
            reference: Reference::new("https://records.example/r3/p.prior", digest(b"proposal"))
                .unwrap(),
            exact_json: b"{}".to_vec(),
            person_server: "https://ps.example".into(),
            auth_token_issuer: "https://ps.example".into(),
            resource_token_jti: "rid-1".into(),
            resource_token: "proposal-token".into(),
            class_reference: Reference::new("https://records.example/r3/c.short", digest(CLASS))
                .unwrap(),
            presented_jti: "ps-1".into(),
            subject: "subject".into(),
            agent_jkt: "jkt".into(),
            tenant: Some("tenant".into()),
            account: Some("account".into()),
            scope: Some("records.read".into()),
            issued_at: 1_000,
            expires_at: 1_005,
            held: Some(R3HeldRequest {
                pending_id: "rid-1".into(),
                method: "POST".into(),
                uri: "https://records.example/records/query".into(),
                headers: Vec::new(),
                body: Vec::new(),
            }),
            released: Some(R3CallResult {
                status: 200,
                content_type: None,
                body: b"run-1".to_vec(),
            }),
            release_until: Some(1_300),
            supersedes: None,
        }
    }

    fn caller(class_digest: &str) -> CallerLineage<'_> {
        CallerLineage {
            person_server: "https://ps.example",
            auth_token_issuer: "https://ps.example",
            subject: "subject",
            tenant: Some("tenant"),
            agent_jkt: "jkt",
            account: Some("account"),
            scope: Some("records.read"),
            class_digest,
            presented_jti: "ps-2",
        }
    }

    #[test]
    fn held_release_matches_only_its_own_lineage_within_its_horizon() {
        let prior = held_release();
        let class = digest(CLASS);
        // The proposal token expired with the short class token (1_005); the
        // held response is still within its own horizon, and the caller presents
        // a different class-token jti.
        assert!(held_release_matches(&prior, &caller(&class), 1_006));
        assert!(held_release_matches(&prior, &caller(&class), 1_299));
        // A live proposal token is not retired, even for the same descriptor.
        let mut live = prior.clone();
        live.expires_at = 2_000;
        assert!(!held_release_matches(&live, &caller(&class), 1_006));
        // The same class token is not a replacement refresh.
        let mut same_token = caller(&class);
        same_token.presented_jti = "ps-1";
        assert!(!held_release_matches(&prior, &same_token, 1_006));
        // Expired held result: the horizon is exclusive.
        assert!(!held_release_matches(&prior, &caller(&class), 1_300));
        assert!(!held_release_matches(&prior, &caller(&class), 1_301));
        // Different holder, subject, tenant, account, scope, entitlement or
        // class document digest.
        let other_class = digest(b"another class document");
        let negatives = [
            CallerLineage {
                agent_jkt: "other-jkt",
                ..caller(&class)
            },
            CallerLineage {
                subject: "other-subject",
                ..caller(&class)
            },
            CallerLineage {
                tenant: None,
                ..caller(&class)
            },
            CallerLineage {
                tenant: Some("other-tenant"),
                ..caller(&class)
            },
            CallerLineage {
                account: None,
                ..caller(&class)
            },
            CallerLineage {
                account: Some("other-account"),
                ..caller(&class)
            },
            CallerLineage {
                scope: None,
                ..caller(&class)
            },
            CallerLineage {
                scope: Some("records.read records.write"),
                ..caller(&class)
            },
            CallerLineage {
                person_server: "https://other-ps.example",
                ..caller(&class)
            },
            CallerLineage {
                auth_token_issuer: "https://other-ps.example",
                ..caller(&class)
            },
            caller(&other_class),
        ];
        for negative in &negatives {
            assert!(!held_release_matches(&prior, negative, 1_006));
        }
        // Only a computed, held response with its horizon qualifies.
        for record in [
            R3ProposalRecord {
                released: None,
                ..held_release()
            },
            R3ProposalRecord {
                held: None,
                ..held_release()
            },
            R3ProposalRecord {
                release_until: None,
                ..held_release()
            },
        ] {
            assert!(!held_release_matches(&record, &caller(&class), 1_006));
        }
    }

    #[test]
    fn held_proposal_matches_only_the_same_operation_parameters_and_account() {
        let query = operation("records.query");
        let stored = stored_proposal("r-1", Some("account"));
        assert!(held_proposal_matches(&stored, &query, &presented("r-1"), Some("account")));
        // Changed parameters.
        assert!(!held_proposal_matches(&stored, &query, &presented("r-2"), Some("account")));
        assert!(!held_proposal_matches(&stored, &query, &BTreeMap::new(), Some("account")));
        // Another operation.
        assert!(!held_proposal_matches(
            &stored,
            &operation("records.delete"),
            &presented("r-1"),
            Some("account")
        ));
        // Account presence and value.
        assert!(!held_proposal_matches(&stored, &query, &presented("r-1"), None));
        assert!(!held_proposal_matches(&stored, &query, &presented("r-1"), Some("other-account")));
    }
}
