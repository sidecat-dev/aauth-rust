mod advance;
mod wire;
use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, PendingResponse, Requirement, same_origin_location,
};
use aauth_rust_signature_key::sign_request;
use std::sync::Arc;
use wire::decode;

/// Explicit bounded PS federation custody. Keep this store separate from AS
/// continuation state. Memory fixtures survive recomposition through shared Arc;
/// process restart durability and expiry collection require a host adapter.
pub struct DeferredConfig {
    /// Atomic role-local custody containing exact original compact credentials.
    pub store: Arc<dyn ContinuationStore>,
    /// Maximum waiting lifetime in seconds,1..=3600, capped by original inputs.
    pub lifetime: i64,
    /// Agent GET interval in seconds,0..=3600; default five.
    pub retry_after: u64,
}
impl DeferredConfig {
    /// Use host custody with300 seconds and five-second Agent polling.
    pub fn new(store: impl ContinuationStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            lifetime: 300,
            retry_after: 5,
        }
    }
}
/// One explicit host action. No action resends the original AS token POST.
pub enum FederationInput {
    /// Apply a queued Agent clarification with POST, otherwise perform one GET.
    Poll,
    /// POST requested identity claims from an admitted host source; sub is forbidden.
    Claims(serde_json::Map<String, Value>),
    /// POST a host/user/Agent clarification answer to the active AS question.
    Clarification(String),
    /// Send one signed DELETE to cancel the AS request, then close PS custody.
    Cancel,
}
/// Local host advancement refusal, distinct from a terminal wire problem cached
/// for the Agent. No error permits an implicit retry of consequential content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdvanceError {
    /// The PS-owned reference is malformed, missing or already consumed.
    #[error("pending federation reference is gone")]
    Gone,
    /// The original request's finite lifetime elapsed.
    #[error("pending federation expired")]
    Expired,
    /// Another transition owns custody or AS Retry-After has not elapsed.
    #[error("pending federation is not ready to advance")]
    NotReady,
    /// The action does not match the AS requirement or includes forbidden input.
    #[error("invalid federation continuation input")]
    InvalidInput,
    /// State persistence, local signing or synchronization failed.
    #[error("federation continuation unavailable")]
    Unavailable,
}
impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Enable deferred AS exchanges after `with_federation`. Payment settlement,
    /// billing caches, identity-claim sources and interaction/code lifecycle stay
    /// with host policy. Normal Agent GETs never contact the AS.
    pub fn with_deferred(mut self, config: DeferredConfig) -> Result<Self, ConfigurationError> {
        if self.federation.is_none()
            || !(1..=3600).contains(&config.lifetime)
            || config.retry_after > 3600
        {
            return Err(ConfigurationError);
        }
        self.deferred = Some(config);
        Ok(self)
    }
    pub(super) fn defer_federation(
        &self,
        response: &Response<Vec<u8>>,
        agent: &VerifiedAgentToken,
        resource: &VerifiedResourceToken,
        presented: &Presented,
        context: &AuthorizationRequest,
        endpoint: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        let pending = PendingResponse::parse(endpoint, response).map_err(|_| {
            super::federation::unreachable(
                &resource.claims().aud,
                Some(response.status()),
                crate::FederationFailureReason::MalformedResponse("invalid AS continuation"),
            )
        })?;
        let now = (self.clock)();
        self.inputs_current(agent, resource, presented, now)?;
        let deadline = now
            .saturating_add(d.lifetime)
            .min(agent.claims().exp)
            .min(resource.claims().exp)
            .min(presented.exp);
        if now >= deadline {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let id = (self.ids)();
        if !safe_id(&id) {
            return Err(Failure::internal());
        }
        let location = format!("{}/token/pending/{id}", self.config.signed_origin);
        let ps_pending = self.agent_pending(&location, &pending)?;
        let value = json!({"state":"waiting","agent_token":agent.compact(),"parameters":context.parameters,"endpoint":endpoint,"deadline":deadline,"next_agent":now.saturating_add(d.retry_after as i64),"next_as":now.saturating_add(pending.retry_after as i64),"as_pending":pending,"ps_pending":ps_pending,"queued":null});
        d.store
            .insert(&id, value)
            .map_err(|_| Failure::internal())?;
        ps_pending.response().map_err(|_| Failure::internal())
    }
    fn agent_pending(
        &self,
        location: &str,
        pending: &PendingResponse,
    ) -> Result<PendingResponse, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        let requirement = match &pending.requirement {
            Requirement::Payment { .. } | Requirement::Claims(_) => Requirement::Approval,
            other => other.clone(),
        };
        PendingResponse::new(
            &self.config.signed_origin,
            location,
            d.retry_after,
            requirement,
        )
        .map_err(|_| Failure::internal())
    }
    fn reference(&self, reference: &str) -> Result<String, AdvanceError> {
        if safe_id(reference) {
            return Ok(reference.into());
        }
        let uri = same_origin_location(&self.config.signed_origin, reference)
            .map_err(|_| AdvanceError::Gone)?;
        let uri: http::Uri = uri.parse().map_err(|_| AdvanceError::Gone)?;
        uri.path()
            .strip_prefix("/token/pending/")
            .filter(|v| safe_id(v))
            .map(str::to_owned)
            .ok_or(AdvanceError::Gone)
    }
    /// Inspect actual AS payment/claims/interaction details for trusted host use.
    /// The Agent polls its own PS Location; this API never dispatches a request.
    pub fn federation_pending(&self, reference: &str) -> Result<PendingResponse, AdvanceError> {
        let d = self.deferred.as_ref().ok_or(AdvanceError::Unavailable)?;
        let id = self.reference(reference)?;
        let value = d
            .store
            .load(&id)
            .map_err(|_| AdvanceError::Unavailable)?
            .ok_or(AdvanceError::Gone)?
            .value;
        serde_json::from_value(value["as_pending"].clone()).map_err(|_| AdvanceError::Unavailable)
    }
    pub(super) fn pending(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        if request.uri().query().is_some()
            || !["GET", "POST", "DELETE"].contains(&request.method().as_str())
            || (request.method() != "POST" && !request.body().is_empty())
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let caller = self.verify_agent(request, now, request.method() == "POST")?;
        let id = self
            .reference(&request.uri().to_string())
            .map_err(|_| Failure::status(StatusCode::GONE, "gone"))?;
        let snapshot = d
            .store
            .load(&id)
            .map_err(|_| Failure::internal())?
            .ok_or_else(|| Failure::status(StatusCode::GONE, "gone"))?;
        let mut value = snapshot.value;
        let original = AgentToken::parse(required_string(&value, "agent_token")?)
            .map_err(Failure::credential)?;
        let original = original.unverified_claims();
        if caller.claims().iss != original.iss
            || caller.claims().sub != original.sub
            || caller.claims().cnf.jwk.thumbprint().ok() != original.cnf.jwk.thumbprint().ok()
            || caller.claims().ps.as_deref() != Some(&self.config.issuer)
            || caller.claims().parent_agent.is_some()
        {
            return Err(Failure::status(StatusCode::FORBIDDEN, "denied"));
        }
        if now >= number(&value, "deadline")? {
            if !d
                .store
                .replace(&id, snapshot.revision, None)
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled());
            }
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let prepared = (|| {
            let original = AgentToken::parse(required_string(&value, "agent_token")?)
                .and_then(|t| t.verify(&self.resolver(), now))
                .map_err(Failure::credential)?;
            let prepared =
                self.prepare_authorization(&original, value["parameters"].clone(), now, None)?;
            Ok::<_, Failure>((original, prepared))
        })();
        let (original_agent, prepared) = match prepared {
            Ok(result) => result,
            Err(error) => {
                if !d
                    .store
                    .replace(&id, snapshot.revision, None)
                    .map_err(|_| Failure::internal())?
                {
                    return Ok(throttled());
                }
                return Err(error);
            }
        };
        if value["state"] == "delivering" {
            return Ok(throttled());
        }
        if request.method() == "DELETE" {
            if value["state"] == "ready" {
                if !d
                    .store
                    .replace(&id, snapshot.revision, None)
                    .map_err(|_| Failure::internal())?
                {
                    return Ok(throttled());
                }
                return Ok(json_response(StatusCode::OK, json!({"status":"cancelled"})));
            }
            return self
                .advance_federation(&id, FederationInput::Cancel)
                .map_err(|_| Failure::internal());
        }
        let pending: PendingResponse =
            serde_json::from_value(value["ps_pending"].clone()).map_err(|_| Failure::internal())?;
        if request.method() == "POST" {
            if value["state"] != "waiting"
                || !matches!(pending.requirement, Requirement::Clarification { .. })
                || !value["queued"].is_null()
            {
                return Err(Failure::parameter("invalid_request"));
            }
            let body =
                strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
            let object = body
                .as_object()
                .ok_or_else(|| Failure::parameter("invalid_request"))?;
            if object.get("action").and_then(Value::as_str) != Some("clarification_response")
                || object
                    .keys()
                    .any(|k| !["action", "clarification_response"].contains(&k.as_str()))
            {
                return Err(Failure::parameter("invalid_request"));
            }
            let answer = object
                .get("clarification_response")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 65536)
                .ok_or_else(|| Failure::parameter("invalid_request"))?;
            value["queued"] = json!(answer);
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value))
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled());
            }
            return pending.response().map_err(|_| Failure::internal());
        }
        if value["state"] == "ready" {
            value["state"] = json!("delivering");
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value.clone()))
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled());
            }
            let result = (|| {
                let response = decode(&value["terminal"])?;
                if response.status() != StatusCode::OK {
                    return Ok(response);
                }
                self.accept_federation(
                    response,
                    &original_agent,
                    &prepared,
                    required_string(&value, "endpoint")?,
                )
            })();
            let held = d
                .store
                .load(&id)
                .map_err(|_| Failure::internal())?
                .ok_or_else(Failure::internal)?;
            if held.value["state"] != "delivering"
                || !d
                    .store
                    .replace(&id, held.revision, None)
                    .map_err(|_| Failure::internal())?
            {
                return Err(Failure::internal());
            }
            return result;
        }
        if now < number(&value, "next_agent")? {
            return Ok(throttled());
        }
        if value["state"] == "waiting" {
            value["next_agent"] = json!(now.saturating_add(d.retry_after as i64));
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value))
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled());
            }
        }
        pending.response().map_err(|_| Failure::internal())
    }
}
fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn number(v: &Value, k: &str) -> Result<i64, Failure> {
    v[k].as_i64().ok_or_else(Failure::internal)
}
fn throttled() -> Response<Vec<u8>> {
    let mut r = Failure::status(StatusCode::TOO_MANY_REQUESTS, "slow_down").response();
    r.headers_mut().insert("retry-after", "1".parse().unwrap());
    r
}
