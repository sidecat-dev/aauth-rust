mod advance;
mod schedule;
use schedule::{agent_delay, throttled_for};
mod wire;
use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, PendingResponse, Requirement, generate_pending_id, same_origin_location,
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
    /// Maximum waiting lifetime in seconds, 1..=3600, capped by original inputs.
    pub lifetime: i64,
    /// Agent GET interval in seconds, 0..=3600; default five.
    pub retry_after: u64,
}
impl DeferredConfig {
    /// Use host custody with 300 seconds and five-second Agent polling.
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
    /// with host policy. Normal Agent GETs never contact the AS. A request
    /// whose resource token, or upstream token when chained, is revoked while
    /// it waits ends at the next poll or advance with the polling error
    /// `revoked` (403).
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
        prepared: &PreparedAuthorization,
        endpoint: &str,
        sent: Option<Budget>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let PreparedAuthorization {
            resource,
            presented,
            context,
            ..
        } = prepared;
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        let pending = PendingResponse::parse(endpoint, response).map_err(|_| {
            super::federation::unreachable(
                &resource.claims().aud,
                Some(response.status()),
                crate::FederationFailureReason::MalformedResponse("invalid AS continuation"),
            )
        })?;
        if matches!(pending.requirement, Requirement::AuthToken { .. }) {
            return Err(super::federation::unreachable(
                &resource.claims().aud,
                Some(response.status()),
                crate::FederationFailureReason::MalformedResponse(
                    "auth-token delivery is not an AS continuation",
                ),
            ));
        }
        let now = (self.clock)();
        self.inputs_current(agent, resource, presented, now)?;
        self.subagent_current(agent, context.subagent.as_ref(), now)?;
        let deadline = now
            .saturating_add(d.lifetime)
            .min(agent.claims().exp)
            .min(
                context
                    .subagent
                    .as_ref()
                    .map_or(i64::MAX, |child| child.claims().exp),
            )
            .min(resource.claims().exp)
            .min(presented.exp)
            // A chained request ends with `expired` once its upstream token does.
            .min(
                context
                    .upstream
                    .as_ref()
                    .map_or(i64::MAX, |up| up.record.expires_at),
            );
        if now >= deadline {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let id = generate_pending_id();
        let location = format!("{}/token/pending/{id}", self.config.signed_origin);
        let ps_pending = self.agent_pending(&location, &pending)?;
        let interval = d.retry_after.max(pending.retry_after);
        let sent_budget = sent.as_ref().map(Budget::to_value).unwrap_or(Value::Null);
        let value = json!({"state":"waiting","agent_token":agent.compact(),"parameters":context.parameters,"endpoint":endpoint,"deadline":deadline,"next_agent":now.saturating_add(interval as i64),"next_as":now.saturating_add(pending.retry_after as i64),"as_pending":pending,"ps_pending":ps_pending,"queued":null,"retrying":false,"rounds":usize::from(matches!(pending.requirement,Requirement::Clarification{..})),"question_deadline":question_deadline(&pending,now),"sent_budget":sent_budget});
        d.store
            .insert(&id, value.clone())
            .map_err(|_| Failure::internal())?;
        pending_wire(&ps_pending, &value, (self.clock)(), d.retry_after)
    }
    fn agent_pending(
        &self,
        location: &str,
        pending: &PendingResponse,
    ) -> Result<PendingResponse, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        let requirement = match &pending.requirement {
            Requirement::Payment { .. } | Requirement::Claims(_) => Requirement::Approval,
            // Codes compare without case, so an AS code read in lower case is
            // relayed in the upper case a server emits.
            Requirement::Interaction { url, code } => Requirement::Interaction {
                url: url.clone(),
                code: code.to_ascii_uppercase(),
            },
            other => other.clone(),
        };
        PendingResponse::new(
            &self.config.signed_origin,
            location,
            d.retry_after.max(pending.retry_after),
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
    /// The returned retry_after is the remaining AS wait at the current clock.
    /// Expired custody returns Expired; in-flight or ready custody returns NotReady.
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
        let now = (self.clock)();
        if expired(&value, now).map_err(|_| AdvanceError::Unavailable)? {
            return Err(AdvanceError::Expired);
        }
        if value["state"] != "waiting" {
            return Err(AdvanceError::NotReady);
        }
        let mut pending: PendingResponse = serde_json::from_value(value["as_pending"].clone())
            .map_err(|_| AdvanceError::Unavailable)?;
        pending.retry_after = number(&value, "next_as")
            .map_err(|_| AdvanceError::Unavailable)?
            .saturating_sub(now)
            .max(0) as u64;
        Ok(pending)
    }
    // Store publication/removal is a host boundary. A prepared grant must still
    // match current trust, retained inputs and binding after that I/O finishes.
    fn check_release(
        &self,
        value: &Value,
        response: &mut Response<Vec<u8>>,
    ) -> Result<(), Failure> {
        if response.status() != StatusCode::OK {
            return Ok(());
        }
        let now = (self.clock)();
        if now >= number(value, "deadline")? {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let original = AgentToken::parse(required_string(value, "agent_token")?)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(Failure::credential)?;
        let mut body = strict_json(response.body()).map_err(|_| Failure::internal())?;
        let auth = AuthToken::parse(required_string(&body, "auth_token")?)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(|_| Failure::internal())?;
        let prepared = self.prepare_stored(&original, value["parameters"].clone(), now)?;
        self.subagent_current(
            &original,
            prepared.context.subagent.as_ref(),
            (self.clock)(),
        )?;
        self.binding(&prepared.retained.principal, prepared.binding_context)?
            .ok_or_else(Failure::internal)?;
        let released = (self.clock)();
        // Custody's deadline is capped by the original child's expiry. This
        // final lease fence therefore also bounds the child, without changing
        // an expired pending request's 408 into a child-parameter error.
        if released >= number(value, "deadline")? {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        self.inputs_current(&original, &prepared.resource, &prepared.presented, released)?;
        check_upstream_current(prepared.context.upstream.as_ref(), released)?;
        if auth.claims().exp <= released {
            return Err(Failure::internal());
        }
        body["expires_in"] = json!(auth.claims().exp - released);
        *response.body_mut() = body.to_string().into_bytes();
        Ok(())
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
        // An intermediary's own `ps`, if any, names its Person Server, not the
        // person's: a chained request is tied to this PS by its upstream token.
        let chained = value["parameters"].get("upstream_token").is_some();
        if caller.claims().iss != original.iss
            || caller.claims().sub != original.sub
            || caller.claims().cnf.jwk.thumbprint().ok() != original.cnf.jwk.thumbprint().ok()
            || (!chained && caller.claims().ps.as_deref() != Some(&self.config.issuer))
            || caller.claims().parent_agent.is_some()
        {
            return Err(Failure::status(StatusCode::FORBIDDEN, "wrong_poller"));
        }
        // Only the delivery owner may consume its claimed row. It rechecks
        // expiry and trust before release; rival cleanup must not steal custody.
        if value["state"] == "delivering" {
            return throttled_for(&value, (self.clock)());
        }
        if expired(&value, now)? {
            if !d
                .store
                .replace(&id, snapshot.revision, None)
                .map_err(|_| Failure::internal())?
            {
                return throttled_for(&value, (self.clock)());
            }
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let prepared = (|| {
            let original = AgentToken::parse(required_string(&value, "agent_token")?)
                .and_then(|t| t.verify(&self.resolver(), now))
                .map_err(Failure::credential)?;
            let prepared = self.prepare_stored(&original, value["parameters"].clone(), now)?;
            Ok::<_, Failure>((original, prepared))
        })();
        // A stored input revoked while the request waits ends it with the
        // polling error `revoked`. A token the Agent sends now, such as an
        // updated request's, is refused with its parameter code instead.
        let (original_agent, prepared) = match prepared {
            Ok(result) => result,
            Err(error) => {
                if !d
                    .store
                    .replace(&id, snapshot.revision, None)
                    .map_err(|_| Failure::internal())?
                {
                    return throttled_for(&value, (self.clock)());
                }
                return Err(error.while_pending());
            }
        };
        if request.method() == "DELETE" {
            if value["state"] == "ready" {
                if !d
                    .store
                    .replace(&id, snapshot.revision, None)
                    .map_err(|_| Failure::internal())?
                {
                    return throttled_for(&value, (self.clock)());
                }
                return Ok(json_response(StatusCode::OK, json!({"status":"cancelled"})));
            }
            return match self.advance_federation(&id, FederationInput::Cancel) {
                Ok(response) => Ok(response),
                Err(AdvanceError::NotReady) => Ok(throttled_for(&value, (self.clock)())?),
                Err(AdvanceError::Gone) => Err(Failure::status(StatusCode::GONE, "gone")),
                Err(AdvanceError::Expired) => {
                    Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"))
                }
                Err(_) => Err(Failure::internal()),
            };
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
            match object.get("action").and_then(Value::as_str) {
                Some("clarification_response") => {
                    if object
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
                }
                Some("updated_request") => self.queue_updated_request(
                    &mut value,
                    object,
                    &original_agent,
                    &prepared.resource,
                    now,
                )?,
                _ => return Err(Failure::parameter("invalid_request")),
            }
            // This POST only queues the answer; it is not the AS's next round.
            // Stop presenting the answered question until explicit host advance
            // publishes a fresh AS requirement, even if its text is identical.
            let acknowledgement = PendingResponse::new(
                &self.config.signed_origin,
                &pending.location,
                d.retry_after,
                Requirement::Approval,
            )
            .map_err(|_| Failure::internal())?;
            value["ps_pending"] =
                serde_json::to_value(&acknowledgement).map_err(|_| Failure::internal())?;
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value.clone()))
                .map_err(|_| Failure::internal())?
            {
                return throttled_for(&value, (self.clock)());
            }
            return pending_wire(&acknowledgement, &value, (self.clock)(), d.retry_after);
        }
        if value["state"] == "ready" {
            value["state"] = json!("delivering");
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value.clone()))
                .map_err(|_| Failure::internal())?
            {
                return throttled_for(&value, (self.clock)());
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
                    stored_sent_budget(&value)?,
                    None,
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
            let mut response = result.map_err(Failure::while_pending)?;
            self.check_release(&value, &mut response)
                .map_err(Failure::while_pending)?;
            return Ok(response);
        }
        if now < number(&value, "next_agent")? {
            return throttled_for(&value, (self.clock)());
        }
        if value["state"] == "waiting" {
            value["next_agent"] =
                json!(now.saturating_add(agent_delay(&value, now, d.retry_after)? as i64));
            if !d
                .store
                .replace(&id, snapshot.revision, Some(value.clone()))
                .map_err(|_| Failure::internal())?
            {
                return throttled_for(&value, (self.clock)());
            }
        }
        pending_wire(&pending, &value, (self.clock)(), d.retry_after)
    }

    /// Prepare a stored exchange again. A chained request's `upstream_token` is
    /// verified anew, since it can expire or be revoked while the request waits.
    fn prepare_stored(
        &self,
        agent: &VerifiedAgentToken,
        parameters: Value,
        now: i64,
    ) -> Result<PreparedAuthorization, Failure> {
        let upstream = match parameters.get("upstream_token") {
            Some(_) => Some(self.verify_upstream(
                required_string(&parameters, "upstream_token")?,
                agent,
                now,
            )?),
            None => None,
        };
        self.prepare_authorization(agent, parameters, now, upstream.as_ref())
    }

    /// Verify the replacement pair before any custody write.
    fn queue_updated_request(
        &self,
        value: &mut Value,
        object: &serde_json::Map<String, Value>,
        agent: &VerifiedAgentToken,
        original: &VerifiedResourceToken,
        now: i64,
    ) -> Result<(), Failure> {
        if object.keys().any(|key| {
            ![
                "action",
                "resource_token",
                "presented_token",
                "justification",
            ]
            .contains(&key.as_str())
        }) {
            return Err(Failure::parameter("invalid_request"));
        }
        let resource_token = object
            .get("resource_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| Failure::parameter("invalid_request"))?;
        let presented_token = object
            .get("presented_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| Failure::parameter("invalid_request"))?;
        let mut parameters = value["parameters"].clone();
        if let Some(justification) = object.get("justification") {
            let text = justification
                .as_str()
                .filter(|text| !text.is_empty() && text.len() <= 65536)
                .ok_or_else(|| Failure::parameter("invalid_request"))?;
            parameters["justification"] = json!(text);
        }
        parameters["resource_token"] = json!(resource_token);
        parameters["presented_token"] = json!(presented_token);
        let updated = self.prepare_stored(agent, parameters.clone(), now)?;
        if !same_updated_resource(original, &updated.resource) {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        self.federation_consent(&updated.context)
            .map_err(Failure::policy)?;
        value["parameters"] = parameters;
        value["updated_request"] = Value::Object(object.clone());
        value["queued"] = json!(true);
        Ok(())
    }
}
fn same_updated_resource(left: &VerifiedResourceToken, right: &VerifiedResourceToken) -> bool {
    let left = left.claims();
    let right = right.claims();
    left.iss == right.iss
        && left.ps == right.ps
        && left.sub == right.sub
        && left.agent_jkt == right.agent_jkt
        && left.mission_s256 == right.mission_s256
        && left.tenant == right.tenant
}
fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn stored_sent_budget(value: &Value) -> Result<Option<Budget>, Failure> {
    match value.get("sent_budget") {
        None | Some(Value::Null) => Ok(None),
        Some(other) => parse_budget(other)
            .map(Some)
            .map_err(|_| Failure::internal()),
    }
}

fn number(v: &Value, k: &str) -> Result<i64, Failure> {
    v[k].as_i64().ok_or_else(Failure::internal)
}

fn question_deadline(pending: &PendingResponse, now: i64) -> Option<i64> {
    match pending.requirement {
        Requirement::Clarification {
            timeout: Some(s), ..
        } => Some(now.saturating_add(i64::try_from(s).unwrap_or(i64::MAX))),
        _ => None,
    }
}
fn same_question(left: &Requirement, right: &Requirement) -> bool {
    matches!((left,right), (Requirement::Clarification{question:a,options:ao,..}, Requirement::Clarification{question:b,options:bo,..}) if a==b && ao==bo)
}
fn expired(value: &Value, now: i64) -> Result<bool, Failure> {
    Ok(now >= number(value, "deadline")?
        || (!(value["state"] == "advancing" && value["answering"] == true)
            && value["question_deadline"]
                .as_i64()
                .is_some_and(|at| now >= at)))
}
fn pending_wire(
    pending: &PendingResponse,
    value: &Value,
    now: i64,
    minimum: u64,
) -> Result<Response<Vec<u8>>, Failure> {
    let mut pending = pending.clone();
    pending.retry_after = agent_delay(value, now, minimum)?;
    if let Some(at) = value["question_deadline"].as_i64()
        && !(value["state"] == "advancing" && value["answering"] == true)
    {
        if now >= at {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        if let Requirement::Clarification { timeout, .. } = &mut pending.requirement {
            *timeout = Some((at - now) as u64);
            pending.body["timeout"] = json!(at - now);
        }
    }
    pending.response().map_err(|_| Failure::internal())
}
