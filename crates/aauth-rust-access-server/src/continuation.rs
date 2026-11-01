use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, PendingResponse, Requirement, generate_interaction_code, generate_pending_id,
};
use serde_json::Map;
use std::sync::Arc;

/// Explicit bounded AS continuation configuration. Use a separate role-local
/// store; hosts supply durable custody if process restart recovery is required.
pub struct DeferredConfig {
    /// Atomic pending store; records contain exact compact request credentials.
    pub store: Arc<dyn ContinuationStore>,
    /// Maximum pending lifetime in seconds, 1..=3600; parents and challenge cap it.
    pub lifetime: i64,
    /// Required GET polling interval in seconds, 0..=3600; default five.
    pub retry_after: u64,
}
impl DeferredConfig {
    /// Use host custody with a 300-second lifetime and five-second GET interval.
    pub fn new(store: impl ContinuationStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            lifetime: 300,
            retry_after: 5,
        }
    }
}
/// Authenticated original authorization plus PS-provided continuation inputs.
/// Claims and Markdown answers are assertions by the authenticated PS, not proof
/// of facts outside that PS's trust. Host policy decides what to accept.
#[derive(Clone, Debug)]
pub struct DeferredContext {
    /// Independently verified Agent, Resource and presented-token context.
    pub authorization: AuthorizationRequest,
    /// Requested identity claims supplied by the owning PS. Never contains sub.
    pub claims: Map<String, Value>,
    /// Accepted clarification_response Markdown strings, bounded to five rounds.
    pub clarifications: Vec<String>,
    /// Interaction code this AS drew for the pending request: 40 bits from the
    /// operating system's secure random source, unchanged for its lifetime. A
    /// returned `Requirement::Interaction` carries exactly this code; any other
    /// code is a host error (`500`) and nothing is emitted.
    pub interaction_code: String,
}
type DeferredPolicy =
    Box<dyn Fn(&DeferredContext) -> Result<Option<Requirement>, PolicyError> + Send + Sync>;
pub(super) struct Deferred {
    config: DeferredConfig,
    policy: DeferredPolicy,
}
impl<
    K: AgentKeyResolver,
    P: Fn(&AuthorizationRequest) -> Result<Decision, PolicyError>,
    C: Fn() -> i64,
    I: Fn() -> String,
> AccessServer<K, P, C, I>
{
    /// Enable deferred policy before ordinary scope issuance. Some(requirement)
    /// waits; None invokes the existing grant policy. The callback must not settle
    /// payments or consume an interaction code implicitly: hosts establish those
    /// decisions independently, then the authenticated PS explicitly polls.
    /// An interaction requirement uses [`DeferredContext::interaction_code`].
    /// Pending URLs end in an identifier from
    /// [`aauth_rust_core::continuation::generate_pending_id`].
    pub fn with_deferred(
        mut self,
        config: DeferredConfig,
        policy: impl Fn(&DeferredContext) -> Result<Option<Requirement>, PolicyError>
        + Send
        + Sync
        + 'static,
    ) -> Result<Self, ConfigurationError> {
        if !(1..=3600).contains(&config.lifetime) || config.retry_after > 3600 {
            return Err(ConfigurationError);
        }
        self.deferred = Some(Deferred {
            config,
            policy: Box::new(policy),
        });
        Ok(self)
    }
    pub(super) fn begin_deferred(
        &self,
        context: AuthorizationRequest,
        presented: Presented,
        body: Value,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        let input = DeferredContext {
            authorization: context,
            claims: Map::new(),
            clarifications: Vec::new(),
            interaction_code: generate_interaction_code(),
        };
        let Some(requirement) = (d.policy)(&input).map_err(Failure::policy)? else {
            return self.issue(input.authorization, presented);
        };
        drawn_code(&requirement, &input.interaction_code)?;
        let deadline = now
            .saturating_add(d.config.lifetime)
            .min(input.authorization.agent.claims().exp)
            .min(
                input
                    .authorization
                    .subagent
                    .as_ref()
                    .map_or(i64::MAX, |child| child.claims().exp),
            )
            .min(input.authorization.resource.claims().exp)
            .min(presented.exp)
            .min(
                input
                    .authorization
                    .upstream
                    .as_ref()
                    .map_or(i64::MAX, UpstreamToken::expires_at),
            )
            .min(input.authorization.expires_at.unwrap_or(i64::MAX));
        let released = (self.clock)();
        current(released, &input.authorization, &presented)?;
        if released >= deadline {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let id = generate_pending_id();
        let location = format!("{}/token/pending/{id}", self.config.signed_origin);
        let pending = PendingResponse::new(
            &self.config.signed_origin,
            &location,
            d.config.retry_after,
            requirement,
        )
        .map_err(|_| Failure::internal())?;
        let value = json!({"state":"waiting","request":body,"person_server":input.authorization.person_server,"deadline":deadline,"next":released.saturating_add(d.config.retry_after as i64),"claims":{},"clarifications":[],"rounds":usize::from(matches!(pending.requirement,Requirement::Clarification{..})),"question_deadline":question_deadline(&pending,released),"interaction_code":input.interaction_code,"pending":pending});
        d.config
            .store
            .insert(&id, value.clone())
            .map_err(|_| Failure::internal())?;
        self.pending_current(&id, &value, &input.authorization.person_server)?;
        pending.response().map_err(|_| Failure::internal())
    }
    fn pending_current(&self, id: &str, value: &Value, owner: &str) -> Result<(), Failure> {
        let result = (|| {
            let now = (self.clock)();
            if pending_expired(value, now)? {
                return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
            }
            let (context, presented) = self.authorize_body(&value["request"], owner, now)?;
            let released = (self.clock)();
            if pending_expired(value, released)? {
                return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
            }
            current(released, &context, &presented)
        })();
        if result.is_err() {
            let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
            if let Some(held) = d.config.store.load(id).map_err(|_| Failure::internal())? {
                if held.value["request"] != value["request"]
                    || held.value["person_server"] != value["person_server"]
                {
                    return Err(Failure::internal());
                }
                d.config
                    .store
                    .replace(id, held.revision, None)
                    .map_err(|_| Failure::internal())?;
            }
        }
        result
    }
    pub(super) fn pending(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let d = self.deferred.as_ref().ok_or_else(Failure::internal)?;
        if request.uri().query().is_some()
            || !["GET", "POST", "DELETE"].contains(&request.method().as_str())
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let post = request.method() == "POST";
        if !post && !request.body().is_empty() {
            return Err(Failure::parameter("invalid_request"));
        }
        let owner = self.verify_ps(request, now, post)?;
        let id = request
            .uri()
            .path()
            .strip_prefix("/token/pending/")
            .filter(|id| safe_id(id))
            .ok_or_else(|| Failure::status(StatusCode::GONE, "gone"))?;
        let snapshot = d
            .config
            .store
            .load(id)
            .map_err(|_| Failure::internal())?
            .ok_or_else(|| Failure::status(StatusCode::GONE, "gone"))?;
        let mut value = snapshot.value;
        if value["person_server"].as_str() != Some(&owner) {
            return Err(Failure::status(StatusCode::FORBIDDEN, "wrong_poller"));
        }
        let expired = pending_expired(&value, now)?;
        if expired || request.method() == "DELETE" {
            if !d
                .config
                .store
                .replace(id, snapshot.revision, None)
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled(1));
            }
            return if expired {
                Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"))
            } else {
                Ok(wire::json_response(
                    StatusCode::OK,
                    json!({"status":"cancelled"}),
                ))
            };
        }
        if value["state"] != "waiting" {
            return Ok(throttled(1));
        }
        // A stored input revoked while the request waits ends it with the
        // polling error `revoked`. A token the PS sends now, such as an
        // updated request's, is refused with its parameter code instead.
        if !post {
            let next = number(&value, "next")?;
            if now < next {
                self.pending_current(id, &value, &owner)
                    .map_err(Failure::while_pending)?;
                return Ok(throttled(next.saturating_sub(now) as u64));
            }
        }
        let previous: PendingResponse =
            serde_json::from_value(value["pending"].clone()).map_err(|_| Failure::internal())?;
        let answered = if post {
            let body =
                strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
            let object = body
                .as_object()
                .ok_or_else(|| Failure::parameter("invalid_request"))?;
            if object.get("action").and_then(Value::as_str) == Some("updated_request") {
                if !matches!(previous.requirement, Requirement::Clarification { .. }) {
                    return Err(Failure::parameter("invalid_request"));
                }
                value["request"] =
                    self.verified_updated_request(&value["request"], object, &owner, now)?;
                if !d
                    .config
                    .store
                    .replace(id, snapshot.revision, Some(value.clone()))
                    .map_err(|_| Failure::internal())?
                {
                    return Ok(throttled(1));
                }
                return pending_wire(&previous, &value, now);
            }
            if [
                "agent_token",
                "subagent_token",
                "resource_token",
                "presented_token",
            ]
            .iter()
            .any(|name| object.contains_key(*name))
            {
                return Err(Failure::parameter("invalid_request"));
            }
            match &previous.requirement {
                Requirement::Claims(names) => {
                    if object.contains_key("sub") {
                        return Err(Failure::parameter("invalid_request"));
                    }
                    let claims = value["claims"]
                        .as_object_mut()
                        .ok_or_else(Failure::internal)?;
                    for name in names {
                        if let Some(v) = object.get(name) {
                            claims.insert(name.clone(), v.clone());
                        }
                    }
                    false
                }
                Requirement::Clarification { .. } => {
                    if object.get("action").and_then(Value::as_str)
                        != Some("clarification_response")
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
                    value["clarifications"]
                        .as_array_mut()
                        .ok_or_else(Failure::internal)?
                        .push(json!(answer));
                    true
                }
                _ => return Err(Failure::parameter("invalid_request")),
            }
        } else {
            false
        };
        if answered {
            // The recipient answered on time. Processing that accepted answer
            // remains bounded by the overall request, not its old question.
            value["question_deadline"] = Value::Null;
        }
        if value["interaction_code"].as_str().is_none() {
            value["interaction_code"] = json!(generate_interaction_code());
        }
        value["state"] = json!("busy");
        if !d
            .config
            .store
            .replace(id, snapshot.revision, Some(value.clone()))
            .map_err(|_| Failure::internal())?
        {
            return Ok(throttled(1));
        }
        let result = (|| {
            let (context, presented) = self.authorize_body(&value["request"], &owner, now)?;
            let input = DeferredContext {
                authorization: context,
                claims: serde_json::from_value(value["claims"].clone())
                    .map_err(|_| Failure::internal())?,
                clarifications: serde_json::from_value(value["clarifications"].clone())
                    .map_err(|_| Failure::internal())?,
                interaction_code: value["interaction_code"]
                    .as_str()
                    .ok_or_else(Failure::internal)?
                    .to_owned(),
            };
            let requirement = (d.policy)(&input).map_err(|e| match e {
                PolicyError::Denied => Failure::status(StatusCode::FORBIDDEN, "denied"),
                _ => Failure::policy(e),
            })?;
            if pending_expired(&value, (self.clock)())? {
                return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
            }
            match requirement {
                None => self.issue(input.authorization, presented),
                Some(requirement) => {
                    drawn_code(&requirement, &input.interaction_code)?;
                    let pending = PendingResponse::new(
                        &self.config.signed_origin,
                        &previous.location,
                        d.config.retry_after,
                        requirement,
                    )
                    .map_err(|_| Failure::internal())?;
                    let current = (self.clock)();
                    if pending_expired(&value, current)? {
                        return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
                    }
                    let new_question =
                        answered || !same_question(&pending.requirement, &previous.requirement);
                    if matches!(pending.requirement, Requirement::Clarification { .. })
                        && new_question
                    {
                        value["rounds"] = json!(number(&value, "rounds")? + 1);
                    }
                    if number(&value, "rounds")? > 5 {
                        return Err(Failure::status(StatusCode::FORBIDDEN, "denied"));
                    }
                    value["state"] = json!("waiting");
                    value["next"] = json!(current.saturating_add(d.config.retry_after as i64));
                    if new_question {
                        value["question_deadline"] = json!(question_deadline(&pending, current));
                    }
                    if value["question_deadline"]
                        .as_i64()
                        .is_some_and(|at| current >= at)
                    {
                        return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
                    }
                    value["pending"] =
                        serde_json::to_value(&pending).map_err(|_| Failure::internal())?;
                    pending_wire(&pending, &value, current)
                }
            }
        })();
        let held = d
            .config
            .store
            .load(id)
            .map_err(|_| Failure::internal())?
            .ok_or_else(|| Failure::status(StatusCode::GONE, "gone"))?;
        if held.value["state"] != "busy" {
            return Err(Failure::internal());
        }
        let waiting = result.as_ref().is_ok_and(|r| {
            [StatusCode::ACCEPTED, StatusCode::PAYMENT_REQUIRED].contains(&r.status())
        });
        if !d
            .config
            .store
            .replace(
                id,
                held.revision,
                if waiting { Some(value.clone()) } else { None },
            )
            .map_err(|_| Failure::internal())?
        {
            // A concurrent cancellation or expiry can consume busy custody
            // after the final load. Never release the prepared response then.
            if d.config
                .store
                .load(id)
                .map_err(|_| Failure::internal())?
                .is_none()
            {
                return Err(Failure::status(StatusCode::GONE, "gone"));
            }
            return Err(Failure::internal());
        }
        let mut response = result.map_err(Failure::while_pending)?;
        if waiting {
            self.pending_current(id, &value, &owner)
                .map_err(Failure::while_pending)?;
        }
        if response.status() == StatusCode::OK {
            // Custody removal can perform host I/O. Revalidate after it, before
            // releasing a credential that was prepared under an earlier clock.
            let now = (self.clock)();
            if pending_expired(&value, now)? {
                return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
            }
            let (context, presented) = self
                .authorize_body(&value["request"], &owner, now)
                .map_err(Failure::while_pending)?;
            let mut body = strict_json(response.body()).map_err(|_| Failure::internal())?;
            let token = AuthToken::parse(required(&body, "auth_token")?)
                .map_err(|_| Failure::internal())?;
            let released = (self.clock)();
            if pending_expired(&value, released)? {
                return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
            }
            current(released, &context, &presented)?;
            if released >= token.unverified_claims().exp {
                return Err(Failure::internal());
            }
            body["expires_in"] = json!(token.unverified_claims().exp - released);
            *response.body_mut() = body.to_string().into_bytes();
        }
        Ok(response)
    }

    /// Verify the posted pair, then return the request that should replace custody.
    fn verified_updated_request(
        &self,
        stored: &Value,
        object: &Map<String, Value>,
        owner: &str,
        now: i64,
    ) -> Result<Value, Failure> {
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
        if let Some(justification) = object.get("justification")
            && justification
                .as_str()
                .is_none_or(|text| text.is_empty() || text.len() > 65536)
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let mut candidate = stored.clone();
        candidate["resource_token"] = json!(resource_token);
        candidate["presented_token"] = json!(presented_token);
        let (context, _) = self.authorize_body(&candidate, owner, now)?;
        let original = ResourceToken::parse(required(stored, "resource_token")?)
            .and_then(|token| token.verify(&self.resolver(), now))
            .map_err(|_| Failure::internal())?;
        if !same_updated_resource(original.claims(), context.resource.claims()) {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        Ok(candidate)
    }
}
fn same_updated_resource(left: &ResourceClaims, right: &ResourceClaims) -> bool {
    left.iss == right.iss
        && left.ps == right.ps
        && left.sub == right.sub
        && left.agent_jkt == right.agent_jkt
        && left.mission_s256 == right.mission_s256
        && left.tenant == right.tenant
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn number(value: &Value, name: &str) -> Result<i64, Failure> {
    value[name].as_i64().ok_or_else(Failure::internal)
}
fn pending_expired(value: &Value, now: i64) -> Result<bool, Failure> {
    Ok(now >= number(value, "deadline")?
        || value["question_deadline"]
            .as_i64()
            .is_some_and(|at| now >= at))
}
fn question_deadline(pending: &PendingResponse, now: i64) -> Option<i64> {
    match pending.requirement {
        Requirement::Clarification {
            timeout: Some(s), ..
        } => Some(now.saturating_add(i64::try_from(s).unwrap_or(i64::MAX))),
        _ => None,
    }
}
fn throttled(retry_after: u64) -> Response<Vec<u8>> {
    let mut r = wire::json_response(StatusCode::TOO_MANY_REQUESTS, json!({"error":"slow_down"}));
    r.headers_mut().insert(
        "retry-after",
        retry_after.max(1).to_string().parse().unwrap(),
    );
    r.headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    r
}

/// A policy emits only the interaction code this AS drew for the request.
fn drawn_code(requirement: &Requirement, drawn: &str) -> Result<(), Failure> {
    match requirement {
        Requirement::Interaction { code, .. } if code != drawn => Err(Failure::internal()),
        _ => Ok(()),
    }
}
fn same_question(left: &Requirement, right: &Requirement) -> bool {
    matches!((left,right), (Requirement::Clarification{question:a,options:ao,..}, Requirement::Clarification{question:b,options:bo,..}) if a==b && ao==bo)
}
fn pending_wire(
    pending: &PendingResponse,
    value: &Value,
    now: i64,
) -> Result<Response<Vec<u8>>, Failure> {
    let mut pending = pending.clone();
    if let Some(at) = value["question_deadline"].as_i64() {
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
