use super::*;
use aauth_rust_core::continuation::{ContinuationStore, PendingResponse, Requirement};
use serde_json::Map;
use std::sync::Arc;

/// Explicit bounded AS continuation configuration. Use a separate role-local
/// store; hosts supply durable custody if process restart recovery is required.
pub struct DeferredConfig {
    /// Atomic pending store; records contain exact compact request credentials.
    pub store: Arc<dyn ContinuationStore>,
    /// Maximum pending lifetime in seconds,1..=3600; parents and challenge cap it.
    pub lifetime: i64,
    /// Required GET polling interval in seconds,0..=3600; default five.
    pub retry_after: u64,
}
impl DeferredConfig {
    /// Use host custody with a300-second lifetime and five-second GET interval.
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
        };
        let Some(requirement) = (d.policy)(&input).map_err(Failure::policy)? else {
            return self.issue(input.authorization, presented);
        };
        let deadline = now
            .saturating_add(d.config.lifetime)
            .min(input.authorization.agent.claims().exp)
            .min(input.authorization.resource.claims().exp)
            .min(presented.exp);
        let released = (self.clock)();
        current(
            released,
            &input.authorization.agent,
            input.authorization.resource.claims(),
            &presented,
        )?;
        if released >= deadline {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let id = (self.ids)();
        if !safe_id(&id) {
            return Err(Failure::internal());
        }
        let location = format!("{}/token/pending/{id}", self.config.signed_origin);
        let pending = PendingResponse::new(
            &self.config.signed_origin,
            &location,
            d.config.retry_after,
            requirement,
        )
        .map_err(|_| Failure::internal())?;
        let value = json!({"state":"waiting","request":body,"person_server":input.authorization.person_server,"deadline":deadline,"next":released.saturating_add(d.config.retry_after as i64),"claims":{},"clarifications":[],"rounds":usize::from(matches!(pending.requirement,Requirement::Clarification{..})),"question_deadline":question_deadline(&pending,released),"pending":pending});
        d.config
            .store
            .insert(&id, value)
            .map_err(|_| Failure::internal())?;
        pending.response().map_err(|_| Failure::internal())
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
            return Err(Failure::status(StatusCode::FORBIDDEN, "denied"));
        }
        let expired = now >= number(&value, "deadline")?
            || value["question_deadline"]
                .as_i64()
                .is_some_and(|at| now >= at);
        if expired || request.method() == "DELETE" {
            if !d
                .config
                .store
                .replace(id, snapshot.revision, None)
                .map_err(|_| Failure::internal())?
            {
                return Ok(throttled());
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
        if value["state"] != "waiting" || (!post && now < number(&value, "next")?) {
            return Ok(throttled());
        }
        let previous: PendingResponse =
            serde_json::from_value(value["pending"].clone()).map_err(|_| Failure::internal())?;
        let answered = if post {
            let body =
                strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
            let object = body
                .as_object()
                .ok_or_else(|| Failure::parameter("invalid_request"))?;
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
        value["state"] = json!("busy");
        if !d
            .config
            .store
            .replace(id, snapshot.revision, Some(value.clone()))
            .map_err(|_| Failure::internal())?
        {
            return Ok(throttled());
        }
        let result = (|| {
            let (context, presented) = self.authorize_body(&value["request"], &owner, now)?;
            let input = DeferredContext {
                authorization: context,
                claims: serde_json::from_value(value["claims"].clone())
                    .map_err(|_| Failure::internal())?,
                clarifications: serde_json::from_value(value["clarifications"].clone())
                    .map_err(|_| Failure::internal())?,
            };
            let requirement = (d.policy)(&input).map_err(|e| match e {
                PolicyError::Denied => Failure::status(StatusCode::FORBIDDEN, "denied"),
                _ => Failure::policy(e),
            })?;
            match requirement {
                None => self.issue(input.authorization, presented),
                Some(requirement) => {
                    let pending = PendingResponse::new(
                        &self.config.signed_origin,
                        &previous.location,
                        d.config.retry_after,
                        requirement,
                    )
                    .map_err(|_| Failure::internal())?;
                    let current = (self.clock)();
                    if current >= number(&value, "deadline")? {
                        return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
                    }
                    if matches!(pending.requirement, Requirement::Clarification { .. })
                        && (answered || pending.requirement != previous.requirement)
                    {
                        value["rounds"] = json!(number(&value, "rounds")? + 1);
                    }
                    if number(&value, "rounds")? > 5 {
                        return Err(Failure::status(StatusCode::FORBIDDEN, "denied"));
                    }
                    value["state"] = json!("waiting");
                    value["next"] = json!(current.saturating_add(d.config.retry_after as i64));
                    value["question_deadline"] = json!(question_deadline(&pending, current));
                    value["pending"] =
                        serde_json::to_value(&pending).map_err(|_| Failure::internal())?;
                    pending.response().map_err(|_| Failure::internal())
                }
            }
        })();
        let held = d
            .config
            .store
            .load(id)
            .map_err(|_| Failure::internal())?
            .ok_or_else(Failure::internal)?;
        if held.value["state"] != "busy" {
            return Err(Failure::internal());
        }
        let waiting = result.as_ref().is_ok_and(|r| {
            [StatusCode::ACCEPTED, StatusCode::PAYMENT_REQUIRED].contains(&r.status())
        });
        if !d
            .config
            .store
            .replace(id, held.revision, if waiting { Some(value) } else { None })
            .map_err(|_| Failure::internal())?
        {
            return Err(Failure::internal());
        }
        result
    }
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
fn question_deadline(pending: &PendingResponse, now: i64) -> Option<i64> {
    match pending.requirement {
        Requirement::Clarification {
            timeout: Some(s), ..
        } => Some(now.saturating_add(i64::try_from(s).unwrap_or(i64::MAX))),
        _ => None,
    }
}
fn throttled() -> Response<Vec<u8>> {
    let mut r = wire::json_response(StatusCode::TOO_MANY_REQUESTS, json!({"error":"slow_down"}));
    r.headers_mut().insert("retry-after", "1".parse().unwrap());
    r.headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    r
}
