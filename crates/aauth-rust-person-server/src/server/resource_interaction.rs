//! Resource-initiated interaction on the direct `/token` path
//! (`draft-hardt-oauth-aauth-protocol`, Resource-Initiated Interaction,
//! Interaction Callback Errors and Interaction Code Format).
//!
//! A resource token that carries an `interaction` claim needs the resource's
//! own user-facing flow before this Person Server consents. The flow is:
//!
//! 1. `/token` answers `202` with this server's interaction URL and code, and
//!    a pending URL the agent polls.
//! 2. The person arrives at that URL. After the host authenticates them and
//!    shows its interstitial, [`PersonServer::redirect_to_resource`] checks
//!    the code and sends the browser to
//!    `{interaction.url}?code={interaction.code}&callback={ps_callback_url}`.
//! 3. The resource redirects back to the per-flow callback URL.
//!    [`PersonServer::resource_interaction_callback`] reads it: an `error`
//!    ends the request with the mapped polling error, and its absence moves
//!    on to this server's consent.
//! 4. [`PersonServer::decide_resource_interaction`] records the person's
//!    consent decision and, on approval, issues the Auth token through host
//!    policy. The agent's next poll receives the token or the error once.
//!
//! For an agent routed to a supervision server, the server's decision comes
//! before step 1 and stands in for step 4 (`draft-hardt-aauth-supervision`:
//! the PS makes no supervision decision of its own). The callback of step 3
//! issues the Auth token within the allowance, and the host shows no consent.
use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, PendingResponse, Requirement, canonical_interaction_code,
    generate_interaction_code, generate_pending_id,
};
use aauth_rust_core::interaction::{
    CallbackError, CallbackReceipt, InteractionOutcome, ResourceInteraction, completion_redirect,
    parse_interaction_query, person_server_redirect, receive_callback,
};
use aauth_rust_core::supervision::Decision;
use std::sync::Arc;

/// Failed code presentations after which the pending interaction is dead.
const FAILURE_LIMIT: u64 = 3;

/// Host egress admission for a resource's interaction URL.
pub type BoxedEgress = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Opt-in resource-initiated interaction for direct, three-party `/token`.
pub struct ResourceInteractionConfig {
    /// Custody for pending token requests and their callback index. Use a
    /// store of its own; process restart durability needs a host adapter.
    pub store: Arc<dyn ContinuationStore>,
    /// HTTPS base of this server's own interaction page, without a query or
    /// fragment. The agent sends the person to `{interaction_base}/{id}`
    /// with `?code=`, where `id` is drawn per request.
    pub interaction_base: String,
    /// HTTPS base of the callback the resource returns the browser to,
    /// without a query or fragment. Each flow gets `{callback_base}/{flow}`
    /// with a fresh 128-bit `flow` that the agent never sees.
    pub callback_base: String,
    /// The host's egress admission for a resource's `interaction.url`,
    /// applied before the person is redirected there. `false` refuses.
    pub admit: BoxedEgress,
    /// Maximum waiting lifetime in seconds, 1..=3600, also capped by the
    /// agent, resource and presented tokens. Default 300.
    pub lifetime: i64,
    /// Agent poll interval in seconds, 0..=3600. Default 5.
    pub retry_after: u64,
}

impl ResourceInteractionConfig {
    /// Configure custody, the two HTTPS bases and egress admission, with a
    /// 300-second lifetime and five-second polling.
    pub fn new(
        store: impl ContinuationStore + 'static,
        interaction_base: &str,
        callback_base: &str,
        admit: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            store: Arc::new(store),
            interaction_base: interaction_base.into(),
            callback_base: callback_base.into(),
            admit: Box::new(admit),
            lifetime: 300,
            retry_after: 5,
        }
    }
}

/// A resource-interaction step the host asked for could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResourceInteractionError {
    /// [`PersonServer::with_resource_interaction`] was not called.
    #[error("resource interaction is not enabled")]
    Disabled,
    /// Unknown, consumed or dead code or flow. Answer the browser `410`
    /// `invalid_code`.
    #[error("interaction code not recognized or already consumed")]
    InvalidCode,
    /// The pending request expired. Answer the browser `408` `expired`.
    #[error("pending interaction expired")]
    Expired,
    /// The request is not at this step, or another step changed it first.
    #[error("pending interaction is not at this step")]
    NotReady,
    /// The resource's interaction URL is not HTTPS or the host refused egress
    /// to it. The agent's request ends with `server_error`.
    #[error("resource interaction URL was refused")]
    Refused,
    /// Custody could not be read or written.
    #[error("resource interaction custody is unavailable")]
    Unavailable,
}

/// What the person sees on this server's interstitial before the redirect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingResourceInteraction {
    /// The resource that needs its own flow, from the resource token's `iss`.
    pub resource: String,
    /// The agent that asked, from its agent token's `sub`.
    pub agent: String,
    /// Requested scopes, as the resource token names them.
    pub scopes: Vec<String>,
    /// The agent's `justification`, when it sent one. Agent-asserted Markdown:
    /// sanitize it and present it as the agent's claim.
    pub justification: Option<String>,
    /// The agent's supervision server already allowed the request. Show the
    /// interstitial, but no consent of this server's: the callback issues.
    pub supervised: bool,
}

/// How the resource's flow ended, read from its callback.
#[derive(Debug)]
pub enum ResourceInteractionCallback {
    /// No `error`: show this server's consent and then call
    /// [`PersonServer::decide_resource_interaction`] with `id`.
    Consent {
        /// The pending request, for the decision.
        id: String,
    },
    /// No `error`, for a supervised agent: the request is finished within
    /// its supervision server's allowance, with no consent of the host's. The
    /// agent's next poll receives the Auth token, or the refusal if issuance
    /// failed. `redirect` returns the browser to the agent's own callback,
    /// with `error` when no token was issued, when it sent one.
    Completed {
        /// Redirect to the agent's callback, when present.
        redirect: Option<Response<Vec<u8>>>,
    },
    /// The callback carried `error`. The request is not completable; the
    /// agent's next poll receives `polling_error`. `redirect` returns the
    /// browser to the agent's own callback with the error, when it sent one.
    Failed {
        /// `denied`, `abandoned`, `expired` or `server_error`.
        polling_error: &'static str,
        /// Redirect to the agent's callback, when present.
        redirect: Option<Response<Vec<u8>>>,
    },
}

pub(super) struct Gate {
    config: ResourceInteractionConfig,
}

fn pending_key(id: &str) -> String {
    format!("pending.{id}")
}
fn callback_key(flow: &str) -> String {
    format!("callback.{flow}")
}

fn https_base(value: &str) -> bool {
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.host().is_some()
        && uri.query().is_none()
        && !value.contains('#')
        && !value.ends_with('/')
        && uri
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@'))
}

fn number(value: &Value, name: &str) -> Result<i64, ResourceInteractionError> {
    value[name]
        .as_i64()
        .ok_or(ResourceInteractionError::Unavailable)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, ResourceInteractionError> {
    value[name]
        .as_str()
        .ok_or(ResourceInteractionError::Unavailable)
}

/// The stored terminal response for the agent.
fn outcome(response: &Response<Vec<u8>>) -> Value {
    let body: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    json!({"status": response.status().as_u16(), "body": body})
}

fn polling_failure(polling_error: &str) -> Value {
    let status = match polling_error {
        "expired" => StatusCode::REQUEST_TIMEOUT,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        "invalid_code" => StatusCode::GONE,
        _ => StatusCode::FORBIDDEN,
    };
    outcome(&Failure::status(status, polling_error).response())
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Accept resource tokens that carry an `interaction` claim on direct
    /// `/token` requests, and run the resource's flow before this server's
    /// consent (`draft-hardt-oauth-aauth-protocol`, Resource-Initiated
    /// Interaction).
    ///
    /// The agent must declare `interaction` in the request's `capabilities`
    /// parameter, since this server reaches the person only through the agent;
    /// otherwise the answer is `403` `user_unreachable`. For an agent routed
    /// to a supervision server ([`Self::with_supervision`]), the request is
    /// put to that server first: a deny refuses it before the person is sent
    /// anywhere, a held act's pending URL relays this flow once allowed, and
    /// the callback issues within the allowance. Such a request is
    /// answered `202` with `requirement=interaction`, this server's
    /// interaction URL and a fresh code, and a pending URL under
    /// `/token/interaction/`. The flow refuses call chaining, sub-agents and
    /// budget offers with `invalid_request`. With AS federation the claim is
    /// still refused as `invalid_resource_token`, and an R3 resource token
    /// never carries it here.
    ///
    /// # Errors
    /// [`ConfigurationError`] for a base that is not an HTTPS URL without a
    /// query, fragment or trailing slash, or a lifetime or interval outside
    /// its range.
    pub fn with_resource_interaction(
        mut self,
        config: ResourceInteractionConfig,
    ) -> Result<Self, ConfigurationError> {
        if !https_base(&config.interaction_base)
            || !https_base(&config.callback_base)
            || !(1..=3600).contains(&config.lifetime)
            || config.retry_after > 3600
        {
            return Err(ConfigurationError);
        }
        self.resource_interaction = Some(Gate { config });
        Ok(self)
    }

    /// Whether `/token` reads the `interaction` claim on this server.
    pub(super) fn resource_interaction_enabled(&self) -> bool {
        self.resource_interaction.is_some() && self.federation.is_none()
    }

    fn interaction_gate(&self) -> Result<&Gate, ResourceInteractionError> {
        self.resource_interaction
            .as_ref()
            .ok_or(ResourceInteractionError::Disabled)
    }

    /// The agent declared it can send the person to an interaction URL.
    pub(super) fn declared_interaction(parameters: &Value) -> Result<(), Failure> {
        let declared = parameters
            .get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value == "interaction"));
        if declared {
            Ok(())
        } else {
            Err(Failure::policy(PolicyError::UserUnreachable))
        }
    }

    /// Step 1: custody for a verified request and its `202`. `supervision` is
    /// the allowance of the agent's supervision server, when it has one.
    pub(super) fn open_resource_interaction(
        &self,
        agent: &VerifiedAgentToken,
        prepared: &PreparedAuthorization,
        interaction: ResourceInteraction,
        supervision: Option<Resumed>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let gate = self
            .resource_interaction
            .as_ref()
            .ok_or_else(Failure::internal)?;
        let parameters = &prepared.context.parameters;
        Self::declared_interaction(parameters)?;
        let supervision = match supervision {
            Some(Resumed { sdi, allowance }) => {
                json!({"sdi": sdi, "allowance": Decision::Allow(allowance).to_value(&sdi)})
            }
            None => Value::Null,
        };
        let now = (self.clock)();
        let deadline = now
            .saturating_add(gate.config.lifetime)
            .min(agent.claims().exp)
            .min(prepared.resource.claims().exp)
            .min(prepared.presented.exp);
        if now >= deadline {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let id = generate_pending_id();
        let flow = generate_pending_id();
        let code = generate_interaction_code();
        let value = json!({
            "state": "waiting",
            "agent_token": agent.compact(),
            "parameters": parameters,
            "deadline": deadline,
            "code": code,
            "failures": 0,
            "callback": flow,
            "agent_callback": null,
            "resource_url": interaction.url(),
            "resource_code": interaction.code(),
            "supervision": supervision,
            "result": null,
        });
        let store = &gate.config.store;
        store
            .insert(&callback_key(&flow), json!({"pending": id}))
            .map_err(|_| Failure::internal())?;
        store
            .insert(&pending_key(&id), value)
            .map_err(|_| Failure::internal())?;
        self.pending_interaction_wire(gate, &id, &code)
    }

    fn pending_interaction_wire(
        &self,
        gate: &Gate,
        id: &str,
        code: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        PendingResponse::new(
            &self.config.signed_origin,
            &format!("{}/token/interaction/{id}", self.config.signed_origin),
            gate.config.retry_after,
            Requirement::Interaction {
                url: format!("{}/{id}", gate.config.interaction_base),
                code: code.to_owned(),
            },
        )
        .and_then(|pending| pending.response())
        .map_err(|_| Failure::internal())
    }

    /// The agent's signed GET of `/token/interaction/{id}`.
    pub(super) fn resource_interaction_poll(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        if request.method() != "GET" || request.uri().query().is_some() {
            return Err(Failure::parameter("invalid_request"));
        }
        let caller = self.verify_agent(request, now, false)?;
        let id = request
            .uri()
            .path()
            .strip_prefix("/token/interaction/")
            .ok_or_else(gone)?;
        self.resource_interaction_poll_at(&caller, id, now)
    }

    /// A poll of the pending interaction `id` by `caller`, at its own URL or
    /// relayed from a supervised act's pending URL.
    pub(super) fn resource_interaction_poll_at(
        &self,
        caller: &VerifiedAgentToken,
        id: &str,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let gate = self
            .resource_interaction
            .as_ref()
            .ok_or_else(Failure::internal)?;
        if id.is_empty() || id.len() > 64 || id.contains('/') {
            return Err(gone());
        }
        let store = &gate.config.store;
        let snapshot = store
            .load(&pending_key(id))
            .map_err(|_| Failure::internal())?
            .ok_or_else(gone)?;
        let value = snapshot.value;
        let original = AgentToken::parse(required_string(&value, "agent_token")?)
            .map_err(Failure::credential)?;
        let original = original.unverified_claims();
        if caller.claims().iss != original.iss
            || caller.claims().sub != original.sub
            || caller.claims().cnf.jwk.thumbprint().ok() != original.cnf.jwk.thumbprint().ok()
        {
            return Err(Failure::status(StatusCode::FORBIDDEN, "wrong_poller"));
        }
        let finish = |result: Value| -> Result<Response<Vec<u8>>, Failure> {
            if !store
                .replace(&pending_key(id), snapshot.revision, None)
                .map_err(|_| Failure::internal())?
            {
                return Err(gone());
            }
            if let Some(flow) = value["callback"].as_str() {
                let _ = remove(store.as_ref(), &callback_key(flow));
            }
            let status = result["status"]
                .as_u64()
                .and_then(|status| StatusCode::from_u16(status as u16).ok())
                .ok_or_else(Failure::internal)?;
            let mut body = result["body"].clone();
            if status == StatusCode::OK {
                let expires_at = body["expires_at"].as_i64().ok_or_else(Failure::internal)?;
                if expires_at <= now {
                    return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
                }
                let compact = body["auth_token"]
                    .as_str()
                    .ok_or_else(Failure::internal)?
                    .to_owned();
                return Ok(token_response("auth_token", compact, expires_at - now));
            }
            if let Some(object) = body.as_object_mut() {
                object.remove("expires_at");
            }
            let mut response = json_response(status, body);
            response.headers_mut().insert(
                "content-type",
                "application/problem+json"
                    .parse()
                    .expect("static content type"),
            );
            Ok(response)
        };
        if !value["result"].is_null() {
            return finish(value["result"].clone());
        }
        if now >= number(&value, "deadline").map_err(|_| Failure::internal())? {
            return finish(polling_failure("expired"));
        }
        if value["state"] == "waiting" {
            let code = required_string(&value, "code")?;
            return self.pending_interaction_wire(gate, id, code);
        }
        // The person has arrived; the agent stops prompting them.
        let mut pending = PendingResponse::new(
            &self.config.signed_origin,
            &format!("{}/token/interaction/{id}", self.config.signed_origin),
            gate.config.retry_after,
            Requirement::Waiting,
        )
        .map_err(|_| Failure::internal())?;
        pending.body = json!({"status":"interacting"});
        pending.response().map_err(|_| Failure::internal())
    }

    /// Step 2, for the interstitial: what the pending request at
    /// `{interaction_base}/{id}` asks for. Reading it changes nothing.
    ///
    /// # Errors
    /// [`ResourceInteractionError::InvalidCode`] for an unknown or finished
    /// request, and [`ResourceInteractionError::Expired`] after its deadline.
    pub fn resource_interaction(
        &self,
        id: &str,
    ) -> Result<PendingResourceInteraction, ResourceInteractionError> {
        let gate = self.interaction_gate()?;
        let snapshot = gate
            .config
            .store
            .load(&pending_key(id))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::InvalidCode)?;
        let value = snapshot.value;
        if !value["result"].is_null() {
            return Err(ResourceInteractionError::InvalidCode);
        }
        if (self.clock)() >= number(&value, "deadline")? {
            return Err(ResourceInteractionError::Expired);
        }
        let agent = AgentToken::parse(text(&value, "agent_token")?)
            .map_err(|_| ResourceInteractionError::Unavailable)?;
        let resource = ResourceToken::parse(text(&value["parameters"], "resource_token")?)
            .map_err(|_| ResourceInteractionError::Unavailable)?;
        let claims = resource.unverified_claims();
        Ok(PendingResourceInteraction {
            resource: claims.iss.clone(),
            agent: agent.unverified_claims().sub.clone(),
            scopes: claims
                .scope
                .as_deref()
                .map(|scope| scope.split(' ').map(str::to_owned).collect())
                .unwrap_or_default(),
            justification: value["parameters"]["justification"]
                .as_str()
                .map(str::to_owned),
            supervised: !value["supervision"].is_null(),
        })
    }

    /// Step 2: the person arrived at `{interaction_base}/{id}` with `query`,
    /// the query string without its leading `?`.
    ///
    /// Call it only after the host has authenticated the person and shown the
    /// interstitial explaining that the resource requires additional
    /// permissions. `query` carries `code` and, when the agent has a browser,
    /// its own `callback`. A matching code is consumed. The resource's
    /// interaction URL is then checked to be HTTPS and passed to the host's
    /// egress admission before the `302` to
    /// `{interaction.url}?code={interaction.code}&callback={ps_callback_url}`
    /// is built. Codes compare without hyphens or case and with Crockford
    /// aliases folded. Three mismatches end the request: the agent's next poll
    /// is `410` `invalid_code`.
    ///
    /// # Errors
    /// [`ResourceInteractionError::InvalidCode`] for a missing, wrong,
    /// consumed or dead code, or a malformed query.
    /// [`ResourceInteractionError::Expired`] after the deadline.
    /// [`ResourceInteractionError::Refused`] when the URL is refused; the
    /// agent then receives `server_error`.
    pub fn redirect_to_resource(
        &self,
        id: &str,
        query: &str,
    ) -> Result<Response<Vec<u8>>, ResourceInteractionError> {
        let gate = self.interaction_gate()?;
        let store = &gate.config.store;
        let snapshot = store
            .load(&pending_key(id))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::InvalidCode)?;
        let mut value = snapshot.value;
        if !value["result"].is_null() || value["state"] != "waiting" {
            return Err(ResourceInteractionError::InvalidCode);
        }
        let now = (self.clock)();
        if now >= number(&value, "deadline")? {
            value["result"] = polling_failure("expired");
            update(store.as_ref(), id, snapshot.revision, value)?;
            return Err(ResourceInteractionError::Expired);
        }
        let expected = canonical_interaction_code(text(&value, "code")?);
        let presented = parse_interaction_query(query).ok().filter(|parsed| {
            expected.is_some() && canonical_interaction_code(&parsed.code) == expected
        });
        let Some(parsed) = presented else {
            let failures = value["failures"].as_u64().unwrap_or(FAILURE_LIMIT) + 1;
            value["failures"] = json!(failures);
            if failures >= FAILURE_LIMIT {
                value["result"] = polling_failure("invalid_code");
            }
            update(store.as_ref(), id, snapshot.revision, value)?;
            return Err(ResourceInteractionError::InvalidCode);
        };
        let url = text(&value, "resource_url")?.to_owned();
        let resource_code = text(&value, "resource_code")?.to_owned();
        let callback = format!(
            "{}/{}",
            gate.config.callback_base,
            text(&value, "callback")?
        );
        let admitted = (gate.config.admit)(&url);
        let redirect = person_server_redirect(&url, &resource_code, &callback, admitted);
        value["agent_callback"] = json!(parsed.callback);
        match redirect {
            Ok(response) => {
                value["state"] = json!("interacting");
                update(store.as_ref(), id, snapshot.revision, value)?;
                Ok(response)
            }
            Err(_) => {
                value["result"] = polling_failure("server_error");
                update(store.as_ref(), id, snapshot.revision, value)?;
                Err(ResourceInteractionError::Refused)
            }
        }
    }

    /// Step 3: the resource returned the browser to `{callback_base}/{flow}`
    /// with `query`, the query string without its leading `?`, if any.
    ///
    /// A callback with an `error` parameter is never completable: the pending
    /// request ends, and the agent's next poll receives the mapped polling
    /// error (`access_denied` as `denied`, `user_abandoned` as `abandoned`,
    /// `interaction_expired` as `expired`, `server_error` and
    /// `temporarily_unavailable` as `server_error`). Without `error`, the
    /// request moves on to this server's consent.
    ///
    /// # Errors
    /// [`ResourceInteractionError::InvalidCode`] for an unknown or used flow,
    /// [`ResourceInteractionError::NotReady`] before the redirect, and
    /// [`ResourceInteractionError::Expired`] after the deadline.
    pub fn resource_interaction_callback(
        &self,
        flow: &str,
        query: Option<&str>,
    ) -> Result<ResourceInteractionCallback, ResourceInteractionError> {
        let gate = self.interaction_gate()?;
        let store = &gate.config.store;
        let index = store
            .load(&callback_key(flow))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::InvalidCode)?;
        let id = text(&index.value, "pending")?.to_owned();
        let snapshot = store
            .load(&pending_key(&id))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::InvalidCode)?;
        let mut value = snapshot.value;
        if !value["result"].is_null() || value["callback"] != flow {
            return Err(ResourceInteractionError::InvalidCode);
        }
        if value["state"] != "interacting" {
            return Err(ResourceInteractionError::NotReady);
        }
        if (self.clock)() >= number(&value, "deadline")? {
            value["result"] = polling_failure("expired");
            update(store.as_ref(), &id, snapshot.revision, value)?;
            return Err(ResourceInteractionError::Expired);
        }
        match receive_callback(query) {
            CallbackReceipt::Continue if !value["supervision"].is_null() => {
                // The supervision server's allow was this request's decision.
                let redirect = self.settle(store.as_ref(), &id, snapshot.revision, value, true)?;
                Ok(ResourceInteractionCallback::Completed { redirect })
            }
            CallbackReceipt::Continue => {
                value["state"] = json!("consenting");
                update(store.as_ref(), &id, snapshot.revision, value)?;
                Ok(ResourceInteractionCallback::Consent { id })
            }
            CallbackReceipt::Abandoned { polling_error } => {
                value["result"] = polling_failure(polling_error);
                let redirect = agent_redirect(&value, Some(callback_error(polling_error)));
                update(store.as_ref(), &id, snapshot.revision, value)?;
                Ok(ResourceInteractionCallback::Failed {
                    polling_error,
                    redirect,
                })
            }
        }
    }

    /// Step 4: the person's consent decision after the resource's flow.
    ///
    /// The host authenticates the person and records `approved` only from
    /// them. A denial ends the request with `denied`. An approval re-verifies
    /// the stored agent, resource and presented tokens at the current time
    /// and then runs [`Policy::authorize`] and issuance exactly as an
    /// immediate `/token` request does; its result, a token or a refusal, is
    /// what the agent's next poll receives once. The returned redirect sends
    /// the browser to the agent's own callback, with `error` when the request
    /// did not complete, if the agent sent one.
    ///
    /// A supervised agent's request never waits here: its callback issues.
    ///
    /// # Errors
    /// [`ResourceInteractionError::InvalidCode`] for an unknown or finished
    /// request, [`ResourceInteractionError::NotReady`] before the resource's
    /// callback, and [`ResourceInteractionError::Expired`] after the deadline.
    pub fn decide_resource_interaction(
        &self,
        id: &str,
        approved: bool,
    ) -> Result<Option<Response<Vec<u8>>>, ResourceInteractionError> {
        let gate = self.interaction_gate()?;
        let store = &gate.config.store;
        let snapshot = store
            .load(&pending_key(id))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::InvalidCode)?;
        let mut value = snapshot.value;
        if !value["result"].is_null() {
            return Err(ResourceInteractionError::InvalidCode);
        }
        if value["state"] != "consenting" {
            return Err(ResourceInteractionError::NotReady);
        }
        if (self.clock)() >= number(&value, "deadline")? {
            value["result"] = polling_failure("expired");
            update(store.as_ref(), id, snapshot.revision, value)?;
            return Err(ResourceInteractionError::Expired);
        }
        self.settle(store.as_ref(), id, snapshot.revision, value, approved)
    }

    /// Decide the request at `revision`: issue on `approved`, else `denied`.
    /// The result is kept for the agent's next poll, and the redirect to the
    /// agent's own callback is returned.
    fn settle(
        &self,
        store: &dyn ContinuationStore,
        id: &str,
        revision: u64,
        mut value: Value,
        approved: bool,
    ) -> Result<Option<Response<Vec<u8>>>, ResourceInteractionError> {
        let now = (self.clock)();
        // Claim the request before policy and issuance, so a concurrent
        // decision cannot issue a second token.
        value["state"] = json!("deciding");
        update(store, id, revision, value.clone())?;
        let revision = store
            .load(&pending_key(id))
            .map_err(|_| ResourceInteractionError::Unavailable)?
            .ok_or(ResourceInteractionError::Unavailable)?
            .revision;
        let result = if approved {
            match self.issue_after_interaction(&value, now) {
                Ok(response) => {
                    let mut stored = outcome(&response);
                    let auth = stored["body"]["auth_token"]
                        .as_str()
                        .and_then(|compact| AuthToken::parse(compact).ok())
                        .map(|token| token.unverified_claims().exp);
                    match auth {
                        Some(exp) => {
                            stored["body"]["expires_at"] = json!(exp);
                            stored
                        }
                        None => polling_failure("server_error"),
                    }
                }
                Err(failure) => outcome(&failure.response()),
            }
        } else {
            polling_failure("denied")
        };
        let error = (result["status"] != 200)
            .then(|| callback_error(result["body"]["error"].as_str().unwrap_or("")));
        value["state"] = json!("decided");
        value["result"] = result;
        let redirect = agent_redirect(&value, error);
        update(store, id, revision, value)?;
        Ok(redirect)
    }

    fn issue_after_interaction(
        &self,
        value: &Value,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = AgentToken::parse(required_string(value, "agent_token")?)
            .and_then(|token| token.verify(&self.resolver(), now))
            .map_err(Failure::credential)?;
        let prepared =
            self.prepare_authorization(&agent, value["parameters"].clone(), now, None)?;
        let resumed = match &value["supervision"] {
            Value::Null => None,
            supervision => {
                let sdi = required_string(supervision, "sdi")?.to_owned();
                let Ok(Decision::Allow(allowance)) =
                    Decision::parse(&supervision["allowance"], &sdi, Act::AuthToken)
                else {
                    return Err(Failure::internal());
                };
                Some(Resumed { sdi, allowance })
            }
        };
        self.grant_auth(&agent, prepared, resumed.as_ref())
    }

    /// End the pending interaction `id` for an agent that withdrew its
    /// request. Later polls of it are `410`.
    pub(super) fn cancel_resource_interaction(&self, id: &str) -> Result<(), Failure> {
        let gate = self
            .resource_interaction
            .as_ref()
            .ok_or_else(Failure::internal)?;
        let store = gate.config.store.as_ref();
        if let Some(snapshot) = store
            .load(&pending_key(id))
            .map_err(|_| Failure::internal())?
        {
            if let Some(flow) = snapshot.value["callback"].as_str() {
                let _ = remove(store, &callback_key(flow));
            }
            store
                .replace(&pending_key(id), snapshot.revision, None)
                .map_err(|_| Failure::internal())?;
        }
        Ok(())
    }
}

fn gone() -> Failure {
    Failure::status(StatusCode::GONE, "gone")
}

/// The pending interaction id of a `202` that opened a resource's flow.
pub(super) fn interaction_reference(origin: &str, response: &Response<Vec<u8>>) -> Option<String> {
    if response.status() != StatusCode::ACCEPTED {
        return None;
    }
    let location = response.headers().get("location")?.to_str().ok()?;
    location
        .strip_prefix(&format!("{origin}/token/interaction/"))
        .map(str::to_owned)
}

fn update(
    store: &dyn ContinuationStore,
    id: &str,
    revision: u64,
    value: Value,
) -> Result<(), ResourceInteractionError> {
    match store.replace(&pending_key(id), revision, Some(value)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ResourceInteractionError::NotReady),
        Err(_) => Err(ResourceInteractionError::Unavailable),
    }
}

fn remove(store: &dyn ContinuationStore, key: &str) -> Result<(), ()> {
    let snapshot = store.load(key).map_err(|_| ())?.ok_or(())?;
    store
        .replace(key, snapshot.revision, None)
        .map(|_| ())
        .map_err(|_| ())
}

/// The callback `error` for a request that ended with `code`.
fn callback_error(code: &str) -> CallbackError {
    match code {
        "access_denied" => CallbackError::AccessDenied,
        other => CallbackError::from_polling_error(other).unwrap_or(CallbackError::ServerError),
    }
}

/// The browser's return to the agent's own callback, with `error` when the
/// request did not complete.
fn agent_redirect(value: &Value, error: Option<CallbackError>) -> Option<Response<Vec<u8>>> {
    let callback = value["agent_callback"].as_str()?;
    let outcome = match error {
        None => InteractionOutcome::Completed,
        Some(error) => InteractionOutcome::Failed(error),
    };
    completion_redirect(callback, outcome).ok()
}
