use super::*;
use aauth_rust_core::continuation::{
    canonical_interaction_code, generate_interaction_code, generate_pending_id,
};
use aauth_rust_jose::strict_json;
use std::collections::BTreeMap;
use std::sync::Mutex;

const MAX_TEXT: usize = 16_384;
const FAILURE_LIMIT: u8 = 3;

/// Host answer and permission policy for the opt-in person channel.
/// Interaction and payment relays stay unavailable: this library has no user channel.
pub trait Governance: Send + Sync {
    /// Answer a `question` interaction. The string is untrusted Markdown.
    ///
    /// # Errors
    ///
    /// [`crate::PolicyError::UserUnreachable`] and [`crate::PolicyError::Denied`]
    /// are terminal refusals. [`crate::PolicyError::Unavailable`] is `500`.
    fn answer(&self, question: &str) -> Result<String, crate::PolicyError>;
    /// Whether the person allows this action. `Ok(false)` is a denied permission,
    /// not a transport failure.
    ///
    /// # Errors
    ///
    /// [`crate::PolicyError::Unavailable`] is `500`. Denial is `Ok(false)`.
    fn permit(&self, action: &str) -> Result<bool, crate::PolicyError>;
}

/// Opening an interaction code failed before any HTTP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceError {
    /// `with_governance` was not called.
    #[error("governance endpoints are not enabled")]
    Disabled,
    /// The expiry is negative.
    #[error("interaction code cannot be emitted")]
    Code,
    /// The in-memory table could not record the code.
    #[error("interaction code could not be stored")]
    Unavailable,
}

/// An interaction code this server drew, and the pending id that redeems it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedInteraction {
    /// Redemption path segment under `/interaction/pending/`: 128 random bits
    /// from [`aauth_rust_core::continuation::generate_pending_id`].
    pub id: String,
    /// Code for the person: 40 random bits from
    /// [`aauth_rust_core::continuation::generate_interaction_code`].
    pub code: String,
}

pub(super) struct Gate {
    policy: Box<dyn Governance>,
    codes: Mutex<BTreeMap<String, PendingCode>>,
}

struct PendingCode {
    canonical: String,
    expires_at: i64,
    failures: u8,
    consumed: bool,
    dead: bool,
    decision: Option<InteractionDecision>,
}

/// Approve or deny recorded for one consumed interaction code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionDecision {
    /// The person approved.
    Approved,
    /// The person denied.
    Denied,
}

enum Route {
    Interaction,
    Permission,
    Audit,
    Redeem(String),
    Decision(String),
}

fn direct_agent(agent: &aauth_rust_core::VerifiedAgentToken) -> Result<(), Failure> {
    if agent.claims().parent_agent.is_some() {
        Err(Failure::credential(aauth_rust_core::TokenError::InvalidJwt))
    } else {
        Ok(())
    }
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Advertise interaction, permission, and audit, and accept interaction codes.
    ///
    /// Metadata gains the three endpoints only after this call. An agent signs
    /// each POST with `jwt`. A token with `parent_agent` is `401 invalid_jwt`.
    /// `interaction` and `payment` return `424
    /// interaction_unavailable` because this library has no relay channel.
    /// A `question` is answered by `governance`. Permission is immediate.
    /// Audit requires an active mission document from [`crate::Store::read_mission_audit`].
    /// Presented codes are correlated only. A decision requires the Person Server
    /// signature used for mission approval. Codes live in process memory.
    pub fn with_governance(mut self, governance: impl Governance + 'static) -> Self {
        self.governance = Some(Gate {
            policy: Box::new(governance),
            codes: Mutex::new(BTreeMap::new()),
        });
        self
    }

    /// Draw a fresh interaction code and remember it until `expires_at` (Unix
    /// seconds). The code carries 40 bits and the redemption id 128 bits, both
    /// from the operating system's cryptographically secure random source.
    ///
    /// # Errors
    ///
    /// Disabled governance, a negative expiry, or an unusable code table.
    pub fn open_interaction_code(
        &self,
        expires_at: i64,
    ) -> Result<OpenedInteraction, GovernanceError> {
        if expires_at < 0 {
            return Err(GovernanceError::Code);
        }
        let code = generate_interaction_code();
        let canonical = canonical_interaction_code(&code).ok_or(GovernanceError::Code)?;
        let id = generate_pending_id();
        let gate = self.governance.as_ref().ok_or(GovernanceError::Disabled)?;
        let mut codes = gate
            .codes
            .lock()
            .map_err(|_| GovernanceError::Unavailable)?;
        if codes.contains_key(&id) {
            return Err(GovernanceError::Unavailable);
        }
        codes.insert(
            id.clone(),
            PendingCode {
                canonical,
                expires_at,
                failures: 0,
                consumed: false,
                dead: false,
                decision: None,
            },
        );
        Ok(OpenedInteraction { id, code })
    }

    /// Decision stored for `id` after a consumed code was signed as this server.
    ///
    /// `Ok(None)` means the code is unknown or no decision has been stored.
    /// The host that resolves the pending interaction reads this value. Redemption
    /// does not set it.
    ///
    /// # Errors
    ///
    /// [`GovernanceError::Disabled`] when governance is off.
    /// [`GovernanceError::Unavailable`] when the process-memory table cannot be read.
    pub fn recorded_interaction_decision(
        &self,
        id: &str,
    ) -> Result<Option<InteractionDecision>, GovernanceError> {
        let gate = self.governance.as_ref().ok_or(GovernanceError::Disabled)?;
        let codes = gate
            .codes
            .lock()
            .map_err(|_| GovernanceError::Unavailable)?;
        Ok(codes.get(id).and_then(|code| code.decision))
    }

    pub(super) fn route_governance(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Option<Response<Vec<u8>>>, Failure> {
        if self.governance.is_none() {
            return Ok(None);
        }
        let Some(route) = parse_route(request.uri().path()) else {
            return Ok(None);
        };
        if request.method() != "POST" {
            return Ok(None);
        }
        let response = match route {
            Route::Interaction => self.interaction(request, now)?,
            Route::Permission => self.permission(request, now)?,
            Route::Audit => self.audit(request, now)?,
            Route::Redeem(id) => self.redeem(request, now, &id)?,
            Route::Decision(id) => self.decide(request, now, &id)?,
        };
        Ok(Some(response))
    }

    fn interaction(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_request(request, now)?;
        direct_agent(&agent)?;
        let body = json_object(request)?;
        self.mission_if_present(&agent, &body, now)?;
        match body.get("type") {
            Some(Value::String(kind)) if kind == "question" => {
                let question = required_text(&body, "question")?;
                let answer = self
                    .governance_policy()?
                    .answer(&question)
                    .map_err(Failure::policy)?;
                Ok(json_response(StatusCode::OK, json!({ "answer": answer })))
            }
            Some(Value::String(kind)) if kind == "interaction" || kind == "payment" => Err(
                Failure::status(StatusCode::FAILED_DEPENDENCY, "interaction_unavailable"),
            ),
            _ => Err(Failure::parameter("invalid_request")),
        }
    }

    fn permission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_request(request, now)?;
        direct_agent(&agent)?;
        let body = json_object(request)?;
        let action = required_text(&body, "action")?;
        self.mission_if_present(&agent, &body, now)?;
        let granted = self
            .governance_policy()?
            .permit(&action)
            .map_err(Failure::policy)?;
        let permission = if granted { "granted" } else { "denied" };
        Ok(json_response(
            StatusCode::OK,
            json!({ "permission": permission }),
        ))
    }

    fn audit(&self, request: &Request<Vec<u8>>, now: i64) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_request(request, now)?;
        direct_agent(&agent)?;
        let body = json_object(request)?;
        let s256 = required_text(&body, "mission_s256")?;
        let _action = required_text(&body, "action")?;
        self.active_mission(&agent, &s256, now)?;
        let mut response = Response::new(Vec::new());
        *response.status_mut() = StatusCode::CREATED;
        Ok(response)
    }

    fn redeem(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let presented = json_object(request)?.get("code").cloned();
        let mut codes = self.codes()?;
        let Some(code) = codes.get_mut(id) else {
            return Err(invalid_code());
        };
        if now >= code.expires_at {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        if code.dead || code.consumed {
            return Err(invalid_code());
        }
        let matched = presented
            .as_ref()
            .and_then(Value::as_str)
            .and_then(canonical_interaction_code)
            .is_some_and(|value| value == code.canonical);
        if !matched {
            code.failures = code.failures.saturating_add(1);
            if code.failures >= FAILURE_LIMIT {
                code.dead = true;
            }
            return Err(invalid_code());
        }
        code.consumed = true;
        Ok(json_response(StatusCode::OK, json!({ "correlated": true })))
    }

    fn decide(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        self.verify_approver(request, now)?;
        let decision = match json_object(request)?.get("decision") {
            Some(Value::String(value)) if value == "approve" || value == "deny" => value.clone(),
            _ => return Err(Failure::parameter("invalid_request")),
        };
        let mut codes = self.codes()?;
        let Some(code) = codes.get_mut(id) else {
            return Err(invalid_code());
        };
        if now >= code.expires_at {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        if code.dead {
            return Err(invalid_code());
        }
        if !code.consumed || code.decision.is_some() {
            return Err(Failure::parameter("invalid_request"));
        }
        let recorded = if decision == "approve" {
            InteractionDecision::Approved
        } else {
            InteractionDecision::Denied
        };
        code.decision = Some(recorded);
        let word = match recorded {
            InteractionDecision::Approved => "approved",
            InteractionDecision::Denied => "denied",
        };
        Ok(json_response(StatusCode::OK, json!({ "decision": word })))
    }

    fn governance_policy(&self) -> Result<&dyn Governance, Failure> {
        self.governance
            .as_ref()
            .map(|gate| gate.policy.as_ref())
            .ok_or_else(Failure::internal)
    }

    fn codes(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, PendingCode>>, Failure> {
        self.governance
            .as_ref()
            .ok_or_else(Failure::internal)?
            .codes
            .lock()
            .map_err(|_| Failure::internal())
    }

    fn mission_if_present(
        &self,
        agent: &VerifiedAgentToken,
        body: &serde_json::Map<String, Value>,
        now: i64,
    ) -> Result<(), Failure> {
        if let Some(s256) = optional_text(body, "mission_s256")? {
            self.active_mission(agent, &s256, now)?;
        }
        Ok(())
    }

    fn active_mission(
        &self,
        agent: &VerifiedAgentToken,
        s256: &str,
        now: i64,
    ) -> Result<(), Failure> {
        let owner = agent.claims();
        let audit = self
            .store
            .read_mission_audit(&self.config.issuer, &owner.iss, &owner.sub, s256)
            .map_err(|_| Failure::internal())?;
        let Some(audit) = audit else {
            return Err(Failure::status(StatusCode::NOT_FOUND, "mission_not_found"));
        };
        if let Some(reason) = audit.termination_at(now).map_err(|_| Failure::internal())? {
            return Err(Failure::mission_terminated(reason));
        }
        Ok(())
    }
}

fn parse_route(path: &str) -> Option<Route> {
    match path {
        "/interaction" => Some(Route::Interaction),
        "/permission" => Some(Route::Permission),
        "/audit" => Some(Route::Audit),
        _ => parse_pending(path),
    }
}

fn parse_pending(path: &str) -> Option<Route> {
    let rest = path.strip_prefix("/interaction/pending/")?;
    if let Some(id) = rest.strip_suffix("/decision") {
        return path_token(id).then(|| Route::Decision(id.to_owned()));
    }
    path_token(rest).then(|| Route::Redeem(rest.to_owned()))
}

fn path_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn json_object(request: &Request<Vec<u8>>) -> Result<serde_json::Map<String, Value>, Failure> {
    match strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))? {
        Value::Object(object) => Ok(object),
        _ => Err(Failure::parameter("invalid_request")),
    }
}

fn required_text(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, Failure> {
    match object.get(name) {
        Some(Value::String(text)) if !text.is_empty() && text.len() <= MAX_TEXT => Ok(text.clone()),
        _ => Err(Failure::parameter("invalid_request")),
    }
}

fn optional_text(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, Failure> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(text)) if !text.is_empty() && text.len() <= MAX_TEXT => {
            Ok(Some(text.clone()))
        }
        _ => Err(Failure::parameter("invalid_request")),
    }
}

fn invalid_code() -> Failure {
    Failure::status(StatusCode::GONE, "invalid_code")
}
