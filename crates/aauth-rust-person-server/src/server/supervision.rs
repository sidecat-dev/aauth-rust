//! Consulting a supervision server (`draft-hardt-aauth-supervision`).
//!
//! With [`PersonServer::with_supervision`], every agent the host routes to a
//! supervision server (SS) has its acts put to that server instead of to host
//! policy: person and auth tokens, permissions, mission proposals, updates
//! and completions. For such an agent this server makes no supervision
//! decision of its own. It relays the act, records the exchange, and
//! enforces the answer: `allow` issues, narrowed as the SS says; `deny`
//! refuses; `ask` holds the act for the person, whose answer the host
//! records with [`PersonServer::resolve_supervision`]. When the SS cannot be
//! consulted the act goes to the person the same way. Afterwards this server
//! reports what happened, in order, through an outbox the host drains with
//! [`PersonServer::deliver_supervision`].
//!
//! The host's [`crate::Policy`] still identifies the person
//! ([`crate::Policy::bind_person`], [`crate::Policy::bind_upstream`]) and
//! derives their directed subjects; with a deciding SS it must not consent
//! there. [`crate::Policy::authorize`], [`crate::Policy::authorize_upstream`],
//! [`crate::Governance::permit`], [`crate::R3Policy`] and the host's mission
//! approval are not called for a supervised agent.
mod held;
mod journal;
mod record;
pub(super) use journal::Report;
pub use record::{RecordError, SupervisionExchange, SupervisionRecord, VerifiedDecision};

use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, PendingResponse, Requirement, generate_pending_id,
};
use aauth_rust_core::supervision::{
    Act, Allowance, Ask, DECISION_COMPONENTS, Decision, Envelope, MissionTerms,
    REQUIRED_DECISION_COMPONENTS, SUPERVISOR_DOCUMENT, SupervisionError, SupervisorMetadata,
    TranscriptEntry, accept_signature_field,
};
use aauth_rust_signature_key::{PreparedResponse, sign_request};
use serde_json::Map;
use std::sync::Arc;

/// The host could not reach a supervision server or its metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("supervision server unreachable")]
pub struct SupervisionUnavailable;

/// Host routing, discovery and transport for supervision servers.
///
/// The person names their supervision servers at this Person Server; how the
/// host takes that setting is its own. Signed decisions are verified with
/// keys the server's [`AgentKeyResolver`] returns for
/// `(supervisor, "aauth-supervisor.json", kid)`, for example from a
/// [`aauth_rust_core::TrustedIssuerKeys`] snapshot of the server's metadata.
pub trait Supervision: Send + Sync {
    /// The agent's deciding supervision server, or `None` when the person
    /// supervises it. The person may name a default server and others for
    /// particular agents; exactly one decides for each agent.
    fn route(&self, person_id: &str, agent: &AgentIdentity) -> Option<String>;
    /// The person's identifier directed to `supervisor`, by the rule used for
    /// resources. It must be stable and appear nowhere else.
    fn subject(&self, person_id: &str, supervisor: &str) -> String;
    /// The person's tenant, asserted at connect. Default none.
    fn tenant(&self, person_id: &str) -> Option<String> {
        let _ = person_id;
        None
    }
    /// `aauth-supervisor.json` bytes for `supervisor`, fetched and cached
    /// under the host's egress admission.
    ///
    /// # Errors
    /// [`SupervisionUnavailable`] when the document cannot be obtained.
    fn metadata(&self, supervisor: &str) -> Result<Vec<u8>, SupervisionUnavailable>;
    /// Send exactly these signed bytes to an endpoint the metadata names,
    /// with a bounded response and deadline. No redirect, rewrite or retry.
    ///
    /// # Errors
    /// [`SupervisionUnavailable`] for a connection failure or timeout.
    fn send(&self, request: &Request<Vec<u8>>)
    -> Result<Response<Vec<u8>>, SupervisionUnavailable>;
}

impl<T: Supervision + ?Sized> Supervision for Box<T> {
    fn route(&self, person_id: &str, agent: &AgentIdentity) -> Option<String> {
        (**self).route(person_id, agent)
    }
    fn subject(&self, person_id: &str, supervisor: &str) -> String {
        (**self).subject(person_id, supervisor)
    }
    fn tenant(&self, person_id: &str) -> Option<String> {
        (**self).tenant(person_id)
    }
    fn metadata(&self, supervisor: &str) -> Result<Vec<u8>, SupervisionUnavailable> {
        (**self).metadata(supervisor)
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, SupervisionUnavailable> {
        (**self).send(request)
    }
}

/// Supervision settings and custody.
pub struct SupervisionConfig {
    /// Routing, discovery and transport.
    pub host: Box<dyn Supervision>,
    /// Custody for held acts, the decision log, the outbox and each agent's
    /// replay record. Use a store of its own; restart durability needs a
    /// host adapter.
    pub store: Arc<dyn ContinuationStore>,
    /// Seconds a held act waits for the SS or the person, 1..=86400, also
    /// capped by the agent token. Default 600.
    pub lifetime: i64,
    /// Agent poll interval in seconds, 0..=3600. Default 5.
    pub retry_after: u64,
    /// `Prefer: wait` sent on every supervision request. Default 30.
    pub wait: u64,
    /// Lifetime of an auth token an SS allows, 1..=3600, before the SS's
    /// `exp` and every parent lifetime cap it. Default 3600.
    pub token_lifetime: i64,
    /// Use only supervision servers that sign their decisions. Default
    /// `true`: a Person Server that will have to show what its supervisor
    /// said needs signed decisions. A server without `jwks_uri` is then
    /// unavailable, and the person is asked.
    pub require_signed: bool,
    /// Clarification rounds relayed for one act, 1..=16. Default 5.
    pub max_rounds: usize,
}

impl SupervisionConfig {
    /// Defaults with this host and custody.
    pub fn new(host: impl Supervision + 'static, store: impl ContinuationStore + 'static) -> Self {
        Self {
            host: Box::new(host),
            store: Arc::new(store),
            lifetime: 600,
            retry_after: 5,
            wait: aauth_rust_core::supervision::RECOMMENDED_WAIT,
            token_lifetime: 3600,
            require_signed: true,
            max_rounds: 5,
        }
    }
}

/// Why the supervision server could not be consulted for an act.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unconsulted {
    /// No metadata, a connection failure, a timeout or a malformed answer.
    Unreachable,
    /// The server answered `server_error`, `invalid_request` or
    /// `unknown_pending`, or a status outside the table.
    Failed(SupervisionError),
    /// The signature on a decision was missing or did not verify.
    BadSignature,
    /// The server publishes no `jwks_uri` and signed decisions are required.
    Unsigned,
    /// The server answered `unsupported_iss`: it dropped the pairing. Tell the person.
    PairingDropped,
    /// The person must confirm this Person Server at the server first: send
    /// them to `{url}?code={code}`, then call [`PersonServer::connect_supervisor`].
    ConnectPending {
        /// The server's confirmation page.
        url: String,
        /// The code to show beside it.
        code: String,
    },
    /// `rate_limited` with a `Retry-After` past the act's deadline.
    RateLimited,
    /// The SS asked more clarification rounds than allowed.
    TooManyRounds,
}

/// What a held act is waiting for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Waiting {
    /// The SS answered `ask`: present the act to the person with this, then
    /// call [`PersonServer::resolve_supervision`].
    Person(Ask),
    /// The SS could not be consulted: present the act to the person, then call
    /// [`PersonServer::resolve_supervision`]. The outcome is reported with
    /// `supervisor: unavailable`.
    Unavailable(Unconsulted),
    /// The SS is deciding: call [`PersonServer::advance_supervision`] after
    /// `retry_after` seconds.
    Supervisor {
        /// Seconds until the next poll of the SS.
        retry_after: u64,
    },
    /// The SS asked the agent a question, relayed at the agent's pending URL.
    Agent {
        /// The question, Markdown.
        question: String,
    },
    /// Allowed, and the Access Server deferred the auth token: advance it
    /// with [`PersonServer::advance_federation`] under this reference. The
    /// agent keeps polling the act's own URL.
    AccessServer {
        /// The federation custody reference.
        reference: String,
    },
    /// Decided; the agent's next poll receives the outcome.
    Decided,
}

/// A supervised act held at this server, for the host. It is attached to the
/// agent's `202` in `http::Response::extensions` and never serialized; read
/// it before handing the response to a framework.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionHold {
    /// Reference for [`PersonServer::resolve_supervision`] and the other host calls.
    pub reference: String,
    /// The supervision decision identifier.
    pub sdi: String,
    /// The act.
    pub act: Act,
    /// The deciding supervision server.
    pub supervisor: String,
    /// The agent.
    pub agent: AgentIdentity,
    /// What it waits for.
    pub waiting: Waiting,
    /// The agent's request body, agent-asserted, for presenting the act.
    pub parameters: Value,
    /// For an R3 auth token act, the exact R3 document or per-call proposal
    /// this server fetched and checked against `r3_s256`. It is
    /// resource-asserted: present its `display` with the act. A supervision
    /// server cannot fetch it, and is not sent it.
    pub r3_document: Option<Vec<u8>>,
}

/// The person's answer to a held act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonAnswer {
    /// `allow` or `deny`.
    pub answer: aauth_rust_core::supervision::Answer,
    /// The reach the person chose: a value the SS offered, or `once`,
    /// `mission` or `always`. `None` is `once`. This server applies none.
    pub apply: Option<String>,
    /// A reason the person gave, never required.
    pub reason: Option<String>,
    /// For a proposal, the mission as the person approved it. `None` takes
    /// the SS's proposed refinement, or else the agent's proposal.
    pub proposed: Option<MissionTerms>,
    /// The clarification chat between the person and the agent, in order.
    pub transcript: Vec<TranscriptEntry>,
}

impl PersonAnswer {
    /// A plain answer, reaching this act only.
    pub fn once(answer: aauth_rust_core::supervision::Answer) -> Self {
        Self {
            answer,
            apply: None,
            reason: None,
            proposed: None,
            transcript: Vec::new(),
        }
    }
}

/// A host supervision call that could not be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SupervisionHostError {
    /// `with_supervision` was not called.
    #[error("supervision is not enabled")]
    Disabled,
    /// No held act under that reference, or it has finished or expired.
    #[error("no held act under that reference")]
    Gone,
    /// The act is not waiting for this call, such as an answer while the SS decides.
    #[error("the held act is not waiting for this")]
    NotReady,
    /// The answer does not fit the act.
    #[error("the answer does not fit the held act")]
    InvalidAnswer,
    /// The store failed.
    #[error("supervision custody is unavailable")]
    Unavailable,
}

/// The outcome of [`PersonServer::connect_supervisor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The server accepts this Person Server for the person.
    Connected,
    /// Send the person to `{url}?code={code}` and call again later.
    Confirm {
        /// The server's confirmation page.
        url: String,
        /// The code to show.
        code: String,
    },
    /// The server refused this Person Server (`unsupported_iss`). Tell the person.
    Refused,
    /// The server could not be reached.
    Unreachable,
}

pub(super) struct Gate {
    config: SupervisionConfig,
}

/// What [`PersonServer::supervise`] decided for one act.
pub(super) enum Supervised {
    /// No deciding SS: host policy decides, as without supervision.
    Host,
    /// The SS, or the person in its place, allowed under `sdi`.
    Allowed { sdi: String, allowance: Allowance },
    /// The SS refused.
    Denied { reason: Option<String> },
    /// The act is held; answer the agent with this `202`.
    Held(Response<Vec<u8>>),
}

/// An allowance already obtained for a held act being resumed.
pub(super) struct Resumed {
    pub(super) sdi: String,
    pub(super) allowance: Allowance,
}

/// One act, as [`PersonServer::supervise`] puts it to the SS.
pub(super) struct ActInput<'a> {
    pub(super) act: Act,
    /// The agent that signed the request.
    pub(super) agent: &'a VerifiedAgentToken,
    /// The accountable person.
    pub(super) person_id: &'a str,
    /// The mission the act belongs to.
    pub(super) mission_s256: Option<&'a str>,
    /// The agent's request body.
    pub(super) parameters: &'a Value,
    /// Members the act adds to it, such as `act` and `agent_token`.
    pub(super) members: Map<String, Value>,
    /// The agent's path, for resuming a held act.
    pub(super) path: &'a str,
    /// Scopes the resource token requires; an SS `scope` must be within them.
    pub(super) requested_scopes: Option<&'a [String]>,
    /// Latest time a held act can still complete.
    pub(super) deadline: i64,
    /// For an R3 auth token act, the exact R3 document or per-call proposal
    /// this server fetched, kept with a held act for presenting it.
    pub(super) r3: Option<&'a [u8]>,
}

/// What an SS said to one request.
enum Answered {
    Decision(Decision),
    Pending {
        location: String,
        retry_after: u64,
        question: Option<Requirement>,
    },
    Failed(SupervisionError, Option<u64>),
    Unreachable(Unconsulted),
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Put the acts of agents the host routes to a supervision server to that
    /// server (`draft-hardt-aauth-supervision`).
    ///
    /// Agents without a deciding server are unchanged: host policy decides.
    /// For an agent [`Supervision::route`] names a server for, this server
    /// makes no supervision decision of its own. Person tokens, auth tokens
    /// (direct and four-party), permissions, and mission proposals, updates
    /// and completions are put to that server, after the request passes
    /// every check it passes today:
    ///
    /// - `allow` proceeds, narrowed to the server's `scope` and `exp`. In
    ///   four-party access the narrowing goes to the Access Server as `scope`
    ///   and `exp` members of the token request, and its token is refused
    ///   when it is wider all the same (`403 access_denied`, or `denied` at a
    ///   poll).
    /// - `deny` refuses: a token request with `403 access_denied`, a
    ///   permission with `permission: denied` and the server's `reason`, a
    ///   mission request with `403 access_denied` and a `reason` member.
    /// - `ask`, a deferred answer, a question for the agent, and a server that
    ///   cannot be consulted all hold the act. The agent receives `202` with
    ///   `Location: {signed_origin}/pending/{id}` and polls it like any deferred
    ///   response; a question reaches it as `requirement=clarification` and its
    ///   answer is relayed. A [`SupervisionHold`] in the response extensions
    ///   tells the host what the act waits for.
    ///
    /// [`crate::Policy::bind_person`] and [`crate::Policy::bind_upstream`] still
    /// identify the person and derive their subjects; they must not consent
    /// for a routed agent. [`crate::Policy::authorize`],
    /// [`crate::Policy::authorize_upstream`], [`crate::Policy::consent`],
    /// [`crate::Governance::permit`] and the signed mission approval are not
    /// consulted for it, and neither is [`crate::R3Policy`]: an R3 request is an auth
    /// token act, and its `allow` grants every operation of the R3 document,
    /// or the proposed call. Its resource-initiated interactions are refused
    /// with `403 access_denied`: their consent step is host consent.
    ///
    /// Every exchange is logged by `sdi` ([`Self::supervision_record`]).
    /// What happened afterwards is reported to the agent's deciding server
    /// in order, through an outbox [`Self::deliver_supervision`] drains, and
    /// each supervision request delivers its pair's outbox first. A server
    /// that becomes an agent's deciding server is sent the agent's active
    /// state before its first act.
    ///
    /// # Errors
    /// [`ConfigurationError`] for a lifetime, interval, wait or round limit
    /// outside its range.
    pub fn with_supervision(
        mut self,
        config: SupervisionConfig,
    ) -> Result<Self, ConfigurationError> {
        if !(1..=86_400).contains(&config.lifetime)
            || config.retry_after > 3600
            || config.wait > 3600
            || !(1..=3600).contains(&config.token_lifetime)
            || !(1..=16).contains(&config.max_rounds)
        {
            return Err(ConfigurationError);
        }
        self.supervision = Some(Gate { config });
        Ok(self)
    }

    fn gate(&self) -> Option<&SupervisionConfig> {
        self.supervision.as_ref().map(|gate| &gate.config)
    }

    /// The deciding SS for an agent, when supervision is on.
    pub(super) fn deciding(&self, person_id: &str, agent: &AgentIdentity) -> Option<String> {
        self.gate()?.host.route(person_id, agent)
    }

    /// The person bound to an agent, when supervision is on: the person a
    /// request names none of itself is for, such as a permission or a
    /// mission request.
    pub(super) fn bound_person(&self, agent: &AgentIdentity) -> Option<String> {
        self.gate()?;
        self.store
            .binding(&self.config.issuer, agent)
            .ok()
            .flatten()
            .filter(|binding| !binding.revoked)
            .map(|binding| binding.person_id)
    }

    /// Put one act to the agent's deciding SS, or leave it to host policy.
    pub(super) fn supervise(
        &self,
        input: ActInput<'_>,
        resumed: Option<&Resumed>,
    ) -> Result<Supervised, Failure> {
        let Some(config) = self.gate() else {
            return Ok(Supervised::Host);
        };
        if let Some(resumed) = resumed {
            return Ok(Supervised::Allowed {
                sdi: resumed.sdi.clone(),
                allowance: resumed.allowance.clone(),
            });
        }
        let identity = Self::identity(input.agent);
        let Some(supervisor) = config.host.route(input.person_id, &identity) else {
            return Ok(Supervised::Host);
        };
        let now = (self.clock)();
        let sub = config.host.subject(input.person_id, &supervisor);
        if input.act == Act::AuthToken {
            self.remember_resource_token(input.person_id, &identity, input.parameters);
        }
        let sdi = format!("d-{}", generate_pending_id());
        let mut body = input
            .parameters
            .as_object()
            .cloned()
            .ok_or_else(Failure::internal)?;
        for (name, value) in input.members {
            body.insert(name, value);
        }
        Envelope {
            sdi: Some(sdi.clone()),
            id: None,
            iat: now,
            sub: sub.clone(),
            agent: identity.subject.clone(),
            mission_s256: input.mission_s256.map(str::to_owned),
        }
        .write(&mut body);
        let target = match input.act {
            Act::MissionProposal => "mission".to_owned(),
            Act::MissionUpdate | Act::MissionCompletion => {
                format!(
                    "mission/{}",
                    input.mission_s256.ok_or_else(Failure::internal)?
                )
            }
            _ => "decision".to_owned(),
        };
        let body = Value::Object(body);
        self.log_open(&sdi, &supervisor, input.act, &identity)
            .map_err(|_| Failure::internal())?;
        let answered = self.consult(
            &supervisor,
            &sub,
            input.person_id,
            &identity,
            input.act,
            &sdi,
            &target,
            &body,
            now,
        );
        let deadline = now
            .saturating_add(config.lifetime)
            .min(input.agent.claims().exp)
            .min(input.deadline);
        let held = HeldAct {
            act: input.act,
            sdi: &sdi,
            supervisor: &supervisor,
            sub: &sub,
            person_id: input.person_id,
            agent: input.agent,
            path: input.path,
            parameters: input.parameters,
            mission_s256: input.mission_s256,
            target: &target,
            body: &body,
            deadline,
            requested_scopes: input.requested_scopes,
            r3: input.r3,
        };
        match answered {
            Answered::Decision(Decision::Allow(allowance))
                if check_allowance(input.act, &allowance, input.requested_scopes, now).is_ok() =>
            {
                self.log_outcome(&sdi, "allow");
                Ok(Supervised::Allowed { sdi, allowance })
            }
            Answered::Decision(Decision::Allow(_)) => {
                self.hold(held, Answered::Unreachable(Unconsulted::Unreachable))
            }
            Answered::Decision(Decision::Deny { reason }) => {
                self.log_outcome(&sdi, "deny");
                Ok(Supervised::Denied { reason })
            }
            other => self.hold(held, other),
        }
    }

    /// Bring the SS current, connect, deliver what is queued for the pair,
    /// then put the act. `unknown_sub` connects and `unknown_mission`
    /// replays the mission, each once, before the act is sent again.
    #[allow(clippy::too_many_arguments)]
    fn consult(
        &self,
        supervisor: &str,
        sub: &str,
        person_id: &str,
        agent: &AgentIdentity,
        act: Act,
        sdi: &str,
        target: &str,
        body: &Value,
        now: i64,
    ) -> Answered {
        let Some(config) = self.gate() else {
            return Answered::Unreachable(Unconsulted::Unreachable);
        };
        let metadata = match self.supervisor_metadata(supervisor) {
            Some(metadata) => metadata,
            None => return Answered::Unreachable(Unconsulted::Unreachable),
        };
        if config.require_signed && metadata.jwks_uri.is_none() {
            return Answered::Unreachable(Unconsulted::Unsigned);
        }
        match self.ensure_connected(&metadata, sub, person_id, now) {
            ConnectOutcome::Connected => {}
            ConnectOutcome::Confirm { url, code } => {
                return Answered::Unreachable(Unconsulted::ConnectPending { url, code });
            }
            ConnectOutcome::Refused => {
                return Answered::Failed(SupervisionError::UnsupportedIss, None);
            }
            ConnectOutcome::Unreachable => return Answered::Unreachable(Unconsulted::Unreachable),
        }
        if self
            .bring_current(&metadata, sub, person_id, agent)
            .is_err()
            || !self.flush(&metadata, sub, now)
        {
            return Answered::Unreachable(Unconsulted::Unreachable);
        }
        let mut connected_again = false;
        let mut replayed = false;
        loop {
            let answered = self.put(&metadata, act, sdi, target, body, now);
            match answered {
                Answered::Failed(SupervisionError::UnknownSub, _) if !connected_again => {
                    connected_again = true;
                    self.forget_connection(supervisor, sub);
                    if self.ensure_connected(&metadata, sub, person_id, now)
                        != ConnectOutcome::Connected
                    {
                        return answered;
                    }
                }
                Answered::Failed(SupervisionError::UnsupportedIss, _) => {
                    // The server dropped the pairing; connect again before the next act.
                    self.forget_connection(supervisor, sub);
                    return answered;
                }
                Answered::Failed(SupervisionError::UnknownMission, _) if !replayed => {
                    replayed = true;
                    let Some(s256) = body["mission_s256"]
                        .as_str()
                        .or_else(|| target.strip_prefix("mission/"))
                    else {
                        return answered;
                    };
                    if !self.replay_mission(&metadata, sub, person_id, agent, s256, now) {
                        return answered;
                    }
                }
                other => return other,
            }
        }
    }

    /// Send one supervision request and read the answer.
    fn put(
        &self,
        metadata: &SupervisorMetadata,
        act: Act,
        sdi: &str,
        target: &str,
        body: &Value,
        now: i64,
    ) -> Answered {
        let endpoint = endpoint_for(metadata, target);
        let Ok(request) =
            self.ss_request("POST", &endpoint, Some(body), Outbound::Supervision, now)
        else {
            return Answered::Unreachable(Unconsulted::Unreachable);
        };
        self.exchange(metadata, act, sdi, &endpoint, request)
    }

    /// Send a signed request in an exchange about `sdi`, log it and its
    /// answer, and read the answer.
    fn exchange(
        &self,
        metadata: &SupervisorMetadata,
        act: Act,
        sdi: &str,
        endpoint: &str,
        request: Request<Vec<u8>>,
    ) -> Answered {
        let Some(config) = self.gate() else {
            return Answered::Unreachable(Unconsulted::Unreachable);
        };
        let response = config.host.send(&request).ok();
        let _ = self.log_exchange(sdi, &request, response.as_ref());
        match response {
            Some(response) => self.read_answer(metadata, act, sdi, endpoint, &request, &response),
            None => Answered::Unreachable(Unconsulted::Unreachable),
        }
    }

    fn read_answer(
        &self,
        metadata: &SupervisorMetadata,
        act: Act,
        sdi: &str,
        endpoint: &str,
        request: &Request<Vec<u8>>,
        response: &Response<Vec<u8>>,
    ) -> Answered {
        if response.body().len() > 1_048_576 {
            return Answered::Unreachable(Unconsulted::Unreachable);
        }
        match response.status() {
            StatusCode::OK => {
                if !is_json(response) {
                    return Answered::Unreachable(Unconsulted::Unreachable);
                }
                if metadata.jwks_uri.is_some()
                    && self.verify_decision(metadata, request, response).is_err()
                {
                    return Answered::Unreachable(Unconsulted::BadSignature);
                }
                match strict_json(response.body())
                    .ok()
                    .and_then(|body| Decision::parse(&body, sdi, act).ok())
                {
                    Some(decision) => Answered::Decision(decision),
                    None => Answered::Unreachable(Unconsulted::Unreachable),
                }
            }
            StatusCode::ACCEPTED => {
                let Ok(pending) = PendingResponse::parse(endpoint, response) else {
                    return Answered::Unreachable(Unconsulted::Unreachable);
                };
                if pending
                    .body
                    .get("sdi")
                    .is_some_and(|echoed| echoed.as_str() != Some(sdi))
                {
                    return Answered::Unreachable(Unconsulted::Unreachable);
                }
                let question = match &pending.requirement {
                    Requirement::Clarification { .. } => Some(pending.requirement.clone()),
                    Requirement::Waiting | Requirement::Approval => None,
                    _ => return Answered::Unreachable(Unconsulted::Unreachable),
                };
                Answered::Pending {
                    location: pending.location,
                    retry_after: pending.retry_after,
                    question,
                }
            }
            _ => {
                let error = SupervisionError::from_response(response);
                let wait = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                if error == SupervisionError::RateLimited && wait.is_none() {
                    return Answered::Failed(SupervisionError::ServerError, None);
                }
                Answered::Failed(error, wait)
            }
        }
    }

    /// A signed decision must name the SS this server called and verify
    /// under its key set, covering at least `@status`, `content-type` and
    /// `content-digest`. A covered request component must match `request`.
    fn verify_decision(
        &self,
        metadata: &SupervisorMetadata,
        request: &Request<Vec<u8>>,
        response: &Response<Vec<u8>>,
    ) -> Result<(), ()> {
        let prepared =
            PreparedResponse::prepare(response, request, "sig", &["jwks_uri"]).map_err(|_| ())?;
        if REQUIRED_DECISION_COMPONENTS
            .iter()
            .any(|component| !prepared.covers(component))
            || prepared.created() > (self.clock)().saturating_add(60)
        {
            return Err(());
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = prepared.key() else {
            return Err(());
        };
        if id != &metadata.issuer || dwk != SUPERVISOR_DOCUMENT {
            return Err(());
        }
        aauth_rust_core::verify_with_refresh(
            &self.keys,
            (id, dwk, kid),
            |key| prepared.verify(key),
            |error| *error == aauth_rust_signature_key::Error::InvalidSignature,
        )
        .map_err(|_| ())?
        .map_err(|_| ())
    }

    /// A request to the SS, signed as this server. A supervision request or
    /// poll carries `Prefer: wait` and `Accept-Signature`; a connect, `Prefer: wait`.
    pub(super) fn ss_request(
        &self,
        method: &str,
        uri: &str,
        body: Option<&Value>,
        outbound: Outbound,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ()> {
        let config = self.gate().ok_or(())?;
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        if outbound != Outbound::Report {
            builder = builder.header("prefer", format!("wait={}", config.wait));
        }
        if outbound == Outbound::Supervision {
            let components: &[&str] = if body.is_some() {
                &DECISION_COMPONENTS
            } else {
                &aauth_rust_core::supervision::POLL_DECISION_COMPONENTS
            };
            builder = builder.header("accept-signature", accept_signature_field(components));
        }
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let mut request = builder.body(bytes).map_err(|_| ())?;
        sign_request(
            &mut request,
            &self.config.signing_key,
            KeyMaterial::JwksUri {
                id: self.config.issuer.clone(),
                dwk: "aauth-person.json".into(),
                kid: self.config.kid.clone(),
            },
            now,
        )
        .map_err(|_| ())?;
        Ok(request)
    }

    /// Admitted metadata of a supervision server.
    pub(super) fn supervisor_metadata(&self, supervisor: &str) -> Option<SupervisorMetadata> {
        let bytes = self.gate()?.host.metadata(supervisor).ok()?;
        SupervisorMetadata::parse(supervisor, &bytes).ok()
    }
}

/// A token this server, or its Access Server, issued for a request.
pub(super) struct Issued<'a> {
    pub(super) kind: TokenKind,
    pub(super) jti: &'a str,
    pub(super) aud: &'a str,
    pub(super) exp: i64,
    pub(super) scope: Option<&'a str>,
    pub(super) issuer: &'a str,
    pub(super) mission_s256: Option<&'a str>,
}

/// Members an act adds to the agent's request body: the decision
/// endpoint's `act`, and the agent token the agent presented.
pub(super) fn act_members(act: Act, agent: &VerifiedAgentToken) -> Map<String, Value> {
    let mut members = Map::new();
    if !act.is_mission() {
        members.insert("act".into(), json!(act.name()));
    }
    if act != Act::MissionUpdate && act != Act::MissionCompletion {
        members.insert("agent_token".into(), json!(agent.compact()));
    }
    members
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Lifetime of an auth token a supervision server allows.
    pub(super) fn supervised_lifetime(&self) -> i64 {
        self.gate().map_or(3600, |config| config.token_lifetime)
    }

    /// Report that the agent was bound to its person on first approval.
    pub(super) fn report_bound(&self, person_id: &str, agent: &AgentIdentity) {
        let mut members = Map::new();
        members.insert("agent_iss".into(), json!(agent.issuer));
        members.insert("agent_sub".into(), json!(agent.subject));
        self.report(
            person_id,
            agent,
            journal::Report::Event(aauth_rust_core::supervision::EventKind::AgentBound, members),
            None,
            None,
            None,
        );
    }

    /// Report a token issued under `sdi`. A token issued without a
    /// supervision server gets an `sdi` of its own, so it can be replayed to
    /// one the person routes the agent to later.
    pub(super) fn report_issued(
        &self,
        person_id: &str,
        agent: &AgentIdentity,
        sdi: Option<&str>,
        issued: Issued<'_>,
    ) {
        if self.supervision.is_none() {
            return;
        }
        let fresh;
        let sdi = match sdi {
            Some(sdi) => sdi,
            None => {
                fresh = format!("d-{}", generate_pending_id());
                &fresh
            }
        };
        let mut members = Map::new();
        members.insert("jti".into(), json!(issued.jti));
        members.insert("aud".into(), json!(issued.aud));
        members.insert("exp".into(), json!(issued.exp));
        let event = match issued.kind {
            TokenKind::Person => aauth_rust_core::supervision::EventKind::PersonTokenIssued,
            TokenKind::Auth => {
                if let Some(scope) = issued.scope {
                    members.insert("scope".into(), json!(scope));
                }
                members.insert("issuer".into(), json!(issued.issuer));
                aauth_rust_core::supervision::EventKind::AuthTokenIssued
            }
        };
        self.report(
            person_id,
            agent,
            journal::Report::Event(event, members),
            Some(sdi),
            issued.mission_s256,
            Some(issued.exp),
        );
    }

    /// A four-party request. The supervision server's narrowing is sent to
    /// the Access Server, and the token it issues is held to that narrowing
    /// when it is delivered, and reported then.
    pub(super) fn federate_supervised(
        &self,
        agent: &VerifiedAgentToken,
        prepared: &PreparedAuthorization,
        resumed: Option<&Resumed>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let r = prepared.resource.claims();
        let supervised = self.supervise(
            ActInput {
                act: Act::AuthToken,
                agent,
                person_id: &prepared.retained.person_id,
                mission_s256: r.mission_s256.as_deref(),
                parameters: &prepared.context.parameters,
                members: act_members(Act::AuthToken, agent),
                path: "/token",
                requested_scopes: Some(&prepared.context.scopes),
                deadline: r.exp.min(prepared.presented.exp),
                r3: None,
            },
            resumed,
        )?;
        let identity = Self::identity(agent);
        let allowed = match supervised {
            Supervised::Host => {
                // Kept for a supervision server the agent is routed to later.
                let unsupervised = AllowedToken::default();
                let response = self.federate_with(
                    agent,
                    prepared,
                    true,
                    None,
                    self.supervision.as_ref().map(|_| &unsupervised),
                )?;
                self.report_federated(&prepared.retained.person_id, &identity, None, &response);
                return Ok(response);
            }
            Supervised::Allowed { sdi, allowance } => {
                AllowedToken::new(sdi, &allowance, resumed.is_some())
            }
            Supervised::Denied { .. } => return Err(Failure::policy(PolicyError::Denied)),
            Supervised::Held(response) => return Ok(response),
        };
        let response = self.federate_with(agent, prepared, false, None, Some(&allowed))?;
        self.report_federated(
            &prepared.retained.person_id,
            &identity,
            allowed.sdi.as_deref(),
            &response,
        );
        Ok(response)
    }

    /// Report the auth token an Access Server issued, once it is released to
    /// the agent: `auth_token.issued` with the Access Server as `issuer`.
    pub(super) fn report_federated(
        &self,
        person_id: &str,
        agent: &AgentIdentity,
        sdi: Option<&str>,
        response: &Response<Vec<u8>>,
    ) {
        if response.status() != StatusCode::OK {
            return;
        }
        let Some(token) = strict_json(response.body())
            .ok()
            .and_then(|body| body["auth_token"].as_str().map(str::to_owned))
        else {
            return;
        };
        let Ok(parsed) = AuthToken::parse(&token) else {
            return;
        };
        let c = parsed.unverified_claims();
        self.report_issued(
            person_id,
            agent,
            sdi,
            Issued {
                kind: TokenKind::Auth,
                jti: &c.jti,
                aud: &c.aud,
                exp: c.exp,
                scope: c.scope.as_deref(),
                issuer: &c.iss,
                mission_s256: c.mission_s256.as_deref(),
            },
        );
    }
}

/// What a supervision server allowed for an auth token, carried to the
/// token's issuance: the token must fit it, and is reported under `sdi`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AllowedToken {
    /// The decision; `None` for an agent no supervision server decides for.
    pub(super) sdi: Option<String>,
    /// The scopes allowed, when the answer narrowed them.
    pub(super) scope: Option<Vec<String>>,
    /// The latest `exp` allowed.
    pub(super) exp: Option<i64>,
    /// The agent is polling: a refusal is the polling error `denied`.
    pub(super) polled: bool,
}

impl AllowedToken {
    pub(super) fn new(sdi: String, allowance: &Allowance, polled: bool) -> Self {
        Self {
            sdi: Some(sdi),
            scope: allowance
                .scope
                .as_ref()
                .map(|scope| scope.split(' ').map(str::to_owned).collect()),
            exp: allowance.exp,
            polled,
        }
    }

    /// Refuse a token another server issued wider than the allowance: a
    /// scope outside it or an `exp` after it.
    pub(super) fn check(&self, granted: &[String], exp: i64) -> Result<(), Failure> {
        let wider = self
            .scope
            .as_ref()
            .is_some_and(|allowed| granted.iter().any(|scope| !allowed.contains(scope)))
            || self.exp.is_some_and(|allowed| exp > allowed);
        if !wider {
            return Ok(());
        }
        Err(if self.polled {
            Failure::status(StatusCode::FORBIDDEN, "denied")
        } else {
            Failure::policy(PolicyError::Denied)
        })
    }

    /// The custody form, read back with [`Self::stored`].
    pub(super) fn to_value(&self) -> Value {
        json!({ "sdi": self.sdi, "scope": self.scope, "exp": self.exp })
    }

    /// An allowance kept with a waiting request. Whoever reads it answers a poll.
    pub(super) fn stored(value: &Value) -> Option<Self> {
        value.as_object()?;
        Some(Self {
            sdi: value["sdi"].as_str().map(str::to_owned),
            scope: value["scope"].as_array().map(|scopes| {
                scopes
                    .iter()
                    .filter_map(|scope| scope.as_str().map(str::to_owned))
                    .collect()
            }),
            exp: value["exp"].as_i64(),
            polled: true,
        })
    }
}

/// What kind of request [`PersonServer::ss_request`] builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outbound {
    /// A supervision request, its poll or a clarification relay.
    Supervision,
    /// A connect, or its poll.
    Connect,
    /// A report or event, a disconnect, or a cancellation.
    Report,
}

/// Everything a held act needs to be put again, answered or resumed.
struct HeldAct<'a> {
    act: Act,
    sdi: &'a str,
    supervisor: &'a str,
    sub: &'a str,
    person_id: &'a str,
    agent: &'a VerifiedAgentToken,
    path: &'a str,
    parameters: &'a Value,
    mission_s256: Option<&'a str>,
    target: &'a str,
    body: &'a Value,
    deadline: i64,
    requested_scopes: Option<&'a [String]>,
    r3: Option<&'a [u8]>,
}

/// An SS `allow` must fit the act: a scope within the requested scopes and
/// an `exp` still ahead, or a proposal's terms.
fn check_allowance(
    act: Act,
    allowance: &Allowance,
    requested: Option<&[String]>,
    now: i64,
) -> Result<(), ()> {
    if allowance.exp.is_some_and(|exp| exp <= now) {
        return Err(());
    }
    if let Some(scope) = &allowance.scope {
        let requested = requested.ok_or(())?;
        if scope
            .split(' ')
            .any(|value| !requested.iter().any(|r| r == value))
        {
            return Err(());
        }
    }
    if act == Act::MissionProposal && allowance.mission.is_none() {
        return Err(());
    }
    Ok(())
}

fn endpoint_for(metadata: &SupervisorMetadata, target: &str) -> String {
    match target.strip_prefix("mission/") {
        Some(s256) => format!("{}/{s256}", metadata.mission_endpoint),
        None if target == "mission" => metadata.mission_endpoint.clone(),
        None if target == "event" => metadata.event_endpoint.clone(),
        None => metadata.decision_endpoint.clone(),
    }
}

fn is_json(response: &Response<Vec<u8>>) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

/// Key of a supervision record: a prefix and the SHA-256 of its parts.
pub(super) fn key(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sv.{prefix}.{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Apply `change` to a record until it lands; `None` removes it.
pub(super) fn update(
    store: &dyn ContinuationStore,
    id: &str,
    mut change: impl FnMut(Option<&Value>) -> Option<Value>,
) -> Result<(), ()> {
    for _ in 0..8 {
        match store.load(id).map_err(|_| ())? {
            None => match change(None) {
                None => return Ok(()),
                Some(value) => match store.insert(id, value) {
                    Ok(()) => return Ok(()),
                    Err(aauth_rust_core::continuation::StoreError::Conflict) => continue,
                    Err(_) => return Err(()),
                },
            },
            Some(snapshot) => {
                if store
                    .replace(id, snapshot.revision, change(Some(&snapshot.value)))
                    .map_err(|_| ())?
                {
                    return Ok(());
                }
            }
        }
    }
    Err(())
}

pub(super) fn load(store: &dyn ContinuationStore, id: &str) -> Option<Value> {
    store.load(id).ok().flatten().map(|snapshot| snapshot.value)
}
