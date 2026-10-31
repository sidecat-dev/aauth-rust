use aauth_rust_core::supervision::{Act, Allowance, Ask};
use serde_json::{Map, Value};

/// A Person Server asking to speak for a person here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The Person Server's verified identity.
    pub ps: String,
    /// The person, as the identifier that Person Server directs to this server.
    pub sub: String,
    /// The person's tenant, when the Person Server asserts one. An
    /// organization's server may accept its people by tenant without asking.
    pub tenant: Option<String>,
}

/// How the server answers a connect it has no record of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectAnswer {
    /// Accept the pairing now, from configuration or a trusted tenant.
    Connected,
    /// Have the person confirm the Person Server first. Requires
    /// [`crate::Config::interaction_url`].
    Confirm,
    /// Refuse this Person Server (`unsupported_iss`).
    Refused,
}

/// One clarification round: the question the server asked and the agent's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    /// The question, Markdown.
    pub question: String,
    /// The agent's answer, Markdown and agent-asserted.
    pub answer: String,
}

/// What this server holds about a mission: the exact approved blob and
/// whether it has ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionView {
    /// The mission identifier.
    pub s256: String,
    /// The approved blob, base64url, exactly as the agent received it.
    pub mission: String,
    /// The approved description.
    pub description: String,
    /// Set once the Person Server reports the mission terminated.
    pub terminated: Option<String>,
}

/// Everything a policy is given for one act.
///
/// `request` is the body exactly as the Person Server sent it. Tokens in it
/// were verified by that Person Server and are forwarded as the agent
/// presented them; their identifiers are directed to other audiences. The
/// `justification`, `description` and clarification answers are
/// agent-asserted; claims inside a resource token are resource-asserted.
#[derive(Clone, Debug)]
pub struct Case {
    /// The Person Server.
    pub ps: String,
    /// The person, as directed to this server.
    pub sub: String,
    /// The agent, `aauth:local@domain`.
    pub agent: String,
    /// What is being decided.
    pub act: Act,
    /// The supervision decision identifier.
    pub sdi: String,
    /// The mission the act belongs to, when it names one.
    pub mission: Option<MissionView>,
    /// The request body.
    pub request: Map<String, Value>,
    /// Clarification rounds so far, oldest first.
    pub rounds: Vec<Round>,
}

impl Case {
    /// The resource a person token act is for, or the `iss` a forwarded
    /// resource token names for an auth token act. The claim is read without
    /// verification; the Person Server verified the token.
    pub fn resource(&self) -> Option<String> {
        match self.act {
            Act::PersonToken => self
                .request
                .get("resource")
                .and_then(Value::as_str)
                .map(str::to_owned),
            Act::AuthToken => {
                let token = self.request.get("resource_token")?.as_str()?;
                aauth_rust_core::ResourceToken::parse(token)
                    .ok()
                    .map(|t| t.unverified_claims().iss.clone())
            }
            _ => None,
        }
    }
    /// The scope a forwarded resource token requires, for an auth token act.
    pub fn requested_scope(&self) -> Option<String> {
        let token = self.request.get("resource_token")?.as_str()?;
        aauth_rust_core::ResourceToken::parse(token)
            .ok()
            .and_then(|t| t.unverified_claims().scope.clone())
    }
    /// The `action` of a permission act.
    pub fn action(&self) -> Option<&str> {
        (self.act == Act::Permission)
            .then(|| self.request.get("action").and_then(Value::as_str))
            .flatten()
    }
}

/// A policy's answer for one act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Allow, narrowed as the allowance says. A proposal's allowance must
    /// carry the approved mission terms.
    Allow(Allowance),
    /// Refuse, with an optional Markdown reason.
    Deny(Option<String>),
    /// Put the act to the person.
    Ask(Ask),
    /// Ask the agent a question before deciding.
    Clarify {
        /// The question, Markdown.
        question: String,
        /// Seconds the agent has to answer.
        timeout: Option<u64>,
        /// Discrete answers, when the question has them.
        options: Vec<String>,
    },
    /// Decide later with [`crate::SupervisionServer::decide_pending`]. The
    /// Person Server is answered `202` and polls.
    Defer,
}

/// Something the Person Server reported: an event, or a mission approval
/// or termination.
#[derive(Clone, Debug)]
pub struct Observation {
    /// The Person Server.
    pub ps: String,
    /// The person, as directed to this server.
    pub sub: String,
    /// The `event` member, or `approved` and `terminated` for mission reports.
    pub name: String,
    /// The report body as received.
    pub body: Map<String, Value>,
}

/// The policy party: who may connect, and what is allowed.
///
/// How a policy forms its answers is its own: rules the person wrote, what
/// the person decided before, or a model. The server applies the person's
/// standing `mission` and `always` answers before it calls [`Self::decide`].
pub trait Policy: Send + Sync {
    /// Whether to accept a Person Server for a person.
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer;
    /// Decide one act.
    fn decide(&self, case: &Case) -> Verdict;
    /// What "this kind" of act means for the `mission` and `always` reaches.
    /// The default is the act with its resource, or a permission's action.
    fn kind(&self, case: &Case) -> String {
        default_kind(case)
    }
    /// Learn from a report after the server recorded it. Custom `apply`
    /// values the policy offered arrive here in `decision.resolved`.
    fn observe(&self, observation: &Observation) {
        let _ = observation;
    }
}

impl<P: Policy + ?Sized> Policy for Box<P> {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        (**self).connect(request)
    }
    fn decide(&self, case: &Case) -> Verdict {
        (**self).decide(case)
    }
    fn kind(&self, case: &Case) -> String {
        (**self).kind(case)
    }
    fn observe(&self, observation: &Observation) {
        (**self).observe(observation)
    }
}

/// The act's name with its resource or action: `auth_token https://calendar.example`,
/// `permission SendEmail`, or the act name alone.
pub fn default_kind(case: &Case) -> String {
    match (case.resource(), case.action()) {
        (Some(resource), _) => format!("{} {resource}", case.act.name()),
        (None, Some(action)) => format!("{} {action}", case.act.name()),
        (None, None) => case.act.name().to_owned(),
    }
}
