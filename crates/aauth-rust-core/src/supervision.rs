//! AAuth Supervision wire values (`draft-hardt-aauth-supervision`), shared by
//! a Person Server and the supervision server (SS) it consults.
//!
//! These types parse and write supervisor metadata, the common request
//! envelope, decisions, the reach of an answer, events and the error table.
//! They authenticate nobody and decide nothing: the Person Server role signs,
//! verifies and enforces, and the supervision server role applies policy.
use crate::{validate_agent_identifier, validate_server_identifier};
use aauth_rust_jose::strict_json;
use http::{Response, StatusCode};
use serde_json::{Map, Value, json};

/// Well-known metadata document name of a supervision server.
pub const SUPERVISOR_DOCUMENT: &str = "aauth-supervisor.json";

/// Components every signed decision covers (Signed Decisions).
pub const REQUIRED_DECISION_COMPONENTS: [&str; 3] = ["@status", "content-type", "content-digest"];

/// Components a Person Server asks to be covered on the answer to a signed
/// POST: the required three, then the request's `content-digest`,
/// `@authority` and `@path`, which bind a synchronous decision to its request.
pub const DECISION_COMPONENTS: [&str; 6] = [
    "@status",
    "content-type",
    "content-digest",
    "content-digest;req",
    "@authority;req",
    "@path;req",
];

/// Components a Person Server asks to be covered on the answer to a poll.
/// A poll is a GET without content, so there is no request digest to bind.
pub const POLL_DECISION_COMPONENTS: [&str; 5] = [
    "@status",
    "content-type",
    "content-digest",
    "@authority;req",
    "@path;req",
];

/// `Prefer: wait` seconds the draft recommends on every supervision request.
pub const RECOMMENDED_WAIT: u64 = 30;

const MAX_TEXT: usize = 65_536;
const MAX_ID: usize = 256;
const MAX_LIST: usize = 128;

/// A supervision message that does not have the shape the draft defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid supervision message: check required members, their types, identifiers and the echoed sdi"
)]
pub struct WireError;

/// An `Accept-Signature` field value asking for `components` under `sig`
/// (RFC 9421 Section 5.1). Components use the `name;req` form.
pub fn accept_signature_field(components: &[&str]) -> String {
    let items = components
        .iter()
        .map(|component| match component.strip_suffix(";req") {
            Some(name) => format!("\"{name}\";req"),
            None => format!("\"{component}\""),
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("sig=({items})")
}

/// Checked supervision server metadata (Supervisor Metadata).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorMetadata {
    /// Server identifier; the `id` the server signs with.
    pub issuer: String,
    /// Optional display name a Person Server may show the person.
    pub name: Option<String>,
    /// Where a Person Server connects and disconnects a person.
    pub connect_endpoint: String,
    /// Where mission proposals, updates and completions are put, and
    /// approvals and terminations reported.
    pub mission_endpoint: String,
    /// Where person token, auth token and permission requests are put.
    pub decision_endpoint: String,
    /// Where a Person Server reports what happened.
    pub event_endpoint: String,
    /// Key set of a server that signs its decisions. `None` is a plain JSON
    /// responder whose decisions rest on the Person Server's record alone.
    pub jwks_uri: Option<String>,
}

impl SupervisorMetadata {
    /// Metadata for `issuer` with the endpoints this library's server
    /// publishes: `/connect`, `/mission`, `/decision`, `/event` and, when
    /// `signs`, `/.well-known/jwks.json`.
    pub fn for_issuer(issuer: &str, name: Option<&str>, signs: bool) -> Self {
        Self {
            issuer: issuer.into(),
            name: name.map(str::to_owned),
            connect_endpoint: format!("{issuer}/connect"),
            mission_endpoint: format!("{issuer}/mission"),
            decision_endpoint: format!("{issuer}/decision"),
            event_endpoint: format!("{issuer}/event"),
            jwks_uri: signs.then(|| format!("{issuer}/.well-known/jwks.json")),
        }
    }

    /// Parse metadata bytes fetched for `expected_issuer`.
    ///
    /// The issuer must equal `expected_issuer` exactly, and every endpoint and
    /// `jwks_uri` must be an absolute HTTPS URL without userinfo, query or
    /// fragment. Display URLs must be HTTPS. Whether an endpoint on another
    /// origin is one the server controls is the host's egress decision.
    ///
    /// # Errors
    /// [`WireError`] for oversized or malformed JSON, a different issuer, or a
    /// missing or unusable endpoint.
    pub fn parse(expected_issuer: &str, bytes: &[u8]) -> Result<Self, WireError> {
        validate_server_identifier(expected_issuer).map_err(|_| WireError)?;
        if bytes.len() > 65_536 {
            return Err(WireError);
        }
        let value = strict_json(bytes).map_err(|_| WireError)?;
        let object = value.as_object().ok_or(WireError)?;
        if object.get("issuer").and_then(Value::as_str) != Some(expected_issuer) {
            return Err(WireError);
        }
        crate::metadata::check_display_uris(&value).map_err(|_| WireError)?;
        let endpoint = |name: &str| -> Result<String, WireError> {
            let url = object.get(name).and_then(Value::as_str).ok_or(WireError)?;
            https_url(url)?;
            Ok(url.to_owned())
        };
        let jwks_uri = match object.get("jwks_uri") {
            None => None,
            Some(_) => Some(endpoint("jwks_uri")?),
        };
        let name = match object.get("name") {
            None => None,
            Some(Value::String(name)) if !name.is_empty() && name.len() <= 256 => {
                Some(name.clone())
            }
            Some(_) => return Err(WireError),
        };
        Ok(Self {
            issuer: expected_issuer.into(),
            name,
            connect_endpoint: endpoint("connect_endpoint")?,
            mission_endpoint: endpoint("mission_endpoint")?,
            decision_endpoint: endpoint("decision_endpoint")?,
            event_endpoint: endpoint("event_endpoint")?,
            jwks_uri,
        })
    }

    /// The metadata document.
    pub fn to_value(&self) -> Value {
        let mut value = json!({
            "issuer": self.issuer,
            "connect_endpoint": self.connect_endpoint,
            "mission_endpoint": self.mission_endpoint,
            "decision_endpoint": self.decision_endpoint,
            "event_endpoint": self.event_endpoint,
        });
        if let Some(name) = &self.name {
            value["name"] = json!(name);
        }
        if let Some(jwks_uri) = &self.jwks_uri {
            value["jwks_uri"] = json!(jwks_uri);
        }
        value
    }
}

fn https_url(url: &str) -> Result<(), WireError> {
    let uri: http::Uri = url.parse().map_err(|_| WireError)?;
    let authority = uri.authority().ok_or(WireError)?;
    if uri.scheme_str() != Some("https")
        || authority.host().is_empty()
        || authority.as_str().contains('@')
        || uri.query().is_some()
        || url.contains('#')
    {
        return Err(WireError);
    }
    Ok(())
}

/// The common members of every request body (Envelope).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Supervision decision identifier; present on every supervision request.
    pub sdi: Option<String>,
    /// Event or report identifier; `(iss, id)` is the deduplication key.
    pub id: Option<String>,
    /// Time of the act at the Person Server, unchanged on a retry.
    pub iat: i64,
    /// The person, as the identifier directed to this supervision server.
    pub sub: String,
    /// The agent, `aauth:local@domain`.
    pub agent: String,
    /// The mission the act belongs to.
    pub mission_s256: Option<String>,
}

impl Envelope {
    /// Read and check the envelope members of a request body.
    ///
    /// # Errors
    /// [`WireError`] for a missing `iat`, `sub` or `agent`, a member of the
    /// wrong type, an empty or oversized identifier, an invalid agent
    /// identifier or a malformed mission digest.
    pub fn parse(object: &Map<String, Value>) -> Result<Self, WireError> {
        let iat = object
            .get("iat")
            .and_then(Value::as_i64)
            .filter(|iat| *iat >= 0)
            .ok_or(WireError)?;
        let sub = identifier(object, "sub")?.ok_or(WireError)?;
        let agent = text(object, "agent")?.ok_or(WireError)?;
        validate_agent_identifier(&agent).map_err(|_| WireError)?;
        let mission_s256 = text(object, "mission_s256")?;
        if mission_s256.as_deref().is_some_and(|s| !is_digest(s)) {
            return Err(WireError);
        }
        Ok(Self {
            sdi: identifier(object, "sdi")?,
            id: identifier(object, "id")?,
            iat,
            sub,
            agent,
            mission_s256,
        })
    }

    /// Write these members into `object`, replacing any already there.
    pub fn write(&self, object: &mut Map<String, Value>) {
        if let Some(sdi) = &self.sdi {
            object.insert("sdi".into(), json!(sdi));
        }
        if let Some(id) = &self.id {
            object.insert("id".into(), json!(id));
        }
        object.insert("iat".into(), json!(self.iat));
        object.insert("sub".into(), json!(self.sub));
        object.insert("agent".into(), json!(self.agent));
        if let Some(mission) = &self.mission_s256 {
            object.insert("mission_s256".into(), json!(mission));
        }
    }
}

/// True for a canonical unpadded base64url SHA-256 digest.
pub fn is_digest(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn text(object: &Map<String, Value>, name: &str) -> Result<Option<String>, WireError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= MAX_TEXT => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(WireError),
    }
}

fn identifier(object: &Map<String, Value>, name: &str) -> Result<Option<String>, WireError> {
    let value = text(object, name)?;
    if value
        .as_deref()
        .is_some_and(|v| v.len() > MAX_ID || v.chars().any(char::is_control))
    {
        return Err(WireError);
    }
    Ok(value)
}

/// The act a supervision request puts to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Act {
    /// A person token, at the decision endpoint.
    PersonToken,
    /// An auth token, at the decision endpoint.
    AuthToken,
    /// Permission for an action no remote resource governs.
    Permission,
    /// A mission proposal, at the mission endpoint.
    MissionProposal,
    /// A mission update, at the mission's URL.
    MissionUpdate,
    /// A mission completion proposal, at the mission's URL.
    MissionCompletion,
}

impl Act {
    /// The `act` member at the decision endpoint, or `proposal`, `update` and
    /// `completion` for the mission endpoint's three supervision requests.
    pub fn name(self) -> &'static str {
        match self {
            Self::PersonToken => "person_token",
            Self::AuthToken => "auth_token",
            Self::Permission => "permission",
            Self::MissionProposal => "proposal",
            Self::MissionUpdate => "update",
            Self::MissionCompletion => "completion",
        }
    }
    /// Read a decision endpoint `act` member.
    pub fn from_decision_act(act: &str) -> Option<Self> {
        match act {
            "person_token" => Some(Self::PersonToken),
            "auth_token" => Some(Self::AuthToken),
            "permission" => Some(Self::Permission),
            _ => None,
        }
    }
    /// Read the name [`Self::name`] writes.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "proposal" => Some(Self::MissionProposal),
            "update" => Some(Self::MissionUpdate),
            "completion" => Some(Self::MissionCompletion),
            other => Self::from_decision_act(other),
        }
    }
    /// Whether the act goes to the mission endpoint.
    pub fn is_mission(self) -> bool {
        matches!(
            self,
            Self::MissionProposal | Self::MissionUpdate | Self::MissionCompletion
        )
    }
}

/// A recommendation or a person's answer of `allow` or `deny`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Allow the act.
    Allow,
    /// Refuse the act.
    Deny,
}

impl Answer {
    /// `allow` or `deny`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
    fn parse(value: &Value) -> Result<Self, WireError> {
        match value.as_str() {
            Some("allow") => Ok(Self::Allow),
            Some("deny") => Ok(Self::Deny),
            _ => Err(WireError),
        }
    }
}

/// A tool object, as a mission proposal and approval carry it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tool {
    /// Tool name.
    pub name: String,
    /// What the tool does, Markdown.
    pub description: String,
}

impl Tool {
    /// Read an array of tool objects.
    ///
    /// # Errors
    /// [`WireError`] for anything but an array of objects with string
    /// `name` and `description`, or more than 128 entries.
    pub fn parse_list(value: &Value) -> Result<Vec<Self>, WireError> {
        let items = value
            .as_array()
            .filter(|items| items.len() <= MAX_LIST)
            .ok_or(WireError)?;
        items
            .iter()
            .map(|item| {
                let object = item.as_object().ok_or(WireError)?;
                Ok(Self {
                    name: text(object, "name")?.ok_or(WireError)?,
                    description: match object.get("description") {
                        Some(Value::String(d)) if d.len() <= MAX_TEXT => d.clone(),
                        _ => return Err(WireError),
                    },
                })
            })
            .collect()
    }
    /// The tool object.
    pub fn to_value(&self) -> Value {
        json!({ "name": self.name, "description": self.description })
    }
}

/// The members a supervision server sets for a mission: on `allow` of a
/// proposal directly, on `ask` under `proposed`, and in `decision.resolved`
/// as the person approved them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionTerms {
    /// The approved description. It may differ from the proposal.
    pub description: String,
    /// Pre-approved tools. Absent means none.
    pub approved_tools: Option<Vec<Tool>>,
    /// Resources the person approved at the outset.
    pub approved_resources: Option<Vec<String>>,
    /// When the mission expires, RFC 3339.
    pub expires_at: Option<String>,
}

impl MissionTerms {
    /// Terms with only a description.
    pub fn described(description: &str) -> Self {
        Self {
            description: description.into(),
            approved_tools: None,
            approved_resources: None,
            expires_at: None,
        }
    }
    /// Read the members from an object.
    ///
    /// # Errors
    /// [`WireError`] for a missing description, malformed tools, a resource
    /// that is not a server identifier, or an `expires_at` that is not RFC 3339.
    pub fn parse(object: &Map<String, Value>) -> Result<Self, WireError> {
        let description = text(object, "description")?.ok_or(WireError)?;
        let approved_tools = object
            .get("approved_tools")
            .map(Tool::parse_list)
            .transpose()?;
        let approved_resources = match object.get("approved_resources") {
            None => None,
            Some(value) => Some(server_list(value)?),
        };
        let expires_at = text(object, "expires_at")?;
        if let Some(at) = &expires_at {
            time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
                .map_err(|_| WireError)?;
        }
        Ok(Self {
            description,
            approved_tools,
            approved_resources,
            expires_at,
        })
    }
    /// Write the members into `object`.
    pub fn write(&self, object: &mut Map<String, Value>) {
        object.insert("description".into(), json!(self.description));
        if let Some(tools) = &self.approved_tools {
            object.insert(
                "approved_tools".into(),
                Value::Array(tools.iter().map(Tool::to_value).collect()),
            );
        }
        if let Some(resources) = &self.approved_resources {
            object.insert("approved_resources".into(), json!(resources));
        }
        if let Some(expires_at) = &self.expires_at {
            object.insert("expires_at".into(), json!(expires_at));
        }
    }
    /// The members as an object.
    pub fn to_value(&self) -> Value {
        let mut object = Map::new();
        self.write(&mut object);
        Value::Object(object)
    }
}

/// Read an array of server identifiers, such as `resources`.
///
/// # Errors
/// [`WireError`] for anything else, a repeated entry, or more than 128.
pub fn server_list(value: &Value) -> Result<Vec<String>, WireError> {
    let items = value
        .as_array()
        .filter(|items| items.len() <= MAX_LIST)
        .ok_or(WireError)?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let server = item.as_str().ok_or(WireError)?;
        validate_server_identifier(server).map_err(|_| WireError)?;
        if out.iter().any(|seen| seen == server) {
            return Err(WireError);
        }
        out.push(server.into());
    }
    Ok(out)
}

/// One reach the server offers for a person's answer (Reach of an Answer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyOption {
    /// The value the server recognizes when it comes back as `apply`.
    pub value: String,
    /// What the Person Server shows the person, Markdown.
    pub label: String,
}

/// The fixed-meaning reach `once`: this act only. Absent `apply` means this.
pub const REACH_ONCE: &str = "once";
/// The fixed-meaning reach `mission`: every act of this kind under this
/// mission, until it terminates.
pub const REACH_MISSION: &str = "mission";
/// The fixed-meaning reach `always`: every act of this kind by this agent,
/// under any mission or none, until the person changes it.
pub const REACH_ALWAYS: &str = "always";

/// What an `allow` permits, narrowed as the decision says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowance {
    /// A scope narrower than requested, for an auth token.
    pub scope: Option<String>,
    /// A time no later than which the issued token's `exp` must be.
    pub exp: Option<i64>,
    /// The approved mission, for a proposal.
    pub mission: Option<MissionTerms>,
}

/// An `ask`: the server does not decide, and the person is asked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ask {
    /// What the Person Server presents alongside the request, Markdown.
    pub summary: Option<String>,
    /// The server's recommendation.
    pub recommendation: Option<Answer>,
    /// For a proposal, the refinement for the person to confirm or edit.
    pub proposed: Option<MissionTerms>,
    /// The reaches the server offers the person.
    pub apply_options: Vec<ApplyOption>,
}

/// A terminal answer to a supervision request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Proceed with the act, narrowed as the allowance says.
    Allow(Allowance),
    /// Refuse the act.
    Deny {
        /// Why, Markdown; passed to the agent where the protocol gives it one.
        reason: Option<String>,
    },
    /// Put the act to the person.
    Ask(Ask),
}

impl Decision {
    /// Read a decision body for `act` and check that it echoes `sdi`.
    ///
    /// An `allow` of a proposal must carry its `description`. Other members
    /// are read only where `act` defines them, and unknown members are ignored.
    ///
    /// # Errors
    /// [`WireError`] for a different or missing `sdi`, an unknown `decision`,
    /// or a member with the wrong shape.
    pub fn parse(value: &Value, sdi: &str, act: Act) -> Result<Self, WireError> {
        let object = value.as_object().ok_or(WireError)?;
        if object.get("sdi").and_then(Value::as_str) != Some(sdi) {
            return Err(WireError);
        }
        match object.get("decision").and_then(Value::as_str) {
            Some("allow") => {
                let mut allowance = Allowance::default();
                match act {
                    Act::MissionProposal => {
                        allowance.mission = Some(MissionTerms::parse(object)?);
                    }
                    Act::PersonToken | Act::AuthToken => {
                        if act == Act::AuthToken
                            && let Some(scope) = text(object, "scope")?
                        {
                            if !valid_scope(&scope) {
                                return Err(WireError);
                            }
                            allowance.scope = Some(scope);
                        }
                        allowance.exp = match object.get("exp") {
                            None => None,
                            Some(exp) => Some(exp.as_i64().filter(|e| *e > 0).ok_or(WireError)?),
                        };
                    }
                    _ => {}
                }
                Ok(Self::Allow(allowance))
            }
            Some("deny") => Ok(Self::Deny {
                reason: text(object, "reason")?,
            }),
            Some("ask") => {
                let apply_options = match object.get("apply_options") {
                    None => Vec::new(),
                    Some(options) => {
                        let items = options
                            .as_array()
                            .filter(|items| items.len() <= MAX_LIST)
                            .ok_or(WireError)?;
                        let mut out: Vec<ApplyOption> = Vec::new();
                        for item in items {
                            let option = item.as_object().ok_or(WireError)?;
                            let value = identifier(option, "value")?.ok_or(WireError)?;
                            if out.iter().any(|seen| seen.value == value) {
                                return Err(WireError);
                            }
                            out.push(ApplyOption {
                                value,
                                label: text(option, "label")?.ok_or(WireError)?,
                            });
                        }
                        out
                    }
                };
                let proposed = match (act, object.get("proposed")) {
                    (Act::MissionProposal, Some(proposed)) => {
                        Some(MissionTerms::parse(proposed.as_object().ok_or(WireError)?)?)
                    }
                    _ => None,
                };
                Ok(Self::Ask(Ask {
                    summary: text(object, "summary")?,
                    recommendation: object
                        .get("recommendation")
                        .map(Answer::parse)
                        .transpose()?,
                    proposed,
                    apply_options,
                }))
            }
            _ => Err(WireError),
        }
    }

    /// The decision body for `sdi`.
    pub fn to_value(&self, sdi: &str) -> Value {
        let mut object = Map::new();
        object.insert("sdi".into(), json!(sdi));
        match self {
            Self::Allow(allowance) => {
                object.insert("decision".into(), json!("allow"));
                if let Some(mission) = &allowance.mission {
                    mission.write(&mut object);
                }
                if let Some(scope) = &allowance.scope {
                    object.insert("scope".into(), json!(scope));
                }
                if let Some(exp) = allowance.exp {
                    object.insert("exp".into(), json!(exp));
                }
            }
            Self::Deny { reason } => {
                object.insert("decision".into(), json!("deny"));
                if let Some(reason) = reason {
                    object.insert("reason".into(), json!(reason));
                }
            }
            Self::Ask(ask) => {
                object.insert("decision".into(), json!("ask"));
                if let Some(summary) = &ask.summary {
                    object.insert("summary".into(), json!(summary));
                }
                if let Some(recommendation) = ask.recommendation {
                    object.insert("recommendation".into(), json!(recommendation.as_str()));
                }
                if let Some(proposed) = &ask.proposed {
                    object.insert("proposed".into(), proposed.to_value());
                }
                if !ask.apply_options.is_empty() {
                    object.insert(
                        "apply_options".into(),
                        Value::Array(
                            ask.apply_options
                                .iter()
                                .map(|o| json!({ "value": o.value, "label": o.label }))
                                .collect(),
                        ),
                    );
                }
            }
        }
        Value::Object(object)
    }
}

/// Space-separated scope values of the protocol's scope syntax, each distinct.
pub fn valid_scope(scope: &str) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    scope.split(' ').all(|value| {
        !value.is_empty()
            && value
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
            && seen.insert(value)
    })
}

/// An `event` the Person Server reports at the event endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// `person_token.issued`: `sdi`, `jti`, `aud`, `exp`.
    PersonTokenIssued,
    /// `auth_token.issued`: `sdi`, `jti`, `aud`, `scope`, `exp`, `issuer`.
    AuthTokenIssued,
    /// `decision.resolved`: what the person decided.
    DecisionResolved,
    /// `audit.recorded`: `action`, `description`, `parameters`, `result`.
    AuditRecorded,
    /// `interaction.requested`: `type`, `url`.
    InteractionRequested,
    /// `agent.bound`: `agent_iss`, `agent_sub`.
    AgentBound,
    /// `revocation.received`: `token_type`, `iss`, `jti`, `exp`.
    RevocationReceived,
}

impl EventKind {
    /// The `event` member.
    pub fn name(self) -> &'static str {
        match self {
            Self::PersonTokenIssued => "person_token.issued",
            Self::AuthTokenIssued => "auth_token.issued",
            Self::DecisionResolved => "decision.resolved",
            Self::AuditRecorded => "audit.recorded",
            Self::InteractionRequested => "interaction.requested",
            Self::AgentBound => "agent.bound",
            Self::RevocationReceived => "revocation.received",
        }
    }
    /// Read an `event` member.
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::PersonTokenIssued,
            Self::AuthTokenIssued,
            Self::DecisionResolved,
            Self::AuditRecorded,
            Self::InteractionRequested,
            Self::AgentBound,
            Self::RevocationReceived,
        ]
        .into_iter()
        .find(|kind| kind.name() == name)
    }
    /// The members this event requires beyond the envelope.
    pub fn required_members(self) -> &'static [&'static str] {
        match self {
            Self::PersonTokenIssued => &["sdi", "jti", "aud", "exp"],
            Self::AuthTokenIssued => &["sdi", "jti", "aud", "exp", "issuer"],
            Self::DecisionResolved => &["sdi", "answer"],
            Self::AuditRecorded => &["mission_s256", "action"],
            Self::InteractionRequested => &["type"],
            Self::AgentBound => &["agent_iss", "agent_sub"],
            Self::RevocationReceived => &["token_type", "iss", "jti", "exp"],
        }
    }
}

/// What the person decided, in `decision.resolved`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The person allowed the act.
    Allow,
    /// The person refused it.
    Deny,
    /// The person did not answer before the request expired.
    Abandoned,
}

impl Resolved {
    /// `allow`, `deny` or `abandoned`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Abandoned => "abandoned",
        }
    }
    /// Read an `answer` member.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// Who spoke in a clarification transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speaker {
    /// The person, at the Person Server.
    Person,
    /// The agent, through the Person Server.
    Agent,
}

/// One line of a clarification transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptEntry {
    /// Who spoke.
    pub from: Speaker,
    /// What they said, Markdown.
    pub text: String,
}

/// The members of `decision.resolved` beyond the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// What the person decided.
    pub answer: Resolved,
    /// The reach the person gave their answer. `None` means `once`.
    pub apply: Option<String>,
    /// The recommendation the server gave in its `ask`, echoed back.
    pub recommendation: Option<Answer>,
    /// For a proposal, the refinement as the person approved it.
    pub proposed: Option<MissionTerms>,
    /// The clarification chat between the person and the agent, in order.
    pub transcript: Vec<TranscriptEntry>,
    /// The Person Server put the act to the person because it could not reach
    /// the server. There is then no recommendation.
    pub supervisor_unavailable: bool,
    /// A reason the person gave, Markdown.
    pub reason: Option<String>,
}

impl Resolution {
    /// The person's plain answer with nothing else.
    pub fn answered(answer: Resolved) -> Self {
        Self {
            answer,
            apply: None,
            recommendation: None,
            proposed: None,
            transcript: Vec::new(),
            supervisor_unavailable: false,
            reason: None,
        }
    }
    /// Write the members into `object`.
    pub fn write(&self, object: &mut Map<String, Value>) {
        object.insert("answer".into(), json!(self.answer.as_str()));
        if let Some(apply) = &self.apply {
            object.insert("apply".into(), json!(apply));
        }
        if let Some(recommendation) = self.recommendation {
            object.insert("recommendation".into(), json!(recommendation.as_str()));
        }
        if let Some(proposed) = &self.proposed {
            object.insert("proposed".into(), proposed.to_value());
        }
        if !self.transcript.is_empty() {
            let entries = self
                .transcript
                .iter()
                .map(|entry| {
                    let from = match entry.from {
                        Speaker::Person => "person",
                        Speaker::Agent => "agent",
                    };
                    json!({ "from": from, "text": entry.text })
                })
                .collect();
            object.insert("transcript".into(), Value::Array(entries));
        }
        if self.supervisor_unavailable {
            object.insert("supervisor".into(), json!("unavailable"));
        }
        if let Some(reason) = &self.reason {
            object.insert("reason".into(), json!(reason));
        }
    }
    /// Read the members from a `decision.resolved` body.
    ///
    /// # Errors
    /// [`WireError`] for a missing or unknown `answer`, or a member with the
    /// wrong shape.
    pub fn parse(object: &Map<String, Value>) -> Result<Self, WireError> {
        let answer = object
            .get("answer")
            .and_then(Value::as_str)
            .and_then(Resolved::parse)
            .ok_or(WireError)?;
        let transcript = match object.get("transcript") {
            None => Vec::new(),
            Some(entries) => entries
                .as_array()
                .filter(|items| items.len() <= MAX_LIST)
                .ok_or(WireError)?
                .iter()
                .map(|entry| {
                    let entry = entry.as_object().ok_or(WireError)?;
                    let from = match entry.get("from").and_then(Value::as_str) {
                        Some("person") => Speaker::Person,
                        Some("agent") => Speaker::Agent,
                        _ => return Err(WireError),
                    };
                    Ok(TranscriptEntry {
                        from,
                        text: text(entry, "text")?.ok_or(WireError)?,
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let supervisor_unavailable = match object.get("supervisor") {
            None => false,
            Some(Value::String(value)) if value == "unavailable" => true,
            Some(_) => return Err(WireError),
        };
        Ok(Self {
            answer,
            apply: identifier(object, "apply")?,
            recommendation: object
                .get("recommendation")
                .map(Answer::parse)
                .transpose()?,
            proposed: object
                .get("proposed")
                .map(|p| p.as_object().ok_or(WireError).and_then(MissionTerms::parse))
                .transpose()?,
            transcript,
            supervisor_unavailable,
            reason: text(object, "reason")?,
        })
    }
}

/// The error table of the draft (Errors).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SupervisionError {
    /// Malformed body, missing member, or unrecognized `action`, `act` or `event`.
    #[error("invalid_request")]
    InvalidRequest,
    /// The server does not accept requests from this Person Server.
    #[error("unsupported_iss")]
    UnsupportedIss,
    /// The server accepts this Person Server but has no connection for this `sub`.
    #[error("unknown_sub")]
    UnknownSub,
    /// The server has no record of `mission_s256`.
    #[error("unknown_mission")]
    UnknownMission,
    /// A poll or clarification reply names a pending URL the server does not
    /// hold, or the poller is not the requester.
    #[error("unknown_pending")]
    UnknownPending,
    /// The server will not take more from this Person Server for now.
    #[error("rate_limited")]
    RateLimited,
    /// Internal failure. Any status or error outside the table reads as this.
    #[error("server_error")]
    ServerError,
}

impl SupervisionError {
    /// The `error` member.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedIss => "unsupported_iss",
            Self::UnknownSub => "unknown_sub",
            Self::UnknownMission => "unknown_mission",
            Self::UnknownPending => "unknown_pending",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
        }
    }
    /// The status the table gives the error.
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedIss => StatusCode::FORBIDDEN,
            Self::UnknownSub | Self::UnknownMission | Self::UnknownPending => StatusCode::NOT_FOUND,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    /// Read an error response. A status or error that is not in the table,
    /// or an error with the wrong status, is [`Self::ServerError`].
    pub fn from_response(response: &Response<Vec<u8>>) -> Self {
        let code = strict_json(response.body())
            .ok()
            .and_then(|body| body.get("error").and_then(Value::as_str).map(str::to_owned));
        let parsed = match code.as_deref() {
            Some("invalid_request") => Self::InvalidRequest,
            Some("unsupported_iss") => Self::UnsupportedIss,
            Some("unknown_sub") => Self::UnknownSub,
            Some("unknown_mission") => Self::UnknownMission,
            Some("unknown_pending") => Self::UnknownPending,
            Some("rate_limited") => Self::RateLimited,
            _ => Self::ServerError,
        };
        if parsed.status() == response.status() {
            parsed
        } else {
            Self::ServerError
        }
    }
    /// The problem response for this error. `rate_limited` carries
    /// `Retry-After`, which the table requires.
    pub fn response(self, retry_after: Option<u64>) -> Response<Vec<u8>> {
        let body = json!({
            "type": "about:blank",
            "title": self.status().canonical_reason().unwrap_or("Request refused"),
            "status": self.status().as_u16(),
            "error": self.code(),
        });
        let mut response = Response::new(body.to_string().into_bytes());
        *response.status_mut() = self.status();
        response.headers_mut().insert(
            "content-type",
            http::HeaderValue::from_static("application/problem+json"),
        );
        if self == Self::RateLimited {
            response.headers_mut().insert(
                "retry-after",
                http::HeaderValue::from(retry_after.unwrap_or(5)),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_round_trip_and_echo_their_sdi() {
        let ask = Decision::Ask(Ask {
            summary: Some("Book a $3,200 fare?".into()),
            recommendation: Some(Answer::Deny),
            proposed: None,
            apply_options: vec![ApplyOption {
                value: "refundable-under-4k".into(),
                label: "Any refundable fare under $4,000".into(),
            }],
        });
        let body = ask.to_value("d-1");
        assert_eq!(Decision::parse(&body, "d-1", Act::AuthToken), Ok(ask));
        assert_eq!(
            Decision::parse(&body, "d-2", Act::AuthToken),
            Err(WireError)
        );
        let allow = Decision::Allow(Allowance {
            scope: Some("calendar.read".into()),
            exp: Some(5000),
            mission: None,
        });
        assert_eq!(
            Decision::parse(&allow.to_value("d-3"), "d-3", Act::AuthToken),
            Ok(allow)
        );
        // A proposal's allow must carry the approved description.
        assert_eq!(
            Decision::parse(
                &json!({"sdi":"d-4","decision":"allow"}),
                "d-4",
                Act::MissionProposal
            ),
            Err(WireError)
        );
        assert_eq!(
            Decision::parse(
                &json!({"sdi":"d-5","decision":"maybe"}),
                "d-5",
                Act::Permission
            ),
            Err(WireError)
        );
    }

    #[test]
    fn errors_outside_the_table_read_as_server_error() {
        let unknown = SupervisionError::UnknownMission.response(None);
        assert_eq!(
            SupervisionError::from_response(&unknown),
            SupervisionError::UnknownMission
        );
        let mut wrong_status = SupervisionError::UnknownSub.response(None);
        *wrong_status.status_mut() = StatusCode::BAD_REQUEST;
        assert_eq!(
            SupervisionError::from_response(&wrong_status),
            SupervisionError::ServerError
        );
        assert_eq!(
            SupervisionError::RateLimited.response(Some(9)).headers()["retry-after"],
            "9"
        );
    }

    #[test]
    fn accept_signature_names_request_components_with_req() {
        assert_eq!(
            accept_signature_field(&DECISION_COMPONENTS),
            "sig=(\"@status\" \"content-type\" \"content-digest\" \"content-digest\";req \"@authority\";req \"@path\";req)"
        );
    }
}
