//! Worked composition: one person, three agents, two supervision servers.
//!
//! Real signing and verification throughout; transport is in-process. Two
//! work agents are routed to the organization's supervision server, which
//! applies standing policy and asks the person only for exceptions. A
//! personal agent is routed to the person's own server, which runs on a
//! machine that sometimes sleeps. Keys, clocks and the person's answers are
//! fixtures.
#![allow(dead_code)]
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::{Act, Allowance, Answer, ApplyOption, Ask, MissionTerms, Tool};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentToken, Confirmation, PersonToken, ResourceClaims,
    TokenError, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, ConnectOutcome,
    Governance, Grant, MemoryStore, Person, PersonAnswer, PersonRequest, PersonServer, Policy,
    PolicyError, Supervision, SupervisionConfig, SupervisionHold, SupervisionUnavailable, Waiting,
};
use aauth_rust_supervision_server::{
    Case, Config as SupervisorConfig, ConnectAnswer, ConnectRequest, Observation,
    Policy as SupervisorPolicy, SupervisionServer, Verdict,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
};

pub const PS: &str = "https://ps.example";
pub const AP: &str = "https://ap.example";
pub const ORG: &str = "https://org-ss.example";
pub const HOME: &str = "https://home-ss.example";
pub const CALENDAR: &str = "https://calendar.example";
pub const AS: &str = "https://as.example";
pub const PERSON: &str = "person-1";
pub const START: i64 = 1_800_000_000;

/// Keys this Person Server admits: the agent provider, the resource, its
/// Access Server, and the two supervision servers the person registered.
/// The Access Server admits the same, with this Person Server.
#[derive(Clone)]
pub struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            (AP, "aauth-agent.json", "ap-1") => 1,
            (PS, "aauth-person.json", "ps-1") => 3,
            (CALENDAR, "aauth-resource.json", "cal-1") => 5,
            (AS, "aauth-access.json", "as-1") => 6,
            (ORG, "aauth-supervisor.json", "org-1") => 7,
            (HOME, "aauth-supervisor.json", "home-1") => 8,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}

/// The one Person Server both supervision servers admit.
#[derive(Clone)]
pub struct PersonServerKeys;
impl AgentKeyResolver for PersonServerKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        match (issuer, dwk, kid) {
            (PS, "aauth-person.json", "ps-1") => Ok(SigningKey::from_seed([3; 32]).public_jwk()),
            (PS, "aauth-person.json", _) => Err(TokenError::UnknownKey),
            _ => Err(TokenError::UntrustedIssuer),
        }
    }
}

/// Host policy: it identifies the person, and decides for agents nobody
/// supervises. Every decision it makes is counted.
pub struct HostPolicy {
    pub decided: Arc<AtomicUsize>,
}
impl Policy for HostPolicy {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: PERSON.into(),
            subject: format!("p1.{}", request.resource.trim_start_matches("https://")),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.decided.fetch_add(1, Ordering::SeqCst);
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
}

/// The person channel for agents nobody supervises.
pub struct Channel {
    pub decided: Arc<AtomicUsize>,
}
impl Governance for Channel {
    fn answer(&self, _: &str) -> Result<String, PolicyError> {
        Ok("yes".into())
    }
    fn permit(&self, _: &str) -> Result<bool, PolicyError> {
        self.decided.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

pub type Observed = Arc<Mutex<Vec<(String, Value)>>>;

/// The organization's standing policy: routine work is allowed, writes to
/// the calendar and sending email go to the person, deleting a mailbox never.
pub struct OrgPolicy {
    pub observed: Observed,
}
impl SupervisorPolicy for OrgPolicy {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        if request.tenant.as_deref() == Some("acme.example") {
            ConnectAnswer::Connected
        } else {
            ConnectAnswer::Refused
        }
    }
    fn decide(&self, case: &Case) -> Verdict {
        match case.act {
            Act::PersonToken | Act::MissionUpdate => Verdict::Allow(Allowance::default()),
            Act::AuthToken => match case.requested_scope().as_deref() {
                Some("calendar.read") => Verdict::Allow(Allowance::default()),
                _ => Verdict::Ask(Ask {
                    summary: Some("The agent wants to change your calendar.".into()),
                    recommendation: Some(Answer::Allow),
                    proposed: None,
                    apply_options: Vec::new(),
                }),
            },
            Act::Permission => match case.action() {
                Some("DeleteMailbox") => {
                    Verdict::Deny(Some("Deleting a mailbox is never delegated.".into()))
                }
                Some("SendEmail") => Verdict::Ask(Ask {
                    summary: Some("Send an email for you?".into()),
                    recommendation: Some(Answer::Allow),
                    proposed: None,
                    apply_options: vec![
                        ApplyOption {
                            value: "once".into(),
                            label: "This email only".into(),
                        },
                        ApplyOption {
                            value: "always".into(),
                            label: "Any email this agent sends".into(),
                        },
                    ],
                }),
                _ => Verdict::Allow(Allowance::default()),
            },
            Act::MissionProposal => Verdict::Allow(Allowance {
                mission: Some(MissionTerms {
                    description: format!(
                        "{}\n\nKeep work data inside the organization.",
                        case.request["description"].as_str().unwrap_or("")
                    ),
                    approved_tools: Some(vec![Tool {
                        name: "WebSearch".into(),
                        description: "Search the web".into(),
                    }]),
                    approved_resources: Some(vec![CALENDAR.into()]),
                    expires_at: None,
                }),
                ..Allowance::default()
            }),
            Act::MissionCompletion => Verdict::Ask(Ask {
                summary: Some("The agent reports the work is done.".into()),
                ..Ask::default()
            }),
        }
    }
    fn observe(&self, observation: &Observation) {
        self.observed.lock().unwrap().push((
            observation.name.clone(),
            Value::Object(observation.body.clone()),
        ));
    }
}

/// The person's own server: it asks the agent about a flight before it
/// decides, lets the calendar be read only, and can be told to decide later.
pub struct HomePolicy {
    pub observed: Observed,
    pub defer: Arc<AtomicBool>,
}
impl SupervisorPolicy for HomePolicy {
    fn connect(&self, _: &ConnectRequest) -> ConnectAnswer {
        ConnectAnswer::Confirm
    }
    fn decide(&self, case: &Case) -> Verdict {
        if self.defer.load(Ordering::SeqCst) {
            return Verdict::Defer;
        }
        match (case.act, case.action()) {
            (Act::Permission, Some("BookFlight")) => match case.rounds.last() {
                None => Verdict::Clarify {
                    question: "Is the fare refundable?".into(),
                    timeout: Some(120),
                    options: Vec::new(),
                },
                Some(round) if round.answer.contains("refundable") => {
                    Verdict::Allow(Allowance::default())
                }
                Some(_) => Verdict::Deny(Some("Only refundable fares.".into())),
            },
            (Act::AuthToken, _) => Verdict::Allow(Allowance {
                scope: Some("calendar.read".into()),
                exp: Some(START + 900),
                mission: None,
            }),
            (Act::MissionProposal, _) => Verdict::Allow(Allowance {
                mission: Some(MissionTerms::described(
                    case.request["description"].as_str().unwrap_or("A mission"),
                )),
                ..Allowance::default()
            }),
            _ => Verdict::Allow(Allowance::default()),
        }
    }
    fn observe(&self, observation: &Observation) {
        self.observed.lock().unwrap().push((
            observation.name.clone(),
            Value::Object(observation.body.clone()),
        ));
    }
}

pub type SupervisorClock = Box<dyn Fn() -> i64 + Send + Sync>;
pub type Server = SupervisionServer<
    PersonServerKeys,
    Box<dyn SupervisorPolicy>,
    MemoryContinuations,
    SupervisorClock,
>;

/// One supervision server, reachable or not, and what reached it.
pub struct Supervisor {
    pub server: RwLock<Server>,
    pub asleep: AtomicBool,
    /// `(path, agent)` of every request delivered to it.
    pub seen: Mutex<Vec<(String, String)>>,
    pub observed: Observed,
    make: Box<dyn Fn() -> Server + Send + Sync>,
}

impl Supervisor {
    fn new(make: Box<dyn Fn() -> Server + Send + Sync>, observed: Observed) -> Arc<Self> {
        Arc::new(Self {
            server: RwLock::new(make()),
            asleep: AtomicBool::new(false),
            seen: Mutex::new(Vec::new()),
            observed,
            make,
        })
    }
    /// Lose every record, as a server restored from nothing would.
    pub fn forget_everything(&self) {
        *self.server.write().unwrap() = (self.make)();
    }
    pub fn saw(&self, agent: &str) -> bool {
        self.seen.lock().unwrap().iter().any(|(_, a)| a == agent)
    }
    pub fn observed_names(&self) -> Vec<String> {
        self.observed
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Host routing, discovery and in-process transport.
pub struct Router {
    pub routes: Arc<Mutex<BTreeMap<String, String>>>,
    pub org: Arc<Supervisor>,
    pub home: Arc<Supervisor>,
}
impl Router {
    fn by_issuer(&self, issuer: &str) -> Option<&Arc<Supervisor>> {
        match issuer {
            ORG => Some(&self.org),
            HOME => Some(&self.home),
            _ => None,
        }
    }
}
impl Supervision for Router {
    fn route(&self, _: &str, agent: &AgentIdentity) -> Option<String> {
        self.routes.lock().unwrap().get(&agent.subject).cloned()
    }
    fn subject(&self, person_id: &str, supervisor: &str) -> String {
        format!("{person_id}.{}", supervisor.trim_start_matches("https://"))
    }
    fn tenant(&self, _: &str) -> Option<String> {
        Some("acme.example".into())
    }
    fn metadata(&self, supervisor: &str) -> Result<Vec<u8>, SupervisionUnavailable> {
        // The host caches metadata, so it is there even while the server sleeps.
        let target = self.by_issuer(supervisor).ok_or(SupervisionUnavailable)?;
        Ok(target.server.read().unwrap().metadata())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, SupervisionUnavailable> {
        let host = request.uri().host().ok_or(SupervisionUnavailable)?;
        let target = self
            .by_issuer(&format!("https://{host}"))
            .ok_or(SupervisionUnavailable)?;
        if target.asleep.load(Ordering::SeqCst) {
            return Err(SupervisionUnavailable);
        }
        let agent = serde_json::from_slice::<Value>(request.body())
            .ok()
            .and_then(|body| body["agent"].as_str().map(str::to_owned))
            .unwrap_or_default();
        target
            .seen
            .lock()
            .unwrap()
            .push((request.uri().path().to_owned(), agent));
        Ok(target.server.read().unwrap().handle(request))
    }
}

pub type Ps = PersonServer<Keys, MemoryStore, HostPolicy, BoxedClock, BoxedTokenIds>;

/// The calendar's Access Server, in process. It defers while `defer` is set.
pub struct Access {
    now: Arc<AtomicI64>,
    defer: Arc<AtomicBool>,
    pending: Arc<MemoryContinuations>,
    ids: Arc<AtomicUsize>,
}
impl aauth_rust_person_server::Federation for Access {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        assert_eq!(issuer, AS);
        Ok(format!("{AS}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        let mut deferred = aauth_rust_access_server::DeferredConfig::new(self.pending.clone());
        deferred.retry_after = 0;
        let (now, ids, defer) = (self.now.clone(), self.ids.clone(), self.defer.clone());
        let server = aauth_rust_access_server::AccessServer::new(
            aauth_rust_access_server::Config::new(AS, "as-1", SigningKey::from_seed([6; 32])),
            Keys,
            |r: &aauth_rust_access_server::AuthorizationRequest| {
                Ok(aauth_rust_access_server::Decision {
                    scopes: r.scopes.clone(),
                    lifetime: 600,
                })
            },
            move || now.load(Ordering::SeqCst),
            move || format!("as-{}", ids.fetch_add(1, Ordering::SeqCst)),
        )
        .unwrap()
        .with_deferred(
            deferred,
            move |_: &aauth_rust_access_server::DeferredContext| {
                Ok(defer
                    .load(Ordering::SeqCst)
                    .then_some(aauth_rust_core::continuation::Requirement::Approval))
            },
        )
        .unwrap();
        Ok(server.handle(request))
    }
}

/// Everything in one place.
pub struct World {
    pub now: Arc<AtomicI64>,
    pub ps: Ps,
    pub org: Arc<Supervisor>,
    pub home: Arc<Supervisor>,
    pub routes: Arc<Mutex<BTreeMap<String, String>>>,
    pub host_decisions: Arc<AtomicUsize>,
    pub defer_home: Arc<AtomicBool>,
    /// The Access Server defers while set, in a world built with one.
    pub defer_access: Arc<AtomicBool>,
    federated: bool,
    /// A work agent: email.
    pub mail: Agent,
    /// A work agent: research.
    pub research: Agent,
    /// A personal agent: travel.
    pub travel: Agent,
}

fn agent(local: &str, seed: u8) -> Agent {
    let ap = AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([seed; 32]);
    let token = ap
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: format!("aauth:{local}@ap.example"),
            jti: format!("{local}-agent-token"),
            iat: START,
            exp: START + 86_000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}

fn supervisor(
    issuer: &'static str,
    kid: &'static str,
    seed: u8,
    now: &Arc<AtomicI64>,
    policy: impl Fn() -> Box<dyn SupervisorPolicy> + Send + Sync + 'static,
    observed: Observed,
) -> Arc<Supervisor> {
    let now = now.clone();
    Supervisor::new(
        Box::new(move || {
            let mut config =
                SupervisorConfig::new(issuer).with_signing(kid, SigningKey::from_seed([seed; 32]));
            config.interaction_url = Some(format!("{issuer}/confirm"));
            let clock = now.clone();
            SupervisionServer::new(
                config,
                PersonServerKeys,
                policy(),
                MemoryContinuations::new(100_000),
                Box::new(move || clock.load(Ordering::SeqCst)) as SupervisorClock,
            )
            .unwrap()
        }),
        observed,
    )
}

impl World {
    pub fn new() -> Self {
        Self::build(false)
    }

    /// A world whose calendar is behind its own Access Server (four-party).
    pub fn federated() -> Self {
        Self::build(true)
    }

    fn build(federated: bool) -> Self {
        let now = Arc::new(AtomicI64::new(START));
        let org_observed: Observed = Arc::default();
        let home_observed: Observed = Arc::default();
        let defer_home = Arc::new(AtomicBool::new(false));
        let org = {
            let observed = org_observed.clone();
            supervisor(
                ORG,
                "org-1",
                7,
                &now,
                move || {
                    Box::new(OrgPolicy {
                        observed: observed.clone(),
                    })
                },
                org_observed,
            )
        };
        let home = {
            let observed = home_observed.clone();
            let defer = defer_home.clone();
            supervisor(
                HOME,
                "home-1",
                8,
                &now,
                move || {
                    Box::new(HomePolicy {
                        observed: observed.clone(),
                        defer: defer.clone(),
                    })
                },
                home_observed,
            )
        };
        let routes = Arc::new(Mutex::new(BTreeMap::new()));
        let host_decisions = Arc::new(AtomicUsize::new(0));
        let ids = Arc::new(AtomicUsize::new(0));
        let defer_access = Arc::new(AtomicBool::new(false));
        let clock = now.clone();
        let mut ps = PersonServer::new(
            Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
            Keys,
            MemoryStore::default(),
            HostPolicy {
                decided: host_decisions.clone(),
            },
            Box::new(move || clock.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || format!("jti-{}", ids.fetch_add(1, Ordering::SeqCst)))
                as BoxedTokenIds,
        )
        .unwrap()
        .with_missions()
        .with_governance(Channel {
            decided: host_decisions.clone(),
        })
        .with_supervision(SupervisionConfig::new(
            Router {
                routes: routes.clone(),
                org: org.clone(),
                home: home.clone(),
            },
            MemoryContinuations::new(100_000),
        ))
        .unwrap();
        if federated {
            let mut custody =
                aauth_rust_person_server::DeferredConfig::new(MemoryContinuations::new(1000));
            custody.retry_after = 0;
            ps = ps
                .with_federation(Access {
                    now: now.clone(),
                    defer: defer_access.clone(),
                    pending: Arc::new(MemoryContinuations::new(1000)),
                    ids: Arc::default(),
                })
                .with_deferred(custody)
                .unwrap();
        }
        Self {
            now,
            ps,
            org,
            home,
            routes,
            host_decisions,
            defer_home,
            defer_access,
            federated,
            mail: agent("mail", 11),
            research: agent("research", 12),
            travel: agent("travel", 13),
        }
    }

    pub fn time(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }

    pub fn advance(&self, seconds: i64) {
        self.now.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Route `agent` to a supervision server, or to the person with `None`.
    pub fn route(&self, agent: &Agent, supervisor: Option<&str>) {
        let mut routes = self.routes.lock().unwrap();
        match supervisor {
            Some(supervisor) => routes.insert(subject(agent), supervisor.into()),
            None => routes.remove(&subject(agent)),
        };
    }

    /// Register the person's own server: it asks the person to confirm.
    pub fn connect_home(&self) {
        let ConnectOutcome::Confirm { code, .. } =
            self.ps.connect_supervisor(PERSON, HOME).unwrap()
        else {
            panic!("the home server asks the person to confirm");
        };
        let server = self.home.server.read().unwrap();
        let pending = server.pending_connection(&code).unwrap();
        assert_eq!(pending.ps, PS);
        server.confirm_connection(&code, true).unwrap();
        drop(server);
        assert_eq!(
            self.ps.connect_supervisor(PERSON, HOME).unwrap(),
            ConnectOutcome::Connected
        );
    }

    pub fn post(&self, agent: &Agent, path: &str, body: Value) -> Response<Vec<u8>> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}{path}"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        agent.sign(&mut request, self.time()).unwrap();
        self.ps.handle(&request)
    }

    /// Poll a pending URL the Person Server returned.
    pub fn poll(&self, agent: &Agent, location: &str) -> Response<Vec<u8>> {
        let mut request = Request::builder()
            .method("GET")
            .uri(location)
            .body(Vec::new())
            .unwrap();
        agent.sign(&mut request, self.time()).unwrap();
        self.ps.handle(&request)
    }

    pub fn person_token(&self, agent: &Agent, mission: Option<&str>) -> Response<Vec<u8>> {
        let mut body = json!({ "resource": CALENDAR });
        if let Some(mission) = mission {
            body["mission_s256"] = json!(mission);
        }
        self.post(agent, "/person", body)
    }

    /// The calendar's challenge for `scope`, answering `person_token`.
    pub fn resource_token(&self, agent: &Agent, person_token: &str, scope: &str) -> String {
        self.challenge(agent, person_token, scope, PS)
    }

    /// The calendar's challenge, addressed to `audience`: this Person
    /// Server, or the calendar's Access Server.
    pub fn challenge(
        &self,
        agent: &Agent,
        person_token: &str,
        scope: &str,
        audience: &str,
    ) -> String {
        let presented = PersonToken::parse(person_token).unwrap();
        let p = presented.unverified_claims();
        mint_resource_token(
            &SigningKey::from_seed([5; 32]),
            "cal-1",
            &ResourceClaims {
                iss: CALENDAR.into(),
                dwk: "aauth-resource.json".into(),
                aud: audience.into(),
                sub: p.sub.clone(),
                jti: format!("rt-{}-{}", self.time(), scope),
                iat: self.time(),
                exp: self.time() + 300,
                ps: PS.into(),
                presented_jti: p.jti.clone(),
                agent_jkt: agent.public_jwk().thumbprint().unwrap(),
                nbf: None,
                tenant: p.tenant.clone(),
                mission_s256: p.mission_s256.clone(),
                scope: Some(scope.into()),
                account: None,
                login_hint: None,
                extra: Default::default(),
            },
        )
        .unwrap()
    }

    /// A person token, then an auth token for `scope` at the calendar.
    pub fn auth_token(&self, agent: &Agent, scope: &str) -> Response<Vec<u8>> {
        let person = self.person_token(agent, None);
        assert_eq!(person.status(), 200, "{}", text(&person));
        let person_token = body(&person)["person_token"].as_str().unwrap().to_owned();
        let audience = if self.federated { AS } else { PS };
        let resource_token = self.challenge(agent, &person_token, scope, audience);
        self.post(
            agent,
            "/token",
            json!({
                "resource_token": resource_token,
                "presented_token": person_token,
                "justification": "Find a free afternoon.",
            }),
        )
    }

    pub fn permission(&self, agent: &Agent, action: &str) -> Response<Vec<u8>> {
        self.post(agent, "/permission", json!({ "action": action }))
    }

    /// The person answers a held act.
    pub fn person_answers(&self, hold: &SupervisionHold, answer: Answer, apply: Option<&str>) {
        let mut answer = PersonAnswer::once(answer);
        answer.apply = apply.map(str::to_owned);
        self.ps
            .resolve_supervision(&hold.reference, answer)
            .unwrap();
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

pub fn subject(agent: &Agent) -> String {
    AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .sub
        .clone()
}

pub fn body(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

pub fn text(response: &Response<Vec<u8>>) -> String {
    format!(
        "{} {}",
        response.status(),
        String::from_utf8_lossy(response.body())
    )
}

pub fn location(response: &Response<Vec<u8>>) -> String {
    response.headers()["location"].to_str().unwrap().to_owned()
}

pub fn hold(response: &Response<Vec<u8>>) -> SupervisionHold {
    response
        .extensions()
        .get::<SupervisionHold>()
        .cloned()
        .unwrap_or_else(|| panic!("no hold on {}", text(response)))
}

/// What the tour found, for the example to print and the test to check.
#[derive(Debug, Default)]
pub struct Tour {
    /// Acts the organization's server allowed on standing policy alone.
    pub allowed_without_the_person: usize,
    /// Exceptions it put to the person.
    pub asked_the_person: usize,
    /// After the person said `always`, the same kind of act was allowed
    /// without asking them again.
    pub reach_remembered: bool,
    /// Decisions host policy made for supervised agents. Must stay zero.
    pub host_decisions: usize,
    /// Whether the organization's server saw anything of the personal agent.
    pub org_saw_the_personal_agent: bool,
    /// Whether the person's own server did.
    pub home_saw_the_personal_agent: bool,
    /// While the person's server slept, the person was asked directly.
    pub person_decided_while_asleep: bool,
    /// Events the person's server received once it woke, in order.
    pub delivered_on_waking: Vec<String>,
    /// The signer a stored decision verifies as, with nothing but public keys.
    pub verified_signer: String,
    /// A stored decision with its body changed no longer verifies.
    pub tampering_detected: bool,
}

/// The four use cases in turn.
pub fn tour() -> Tour {
    let world = World::new();
    let mut tour = Tour::default();
    world.route(&world.mail, Some(ORG));
    world.route(&world.research, Some(ORG));
    world.route(&world.travel, Some(HOME));
    world.connect_home();

    // One person, many agents, one server applying standing policy.
    for response in [
        world.auth_token(&world.mail, "calendar.read"),
        world.permission(&world.mail, "ArchiveEmail"),
        world.auth_token(&world.research, "calendar.read"),
    ] {
        assert_eq!(response.status(), 200, "{}", text(&response));
        tour.allowed_without_the_person += 1;
    }
    let asked = world.permission(&world.research, "SendEmail");
    assert_eq!(asked.status(), 202, "{}", text(&asked));
    let held = hold(&asked);
    assert!(matches!(&held.waiting, Waiting::Person(ask) if ask.apply_options.len() == 2));
    tour.asked_the_person += 1;
    world.person_answers(&held, Answer::Allow, Some("always"));
    let granted = world.poll(&world.research, &location(&asked));
    assert_eq!(
        body(&granted)["permission"],
        "granted",
        "{}",
        text(&granted)
    );
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let again = world.permission(&world.research, "SendEmail");
    tour.reach_remembered = body(&again)["permission"] == "granted";
    tour.host_decisions = world.host_decisions.load(Ordering::SeqCst);

    // Different agents of the same person, different servers.
    let personal = world.person_token(&world.travel, None);
    assert_eq!(personal.status(), 200, "{}", text(&personal));
    tour.org_saw_the_personal_agent = world.org.saw(&subject(&world.travel));
    tour.home_saw_the_personal_agent = world.home.saw(&subject(&world.travel));

    // A server that is unavailable for a while.
    world.home.asleep.store(true, Ordering::SeqCst);
    let asleep = world.permission(&world.travel, "BookTrain");
    let held = hold(&asleep);
    assert!(matches!(held.waiting, Waiting::Unavailable(_)));
    world.person_answers(&held, Answer::Allow, None);
    let granted = world.poll(&world.travel, &location(&asleep));
    tour.person_decided_while_asleep = body(&granted)["permission"] == "granted";
    assert_eq!(world.ps.deliver_supervision().unwrap(), 1);
    world.home.asleep.store(false, Ordering::SeqCst);
    let before = world.home.observed_names().len();
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    tour.delivered_on_waking = world.home.observed_names()[before..].to_vec();

    // A verifiable record of who decided what.
    let issued = world
        .org
        .observed
        .lock()
        .unwrap()
        .iter()
        .find(|(name, _)| name == "auth_token.issued")
        .map(|(_, body)| body["sdi"].as_str().unwrap().to_owned())
        .unwrap();
    let mut record = world.ps.supervision_record(&issued).unwrap().unwrap();
    tour.verified_signer = record.verify(&Keys).unwrap().supervisor;
    if let Some(response) = record
        .exchanges
        .last_mut()
        .and_then(|e| e.response.as_mut())
    {
        *response.body_mut() = response.body().replace_ascii("allow", "deny");
    }
    tour.tampering_detected = record.verify(&Keys).is_err();
    tour
}

trait ReplaceAscii {
    fn replace_ascii(&self, from: &str, to: &str) -> Vec<u8>;
}
impl ReplaceAscii for Vec<u8> {
    fn replace_ascii(&self, from: &str, to: &str) -> Vec<u8> {
        String::from_utf8_lossy(self).replace(from, to).into_bytes()
    }
}
