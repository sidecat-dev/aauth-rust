use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::{
    Act, Allowance, Answer, ApplyOption, Ask, DECISION_COMPONENTS, accept_signature_field,
};
use aauth_rust_core::{AgentKeyResolver, ApprovedMission, TokenError};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, PreparedResponse, sign_request};
use aauth_rust_supervision_server::{
    Case, Config, ConnectAnswer, ConnectRequest, Observation, Policy, SupervisionServer, Verdict,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const SS: &str = "https://ss.example";
const PS: &str = "https://ps.example";
const OTHER_PS: &str = "https://other-ps.example";
const NOW: i64 = 1_800_000_000;
const SUB: &str = "person-at-ss";
const AGENT: &str = "aauth:assistant@agent.example";

struct PersonServers;
impl AgentKeyResolver for PersonServers {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            (PS, "aauth-person.json", "ps-1") => 3,
            (OTHER_PS, "aauth-person.json", "ps-1") => 4,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}

struct Rules {
    decided: Arc<AtomicUsize>,
    observed: Arc<AtomicUsize>,
}
impl Policy for Rules {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        match request.tenant.as_deref() {
            Some("acme.example") => ConnectAnswer::Connected,
            Some(_) => ConnectAnswer::Refused,
            None => ConnectAnswer::Confirm,
        }
    }
    fn decide(&self, case: &Case) -> Verdict {
        self.decided.fetch_add(1, Ordering::SeqCst);
        match case.action() {
            Some("Write") => Verdict::Ask(Ask {
                summary: Some("Write?".into()),
                recommendation: Some(Answer::Deny),
                proposed: None,
                apply_options: vec![ApplyOption {
                    value: "always".into(),
                    label: "Always".into(),
                }],
            }),
            Some("Wait") => Verdict::Defer,
            Some("Ask") if case.rounds.is_empty() => Verdict::Clarify {
                question: "Why?".into(),
                timeout: Some(60),
                options: Vec::new(),
            },
            _ => Verdict::Allow(Allowance::default()),
        }
    }
    fn observe(&self, _: &Observation) {
        self.observed.fetch_add(1, Ordering::SeqCst);
    }
}

type Server = SupervisionServer<PersonServers, Rules, MemoryContinuations, fn() -> i64>;

struct Fixture {
    server: Server,
    decided: Arc<AtomicUsize>,
    observed: Arc<AtomicUsize>,
}

fn now() -> i64 {
    NOW
}

fn fixture() -> Fixture {
    let decided = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(AtomicUsize::new(0));
    let mut config = Config::new(SS).with_signing("ss-1", SigningKey::from_seed([9; 32]));
    config.interaction_url = Some(format!("{SS}/confirm"));
    let server = SupervisionServer::new(
        config,
        PersonServers,
        Rules {
            decided: decided.clone(),
            observed: observed.clone(),
        },
        MemoryContinuations::new(10_000),
        now as fn() -> i64,
    )
    .unwrap();
    Fixture {
        server,
        decided,
        observed,
    }
}

fn signed_by(
    ps: &str,
    seed: u8,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> Request<Vec<u8>> {
    let mut builder = Request::builder().method(method).uri(uri).header(
        "accept-signature",
        accept_signature_field(&DECISION_COMPONENTS),
    );
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder
        .body(body.map(|b| b.to_string().into_bytes()).unwrap_or_default())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::JwksUri {
            id: ps.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        NOW,
    )
    .unwrap();
    request
}

fn post(path: &str, body: Value) -> Request<Vec<u8>> {
    signed_by(PS, 3, "POST", &format!("{SS}{path}"), Some(&body))
}

fn connect(fixture: &Fixture) {
    let response = fixture.server.handle(&post(
        "/connect",
        json!({ "action": "connect", "id": "c-1", "iat": NOW, "sub": SUB, "tenant": "acme.example" }),
    ));
    assert_eq!(response.status(), 200, "{}", text(&response));
}

fn permission(sdi: &str, action: &str) -> Request<Vec<u8>> {
    post(
        "/decision",
        json!({ "sdi": sdi, "act": "permission", "iat": NOW, "sub": SUB, "agent": AGENT, "action": action }),
    )
}

fn event(id: &str, members: Value) -> Request<Vec<u8>> {
    let mut body = json!({ "id": id, "iat": NOW, "sub": SUB, "agent": AGENT });
    for (name, value) in members.as_object().unwrap() {
        body[name] = value.clone();
    }
    post("/event", body)
}

fn body(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

fn text(response: &Response<Vec<u8>>) -> String {
    format!(
        "{} {}",
        response.status(),
        String::from_utf8_lossy(response.body())
    )
}

fn verify(response: &Response<Vec<u8>>, request: &Request<Vec<u8>>) -> PreparedResponse {
    let prepared = PreparedResponse::prepare(response, request, "sig", &["jwks_uri"]).unwrap();
    let KeyMaterial::JwksUri { id, dwk, kid } = prepared.key() else {
        panic!("signer is named by jwks_uri");
    };
    assert_eq!(
        (id.as_str(), dwk.as_str(), kid.as_str()),
        (SS, "aauth-supervisor.json", "ss-1")
    );
    prepared
        .verify(&SigningKey::from_seed([9; 32]).public_jwk())
        .unwrap();
    prepared
}

#[test]
fn a_decision_is_signed_for_its_request_and_repeated_exactly() {
    let fixture = fixture();
    connect(&fixture);
    let request = permission("d-1", "Read");
    let first = fixture.server.handle(&request);
    assert_eq!(body(&first), json!({ "sdi": "d-1", "decision": "allow" }));
    let prepared = verify(&first, &request);
    for component in DECISION_COMPONENTS {
        assert!(prepared.covers(component), "{component}");
    }
    // A retry under the same sdi gets the same signed bytes, without deciding again.
    let again = fixture.server.handle(&permission("d-1", "Read"));
    assert_eq!(again.body(), first.body());
    assert_eq!(again.headers()["signature"], first.headers()["signature"]);
    assert_eq!(fixture.decided.load(Ordering::SeqCst), 1);
    // The signature does not verify as the answer to another request.
    let other = permission("d-2", "Read");
    assert!(
        PreparedResponse::prepare(&first, &other, "sig", &["jwks_uri"])
            .and_then(|p| p.verify(&SigningKey::from_seed([9; 32]).public_jwk()))
            .is_err()
    );
    // The same sdi for a different act is a defect, not a repeat.
    let mismatched = fixture.server.handle(&post(
        "/decision",
        json!({ "sdi": "d-1", "act": "permission", "iat": NOW, "sub": SUB,
                "agent": "aauth:other@agent.example", "action": "Read" }),
    ));
    assert_eq!(body(&mismatched)["error"], "invalid_request");
}

#[test]
fn only_a_connected_person_at_an_admitted_person_server_is_answered() {
    let fixture = fixture();
    let unknown = fixture.server.handle(&permission("d-1", "Read"));
    assert_eq!(
        (unknown.status().as_u16(), body(&unknown)["error"].clone()),
        (404, json!("unknown_sub"))
    );
    let stranger = fixture.server.handle(&signed_by(
        "https://stranger.example",
        5,
        "POST",
        &format!("{SS}/decision"),
        Some(&json!({})),
    ));
    assert_eq!(
        (stranger.status().as_u16(), body(&stranger)["error"].clone()),
        (403, json!("unsupported_iss"))
    );
    let mut unsigned = permission("d-1", "Read");
    unsigned.headers_mut().remove("signature");
    let refused = fixture.server.handle(&unsigned);
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["signature-error"],
        "error=invalid_signature"
    );
    let refused_tenant = fixture.server.handle(&post(
        "/connect",
        json!({ "action": "connect", "id": "c-1", "iat": NOW, "sub": SUB, "tenant": "elsewhere.example" }),
    ));
    assert_eq!(body(&refused_tenant)["error"], "unsupported_iss");
    // A disconnected person is unknown again.
    connect(&fixture);
    assert_eq!(
        fixture.server.handle(&permission("d-2", "Read")).status(),
        200
    );
    let gone = fixture.server.handle(&post(
        "/connect",
        json!({ "action": "disconnect", "id": "c-2", "iat": NOW, "sub": SUB }),
    ));
    assert_eq!(gone.status(), 200);
    assert_eq!(
        body(&fixture.server.handle(&permission("d-3", "Read")))["error"],
        "unknown_sub"
    );
}

#[test]
fn a_person_confirms_a_connect_at_the_server() {
    let fixture = fixture();
    let pending = fixture.server.handle(&post(
        "/connect",
        json!({ "action": "connect", "id": "c-1", "iat": NOW, "sub": SUB }),
    ));
    assert_eq!(pending.status(), 202, "{}", text(&pending));
    let requirement = pending.headers()["aauth-requirement"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(requirement.starts_with("requirement=interaction; url=\"https://ss.example/confirm\""));
    let code = requirement
        .rsplit("code=\"")
        .next()
        .unwrap()
        .trim_end_matches('"')
        .to_owned();
    let location = pending.headers()["location"].to_str().unwrap().to_owned();
    let poll = || {
        fixture
            .server
            .handle(&signed_by(PS, 3, "GET", &location, None))
    };
    assert_eq!(poll().status(), 202);
    let waiting = fixture
        .server
        .pending_connection(&code.to_lowercase())
        .unwrap();
    assert_eq!((waiting.ps.as_str(), waiting.sub.as_str()), (PS, SUB));
    fixture.server.confirm_connection(&code, true).unwrap();
    assert!(
        fixture.server.pending_connection(&code).is_err(),
        "the code is single use"
    );
    assert_eq!(poll().status(), 200);
    assert!(fixture.server.connected(PS, SUB).unwrap());
    // Another Person Server cannot read this connect's pending URL.
    let other = fixture
        .server
        .handle(&signed_by(OTHER_PS, 4, "GET", &location, None));
    assert_ne!(other.status(), 200);
}

#[test]
fn requests_without_their_members_are_invalid() {
    let fixture = fixture();
    connect(&fixture);
    let missing_act = fixture.server.handle(&post(
        "/decision",
        json!({ "sdi": "d-1", "iat": NOW, "sub": SUB, "agent": AGENT }),
    ));
    let s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let missing_action = fixture.server.handle(&post(
        &format!("/mission/{s256}"),
        json!({ "id": "e-1", "iat": NOW, "sub": SUB, "agent": AGENT }),
    ));
    let unknown_event = fixture
        .server
        .handle(&event("e-2", json!({ "event": "agent.renamed" })));
    let missing_member = fixture
        .server
        .handle(&event("e-3", json!({ "event": "agent.bound" })));
    for response in [missing_act, missing_action, unknown_event, missing_member] {
        assert_eq!(
            (response.status().as_u16(), body(&response)["error"].clone()),
            (400, json!("invalid_request")),
            "{}",
            text(&response)
        );
    }
}

#[test]
fn events_are_recorded_once_and_name_only_missions_the_server_holds() {
    let fixture = fixture();
    connect(&fixture);
    let bound =
        json!({ "event": "agent.bound", "agent_iss": "https://agent.example", "agent_sub": AGENT });
    assert_eq!(
        fixture.server.handle(&event("e-1", bound.clone())).status(),
        201
    );
    assert_eq!(fixture.server.handle(&event("e-1", bound)).status(), 201);
    assert_eq!(fixture.observed.load(Ordering::SeqCst), 1);

    let mission = ApprovedMission::mint(AGENT, NOW, "Plan the offsite.").unwrap();
    let audit =
        json!({ "event": "audit.recorded", "mission_s256": mission.s256(), "action": "WebSearch" });
    let unknown = fixture.server.handle(&event("e-2", audit.clone()));
    assert_eq!(
        (unknown.status().as_u16(), body(&unknown)["error"].clone()),
        (404, json!("unknown_mission"))
    );
    let report = |mission_bytes: &str, id: &str| {
        fixture.server.handle(&post(
            &format!("/mission/{}", mission.s256()),
            json!({ "action": "approved", "id": id, "sdi": "d-1", "iat": NOW, "sub": SUB,
                    "agent": AGENT, "s256": mission.s256(), "mission": mission_bytes }),
        ))
    };
    let other = ApprovedMission::mint(AGENT, NOW, "Something else.").unwrap();
    assert_eq!(
        body(&report(other.encoded(), "e-3"))["error"],
        "invalid_request"
    );
    assert_eq!(report(mission.encoded(), "e-4").status(), 201);
    assert_eq!(fixture.server.handle(&event("e-2", audit)).status(), 201);
    // Another agent cannot act under this agent's mission.
    let foreign = fixture.server.handle(&post(
        "/decision",
        json!({ "sdi": "d-9", "act": "permission", "iat": NOW, "sub": SUB,
                "agent": "aauth:other@agent.example", "action": "Read", "mission_s256": mission.s256() }),
    ));
    assert_eq!(body(&foreign)["error"], "invalid_request");
}

#[test]
fn an_answer_with_reach_is_applied_to_later_acts_of_the_same_kind() {
    let fixture = fixture();
    connect(&fixture);
    let asked = fixture.server.handle(&permission("d-1", "Write"));
    assert_eq!(body(&asked)["decision"], "ask");
    assert_eq!(body(&asked)["apply_options"][0]["value"], "always");
    let resolved = fixture.server.handle(&event(
        "e-1",
        json!({ "event": "decision.resolved", "sdi": "d-1", "answer": "allow", "apply": "always",
                "recommendation": "deny" }),
    ));
    assert_eq!(resolved.status(), 201);
    let standing = fixture.server.standing(PS, SUB, AGENT).unwrap();
    assert_eq!(standing.len(), 1);
    assert_eq!(standing[0].kind, "permission Write");
    let decided = fixture.decided.load(Ordering::SeqCst);
    let later = fixture.server.handle(&permission("d-2", "Write"));
    assert_eq!(body(&later)["decision"], "allow");
    assert_eq!(
        fixture.decided.load(Ordering::SeqCst),
        decided,
        "the policy was not asked"
    );
    // Another kind of act is still the policy's.
    assert_eq!(
        body(&fixture.server.handle(&permission("d-3", "Read")))["decision"],
        "allow"
    );
    assert_eq!(fixture.decided.load(Ordering::SeqCst), decided + 1);
}

#[test]
fn a_deferred_or_clarified_decision_is_answered_at_its_pending_url_only_to_its_requester() {
    let fixture = fixture();
    connect(&fixture);
    let deferred = fixture.server.handle(&permission("d-1", "Wait"));
    assert_eq!(deferred.status(), 202);
    assert_eq!(deferred.headers()["cache-control"], "no-store");
    let location = deferred.headers()["location"].to_str().unwrap().to_owned();
    let poll = signed_by(PS, 3, "GET", &location, None);
    assert_eq!(fixture.server.handle(&poll).status(), 202);
    // A repeat of the request while it waits points at the same URL.
    let repeat = fixture.server.handle(&permission("d-1", "Wait"));
    assert_eq!(repeat.headers()["location"], location.as_str());
    fixture
        .server
        .decide_pending(PS, "d-1", Verdict::Deny(Some("Not now.".into())))
        .unwrap();
    let decided = fixture.server.handle(&poll);
    assert_eq!(
        body(&decided),
        json!({ "sdi": "d-1", "decision": "deny", "reason": "Not now." })
    );
    let prepared = verify(&decided, &poll);
    assert!(prepared.covers("@path;req") && !prepared.covers("content-digest;req"));
    let other = fixture
        .server
        .handle(&signed_by(OTHER_PS, 4, "GET", &location, None));
    assert_eq!(body(&other)["error"], "unknown_pending");

    let clarify = fixture.server.handle(&permission("d-2", "Ask"));
    assert_eq!(
        clarify.headers()["aauth-requirement"],
        "requirement=clarification"
    );
    assert_eq!(body(&clarify)["decision"], "clarify");
    assert_eq!(body(&clarify)["clarification"], "Why?");
    let location = clarify.headers()["location"].to_str().unwrap().to_owned();
    let answer = signed_by(
        PS,
        3,
        "POST",
        &location,
        Some(
            &json!({ "action": "clarification_response", "clarification_response": "To finish." }),
        ),
    );
    let answered = fixture.server.handle(&answer);
    assert_eq!(body(&answered)["decision"], "allow", "{}", text(&answered));
    verify(&answered, &answer);
    let case = fixture.server.pending_case(PS, "d-2").unwrap();
    assert_eq!(case.act, Act::Permission);
    assert_eq!(case.rounds[0].answer, "To finish.");
}
