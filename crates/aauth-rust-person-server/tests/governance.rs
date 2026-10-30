use aauth_rust_agent::{Agent, PermissionDecision};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::continuation::{canonical_interaction_code, is_emitted_interaction_code};
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Governance, GovernanceError, Grant,
    MemoryStore, OpenedInteraction, Person, PersonRequest, PersonServer, Policy, PolicyError,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Err(PolicyError::Denied)
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

struct Channel;
impl Governance for Channel {
    fn answer(&self, question: &str) -> Result<String, PolicyError> {
        if question == "unreachable" {
            return Err(PolicyError::UserUnreachable);
        }
        Ok("yes".into())
    }
    fn permit(&self, action: &str) -> Result<bool, PolicyError> {
        Ok(action == "SendEmail")
    }
}

struct Fixture {
    server: PersonServer<AgentProviderKeys, MemoryStore, Host, BoxedClock, BoxedTokenIds>,
    owner: Agent,
}

fn issue(ap: &AgentProvider) -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = ap
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Agent@ap.example".into(),
            jti: "agent-1".into(),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some("https://ps.example".into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}

fn fixture(enabled: bool) -> Fixture {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let ids = Arc::new(AtomicUsize::new(0));
    let mut server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        keys,
        MemoryStore::default(),
        Host,
        Box::new(|| 1000i64) as BoxedClock,
        Box::new(move || format!("id-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
    )
    .unwrap()
    .with_missions();
    if enabled {
        server = server.with_governance(Channel);
    }
    Fixture {
        server,
        owner: issue(&ap),
    }
}

fn body_of(response: &http::Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or_else(|_| {
        panic!(
            "status {} body {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
    })
}

fn error_of(response: &http::Response<Vec<u8>>) -> String {
    body_of(response)["error"].as_str().unwrap_or("").to_owned()
}

fn approver(path: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        1000,
    )
    .unwrap();
    request
}

fn raw_post(agent: &Agent, path: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

fn approve_mission(fixture: &Fixture) -> String {
    let proposed = fixture.server.handle(&raw_post(
        &fixture.owner,
        "/mission",
        json!({ "description": "draft the note" }),
    ));
    assert_eq!(proposed.status(), 202, "{}", error_of(&proposed));
    let id = proposed.headers()["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let approved = fixture.server.handle(&approver(
        &format!("/mission/proposal/{id}/approval"),
        json!({ "decision": "approve" }),
    ));
    assert_eq!(approved.status(), 200, "{}", error_of(&approved));
    let mut poll = Request::builder()
        .method("GET")
        .uri(format!("https://ps.example/mission/proposal/{id}"))
        .body(Vec::new())
        .unwrap();
    fixture.owner.sign(&mut poll, 1000).unwrap();
    let poll = fixture.server.handle(&poll);
    assert_eq!(poll.status(), 200, "{}", error_of(&poll));
    body_of(&poll)["s256"].as_str().unwrap().to_owned()
}

#[test]
fn disabled_governance_is_not_advertised() {
    let fixture = fixture(false);
    let published: Value = serde_json::from_slice(&fixture.server.metadata()).unwrap();
    assert!(published.get("interaction_endpoint").is_none());
    assert!(published.get("permission_endpoint").is_none());
    assert!(published.get("audit_endpoint").is_none());
    let response = fixture.server.handle(
        &fixture
            .owner
            .post_interaction("https://ps.example/interaction", "interaction", 1000)
            .unwrap(),
    );
    assert_eq!(response.status(), 404);
}

#[test]
fn signed_interaction_requires_agent_jwt_and_type() {
    let fixture = fixture(true);
    let published: Value = serde_json::from_slice(&fixture.server.metadata()).unwrap();
    assert_eq!(
        published["interaction_endpoint"],
        "https://ps.example/interaction"
    );
    let unsigned = Request::builder()
        .method("POST")
        .uri("https://ps.example/interaction")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "type": "interaction" })).unwrap())
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let missing = fixture
        .server
        .handle(&raw_post(&fixture.owner, "/interaction", json!({})));
    assert_eq!(missing.status(), 400);
    assert_eq!(error_of(&missing), "invalid_request");
    let unknown_type = fixture.server.handle(&raw_post(
        &fixture.owner,
        "/interaction",
        json!({ "type": "not-a-type" }),
    ));
    assert_eq!(unknown_type.status(), 400);
    assert_eq!(error_of(&unknown_type), "invalid_request");
    let relay = fixture.server.handle(
        &fixture
            .owner
            .post_interaction("https://ps.example/interaction", "interaction", 1000)
            .unwrap(),
    );
    assert_eq!(relay.status(), 424);
    assert_eq!(error_of(&relay), "interaction_unavailable");
    let payment = fixture.server.handle(
        &fixture
            .owner
            .post_interaction("https://ps.example/interaction", "payment", 1000)
            .unwrap(),
    );
    assert_eq!(payment.status(), 424);
    let question = fixture.server.handle(
        &fixture
            .owner
            .post_question("https://ps.example/interaction", "Refundable?", 1000)
            .unwrap(),
    );
    assert_eq!(question.status(), 200, "{}", error_of(&question));
    assert_eq!(body_of(&question)["answer"], "yes");
}

#[test]
fn signed_permission_requires_action_and_denial_does_not_proceed() {
    let fixture = fixture(true);
    let unsigned = Request::builder()
        .method("POST")
        .uri("https://ps.example/permission")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "action": "SendEmail" })).unwrap())
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let missing = fixture
        .server
        .handle(&raw_post(&fixture.owner, "/permission", json!({})));
    assert_eq!(missing.status(), 400);
    assert_eq!(error_of(&missing), "invalid_request");
    let denied = fixture.server.handle(
        &fixture
            .owner
            .post_permission("https://ps.example/permission", "SendWire", 1000)
            .unwrap(),
    );
    assert_eq!(denied.status(), 200, "{}", error_of(&denied));
    let decision = PermissionDecision::parse(denied.body()).unwrap();
    assert!(!decision.may_proceed());
    let granted = fixture.server.handle(
        &fixture
            .owner
            .post_permission("https://ps.example/permission", "SendEmail", 1000)
            .unwrap(),
    );
    assert!(
        PermissionDecision::parse(granted.body())
            .unwrap()
            .may_proceed()
    );
    assert!(
        fixture
            .owner
            .post_permission("https://ps.example/permission", "", 1000)
            .is_err()
    );
    assert!(
        fixture
            .owner
            .post_audit("https://ps.example/audit", "", "WebSearch", 1000)
            .is_err()
    );
    assert!(
        fixture
            .owner
            .post_audit("https://ps.example/audit", "abc", "", 1000)
            .is_err()
    );
}

#[test]
fn signed_audit_requires_mission_and_action() {
    let fixture = fixture(true);
    let mission = approve_mission(&fixture);
    let missing_mission = fixture.server.handle(&raw_post(
        &fixture.owner,
        "/audit",
        json!({ "action": "WebSearch" }),
    ));
    assert_eq!(missing_mission.status(), 400);
    assert_eq!(error_of(&missing_mission), "invalid_request");
    let missing_action = fixture.server.handle(&raw_post(
        &fixture.owner,
        "/audit",
        json!({ "mission_s256": mission }),
    ));
    assert_eq!(missing_action.status(), 400);
    let unsigned = Request::builder()
        .method("POST")
        .uri("https://ps.example/audit")
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({ "mission_s256": mission, "action": "WebSearch" })).unwrap(),
        )
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let recorded = fixture.server.handle(
        &fixture
            .owner
            .post_audit("https://ps.example/audit", &mission, "WebSearch", 1000)
            .unwrap(),
    );
    assert_eq!(recorded.status(), 201);
    assert!(recorded.body().is_empty());
    let unknown = fixture.server.handle(
        &fixture
            .owner
            .post_audit(
                "https://ps.example/audit",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "WebSearch",
                1000,
            )
            .unwrap(),
    );
    assert_eq!(unknown.status(), 404);
    assert_eq!(error_of(&unknown), "mission_not_found");
}

/// A drawn code holding `symbol`. Each draw holds a given symbol with
/// probability above one in five, so 512 draws all missing it do not happen.
fn open_with(fixture: &Fixture, symbol: char) -> OpenedInteraction {
    (0..512)
        .map(|_| fixture.server.open_interaction_code(2000).unwrap())
        .find(|opened| opened.code.contains(symbol))
        .expect("a drawn code holds the symbol")
}

/// `code` as a person may type it: lowercase, regrouped, with `i` for `1`
/// and `o` for `0`.
fn as_typed(code: &str) -> String {
    let typed: String = code
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            '1' => 'i',
            '0' => 'o',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    format!("{}-{}-{}", &typed[..2], &typed[2..5], &typed[5..])
}

#[test]
fn opened_codes_and_redemption_ids_are_drawn_by_the_server() {
    let disabled = fixture(false);
    let fixture = fixture(true);
    let mut codes = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for _ in 0..256 {
        let opened = fixture.server.open_interaction_code(2000).unwrap();
        assert_eq!(opened.code.len(), 9, "{}", opened.code);
        assert_eq!(opened.code.as_bytes()[4], b'-');
        assert!(is_emitted_interaction_code(&opened.code));
        assert_eq!(canonical_interaction_code(&opened.code).unwrap().len(), 8);
        // 128 random bits, not the host's sequential token-ID source.
        assert_eq!(opened.id.len(), 22, "{}", opened.id);
        assert!(!opened.id.starts_with("id-"));
        assert!(codes.insert(opened.code));
        assert!(ids.insert(opened.id));
    }
    assert_eq!(
        fixture.server.open_interaction_code(-1),
        Err(GovernanceError::Code)
    );
    assert_eq!(
        disabled.server.open_interaction_code(2000),
        Err(GovernanceError::Disabled)
    );
}

#[test]
fn hyphen_case_and_aliases_compare_as_one_code() {
    let fixture = fixture(true);
    for symbol in ['1', '0'] {
        let opened = open_with(&fixture, symbol);
        let typed = as_typed(&opened.code);
        assert_ne!(typed, opened.code);
        let response = fixture.server.handle(&raw_post(
            &fixture.owner,
            &format!("/interaction/pending/{}", opened.id),
            json!({ "code": typed }),
        ));
        assert_eq!(response.status(), 200, "{}", error_of(&response));
        assert_eq!(body_of(&response), json!({ "correlated": true }));
    }
}

#[test]
fn code_presentation_does_not_authorize() {
    let fixture = fixture(true);
    let OpenedInteraction { id, code } = fixture.server.open_interaction_code(2000).unwrap();
    let path = format!("/interaction/pending/{id}");
    let OpenedInteraction {
        id: browser_id,
        code: browser_code,
    } = fixture.server.open_interaction_code(2000).unwrap();
    let browser = Request::builder()
        .method("POST")
        .uri(format!(
            "https://ps.example/interaction/pending/{browser_id}"
        ))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "code": browser_code })).unwrap())
        .unwrap();
    let browser = fixture.server.handle(&browser);
    assert_eq!(browser.status(), 200, "{}", error_of(&browser));
    assert_eq!(body_of(&browser), json!({ "correlated": true }));
    assert!(
        fixture
            .server
            .recorded_interaction_decision(&browser_id)
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .server
            .recorded_interaction_decision(&id)
            .unwrap()
            .is_none()
    );
    let early = fixture.server.handle(&approver(
        &format!("{path}/decision"),
        json!({ "decision": "approve" }),
    ));
    assert_eq!(early.status(), 400);
    assert_eq!(error_of(&early), "invalid_request");
    assert!(
        fixture
            .server
            .recorded_interaction_decision(&id)
            .unwrap()
            .is_none()
    );
    let correlated =
        fixture
            .server
            .handle(&raw_post(&fixture.owner, &path, json!({ "code": code })));
    assert_eq!(body_of(&correlated), json!({ "correlated": true }));
    assert!(body_of(&correlated).get("decision").is_none());
    assert!(body_of(&correlated).get("permission").is_none());
    let unsigned = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}/decision"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "decision": "approve" })).unwrap())
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let approved = fixture.server.handle(&approver(
        &format!("{path}/decision"),
        json!({ "decision": "approve" }),
    ));
    assert_eq!(approved.status(), 200, "{}", error_of(&approved));
    assert_eq!(body_of(&approved)["decision"], "approved");
    assert_eq!(
        fixture.server.recorded_interaction_decision(&id).unwrap(),
        Some(aauth_rust_person_server::InteractionDecision::Approved)
    );
    let again = fixture.server.handle(&approver(
        &format!("{path}/decision"),
        json!({ "decision": "deny" }),
    ));
    assert_eq!(again.status(), 400);
    assert_eq!(error_of(&again), "invalid_request");
    assert_eq!(
        fixture.server.recorded_interaction_decision(&id).unwrap(),
        Some(aauth_rust_person_server::InteractionDecision::Approved)
    );
}

#[test]
fn consumed_code_is_invalid() {
    let fixture = fixture(true);
    let OpenedInteraction { id, code } = fixture.server.open_interaction_code(2000).unwrap();
    let path = format!("/interaction/pending/{id}");
    let first = fixture
        .server
        .handle(&raw_post(&fixture.owner, &path, json!({ "code": code })));
    assert_eq!(first.status(), 200);
    let second = fixture
        .server
        .handle(&raw_post(&fixture.owner, &path, json!({ "code": code })));
    assert_eq!(second.status(), 410);
    assert_eq!(error_of(&second), "invalid_code");
}

#[test]
fn failed_attempts_terminally_invalidate_the_code() {
    let fixture = fixture(true);
    let OpenedInteraction { id, code } = fixture.server.open_interaction_code(2000).unwrap();
    let path = format!("/interaction/pending/{id}");
    for _ in 0..3 {
        let wrong = fixture.server.handle(&raw_post(
            &fixture.owner,
            &path,
            json!({ "code": "ZZZZZZZZ" }),
        ));
        assert_eq!(wrong.status(), 410);
        assert_eq!(error_of(&wrong), "invalid_code");
    }
    let right = fixture
        .server
        .handle(&raw_post(&fixture.owner, &path, json!({ "code": code })));
    assert_eq!(right.status(), 410);
    assert_eq!(error_of(&right), "invalid_code");
}

#[test]
fn expired_pending_interaction_rejects_the_code() {
    let fixture = fixture(true);
    let OpenedInteraction { id, code } = fixture.server.open_interaction_code(1000).unwrap();
    let response = fixture.server.handle(&raw_post(
        &fixture.owner,
        &format!("/interaction/pending/{id}"),
        json!({ "code": code }),
    ));
    assert_eq!(response.status(), 408);
    assert_eq!(error_of(&response), "expired");
}

#[test]
fn child_agent_token_does_not_post_an_interaction() {
    let fixture = fixture(true);
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let parent = issue(&ap);
    let child_key = SigningKey::from_seed([4; 32]);
    let child = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent+worker@ap.example".into(),
        jti: "child-interaction".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: child_key.public_jwk(),
        },
        ps: Some("https://ps.example".into()),
        parent_agent: Some("aauth:Agent@ap.example".into()),
        nbf: None,
        extra: Default::default(),
    };
    let compact = ap.issue_subagent(&child, parent.token(), 1000).unwrap();
    let child = Agent::new(child_key, compact).unwrap();
    let response = fixture.server.handle(&raw_post(
        &child,
        "/interaction",
        json!({ "type": "question", "question": "ship it?" }),
    ));
    assert_eq!(response.status(), 401, "{}", error_of(&response));
    assert_eq!(error_of(&response), "invalid_jwt");
}
