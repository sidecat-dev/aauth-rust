use aauth_rust_agent::{AccessSession, Agent};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{
    AgentIdentityResource, BoxedPolicy, Decision, SessionAdmit, SessionLedger,
};
use http::{Request, Response};

fn agent(seed: u8, subject: &str) -> (Agent, AgentProviderKeys) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([seed; 32]);
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: subject.into(),
        jti: format!("agent-{seed}"),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let token = ap.issue(&claims).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    (Agent::new(key, token).unwrap(), keys)
}

fn resource(keys: AgentProviderKeys) -> AgentIdentityResource<AgentProviderKeys, BoxedPolicy> {
    AgentIdentityResource::new(
        "https://resource.example/data",
        keys,
        Box::new(|_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true) as BoxedPolicy,
    )
    .unwrap()
}

fn request() -> Request<Vec<u8>> {
    Request::builder()
        .method("GET")
        .uri("https://resource.example/data")
        .body(Vec::new())
        .unwrap()
}

fn signed(agent: &Agent, session: &AccessSession) -> Request<Vec<u8>> {
    let mut request = request();
    session.apply(&mut request).unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

#[test]
fn signed_session_covers_authorization() {
    let (owner, keys) = agent(2, "aauth:Agent@ap.example");
    let resource = resource(keys);
    let ledger = SessionLedger::new();
    ledger
        .issue("aauth:Agent@ap.example", "opaque-session-token")
        .unwrap();
    let session = AccessSession::receive(["opaque-session-token"]).unwrap();
    let request = signed(&owner, &session);
    let covered = request.headers()["signature-input"].to_str().unwrap();
    assert!(covered.contains("\"authorization\""));
    assert_eq!(
        request.headers()["authorization"].to_str().unwrap(),
        "AAuth opaque-session-token"
    );
    assert!(matches!(
        resource.authorize(&request, 1000),
        Decision::Granted(_)
    ));
    assert_eq!(
        resource.admit_session(&ledger, &request, 1000),
        SessionAdmit::Granted {
            holder: "aauth:Agent@ap.example".into(),
        }
    );
}

#[test]
fn session_token_is_not_a_standalone_bearer() {
    let (owner, keys) = agent(2, "aauth:Agent@ap.example");
    let (other, _) = agent(9, "aauth:Other@ap.example");
    let resource = resource(keys);
    let ledger = SessionLedger::new();
    ledger
        .issue("aauth:Agent@ap.example", "opaque-session-token")
        .unwrap();
    let session = AccessSession::receive(["opaque-session-token"]).unwrap();

    let mut bare = request();
    bare.headers_mut().insert(
        "authorization",
        "AAuth opaque-session-token".parse().unwrap(),
    );
    assert!(matches!(
        resource.authorize(&bare, 1000),
        Decision::AgentTokenRequired
    ));
    assert_eq!(
        resource.admit_session(&ledger, &bare, 1000),
        SessionAdmit::Standalone
    );

    let mut uncovered = request();
    owner.sign(&mut uncovered, 1000).unwrap();
    uncovered.headers_mut().insert(
        "authorization",
        "AAuth opaque-session-token".parse().unwrap(),
    );
    assert!(matches!(
        resource.authorize(&uncovered, 1000),
        Decision::SignatureFailure(_)
    ));
    assert_eq!(
        resource.admit_session(&ledger, &uncovered, 1000),
        SessionAdmit::Standalone
    );

    let foreign = signed(&other, &session);
    assert!(matches!(
        resource.authorize(&foreign, 1000),
        Decision::Granted(_)
    ));
    assert_eq!(
        resource.admit_session(&ledger, &foreign, 1000),
        SessionAdmit::Unbound
    );

    assert_eq!(
        resource.admit_session(&ledger, &request(), 1000),
        SessionAdmit::Invalid
    );
    let mut spaced = request();
    spaced
        .headers_mut()
        .insert("authorization", "AAuth opaque token".parse().unwrap());
    owner.sign(&mut spaced, 1000).unwrap();
    assert_eq!(
        resource.admit_session(&ledger, &spaced, 1000),
        SessionAdmit::Invalid
    );
    let mut doubled = request();
    doubled.headers_mut().append(
        "authorization",
        "AAuth opaque-session-token".parse().unwrap(),
    );
    doubled
        .headers_mut()
        .append("authorization", "AAuth second-token".parse().unwrap());
    owner.sign(&mut doubled, 1000).unwrap();
    assert_eq!(
        resource.admit_session(&ledger, &doubled, 1000),
        SessionAdmit::Invalid
    );
}

#[test]
fn replaced_session_token_is_used_on_the_next_request() {
    let (owner, keys) = agent(2, "aauth:Agent@ap.example");
    let resource = resource(keys);
    let ledger = SessionLedger::new();
    ledger
        .issue("aauth:Agent@ap.example", "opaque-session-token")
        .unwrap();
    let mut session = AccessSession::receive(["opaque-session-token"]).unwrap();
    let first = signed(&owner, &session);
    assert!(matches!(
        resource.admit_session(&ledger, &first, 1000),
        SessionAdmit::Granted { .. }
    ));

    ledger
        .issue("aauth:Agent@ap.example", "next-session-token")
        .unwrap();
    let mut response = Response::new(Vec::new());
    SessionLedger::set_access_header(&mut response, "next-session-token").unwrap();
    assert_eq!(
        response.headers()["aauth-access"].to_str().unwrap(),
        "next-session-token"
    );
    session
        .note([response.headers()["aauth-access"].to_str().unwrap()])
        .unwrap();
    assert!(session.note(Vec::<&str>::new()).is_ok());
    assert!(session.note(["first", "second"]).is_err());
    assert_eq!(session.token(), "next-session-token");

    let next = signed(&owner, &session);
    assert_eq!(
        next.headers()["authorization"].to_str().unwrap(),
        "AAuth next-session-token"
    );
    assert!(
        next.headers()["signature-input"]
            .to_str()
            .unwrap()
            .contains("\"authorization\"")
    );
    assert_eq!(
        resource.admit_session(&ledger, &next, 1000),
        SessionAdmit::Granted {
            holder: "aauth:Agent@ap.example".into(),
        }
    );
    assert_eq!(
        resource.admit_session(&ledger, &first, 1000),
        SessionAdmit::Unbound
    );
}
