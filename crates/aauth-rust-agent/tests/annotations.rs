//! Published operation annotations are advisory. An operation annotated as
//! needing no more than the Agent holds may still answer `401` or `202` with
//! an `AAuth-Requirement`, and the Agent acts on that runtime requirement.
use std::collections::BTreeMap;

use aauth_rust_agent::{Agent, PollSession, Requirement};
use aauth_rust_core::continuation::Requirement as Pending;
use aauth_rust_core::{
    AgentKeyResolver, Confirmation, PersonClaims, ResourceClaims, TokenError, mint_person_token,
    mint_resource_token,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_r3::{
    AccessMode, AuthoritativeSnapshot, McpCodec, Operation, ToolsListPage, ToolsListSnapshot,
};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest};
use http::{Request, Response};
use serde_json::json;

const NOW: i64 = 1_700_000_000;
const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";
const MCP_ENDPOINT: &str = "https://resource.example/mcp";

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            (PS, "aauth-person.json", "ps-1") => 3,
            (RESOURCE, "aauth-resource.json", "resource-1") => 4,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}

fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = Jws::sign(
        &json!({"typ": "aa-agent+jwt", "alg": "Ed25519", "kid": "ap"}),
        json!({
            "iss": "https://ap.example",
            "dwk": "aauth-agent.json",
            "sub": "aauth:caller@ap.example",
            "jti": "agent-1",
            "iat": NOW,
            "exp": NOW + 3600,
            "ps": PS,
            "cnf": {"jwk": key.public_jwk()}
        })
        .to_string()
        .as_bytes(),
        &SigningKey::from_seed([1; 32]),
    )
    .unwrap();
    Agent::new(key, token).unwrap()
}

fn person(agent: &Agent) -> String {
    mint_person_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "person-1".into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: NOW + 3600,
            cnf: Confirmation {
                jwk: agent.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )
    .unwrap()
}

/// The Resource's challenge to the Person token the Agent presented.
fn challenge(agent: &Agent, jti: &str) -> String {
    mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            sub: "person-1".into(),
            jti: jti.into(),
            iat: NOW,
            exp: NOW + 300,
            ps: PS.into(),
            presented_jti: "person-1".into(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
    )
    .unwrap()
}

/// The Resource's published `tools/list`, with access-mode annotations.
fn published() -> AuthoritativeSnapshot {
    let page = br#"{"tools":[
        {"name":"records.list","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"agent-token"}},
        {"name":"records.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token"}}
    ]}"#;
    McpCodec::parse_definition(
        MCP_ENDPOINT,
        &ToolsListSnapshot::new(vec![ToolsListPage::initial(page)]),
    )
    .unwrap()
}

/// The credential the annotation tells the Agent to expect for `tool`.
fn planned(snapshot: &AuthoritativeSnapshot, tool: &str) -> AccessMode {
    let operation = Operation::new(
        &McpCodec::vocabulary().unwrap(),
        format!(r#"{{"tool":"{tool}"}}"#).as_bytes(),
    )
    .unwrap();
    snapshot
        .hints_for(&operation)
        .unwrap()
        .unwrap()
        .plan(AccessMode::AgentToken)
        .access_mode()
}

/// Sign a `tools/call` and return the credential it presents.
fn call(signer: &Agent, tool: &str) -> String {
    let mut request = Request::post(MCP_ENDPOINT)
        .header("content-type", "application/json")
        .body(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool}})
                .to_string()
                .into_bytes(),
        )
        .unwrap();
    signer.sign(&mut request, NOW).unwrap();
    let proof = PreparedRequest::prepare(&request, "sig", NOW, 60).unwrap();
    proof.verify(&signer.public_jwk()).unwrap();
    let KeyMaterial::Jwt(token) = proof.key() else {
        panic!("jwt credential expected");
    };
    token.clone()
}

fn unauthorized(requirement: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(401)
        .header("aauth-requirement", requirement)
        .body(Vec::new())
        .unwrap()
}

fn pending(location: &str, requirement: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(202)
        .header("location", location)
        .header("retry-after", "0")
        .header("cache-control", "no-store")
        .header("content-type", "application/json")
        .header("aauth-requirement", requirement)
        .body(br#"{"status":"pending"}"#.to_vec())
        .unwrap()
}

#[test]
fn a_runtime_401_requirement_overrides_the_published_annotation() {
    let snapshot = published();
    let agent = agent();
    let person = person(&agent);
    let presenting = agent.with_token(person.clone()).unwrap();

    // Annotated person-token: the Person token the Agent holds should suffice.
    assert_eq!(planned(&snapshot, "records.read"), AccessMode::PersonToken);
    assert_eq!(call(&presenting, "records.read"), person);
    // The Resource asks for an Auth token anyway.
    let resource_token = challenge(&agent, "challenge-1");
    let response = unauthorized(&format!(
        "requirement=auth-token; resource-token=\"{resource_token}\""
    ));
    let Some(Requirement::AuthToken {
        resource_token: extracted,
    }) = Requirement::from_headers(response.headers()).unwrap()
    else {
        panic!("auth-token requirement expected");
    };
    assert_eq!(extracted, resource_token);
    let verified = agent
        .verify_resource_challenge(&extracted, RESOURCE, PS, &person, &Keys, NOW)
        .unwrap();
    assert_eq!(verified.claims().presented_jti, "person-1");

    // The same operation asks for the Agent token instead of the Person token.
    let response = unauthorized("requirement=agent-token");
    assert_eq!(
        Requirement::from_headers(response.headers()).unwrap(),
        Some(Requirement::AgentToken)
    );
    assert_eq!(call(&agent, "records.read"), agent.token());

    // Annotated agent-token: the Agent token should suffice, yet a Person
    // token is required at runtime.
    assert_eq!(planned(&snapshot, "records.list"), AccessMode::AgentToken);
    assert_eq!(call(&agent, "records.list"), agent.token());
    let response = unauthorized("requirement=person-token");
    assert_eq!(
        Requirement::from_headers(response.headers()).unwrap(),
        Some(Requirement::PersonToken)
    );
}

#[test]
fn a_runtime_202_requirement_overrides_the_published_annotation() {
    let snapshot = published();
    let agent = agent();

    // Annotated agent-token, but the Resource first binds the Agent to an
    // account through a person.
    assert_eq!(planned(&snapshot, "records.list"), AccessMode::AgentToken);
    assert_eq!(call(&agent, "records.list"), agent.token());
    let response = pending(
        "/pending/link-1",
        "requirement=interaction; url=\"https://resource.example/link\"; code=\"ABCD-EFGH\"",
    );
    let session = PollSession::new(MCP_ENDPOINT, &response, NOW, NOW + 600).unwrap();
    assert_eq!(
        session.pending().requirement,
        Pending::Interaction {
            url: "https://resource.example/link".into(),
            code: "ABCD-EFGH".into(),
        }
    );
    let poll = session.request(&agent, NOW).unwrap();
    assert_eq!(poll.method(), "GET");
    assert_eq!(poll.uri(), "https://resource.example/pending/link-1");
    let proof = PreparedRequest::prepare(&poll, "sig", NOW, 60).unwrap();
    proof.verify(&agent.public_jwk()).unwrap();

    // Annotated person-token, but the Resource holds the call for an Auth
    // token. The Agent verifies the challenge it is given.
    assert_eq!(planned(&snapshot, "records.read"), AccessMode::PersonToken);
    let person = person(&agent);
    assert_eq!(
        call(&agent.with_token(person.clone()).unwrap(), "records.read"),
        person
    );
    let resource_token = challenge(&agent, "challenge-2");
    let response = pending(
        "/pending/held-1",
        &format!("requirement=auth-token; resource-token=\"{resource_token}\""),
    );
    let session = PollSession::new(MCP_ENDPOINT, &response, NOW, NOW + 600).unwrap();
    let Pending::AuthToken {
        resource_token: extracted,
    } = &session.pending().requirement
    else {
        panic!("held auth-token requirement expected");
    };
    agent
        .verify_resource_challenge(extracted, RESOURCE, PS, &person, &Keys, NOW)
        .unwrap();
    assert_eq!(
        session.request(&agent, NOW).unwrap().uri(),
        "https://resource.example/pending/held-1"
    );
}
