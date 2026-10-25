#![cfg(unix)]

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Grant, Person, PersonRequest,
    PersonServer, Policy, PolicyError,
};
use aauth_rust_person_server_redb::RedbStore;
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
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

fn agent() -> (Agent, AgentProviderKeys) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
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
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    (Agent::new(key, token).unwrap(), keys)
}

fn server(
    store: RedbStore,
    keys: AgentProviderKeys,
) -> PersonServer<AgentProviderKeys, RedbStore, Host, BoxedClock, BoxedTokenIds> {
    let ids = Arc::new(AtomicUsize::new(0));
    PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        keys,
        store,
        Host,
        Box::new(|| 1000i64) as BoxedClock,
        Box::new(move || format!("proposal-{}", ids.fetch_add(1, Ordering::SeqCst)))
            as BoxedTokenIds,
    )
    .unwrap()
    .with_missions()
}

fn signed(agent: &Agent, method: &str, path: &str, body: Option<Value>) -> Request<Vec<u8>> {
    let bytes = body
        .as_ref()
        .map(|value| serde_json::to_vec(value).unwrap())
        .unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://ps.example{path}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder.body(bytes).unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

#[test]
fn approved_mission_bytes_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let (owner, keys) = agent();
    let running = server(RedbStore::open(&path).unwrap(), keys);
    let proposed = running.handle(&signed(
        &owner,
        "POST",
        "/mission",
        Some(json!({ "description": "draft the note" })),
    ));
    assert_eq!(proposed.status(), 202);
    let proposal = proposed.headers()["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let mut approval = Request::builder()
        .method("POST")
        .uri(format!(
            "https://ps.example/mission/proposal/{proposal}/approval"
        ))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "decision": "approve" })).unwrap())
        .unwrap();
    sign_request(
        &mut approval,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        1000,
    )
    .unwrap();
    let approved = running.handle(&approval);
    assert_eq!(approved.status(), 200);
    let delivered = running.handle(&signed(
        &owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(delivered.status(), 200);
    let delivered: Value = serde_json::from_slice(delivered.body()).unwrap();
    let s256 = delivered["s256"].as_str().unwrap().to_owned();
    let mission = delivered["mission"].as_str().unwrap().to_owned();
    drop(running);
    let (owner, keys) = agent();
    let running = server(RedbStore::open(&path).unwrap(), keys);
    let audit = running.handle(&signed(&owner, "GET", &format!("/mission/{s256}"), None));
    assert_eq!(audit.status(), 200);
    let audit: Value = serde_json::from_slice(audit.body()).unwrap();
    assert_eq!(audit["mission"], mission);
    assert_eq!(audit["s256"], s256);
    assert_eq!(audit["updates"].as_array().unwrap().len(), 0);
}
