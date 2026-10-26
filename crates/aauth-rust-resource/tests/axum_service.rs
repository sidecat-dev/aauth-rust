#[path = "../examples/framework/mod.rs"]
mod framework;

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, BoxedAdmissionPolicy, Deny};
use axum::{
    Router,
    body::{Body, to_bytes},
};
use http::Request;
use std::sync::Arc;
use tower::ServiceExt;

fn fixture() -> (Agent, Router) {
    fixture_for("https://resource.example")
}
fn fixture_for(origin: &str) -> (Agent, Router) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let now = framework::now();
    let token = ap
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Agent@ap.example".into(),
            jti: "framework-1".into(),
            iat: now,
            exp: now + 300,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: None,
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    let keys = Arc::new(
        AgentProviderKeys::from_documents(
            "https://ap.example",
            &ap.metadata().unwrap(),
            &ap.jwks().unwrap(),
        )
        .unwrap(),
    );
    let policy: BoxedAdmissionPolicy<String> =
        Box::new(|_: &VerifiedAgentToken, req: &Request<Vec<u8>>| {
            if req.method() == "GET" {
                Ok("demo-account".into())
            } else {
                Err(Deny)
            }
        });
    let resource = Arc::new(AgentIdentityResource::for_origin(origin, keys, policy).unwrap());
    (
        Agent::new(key, token).unwrap(),
        framework::router(
            origin.parse().unwrap(),
            "https://resource.example",
            resource,
        )
        .unwrap(),
    )
}
fn proxy_request(agent: &Agent, uri: &str, body: Vec<u8>) -> Request<Body> {
    let mut req = Request::builder().uri(uri).body(Vec::new()).unwrap();
    agent.sign(&mut req, framework::now()).unwrap();
    let path = req
        .uri()
        .path_and_query()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    *req.uri_mut() = path;
    req.map(|_| Body::from(body))
}

#[tokio::test]
async fn axum_adapts_origin_form_and_delivers_typed_policy_context() {
    let (agent, app) = fixture();
    let unsigned = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.status(), 401);
    assert_eq!(
        unsigned.headers()["aauth-requirement"],
        "requirement=agent-token"
    );
    let response = app
        .clone()
        .oneshot(proxy_request(
            &agent,
            "https://resource.example/whoami?q=1",
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        body.as_ref(),
        b"verified aauth:Agent@ap.example account=demo-account\n"
    );
    let foreign = app
        .oneshot(proxy_request(
            &agent,
            "https://attacker.example/whoami",
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), 401);
    assert_eq!(
        foreign.headers()["signature-error"],
        "error=invalid_signature"
    );
}

#[tokio::test]
async fn axum_reads_real_bodies_and_rejects_over_limit_bodies_before_the_gate() {
    let (agent, app) = fixture();
    let response = app
        .clone()
        .oneshot(proxy_request(
            &agent,
            "https://resource.example/whoami",
            b"changed".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["signature-error"],
        "error=invalid_input, required_input=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-digest\")"
    );
    let oversized = app
        .oneshot(proxy_request(
            &agent,
            "https://resource.example/whoami",
            vec![1; 2048],
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    assert!(!oversized.headers().contains_key("signature-error"));
}

#[tokio::test]
async fn axum_publishes_resource_metadata_without_requiring_an_agent() {
    let (_, app) = fixture();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/aauth-resource.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    let content = to_bytes(response.into_body(), 1024).await.unwrap();
    let document: serde_json::Value = serde_json::from_slice(&content).unwrap();
    assert_eq!(
        document,
        serde_json::json!({"issuer":"https://resource.example","access_mode":"agent-token","signature_window":60})
    );
}

#[tokio::test]
async fn axum_publishes_a_canonical_identity_while_verifying_a_port_bound_target() {
    let (agent, app) = fixture_for("https://resource.example:8443");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/aauth-resource.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let content = to_bytes(response.into_body(), 1024).await.unwrap();
    let document: serde_json::Value = serde_json::from_slice(&content).unwrap();
    assert_eq!(document["issuer"], "https://resource.example");
    for (uri, status) in [
        ("https://resource.example:8443/whoami", 200),
        ("https://resource.example/whoami", 401),
    ] {
        let response = app
            .clone()
            .oneshot(proxy_request(&agent, uri, Vec::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "target {uri}");
    }
}

#[tokio::test]
async fn axum_reuses_one_resource_for_several_router_paths() {
    let (agent, app) = fixture();
    for path in ["/whoami", "/orders?sku=cat%2Ftree"] {
        let response = app
            .clone()
            .oneshot(proxy_request(
                &agent,
                &format!("https://resource.example{path}"),
                Vec::new(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "path {path}");
    }
}
