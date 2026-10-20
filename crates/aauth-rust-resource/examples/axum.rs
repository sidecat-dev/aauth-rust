//! One-shot framework integration on the private HTTP hop behind a TLS proxy.
mod framework;
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, BoxedAdmissionPolicy, Deny};
use axum::body::{Body, to_bytes};
use http::Request;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = framework::now();
    let ap = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;
    let key = SigningKey::generate();
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent@ap.example".into(),
        jti: "framework-demo-1".into(),
        iat: now,
        exp: now + 300,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: [("account".into(), serde_json::json!("demo-account"))].into(),
    };
    let agent = Agent::new(key, ap.issue(&claims)?)?;
    let keys = Arc::new(AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata()?,
        &ap.jwks()?,
    )?);
    let policy: BoxedAdmissionPolicy<String> =
        Box::new(|token: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            token
                .claims()
                .extra
                .get("account")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or(Deny)
        });
    let resource = Arc::new(AgentIdentityResource::for_origin(
        "https://resource.example",
        keys,
        policy,
    )?);
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let app = framework::router("https://resource.example".parse()?, resource);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut request = Request::builder()
        .uri("https://resource.example/whoami?profile=demo")
        .body(Vec::new())?;
    agent.sign(&mut request, now)?;
    // Demo socket map: TLS terminates before this hop; signed origin stays logical.
    *request.uri_mut() = format!("http://{address}/whoami?profile=demo").parse()?;
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build_http();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.request(request.map(Body::from)),
    )
    .await??;
    assert_eq!(response.status(), 200);
    let body = to_bytes(Body::new(response.into_body()), 1024).await?;
    print!("{}", std::str::from_utf8(&body)?);
    drop(client);
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    Ok(())
}
