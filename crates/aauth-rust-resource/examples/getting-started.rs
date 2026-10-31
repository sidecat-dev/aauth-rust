//! An Agent calls an API over TLS on this machine.
//!
//! Two servers run on loopback ports: an Agent Provider that issues Agent
//! tokens, and an API that checks them. `support/tls.rs` is a small HTTP/1.1
//! transport for the examples, not a server library.
#[path = "support/tls.rs"]
mod tls;

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken, metadata_jwks_uri,
};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::AgentIdentityResource;
use http::{Request, Response};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), Error> {
    // The Agent Provider signs Agent tokens and publishes the key that checks them.
    let provider = Arc::new(AgentProvider::new(
        "https://ap.example",
        "ap-key-1",
        SigningKey::generate(),
    )?);
    let published = provider.clone();
    let ap = tls::TlsServer::start("ap.example", move |request| {
        let document = match request.uri().path() {
            "/.well-known/aauth-agent.json" => published.metadata(),
            "/.well-known/jwks.json" => published.jwks(),
            _ => return status(404),
        };
        Response::new(document.unwrap())
    })?;

    // The API fetches the provider's public key over TLS, then checks every request.
    let metadata = ap.send(&get("https://ap.example/.well-known/aauth-agent.json")?)?;
    let jwks_uri = metadata_jwks_uri("https://ap.example", metadata.body())?;
    let jwks = ap.send(&get(&jwks_uri)?)?;
    let keys =
        AgentProviderKeys::from_documents("https://ap.example", metadata.body(), jwks.body())?;
    let resource = AgentIdentityResource::for_origin(
        "https://api.example",
        keys,
        |agent: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            agent.claims().sub == "aauth:assistant@ap.example"
        },
    )?;
    let api = tls::TlsServer::start("api.example", move |request| {
        match resource.authorize(&request, now()).into_result() {
            Ok((agent, ())) => Response::new(format!("hello, {}", agent.claims().sub).into_bytes()),
            Err(refusal) => *refusal,
        }
    })?;

    // Without a signature, the API answers 401 and says what it needs.
    let response = api.send(&get("https://api.example/hello")?)?;
    println!(
        "unsigned: {} {}",
        response.status().as_u16(),
        requirement(&response)
    );

    // The Agent signs the request with its own key and presents its Agent token.
    let assistant = enroll(&provider, "assistant")?;
    let mut request = get("https://api.example/hello")?;
    assistant.sign(&mut request, now())?;
    let response = api.send(&request)?;
    println!(
        "signed: {} {}",
        response.status().as_u16(),
        String::from_utf8_lossy(response.body())
    );

    // A valid signature from an agent the API's policy does not admit gets 403.
    let other = enroll(&provider, "other")?;
    let mut request = get("https://api.example/hello")?;
    other.sign(&mut request, now())?;
    println!("not admitted: {}", api.send(&request)?.status().as_u16());
    Ok(())
}

/// The agent makes its own key; the provider issues a token that names it.
fn enroll(provider: &AgentProvider, name: &str) -> Result<Agent, Error> {
    let key = SigningKey::generate();
    let issued = now();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: format!("aauth:{name}@ap.example"),
        jti: format!("{name}-{issued}"),
        iat: issued,
        exp: issued + 600,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

fn get(uri: &str) -> Result<Request<Vec<u8>>, Error> {
    Ok(Request::builder().uri(uri).body(Vec::new())?)
}

fn status(code: u16) -> Response<Vec<u8>> {
    Response::builder().status(code).body(Vec::new()).unwrap()
}

fn requirement(response: &Response<Vec<u8>>) -> &str {
    response
        .headers()
        .get("aauth-requirement")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}
