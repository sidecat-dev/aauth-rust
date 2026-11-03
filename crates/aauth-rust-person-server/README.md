# aauth-rust-person-server

The AAuth Person Server role: the server that knows which person an agent
acts for and what that person allows. It binds agents to people, issues
Person tokens that tell an API who the person is, and issues Auth tokens
for what the person approved, itself or through an API's Access Server. Use
it to run the server that speaks for your users.

```toml
[dependencies]
aauth-rust-person-server = "0.1.0-alpha.27"
aauth-rust-core = "0.1.0-alpha.27"
aauth-rust-jose = "0.1.0-alpha.27"
http = "1"
serde_json = "1"
```

The example runs in one process, so it also uses `aauth-rust-agent` and
`aauth-rust-agent-provider` to play the agent and its provider.

```rust
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, PersonToken, TrustedIssuerKeys};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer,
    Policy, PolicyError,
};
use http::Request;
use serde_json::{Value, json};
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PS: &str = "https://ps.example";

/// Your decisions: who the person is, and what they allow.
struct People;
impl Policy for People {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        // Look the agent up in your own accounts.
        if request.agent.claims().sub != "aauth:assistant@ap.example" {
            return Err(PolicyError::Denied);
        }
        Ok(Person {
            id: "person-1".into(),      // your internal id, never published
            subject: "u-7f3c9a".into(), // what the API sees
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        if request.scopes == ["notes.read"] {
            Ok(Grant { scopes: request.scopes.clone(), lifetime: 600 })
        } else {
            Err(PolicyError::Denied)
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // The agent, and the Agent Provider this Person Server trusts.
    let provider = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;
    let agent = enroll(&provider)?;
    let providers =
        AgentProviderKeys::from_documents("https://ap.example", &provider.metadata()?, &provider.jwks()?)?;

    // The Person Server. MemoryStore keeps its records in memory only.
    let ids = AtomicU64::new(0);
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::generate()),
        providers,
        MemoryStore::default(),
        People,
        now,
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?;

    // The agent asks for a Person token for the notes API.
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(json!({"resource": "https://api.example"}).to_string().into_bytes())?;
    agent.sign(&mut request, now())?;
    let response = ps.handle(&request);
    let body: Value = serde_json::from_slice(response.body())?;
    let token = body["person_token"].as_str().ok_or("no Person token")?;

    // The API checks it with the Person Server's published keys.
    let metadata = ps.handle(&Request::get(format!("{PS}/.well-known/aauth-person.json")).body(Vec::new())?);
    let jwks = ps.handle(&Request::get(format!("{PS}/.well-known/jwks.json")).body(Vec::new())?);
    let keys = TrustedIssuerKeys::from_documents(PS, "aauth-person.json", metadata.body(), jwks.body())?;
    let person = PersonToken::parse(token)?.verify(&keys, now())?;
    println!("{} for {}", person.claims().sub, person.claims().aud);
    Ok(())
}

/// An agent with its own key and an Agent token naming this Person Server.
fn enroll(provider: &AgentProvider) -> Result<Agent, Box<dyn Error>> {
    let key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:assistant@ap.example".into(),
        jti: "assistant-1".into(),
        iat: now(),
        exp: now() + 3600,
        cnf: Confirmation { jwk: key.public_jwk() },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
```

```text
u-7f3c9a for https://api.example
```

The API sees `u-7f3c9a`, the subject your policy chose for it, never the
internal `person-1`.

## Why use it

- **Your accounts, your consent screens.** The library checks every
  request's signature and tokens, keeps the records, and signs the tokens.
  Who the person is and what they allow are the two `Policy` methods, and
  they see only verified requests.
- **Every grant path of the protocol.** Auth tokens issued directly, Auth
  tokens from an API's Access Server through `with_federation`, deferred
  answers while the person decides, call chaining from one API to another,
  missions, R3 operations, budgets and supervision.
- **Storage you choose.** The `Store` trait is the only state. `MemoryStore`
  is for tests and examples; `aauth-rust-person-server-redb` is a durable
  store, and the crate ships the contract tests your own store must pass.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. Pure Rust.
- The host authenticates the person, supplies the trusted issuers' keys, an
  atomic store, the clock in Unix seconds, and fresh token ids.
- It routes nothing and fetches nothing: your HTTP server passes requests to
  `handle`, and reaching an Access Server or a supervision server goes
  through adapters you supply.

## Specifications

Implements the Person Server side of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`), including call chaining and missions,
and of R3, Budgets and Supervision, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-person-server)
- [Person Server guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/person-server.md): the full flow to an Auth token, and the endpoints
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
