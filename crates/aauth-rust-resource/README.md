# aauth-rust-resource

The AAuth Resource role: put it in front of your API's handlers, and every
request is checked before your code runs. It verifies the agent's signature
and token, asks your policy whether to admit it, and gives you either the
verified caller or the exact 401 or 403 to send. Use it in any HTTP API that
AI agents and other software agents call.

```toml
[dependencies]
aauth-rust-resource = "0.1.0-alpha.26"
aauth-rust-core = "0.1.0-alpha.26"
http = "1"
```

The example runs the whole exchange in one process, so it also uses
`aauth-rust-agent`, `aauth-rust-agent-provider` and `aauth-rust-jose` to play
the agent and its provider.

```rust
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::AgentIdentityResource;
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // The Agent Provider you trust, by the documents it publishes.
    let provider = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &provider.metadata()?,
        &provider.jwks()?,
    )?;

    // Your API at https://api.example, admitting only the assistant.
    let api = AgentIdentityResource::for_origin(
        "https://api.example",
        keys,
        |agent: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            agent.claims().sub == "aauth:assistant@ap.example"
        },
    )?;

    // A request with no signature gets a 401 that says what is needed.
    let unsigned = Request::builder().uri("https://api.example/hello").body(Vec::new())?;
    let refusal = api.authorize(&unsigned, now).into_response();
    println!("{} {:?}", refusal.status().as_u16(), refusal.headers()["aauth-requirement"]);

    // The assistant signs the same request with its key and Agent token.
    let assistant = enroll(&provider, "assistant", now)?;
    let mut request = Request::builder().uri("https://api.example/hello").body(Vec::new())?;
    assistant.sign(&mut request, now)?;
    match api.authorize(&request, now).into_result() {
        Ok((agent, ())) => println!("200 hello, {}", agent.claims().sub),
        Err(refusal) => println!("{}", refusal.status().as_u16()),
    }
    Ok(())
}

/// An agent with its own key, and the Agent token its provider issued for it.
fn enroll(provider: &AgentProvider, name: &str, now: i64) -> Result<Agent, Box<dyn std::error::Error>> {
    let key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: format!("aauth:{name}@ap.example"),
        jti: format!("{name}-{now}"),
        iat: now,
        exp: now + 600,
        cnf: Confirmation { jwk: key.public_jwk() },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}
```

```text
401 "requirement=agent-token"
200 hello, aauth:assistant@ap.example
```

An agent the policy refuses gets `403`, with no `Signature-Error`, so it knows
its signature was accepted.

## Why use it

- **Verification before policy.** Your policy runs only after the signature,
  the token's issuer and expiry, and the binding between them are checked, so
  it sees a verified caller and nothing else.
- **Three ways to decide who gets in.** `AgentIdentityResource` admits by the
  agent's identity. `PersonIdentityResource` asks for a Person token that
  names the person. `PsAuthorizationResource` issues Resource tokens and
  accepts Auth tokens with scopes, from the person's Person Server or from
  your own Access Server. R3 operations, budgets, Events and revocation are
  opt-in on top.
- **Any HTTP stack.** It works on buffered `http::Request<Vec<u8>>` values
  and returns `http::Response` refusals, and the repository has an axum
  example. The tradeoff: you route the well-known documents and collect the
  body yourself; `metadata()` gives you the document to serve.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. The library is pure Rust; the
  repository's TLS examples need a C compiler.
- It opens no connections. The host supplies the trusted issuers and their
  keys (fetched with `aauth-rust-discovery` or your own client), the clock in
  Unix seconds, and storage for any state the opt-in features keep.
- Signatures are accepted for 60 seconds either side of your clock. Bodies
  are checked up to 1 MiB.

## Specifications

Implements the Resource side of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`) and of R3, Budgets and Events, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-resource)
- [Resource guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/resource.md): each way to decide, and the endpoints to serve
- [Get started](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/getting-started.md): an agent calling an API over TLS
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
