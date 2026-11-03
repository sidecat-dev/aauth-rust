# aauth-rust

[AAuth](https://github.com/dickhardt/AAuth) tells an API which software agent
is calling it and on whose behalf: the agent signs every HTTP request with
its own key, and the API checks that signature and the token sent with it,
asking for a token that names the person when it needs one. This crate is
every role of AAuth for Rust in one dependency, one module per crate.

```sh
cargo add aauth-rust http
```

An agent calls an API, in one process: the Agent Provider vouches for the
agent, the agent signs its request, and the Resource checks it before the
API's handler runs.

```rust
use aauth_rust::agent::Agent;
use aauth_rust::agent_provider::AgentProvider;
use aauth_rust::core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust::jose::SigningKey;
use aauth_rust::resource::AgentIdentityResource;
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // The Agent Provider vouches for the assistant and the key it signs with.
    let provider = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;
    let key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(), // the provider's well-known metadata document
        sub: "aauth:assistant@ap.example".into(),
        jti: format!("assistant-{now}"),
        iat: now,
        exp: now + 600,
        cnf: Confirmation { jwk: key.public_jwk() }, // binds the token to the agent's key
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let agent = Agent::new(key, token)?;

    // The API trusts that provider, by the documents it publishes.
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &provider.metadata()?,
        &provider.jwks()?,
    )?;
    let api = AgentIdentityResource::for_origin(
        "https://api.example",
        keys,
        |agent: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            agent.claims().sub == "aauth:assistant@ap.example"
        },
    )?;

    // The agent signs; the API admits it and knows who is calling.
    let mut request = Request::builder().uri("https://api.example/hello").body(Vec::new())?;
    agent.sign(&mut request, now)?;
    match api.authorize(&request, now).into_result() {
        Ok((caller, ())) => println!("hello, {}", caller.claims().sub),
        Err(refusal) => println!("refused: {}", refusal.status().as_u16()),
    }
    Ok(())
}
```

```text
hello, aauth:assistant@ap.example
```

Each module is one crate of the family:

| Module | Crate | Role |
| --- | --- | --- |
| `agent` | [aauth-rust-agent](https://crates.io/crates/aauth-rust-agent) | Agent: signs an agent's requests and checks the tokens it receives |
| `agent_provider` | [aauth-rust-agent-provider](https://crates.io/crates/aauth-rust-agent-provider) | Agent Provider: issues Agent tokens and publishes its keys |
| `resource` | [aauth-rust-resource](https://crates.io/crates/aauth-rust-resource) | Resource, the API: checks requests before your handler runs |
| `person_server` | [aauth-rust-person-server](https://crates.io/crates/aauth-rust-person-server) | Person Server: speaks for the person, and issues their tokens |
| `person_server_redb` | [aauth-rust-person-server-redb](https://crates.io/crates/aauth-rust-person-server-redb) | Durable file storage for a Person Server, on Unix |
| `access_server` | [aauth-rust-access-server](https://crates.io/crates/aauth-rust-access-server) | Access Server: decides access by the API's own rules |
| `supervision_server` | [aauth-rust-supervision-server](https://crates.io/crates/aauth-rust-supervision-server) | Supervision Server: approves or refuses an agent's acts for the person |
| `discovery` | [aauth-rust-discovery](https://crates.io/crates/aauth-rust-discovery) | Fetches other servers' keys and delivers revocations over HTTPS |
| `core`, `signature_key`, `jose` | [core](https://crates.io/crates/aauth-rust-core), [signature-key](https://crates.io/crates/aauth-rust-signature-key), [jose](https://crates.io/crates/aauth-rust-jose) | Tokens, HTTP signatures and keys, shared by every role |
| `r3`, `budgets` | [r3](https://crates.io/crates/aauth-rust-r3), [budgets](https://crates.io/crates/aauth-rust-budgets) | Named operations and spending caps, shared by the roles |

## Why use it

- **One version for the whole family.** The crates are released together;
  one dependency keeps them in step.
- **Keep only the roles you run.** Every module is on by default. Each role
  module and `discovery` has a Cargo feature of the same name, so an API that
  only checks requests can keep just the Resource:

  ```toml
  [dependencies]
  aauth-rust = { version = "0.1.0-alpha.27", default-features = false, features = ["resource"] }
  ```

- **No network unless you ask.** The protocol modules open no connections:
  your service sends and receives the messages, and the libraries sign, check
  and decide. `discovery` is the one module that connects, and it refuses
  private addresses and other unsafe destinations unless you allow them.

## Compatibility and limits

- Rust 1.99 or later, edition 2024.
- The default features include `discovery`, whose TLS library needs a C
  compiler to build. Without `discovery`, everything is pure Rust.
- `person_server_redb` works on Unix only.
- The host supplies the transport, the trusted issuers and their keys, the
  clock in Unix seconds, key custody and storage.

## Specifications

Implements the AAuth protocol draft (`draft-hardt-oauth-aauth-protocol`) and
the Bootstrap, Budgets, Events, R3 and Supervision drafts, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
and HTTP Signature Keys (`draft-hardt-httpbis-signature-key`), from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades passes, for every role.

## Links

- [API documentation](https://docs.rs/aauth-rust)
- [Guides](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/README.md): one per role and feature
- [Get started](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/getting-started.md): an agent calling an API over TLS
- [How AAuth works](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/how-aauth-works.md)
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
