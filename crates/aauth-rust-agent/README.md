# aauth-rust-agent

The AAuth Agent role, for HTTP clients that call APIs on a person's behalf.
It signs each request with the agent's own key and current token, reads what
an API asks for when it refuses, and checks the tokens servers hand back
before they are used. Use it in any agent, CLI or service that calls AAuth
APIs.

```toml
[dependencies]
aauth-rust-agent = "0.1.0-alpha.26"
aauth-rust-core = "0.1.0-alpha.26"
aauth-rust-jose = "0.1.0-alpha.26"
http = "1"
serde_json = "1"
```

```rust
use aauth_rust_agent::{Agent, Requirement};
use aauth_rust_core::{AgentClaims, Confirmation};
use aauth_rust_jose::{Jws, SigningKey};
use http::{Request, Response};
use serde_json::json;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // The agent's own key, and the Agent token its provider issued for it.
    let key = SigningKey::generate();
    let token = token_from_your_provider(&key, now)?;
    let agent = Agent::new(key, token)?;

    // Sign last, once the request is final, then send it with your HTTP client.
    let mut request = Request::builder()
        .method("POST")
        .uri("https://api.example/notes")
        .header("content-type", "application/json")
        .body(br#"{"text":"hello"}"#.to_vec())?;
    agent.sign(&mut request, now)?;
    println!("{}", request.headers()["signature-input"].to_str()?);

    // When the API refuses with 401, AAuth-Requirement says what it needs next.
    let response = Response::builder()
        .status(401)
        .header("aauth-requirement", "requirement=person-token")
        .body(Vec::<u8>::new())?;
    match Requirement::from_headers(response.headers())? {
        Some(Requirement::PersonToken) => println!("next: a Person token from the Person Server"),
        Some(Requirement::AuthToken { .. }) => println!("next: exchange the Resource token"),
        other => println!("next: {other:?}"),
    }
    Ok(())
}

/// Stands in for the Agent Provider, which issues a token naming the agent's
/// public key. aauth-rust-agent-provider is the provider's side.
fn token_from_your_provider(key: &SigningKey, now: i64) -> Result<String, Box<dyn Error>> {
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:assistant@ap.example".into(),
        jti: "token-1".into(),
        iat: now,
        exp: now + 600,
        cnf: Confirmation { jwk: key.public_jwk() },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let header = json!({"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": "ap-1"});
    Ok(Jws::sign(&header, &serde_json::to_vec(&claims)?, &SigningKey::generate())?)
}
```

```text
sig=("@method" "@authority" "@path" "content-digest" "content-type" "signature-key");created=1793674158
next: a Person token from the Person Server
```

`Agent::new` refuses a token whose confirmation key is not the agent's own.

## Why use it

- **Nothing is sent twice by accident.** The crate signs and checks; it never
  sends, waits or retries. Your HTTP client sends each request, so retries and
  timeouts stay yours. The tradeoff is that you write the send loop.
- **Tokens are checked before use.** `verify_resource_challenge` and
  `verify_auth_delivery` check the Resource and Auth tokens a server hands
  back, against the issuers you trust, before the agent presents them.
- **The rest of the agent's side.** Polling a deferred answer with
  `PollSession`, enrolling a key and refreshing the Agent token with
  `BootstrapClient`, asking for a sub-agent's token, Events subscriptions,
  missions and R3 operation requests.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. Pure Rust.
- The agent's key must outlive a restart, because its Agent token names it.
  Save it with `aauth-rust-jose`, or keep it in a keystore with
  `SigningKey::external`.
- Bodies are buffered and signed up to 1 MiB. Requests must be `https`.
- The host supplies the transport, the clock in Unix seconds, the trusted
  issuers' keys, and storage for tokens.

## Specifications

Implements the Agent side of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`) and of Bootstrap, Events, R3 and
Budgets, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-agent)
- [Agent guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/agent.md): the response flow, keys and tokens
- [Get started](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/getting-started.md): an agent calling an API over TLS
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
