# aauth-rust-core

The AAuth tokens shared by every role: the claims of Agent, Person, Resource
and Auth tokens, and the checks that a token was signed by an issuer you
trust and is still valid. The role crates are built on it; use it directly
when your service reads AAuth tokens itself. To protect an HTTP API, use
[aauth-rust-resource](https://crates.io/crates/aauth-rust-resource) instead:
it checks the request's signature as well as its token.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-core@0.1.0-alpha.28 aauth-rust-jose@0.1.0-alpha.28 serde_json@1
```

```rust
use aauth_rust_core::{AgentClaims, AgentProviderKeys, AgentToken, Confirmation};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::json;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // The documents an Agent Provider publishes, as your service fetched them.
    let provider = SigningKey::generate();
    let metadata = json!({
        "issuer": "https://ap.example",
        "jwks_uri": "https://ap.example/.well-known/jwks.json",
    });
    let mut jwk = serde_json::to_value(provider.public_jwk())?;
    jwk["kid"] = json!("ap-1");
    let jwks = json!({"keys": [jwk]});
    let trusted = AgentProviderKeys::from_documents(
        "https://ap.example",
        metadata.to_string().as_bytes(),
        jwks.to_string().as_bytes(),
    )?;

    // A token from that provider verifies, and its claims can be used.
    let token = agent_token("https://ap.example", &provider, now)?;
    let verified = AgentToken::parse(&token)?.verify(&trusted, now)?;
    println!("verified: {}", verified.claims().sub);

    // After it expires, it is refused.
    let later = AgentToken::parse(&token)?.verify(&trusted, now + 3600).unwrap_err();
    println!("expired: {later:?}, wire code {}", later.code());

    // A provider you did not trust is refused before any key is looked up.
    let stranger = agent_token("https://elsewhere.example", &provider, now)?;
    let refused = AgentToken::parse(&stranger)?.verify(&trusted, now).unwrap_err();
    println!("untrusted: {refused:?}, wire code {}", refused.code());
    Ok(())
}

/// An Agent token as a provider issues one. In a provider, use
/// aauth-rust-agent-provider instead.
fn agent_token(issuer: &str, key: &SigningKey, now: i64) -> Result<String, Box<dyn Error>> {
    let domain = issuer.trim_start_matches("https://");
    let claims = AgentClaims {
        iss: issuer.into(),
        dwk: "aauth-agent.json".into(), // the issuer's well-known metadata document
        sub: format!("aauth:assistant@{domain}"),
        jti: "token-1".into(),
        iat: now,
        exp: now + 600,
        cnf: Confirmation { jwk: SigningKey::generate().public_jwk() }, // binds the token to the agent's key
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let header = json!({"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": "ap-1"});
    Ok(Jws::sign(&header, &serde_json::to_vec(&claims)?, key)?)
}
```

```text
verified: aauth:assistant@ap.example
expired: ExpiredJwt, wire code expired_jwt
untrusted: UntrustedIssuer, wire code invalid_key
```

## Why use it

- **Trust is yours, and explicit.** A key resolver answers only for the
  issuers you configured. A token naming any other issuer fails with
  `UntrustedIssuer` before a key is looked up or fetched, so a token can
  never make your service contact a server it chose.
- **Parsing grants nothing.** `parse` keeps the exact compact bytes and
  checks the claim syntax. Claims are usable only from the verified value,
  after the issuer's signature, `exp` and `nbf` are checked.
- **Errors carry the wire code.** Every `TokenError` has the protocol's error
  code from `code()` and a message saying what to fix. This crate does not
  check HTTP request signatures or decide policy: the role crates do.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- Times are Unix seconds, and `exp` has no leeway. Your host supplies the
  clock.
- It never fetches. Your service fetches the metadata and JWKS of the issuers
  it trusts, with its own limits, or uses `aauth-rust-discovery`.

## Specifications

Implements the token, identifier and metadata rules of the AAuth protocol
draft (`draft-hardt-oauth-aauth-protocol`), with the token and wire values of
the Events and Supervision drafts, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e).

## Links

- [API documentation](https://docs.rs/aauth-rust-core)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::core` in the umbrella crate, with the rest of the family
- [How AAuth works](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/how-aauth-works.md): the parties and the tokens
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
