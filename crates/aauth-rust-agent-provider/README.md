# aauth-rust-agent-provider

The AAuth Agent Provider role: a server that vouches for agents by issuing
Agent tokens, each naming an agent and the public key it signs with, and
publishes the keys that let any API check those tokens. Use it to run the
provider for your own agents.

```toml
[dependencies]
aauth-rust-agent-provider = "0.1.0-alpha.26"
aauth-rust-core = "0.1.0-alpha.26"
aauth-rust-jose = "0.1.0-alpha.26"
```

```rust
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, AgentToken, Confirmation};
use aauth_rust_jose::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let provider = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;

    // An agent made its own key and sent you the public half. You decided it
    // is the assistant; now you vouch for it for ten minutes.
    let agent_key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:assistant@ap.example".into(),
        jti: format!("assistant-{now}"),
        iat: now,
        exp: now + 600,
        cnf: Confirmation { jwk: agent_key.public_jwk() },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;

    // Serve these at /.well-known/aauth-agent.json and /.well-known/jwks.json.
    let metadata = provider.metadata()?;
    let jwks = provider.jwks()?;
    println!("{}", String::from_utf8(metadata.clone())?);

    // Any API that trusts this provider checks the token with those documents.
    let keys = AgentProviderKeys::from_documents("https://ap.example", &metadata, &jwks)?;
    let verified = AgentToken::parse(&token)?.verify(&keys, now)?;
    assert_eq!(verified.claims().sub, "aauth:assistant@ap.example");
    Ok(())
}
```

```text
{"issuer":"https://ap.example","jwks_uri":"https://ap.example/.well-known/jwks.json"}
```

## Why use it

- **Issuance policy stays yours.** `issue` signs exactly the claims you pass,
  after checking them against the token profile. How you decide that an agent
  is who it says it is happens before that call, in your code.
- **Keys that never leave a keystore.** The provider's signing key can be a
  `SigningKey::external` held by an HSM or a remote signer.
- **The provider's other duties.** The `bootstrap` module enrolls an agent
  install's durable key, refreshes its Agent token and issues sub-agent
  tokens; it also issues for agents of a self-hosted domain. The `events`
  module runs the Events inbox that relays an API's notifications to the
  agent.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. Pure Rust.
- It routes nothing: your HTTP server serves the two documents and calls
  `issue`. The host supplies each token's claims, with a unique `jti` and
  times in Unix seconds from its clock, and keeps the provider's key.

## Specifications

Implements the Agent Provider side of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`) and of Bootstrap and Events, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-agent-provider)
- [Agent Provider guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/agent-provider.md)
- [Bootstrap guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/features/bootstrap.md): enrollment, refresh and sub-agents
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
