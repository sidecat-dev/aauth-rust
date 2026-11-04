# aauth-rust-supervision-server

The AAuth Supervision Server role: a server a person connects to their
Person Server, which then asks it about every act of the agents routed there
(proposed missions, token requests, permissions) and gets back `allow`,
`deny` or `ask`. Use it to build an approval service that applies a person's
or an organization's standing rules to their agents.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-core@0.1.0-alpha.29 aauth-rust-jose@0.1.0-alpha.29 aauth-rust-signature-key@0.1.0-alpha.29 aauth-rust-supervision-server@0.1.0-alpha.29 http@1 serde_json@1
```

```rust
use aauth_rust_core::TrustedIssuerKeys;
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::supervision::{Allowance, DECISION_COMPONENTS, accept_signature_field};
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use aauth_rust_supervision_server::{
    Case, Config, ConnectAnswer, ConnectRequest, Policy, SupervisionServer, Verdict,
};
use http::Request;
use serde_json::{Value, json};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

const PS: &str = "https://ps.example";

/// Your standing rules: who may connect, and what their agents may do.
struct Rules;
impl Policy for Rules {
    fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
        match request.tenant.as_deref() {
            Some("acme.example") => ConnectAnswer::Connected,
            _ => ConnectAnswer::Refused,
        }
    }
    fn decide(&self, case: &Case) -> Verdict {
        match case.action() {
            Some("SendEmail") => Verdict::Ask(Default::default()), // the person decides
            _ => Verdict::Allow(Allowance::default()),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // The one Person Server this server answers, known by its published keys.
    let ps_key = SigningKey::generate();
    let (metadata, jwks) = published(PS, &ps_key)?;
    let person_servers = TrustedIssuerKeys::from_documents(PS, "aauth-person.json", &metadata, &jwks)?;
    let server = SupervisionServer::new(
        Config::new("https://ss.example").with_signing("ss-1", SigningKey::generate()),
        person_servers,
        Rules,
        MemoryContinuations::new(10_000),
        now,
    )?;

    // The Person Server connects a person, then asks about two acts of their agent.
    let connect = json!({"action": "connect", "id": "c-1", "iat": now(),
                         "sub": "person-1", "tenant": "acme.example"});
    assert_eq!(server.handle(&from_ps(&ps_key, "/connect", connect)?).status(), 200);
    // sdi is the decision's id, which the Person Server mints for each act.
    for (sdi, action) in [("d-1", "ReadInbox"), ("d-2", "SendEmail")] {
        let act = json!({"sdi": sdi, "act": "permission", "iat": now(), "sub": "person-1",
                         "agent": "aauth:assistant@ap.example", "action": action});
        let answer = server.handle(&from_ps(&ps_key, "/decision", act)?);
        let body: Value = serde_json::from_slice(answer.body())?;
        println!("{action}: {}", body["decision"]);
    }
    Ok(())
}

/// A request signed by the Person Server, as it arrives over HTTPS.
fn from_ps(key: &SigningKey, path: &str, body: Value) -> Result<Request<Vec<u8>>, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("https://ss.example{path}"))
        .header("content-type", "application/json")
        .header("accept-signature", accept_signature_field(&DECISION_COMPONENTS))
        .body(body.to_string().into_bytes())?;
    let signer = KeyMaterial::JwksUri {
        id: PS.into(),
        dwk: "aauth-person.json".into(), // the issuer's well-known metadata document
        kid: "ps-1".into(),
    };
    sign_request(&mut request, key, signer, now())?;
    Ok(request)
}

/// The metadata and JWKS a Person Server publishes.
fn published(issuer: &str, key: &SigningKey) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let metadata = json!({"issuer": issuer, "jwks_uri": format!("{issuer}/.well-known/jwks.json")});
    let mut jwk = serde_json::to_value(key.public_jwk())?;
    jwk["kid"] = json!("ps-1");
    Ok((metadata.to_string().into_bytes(), json!({"keys": [jwk]}).to_string().into_bytes()))
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
```

```text
ReadInbox: "allow"
SendEmail: "ask"
```

## Why use it

- **It only answers.** The server issues no tokens and calls no one. Every
  decision is the response to a Person Server's signed request, and with a
  signing key each terminal answer is signed, so the Person Server's record
  shows who decided what.
- **Your policy sees a checked case.** The Person Server's signature, the
  person's connection and the act are verified before `decide` runs. A retry
  under the same decision id gets the same signed answer without deciding
  again.
- **More than yes or no.** A verdict can allow with narrowing, deny, ask the
  person, ask the agent a question first, or defer, and `observe` receives
  what the Person Server reports afterwards.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- The host supplies the policy, the keys of the Person Servers it admits, one
  atomic `ContinuationStore` for every record, and the clock in Unix seconds.
  `MemoryContinuations` keeps records in memory only.
- It routes nothing and sends nothing: your HTTP server passes requests to
  `handle` and sends back what it returns.

## Specifications

Implements Supervision (`draft-hardt-aauth-supervision`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with request and response signatures from HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-supervision-server)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::supervision_server` in the umbrella crate, with the rest of the family
- [Supervision Server guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/supervision-server.md)
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
