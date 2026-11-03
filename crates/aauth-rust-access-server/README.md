# aauth-rust-access-server

The AAuth Access Server role: the server that decides access to an API by
the API's own rules. A person's Person Server asks it for an Auth token for
an agent, and it checks every signature and token in the request, runs your
policy, and issues the Auth token the API will accept. Use it when your API
keeps its own access rules instead of trusting each person's Person Server.

```toml
[dependencies]
aauth-rust-access-server = "0.1.0-alpha.28"
aauth-rust-core = "0.1.0-alpha.28"
aauth-rust-jose = "0.1.0-alpha.28"
http = "1"
# used by the example to play the other parties
aauth-rust-agent-provider = "0.1.0-alpha.28"
aauth-rust-signature-key = "0.1.0-alpha.28"
serde_json = "1"
```

In the example, `from_person_server` stands in for the Person Server and the
API.

```rust
use aauth_rust_access_server::{AccessServer, AuthorizationRequest, Config, Decision, PolicyError};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonClaims, ResourceClaims,
    TokenError, mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const AS: &str = "https://as.example";
const PS: &str = "https://ps.example";
const API: &str = "https://api.example";

fn main() -> Result<(), Box<dyn Error>> {
    let others = Others::new()?;
    let as_key = SigningKey::generate();
    let trust = Trust(vec![
        ("https://ap.example", "aauth-agent.json", "ap-1", others.ap.clone()),
        (PS, "aauth-person.json", "ps-1", others.ps.public_jwk()),
        (API, "aauth-resource.json", "api-1", others.api.public_jwk()),
        (AS, "aauth-access.json", "as-1", as_key.public_jwk()),
    ]);

    // The API's rule: Person Server ps.example may have notes.read, for an hour.
    let ids = AtomicU64::new(0);
    let server = AccessServer::new(
        Config::new(AS, "as-1", as_key),
        trust.clone(),
        |request: &AuthorizationRequest| {
            if request.person_server == PS && request.scopes == ["notes.read"] {
                Ok(Decision { scopes: request.scopes.clone(), lifetime: 3600 })
            } else {
                Err(PolicyError::Denied)
            }
        },
        now,
        move || format!("as-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?;

    // The Person Server asks for an Auth token for its agent.
    let response = server.handle(&others.from_person_server("notes.read")?);
    let body: Value = serde_json::from_slice(response.body())?;
    let issued = AuthToken::parse(body["auth_token"].as_str().ok_or("no Auth token")?)?;
    let auth = issued.verify(&trust, now())?;
    let scope = auth.claims().scope.as_deref().unwrap_or("");
    println!("{} {scope} for {}", response.status().as_u16(), auth.claims().aud);

    // A scope the rule does not allow is refused.
    let refused = server.handle(&others.from_person_server("notes.write")?);
    println!("{}", refused.status().as_u16());
    Ok(())
}

/// The keys this deployment trusts: issuer, metadata document, kid, key.
#[derive(Clone)]
struct Trust(Vec<(&'static str, &'static str, &'static str, Jwk)>);
impl AgentKeyResolver for Trust {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let found = self.0.iter().find(|(i, d, k, _)| (*i, *d, *k) == (issuer, dwk, kid));
        found.map(|(.., key)| key.clone()).ok_or(TokenError::UntrustedIssuer)
    }
}

/// Stand-ins for the agent's provider, the Person Server and the API.
struct Others {
    provider: AgentProvider,
    ap: Jwk,
    ps: SigningKey,
    api: SigningKey,
    agent: SigningKey,
}
impl Others {
    fn new() -> Result<Self, Box<dyn Error>> {
        let key = SigningKey::generate();
        let ap = key.public_jwk();
        let provider = AgentProvider::new("https://ap.example", "ap-1", key)?;
        let (ps, api, agent) = (SigningKey::generate(), SigningKey::generate(), SigningKey::generate());
        Ok(Self { provider, ap, ps, api, agent })
    }

    /// What the Person Server sends: the Agent token, its Person token and
    /// the API's Resource token, signed with the Person Server's key.
    fn from_person_server(&self, scope: &str) -> Result<Request<Vec<u8>>, Box<dyn Error>> {
        // cnf binds each token to the agent's key.
        let (now, cnf) = (now(), Confirmation { jwk: self.agent.public_jwk() });
        let agent_token = self.provider.issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(), // the issuer's well-known metadata document
            sub: "aauth:assistant@ap.example".into(),
            jti: format!("agent-{scope}"),
            iat: now,
            exp: now + 3600,
            cnf: cnf.clone(),
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })?;
        let person_token = mint_person_token(&self.ps, "ps-1", &PersonClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: API.into(),
            sub: "u-7f3c9a".into(),
            jti: format!("person-{scope}"),
            iat: now,
            exp: now + 3600,
            cnf: cnf.clone(),
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        })?;
        let resource_token = mint_resource_token(&self.api, "api-1", &ResourceClaims {
            iss: API.into(),
            dwk: "aauth-resource.json".into(),
            aud: AS.into(),
            sub: "u-7f3c9a".into(),
            jti: format!("challenge-{scope}"),
            iat: now,
            exp: now + 300,
            ps: PS.into(),
            presented_jti: format!("person-{scope}"),
            agent_jkt: cnf.jwk.thumbprint()?, // the agent key's JWK thumbprint
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some(scope.into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        })?;
        let body = json!({"agent_token": agent_token, "presented_token": person_token,
                          "resource_token": resource_token});
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{AS}/token"))
            .header("content-type", "application/json")
            .body(body.to_string().into_bytes())?;
        let signer = KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        };
        sign_request(&mut request, &self.ps, signer, now)?;
        Ok(request)
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
```

```text
200 notes.read for https://api.example
403
```

## Why use it

- **Your policy sees only verified requests.** Before your policy runs, the
  server checks the Person Server's request signature, the Agent token, the
  API's Resource token, the Person token it was issued against, and the
  links between them. The policy gets the Person Server, the agent, the
  person's subject and the requested scopes, already checked.
- **Answers that take time.** `with_deferred` lets the server ask for claims,
  clarification, the person's interaction, approval or payment while the
  agent waits and polls.
- **Operations as well as scopes.** `with_r3` issues Auth tokens for R3
  operation documents, fetched and checked against their hash. Budgets,
  revocation and call chaining are opt-in too. Per-call R3 proposals are
  refused: those go to the Person Server.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. Pure Rust.
- It routes nothing and fetches nothing: your HTTP server passes requests to
  `handle`. The host admits issuers before keys are resolved, and supplies
  the clock in Unix seconds and fresh token ids.
- An Auth token lives at most an hour, and never past the token it was
  issued against.

## Specifications

Implements the Access Server side of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`), including deferred answers, call
chaining and missions, and of R3 and Budgets, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
Every requirement the [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
suite grades for this role passes.

## Links

- [API documentation](https://docs.rs/aauth-rust-access-server)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::access_server` in the umbrella crate, with the rest of the family
- [Access Server guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/access-server.md): the four-party flow with a real Person Server and API
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
