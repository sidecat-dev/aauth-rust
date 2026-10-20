//! Worked composition only: actual signing and verification, in-process transport.
//! Keys/time/person login are public fixtures. The four-party Resource example
//! separately executes real TLS; this example isolates the mixed /token router.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonToken, ResourceClaims,
    ResourceToken, TokenError, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey, strict_json};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedTokenIds, Config, Federation, FederationError, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError, Store, TokenReference,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const ORDERS: &str = "https://orders.example";
const NOW: i64 = 1800000000;
fn now() -> i64 {
    NOW
}
#[derive(Clone)]
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> std::result::Result<Jwk, TokenError> {
        // Explicitly admitted fixture snapshots, never arbitrary issuer fetching.
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap") => 1,
            (PS, "aauth-person.json", "ps") => 3,
            (AS, "aauth-access.json", "as") => 4,
            (ORDERS, "aauth-resource.json", "orders") => 5,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}
struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, r: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        if r.resource != ORDERS {
            return Err(PolicyError::Denied);
        }
        // This fixture represents a person already authenticated by the host.
        // A production policy obtains that fact from its login/account context.
        Ok(Person {
            id: "internal-account-1".into(),
            subject: "opaque-orders-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, r: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        if r.scopes != ["orders.quote"] {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: r.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, r: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        if r.resource.claims().aud != AS || r.scopes != ["orders.write"] {
            return Err(PolicyError::Denied);
        }
        Ok(())
    }
}
struct LocalAccess {
    calls: Arc<AtomicUsize>,
}
impl Federation for LocalAccess {
    fn endpoint(&self, issuer: &str) -> std::result::Result<String, FederationError> {
        if issuer != AS {
            return Err(FederationError);
        }
        Ok(format!("{AS}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        let serial = self.calls.fetch_add(1, Ordering::SeqCst);
        let server = aauth_rust_access_server::AccessServer::new(
            aauth_rust_access_server::Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            |r: &aauth_rust_access_server::AuthorizationRequest| {
                if r.person_server != PS
                    || r.resource.claims().iss != ORDERS
                    || r.scopes != ["orders.write"]
                {
                    return Err(aauth_rust_access_server::PolicyError::Denied);
                }
                Ok(aauth_rust_access_server::Decision {
                    scopes: r.scopes.clone(),
                    lifetime: 600,
                })
            },
            now,
            move || format!("as-{serial}"),
        )
        .map_err(|_| FederationError)?;
        // No rewriting: real AS verification sees the PS's exact signed request.
        Ok(server.handle(request))
    }
}
type Server = PersonServer<Keys, MemoryStore, HostPolicy, fn() -> i64, BoxedTokenIds>;
struct MixedPs {
    direct: Server,
    federated: Server,
}
impl MixedPs {
    fn handle(&self, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        // Collection is already bounded by the host before routing. Parse only
        // an unverified hint; either selected handler still verifies everything.
        let audience = if request.method() == "POST" && request.uri().path() == "/token" {
            strict_json(request.body())
                .ok()
                .and_then(|v| {
                    v.get("resource_token")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .and_then(|t| ResourceToken::parse(&t).ok())
                .map(|t| t.unverified_claims().aud.clone())
        } else {
            None
        };
        if audience.as_deref() == Some(AS) {
            self.federated.handle(request)
        } else {
            // /person, discovery and direct challenges use the direct instance.
            // Malformed/unknown audiences also go here for authenticated refusal;
            // direct mode requires aud=PS. Never retry here after a federated error.
            self.direct.handle(request)
        }
    }
}
pub struct Transcript {
    pub direct_issuer: String,
    pub federated_issuer: String,
    pub direct_subject: String,
    pub federated_subject: String,
    pub shared_discovery_key: bool,
    pub shared_binding_and_retention: bool,
    pub tampered_routing_status: u16,
    pub unknown_audience_status: u16,
    pub access_calls: usize,
}
fn post(agent: &Agent, path: &str, body: Value) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body)?)?;
    agent.sign(&mut request, NOW)?;
    Ok(request)
}
fn token(response: Response<Vec<u8>>, name: &str) -> Result<String> {
    if response.status() != 200 {
        return Err(format!(
            "unexpected PS response: {} {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
        .into());
    }
    let value = strict_json(response.body())?;
    Ok(value
        .get(name)
        .and_then(Value::as_str)
        .ok_or("missing token")?
        .into())
}
fn challenge(
    holder: &Agent,
    person: &aauth_rust_core::VerifiedPersonToken,
    audience: &str,
    scope: &str,
    seed: u8,
) -> Result<String> {
    Ok(mint_resource_token(
        &SigningKey::from_seed([seed; 32]),
        "orders",
        &ResourceClaims {
            iss: ORDERS.into(),
            dwk: "aauth-resource.json".into(),
            aud: audience.into(),
            sub: person.claims().sub.clone(),
            jti: format!("challenge-{audience}-{scope}"),
            iat: NOW,
            exp: NOW + 300,
            ps: PS.into(),
            presented_jti: person.claims().jti.clone(),
            agent_jkt: holder.public_jwk().thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some(scope.into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
    )?)
}
pub fn run() -> Result<Transcript> {
    let store = MemoryStore::default();
    let ids = Arc::new(AtomicUsize::new(0));
    // Provision one seed in the host, then construct the two non-Clone keys.
    // Do not generate separate keys with the same published kid.
    let ps_seed = [3; 32];
    let make = || {
        let ids = ids.clone();
        PersonServer::new(
            Config::new(PS, "ps", SigningKey::from_seed(ps_seed)),
            Keys,
            store.clone(),
            HostPolicy,
            now as fn() -> i64,
            Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
        )
    };
    let access_calls = Arc::new(AtomicUsize::new(0));
    let servers = MixedPs {
        direct: make()?,
        federated: make()?.with_federation(LocalAccess {
            calls: access_calls.clone(),
        }),
    };
    let shared_discovery_key = servers.direct.jwks() == servers.federated.jwks()
        && servers.direct.metadata() == servers.federated.metadata();
    let key = SigningKey::from_seed([2; 32]);
    let agent_token =
        AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))?.issue(
            &AgentClaims {
                iss: "https://ap.example".into(),
                dwk: "aauth-agent.json".into(),
                sub: "aauth:Caller@ap.example".into(),
                jti: "agent-1".into(),
                iat: NOW,
                exp: NOW + 3600,
                cnf: Confirmation {
                    jwk: key.public_jwk(),
                },
                ps: Some(PS.into()),
                parent_agent: None,
                nbf: None,
                extra: Default::default(),
            },
        )?;
    let agent = Agent::new(key, agent_token)?;
    let person = token(
        servers.handle(&post(&agent, "/person", json!({"resource":ORDERS}))?),
        "person_token",
    )?;
    let verified_person = PersonToken::parse(&person)?.verify(&Keys, NOW)?;
    let mut grants = Vec::new();
    for (audience, scope) in [(PS, "orders.quote"), (AS, "orders.write")] {
        // In a real service these challenges come from the Resource handler.
        let resource = challenge(&agent, &verified_person, audience, scope, 5)?;
        let compact = token(
            servers.handle(&post(
                &agent,
                "/token",
                json!({"resource_token":resource,"presented_token":person}),
            )?),
            "auth_token",
        )?;
        let verified = AuthToken::parse(&compact)?.verify(&Keys, NOW)?;
        if verified.claims().aud != ORDERS || verified.claims().scope.as_deref() != Some(scope) {
            return Err("grant profile mismatch".into());
        }
        grants.push(verified);
    }
    let direct = grants[0].claims();
    let federated = grants[1].claims();
    let direct_row = store
        .token(&TokenReference {
            issuer: PS.into(),
            jti: direct.jti.clone(),
        })?
        .ok_or("missing direct record")?;
    let fed_row = store
        .token(&TokenReference {
            issuer: AS.into(),
            jti: federated.jti.clone(),
        })?
        .ok_or("missing federated record")?;
    let shared_binding_and_retention = direct_row.principal == fed_row.principal
        && direct_row.person_id == fed_row.person_id
        && direct_row.presented == fed_row.presented
        && fed_row.person_server.as_deref() == Some(PS)
        && store.binding(PS, &direct_row.principal)?.is_some();
    let wrong_signature = challenge(&agent, &verified_person, AS, "orders.write", 9)?;
    let tampered = servers.handle(&post(
        &agent,
        "/token",
        json!({"resource_token":wrong_signature,"presented_token":person}),
    )?);
    let unknown = challenge(
        &agent,
        &verified_person,
        "https://other-as.example",
        "orders.write",
        5,
    )?;
    let unknown = servers.handle(&post(
        &agent,
        "/token",
        json!({"resource_token":unknown,"presented_token":person}),
    )?);
    Ok(Transcript {
        direct_issuer: direct.iss.clone(),
        federated_issuer: federated.iss.clone(),
        direct_subject: direct.sub.clone(),
        federated_subject: federated.sub.clone(),
        shared_discovery_key,
        shared_binding_and_retention,
        tampered_routing_status: tampered.status().as_u16(),
        unknown_audience_status: unknown.status().as_u16(),
        access_calls: access_calls.load(Ordering::SeqCst),
    })
}
