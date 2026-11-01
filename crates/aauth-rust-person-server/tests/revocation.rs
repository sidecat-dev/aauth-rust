//! Revocation endpoint, cascade, and presentation at a Person Server.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentProviderKeys, AgentToken, AuthClaims, AuthToken,
    CallOutcome, Confirmation, PersonToken, ResourceClaims, ResourceToken, RevocationDirectory,
    RevocationLimits, RevocationSender, RevocationTarget, TokenError, mint_auth_token,
    mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError, Store,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

const PS: &str = "https://ps.example";
const AP: &str = "https://ap.example";
const RESOURCE: &str = "https://resource.example";
const AS: &str = "https://as.example";

struct Keys {
    ap: AgentProviderKeys,
    resource: Jwk,
    access: Jwk,
}
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer == RESOURCE && dwk == "aauth-resource.json" && kid == "resource-1" {
            return Ok(self.resource.clone());
        }
        if issuer == AS && dwk == "aauth-access.json" && kid == "as-1" {
            return Ok(self.access.clone());
        }
        if issuer == PS && dwk == "aauth-person.json" && kid == "ps-1" {
            return Ok(SigningKey::from_seed([3; 32]).public_jwk());
        }
        self.ap.key(issuer, dwk, kid)
    }
}
struct Host {
    bound: Arc<AtomicUsize>,
    authorized: Arc<AtomicUsize>,
}
impl Policy for Host {
    fn bind_person(&self, req: &PersonRequest) -> Result<Person, PolicyError> {
        self.bound.fetch_add(1, Ordering::SeqCst);
        Ok(Person {
            id: "internal-person".into(),
            subject: format!("directed-{}", req.resource),
            tenant: Some("tenant-1".into()),
        })
    }
    fn authorize(&self, req: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.authorized.fetch_add(1, Ordering::SeqCst);
        Ok(Grant {
            scopes: req.scopes.clone(),
            lifetime: 3600,
        })
    }
    fn consent(&self, _req: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}
struct Scripted {
    calls: Mutex<Vec<(String, String, i64)>>,
    deferred: AtomicBool,
}
impl RevocationDirectory for Scripted {
    fn revoke(&self, sender: &RevocationSender<'_>, target: &RevocationTarget<'_>) -> CallOutcome {
        assert_eq!(sender.dwk, "aauth-person.json");
        self.calls.lock().expect("directory").push((
            target.recipient.to_owned(),
            target.jti.to_owned(),
            target.exp,
        ));
        if self.deferred.load(Ordering::SeqCst) {
            CallOutcome::Deferred
        } else {
            CallOutcome::Recorded
        }
    }
}

fn agent_token(jti: &str) -> (Agent, AgentProviderKeys) {
    let ap = AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let token = ap
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Agent@ap.example".into(),
            jti: jti.into(),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    let keys = AgentProviderKeys::from_documents(AP, &ap.metadata().unwrap(), &ap.jwks().unwrap())
        .unwrap();
    (Agent::new(key, token).unwrap(), keys)
}
struct Built {
    server: PersonServer<Keys, MemoryStore, Host, BoxedClock, BoxedTokenIds>,
    store: MemoryStore,
    authorized: Arc<AtomicUsize>,
}
fn harness(limits: RevocationLimits, directory: Option<Arc<Scripted>>) -> Built {
    let (_agent, ap) = agent_token("agent-1");
    let store = MemoryStore::default();
    let authorized = Arc::new(AtomicUsize::new(0));
    let ids = AtomicUsize::new(0);
    let clock: BoxedClock = Box::new(|| 1000);
    let token_ids: BoxedTokenIds =
        Box::new(move || format!("issued-{}", ids.fetch_add(1, Ordering::SeqCst)));
    let mut server = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
            access: SigningKey::from_seed([7; 32]).public_jwk(),
        },
        store.clone(),
        Host {
            bound: Arc::new(AtomicUsize::new(0)),
            authorized: authorized.clone(),
        },
        clock,
        token_ids,
    )
    .unwrap()
    .with_revocation_limits(limits);
    if let Some(directory) = directory {
        server = server.with_revocation_directory(directory);
    }
    Built {
        server,
        store,
        authorized,
    }
}
fn signed_agent(agent: &Agent, path: &str, body: Value) -> Request<Vec<u8>> {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut req, 1000).unwrap();
    req
}
struct ServerKey {
    seed: u8,
    id: &'static str,
    dwk: &'static str,
    kid: &'static str,
}
fn ap_key() -> ServerKey {
    ServerKey {
        seed: 1,
        id: AP,
        dwk: "aauth-agent.json",
        kid: "ap-1",
    }
}
fn resource_key() -> ServerKey {
    ServerKey {
        seed: 4,
        id: RESOURCE,
        dwk: "aauth-resource.json",
        kid: "resource-1",
    }
}
fn signed_server(
    method: &str,
    path: &str,
    key: ServerKey,
    body: Option<Value>,
    now: i64,
) -> Request<Vec<u8>> {
    let bytes = body
        .as_ref()
        .map(|value| serde_json::to_vec(value).unwrap())
        .unwrap_or_default();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("{PS}{path}"))
        .body(bytes)
        .unwrap();
    if body.is_some() {
        req.headers_mut().insert(
            "content-type",
            "application/json".parse().expect("content-type"),
        );
    }
    sign_request(
        &mut req,
        &SigningKey::from_seed([key.seed; 32]),
        KeyMaterial::JwksUri {
            id: key.id.into(),
            dwk: key.dwk.into(),
            kid: key.kid.into(),
        },
        now,
    )
    .unwrap();
    req
}
fn revoke(key: ServerKey, body: Value) -> Request<Vec<u8>> {
    signed_server("POST", "/revoke", key, Some(body), 1000)
}
fn value(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}
fn resource_token(agent: &Agent, person: &str) -> String {
    resource_token_for(agent, person, PS, "resource-1")
}
fn resource_token_for(agent: &Agent, person: &str, audience: &str, jti: &str) -> String {
    let person = PersonToken::parse(person).unwrap();
    let claims = person.unverified_claims();
    mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: audience.into(),
            sub: claims.sub.clone(),
            jti: jti.into(),
            iat: 1000,
            exp: 1300,
            ps: claims.iss.clone(),
            presented_jti: claims.jti.clone(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            nbf: None,
            tenant: claims.tenant.clone(),
            mission_s256: None,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
/// A challenge naming an Auth token from the AS, for a step-up through it.
fn step_up_token_for(agent: &Agent, auth: &str, jti: &str) -> String {
    let auth = AuthToken::parse(auth).unwrap();
    let claims = auth.unverified_claims();
    mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: AS.into(),
            sub: claims.sub.clone(),
            jti: jti.into(),
            iat: 1000,
            exp: 1300,
            ps: claims.ps.clone(),
            presented_jti: claims.jti.clone(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            nbf: None,
            tenant: claims.tenant.clone(),
            mission_s256: None,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
/// An Access Server that grants every request. Its Auth tokens take their
/// `jti` from `jtis`, in call order.
struct CountingAs {
    calls: Arc<AtomicUsize>,
    jtis: &'static [&'static str],
}
impl aauth_rust_person_server::Federation for CountingAs {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        if issuer == AS {
            Ok(format!("{AS}/token"))
        } else {
            Err(aauth_rust_person_server::FederationError)
        }
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(request.body()).expect("token body");
        let agent = AgentToken::parse(body["agent_token"].as_str().unwrap()).unwrap();
        let resource = ResourceToken::parse(body["resource_token"].as_str().unwrap())
            .unwrap()
            .unverified_claims()
            .clone();
        let compact = mint_auth_token(
            &SigningKey::from_seed([7; 32]),
            "as-1",
            &AuthClaims {
                iss: AS.into(),
                dwk: "aauth-access.json".into(),
                aud: resource.iss.clone(),
                ps: resource.ps.clone(),
                sub: resource.sub.clone(),
                cnf: Confirmation {
                    jwk: agent.unverified_claims().cnf.jwk.clone(),
                },
                jti: self.jtis[call].into(),
                iat: 1000,
                exp: 1200,
                scope: Some("read".into()),
                account: resource.account.clone(),
                nbf: None,
                mission_s256: resource.mission_s256.clone(),
                tenant: resource.tenant.clone(),
                extra: Default::default(),
            },
        )
        .unwrap();
        let mut response = Response::new(json!({"auth_token": compact}).to_string().into_bytes());
        *response.status_mut() = http::StatusCode::OK;
        response.headers_mut().insert(
            "content-type",
            "application/json".parse().expect("content-type"),
        );
        Ok(response)
    }
}

#[test]
fn signed_revocation_names_jti_exp_and_the_verified_issuer() {
    let server = harness(RevocationLimits::default(), None).server;
    let published: Value = serde_json::from_slice(&server.metadata()).unwrap();
    assert_eq!(published["revocation_endpoint"], format!("{PS}/revoke"));
    let body = json!({"jti":"kept","exp":1500,"iss":"https://evil.example"});
    let accepted = revoke(ap_key(), body);
    let covered = accepted.headers()["signature-input"].to_str().unwrap();
    assert!(covered.contains("content-digest"));
    assert!(covered.contains("content-type"));
    let response = server.handle(&accepted);
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert!(response.body().is_empty());
    assert!(!response.headers().contains_key("content-type"));
    assert_eq!(server.revocation_exp(AP, "kept"), Some(1500));
    assert!(
        server
            .revocation_exp("https://evil.example", "kept")
            .is_none()
    );
    let repeat = server.handle(&revoke(ap_key(), json!({"jti":"kept","exp":1800})));
    assert_eq!(repeat.status(), 200);
    assert_eq!(server.revocation_exp(AP, "kept"), Some(1500));
    let other = server.handle(&revoke(resource_key(), json!({"jti":"kept","exp":1800})));
    assert_eq!(other.status(), 200);
    assert_eq!(server.revocation_exp(AP, "kept"), Some(1500));
    assert_eq!(server.revocation_exp(RESOURCE, "kept"), Some(1800));

    let mut uncovered = Request::builder()
        .method("POST")
        .uri(format!("{PS}/revoke"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut uncovered,
        &SigningKey::from_seed([1; 32]),
        KeyMaterial::JwksUri {
            id: AP.into(),
            dwk: "aauth-agent.json".into(),
            kid: "ap-1".into(),
        },
        1000,
    )
    .unwrap();
    *uncovered.body_mut() = serde_json::to_vec(&json!({"jti":"x","exp":1500})).unwrap();
    uncovered.headers_mut().insert(
        "content-type",
        "application/json".parse().expect("content-type"),
    );
    let mut forged = Request::builder()
        .method("POST")
        .uri(format!("{PS}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"jti":"forged","exp":1500})).unwrap())
        .unwrap();
    sign_request(
        &mut forged,
        &SigningKey::from_seed([9; 32]),
        KeyMaterial::JwksUri {
            id: AP.into(),
            dwk: "aauth-agent.json".into(),
            kid: "ap-1".into(),
        },
        1000,
    )
    .unwrap();
    let forged = server.handle(&forged);
    assert_eq!(forged.status(), 401);
    assert!(server.revocation_exp(AP, "forged").is_none());

    let rejected = server.handle(&uncovered);
    assert_eq!(rejected.status(), 401);
    assert!(
        rejected.headers()["signature-error"]
            .to_str()
            .unwrap()
            .contains("error=invalid_input")
    );

    for body in [
        json!({"exp":1500}),
        json!({"jti":"","exp":1500}),
        json!({"jti":"bad jti","exp":1500}),
        json!({"jti":"x","exp":-1}),
        json!({"jti":"x"}),
        json!({"jti":"x","exp":1000 + 86_400 + 1}),
        json!("nope"),
    ] {
        let response = server.handle(&revoke(ap_key(), body));
        assert_eq!(
            response.status(),
            400,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        assert_eq!(value(&response)["error"], "invalid_request");
    }
    assert!(server.revocation_exp(AP, "x").is_none());
}

#[test]
fn revocation_rate_limit_requires_retry_after() {
    let limits = RevocationLimits {
        rate: 1,
        ..RevocationLimits::default()
    };
    let server = harness(limits, None).server;
    let first = server.handle(&revoke(ap_key(), json!({"jti":"one","exp":1500})));
    assert_eq!(first.status(), 200);
    let second = server.handle(&revoke(ap_key(), json!({"jti":"two","exp":1500})));
    assert_eq!(second.status(), 429);
    assert_eq!(value(&second)["error"], "rate_limited");
    assert_eq!(second.headers()["retry-after"], "5");
    assert!(server.revocation_exp(AP, "two").is_none());
}

#[test]
fn agent_provider_revocation_is_an_empty_200_and_denies_that_agent_token() {
    let directory = Arc::new(Scripted {
        calls: Mutex::new(Vec::new()),
        deferred: AtomicBool::new(false),
    });
    let built = harness(RevocationLimits::default(), Some(directory.clone()));
    let server = built.server;
    let store = built.store;
    let (agent, _) = agent_token("agent-1");
    let person = server.handle(&signed_agent(
        &agent,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    let person_jti = PersonToken::parse(value(&person)["person_token"].as_str().unwrap())
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    let response = server.handle(&revoke(ap_key(), json!({"jti":"agent-1","exp":2000})));
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert!(response.body().is_empty());
    assert!(!response.headers().contains_key("content-type"));
    let calls = directory.calls.lock().unwrap().clone();
    assert_eq!(calls, vec![(RESOURCE.into(), person_jti, 2000)]);
    let denied = server.handle(&signed_agent(
        &agent,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    assert_eq!(denied.status(), 401);
    assert_eq!(denied.headers()["signature-error"], "error=revoked_jwt");
    assert_eq!(value(&denied)["error"], "revoked_jwt");
    let binding = store
        .binding(
            PS,
            &AgentIdentity {
                issuer: AP.into(),
                subject: "aauth:Agent@ap.example".into(),
            },
        )
        .unwrap()
        .unwrap();
    assert!(!binding.revoked);
    let (fresh, _) = agent_token("agent-2");
    let again = server.handle(&signed_agent(
        &fresh,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    assert_eq!(
        again.status(),
        200,
        "{}",
        String::from_utf8_lossy(again.body())
    );
    assert!(
        !store
            .binding(
                PS,
                &AgentIdentity {
                    issuer: AP.into(),
                    subject: "aauth:Agent@ap.example".into(),
                },
            )
            .unwrap()
            .unwrap()
            .revoked
    );
}

#[test]
fn deferred_revocation_poll_is_limited_to_the_caller() {
    let directory = Arc::new(Scripted {
        calls: Mutex::new(Vec::new()),
        deferred: AtomicBool::new(true),
    });
    let server = harness(RevocationLimits::default(), Some(directory.clone())).server;
    let (agent, _) = agent_token("agent-1");
    assert_eq!(
        server
            .handle(&signed_agent(
                &agent,
                "/person",
                json!({"resource": RESOURCE})
            ))
            .status(),
        200
    );
    let pending = server.handle(&revoke(ap_key(), json!({"jti":"agent-1","exp":2000})));
    assert_eq!(
        pending.status(),
        202,
        "{}",
        String::from_utf8_lossy(pending.body())
    );
    assert_eq!(value(&pending)["status"], "pending");
    let pending_location = pending.headers()["location"].to_str().unwrap();
    let pending_id = pending_location
        .strip_prefix(&format!("{PS}/revoke/pending/"))
        .unwrap();
    // 128 random bits, not the host's sequential token-ID source.
    assert_eq!(pending_id.len(), 22, "{pending_location}");
    assert!(!pending_id.starts_with("issued-"));
    assert_eq!(pending.headers()["retry-after"], "5");
    assert_eq!(pending.headers()["cache-control"], "no-store");
    assert!(!pending.headers().contains_key("aauth-requirement"));
    let location = pending.headers()["location"].to_str().unwrap().to_owned();
    let path = location.trim_start_matches(PS);
    assert!(directory.deferred.load(Ordering::SeqCst));
    let other = server.handle(&signed_server("GET", path, resource_key(), None, 1000));
    let unknown = server.handle(&signed_server(
        "GET",
        "/revoke/pending/missing",
        ap_key(),
        None,
        1000,
    ));
    assert_eq!(other.status(), unknown.status());
    assert_eq!(other.body(), unknown.body());
    assert_eq!(other.headers(), unknown.headers());
    assert_eq!(other.status(), 404);
    assert!(other.body().is_empty());
    assert!(!other.headers().contains_key("content-type"));
    directory.deferred.store(false, Ordering::SeqCst);
    let poll = server.handle(&signed_server("GET", path, ap_key(), None, 1000));
    assert_eq!(
        poll.status(),
        200,
        "{}",
        String::from_utf8_lossy(poll.body())
    );
    assert!(poll.body().is_empty());
    assert!(!poll.headers().contains_key("content-type"));
    let gone = server.handle(&signed_server("GET", path, ap_key(), None, 1000));
    assert_eq!(gone.status(), 410);
    assert_eq!(value(&gone)["error"], "gone");
    let unsigned = Request::builder()
        .method("GET")
        .uri(location)
        .body(Vec::new())
        .unwrap();
    assert_eq!(server.handle(&unsigned).status(), 401);
}

#[test]
fn resource_token_revocation_is_immediate_and_refuses_the_token() {
    let built = harness(RevocationLimits::default(), None);
    let server = built.server;
    let authorized = built.authorized;
    let (agent, _) = agent_token("agent-1");
    let person = server.handle(&signed_agent(
        &agent,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    let person_token = value(&person)["person_token"].as_str().unwrap().to_owned();
    let resource = resource_token(&agent, &person_token);
    let mut revoke_request = revoke(resource_key(), json!({"jti":"resource-1","exp":1300}));
    revoke_request
        .headers_mut()
        .insert("prefer", "wait=0".parse().unwrap());
    let recorded = server.handle(&revoke_request);
    assert_eq!(recorded.status(), 200);
    assert!(recorded.body().is_empty());
    assert!(!recorded.headers().contains_key("content-type"));
    assert!(!recorded.headers().contains_key("location"));
    let refused = server.handle(&signed_agent(
        &agent,
        "/token",
        json!({"resource_token": resource, "presented_token": person_token}),
    ));
    assert_eq!(
        refused.status(),
        400,
        "{}",
        String::from_utf8_lossy(refused.body())
    );
    assert_eq!(value(&refused)["error"], "revoked_resource_token");
    assert_eq!(authorized.load(Ordering::SeqCst), 0);
}

#[test]
fn person_server_revokes_its_person_token_and_does_not_present_it() {
    let directory = Arc::new(Scripted {
        calls: Mutex::new(Vec::new()),
        deferred: AtomicBool::new(false),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let built = harness(RevocationLimits::default(), Some(directory.clone()));
    let server = built.server.with_federation(CountingAs {
        calls: calls.clone(),
        jtis: &["as-auth"],
    });
    let (agent, _) = agent_token("agent-1");
    let person = server.handle(&signed_agent(
        &agent,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    let person_token = value(&person)["person_token"].as_str().unwrap().to_owned();
    let person_claims = PersonToken::parse(&person_token)
        .unwrap()
        .unverified_claims()
        .clone();
    let challenge = resource_token_for(&agent, &person_token, AS, "resource-fed");
    let granted = server.handle(&signed_agent(
        &agent,
        "/token",
        json!({"resource_token": challenge, "presented_token": person_token}),
    ));
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let cascade = server.revoke_person_token(&person_claims.jti);
    assert_eq!(
        cascade.status(),
        200,
        "{}",
        String::from_utf8_lossy(cascade.body())
    );
    let downstream = value(&cascade)["downstream"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["recipient"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(downstream, vec![RESOURCE.to_owned(), AS.to_owned()]);
    assert_eq!(
        directory.calls.lock().unwrap().clone(),
        vec![
            (
                RESOURCE.into(),
                person_claims.jti.clone(),
                person_claims.exp
            ),
            (AS.into(), person_claims.jti.clone(), person_claims.exp),
        ]
    );
    let refused = server.handle(&signed_agent(
        &agent,
        "/token",
        json!({"resource_token": challenge, "presented_token": person_token}),
    ));
    assert_eq!(refused.status(), 400);
    assert_eq!(value(&refused)["error"], "revoked_presented_token");
    assert!(value(&refused).get("auth_token").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A server whose revocations reach `directory`, federating with a
/// [`CountingAs`] that issues `jtis` in turn.
fn federated(
    directory: &Arc<Scripted>,
    jtis: &'static [&'static str],
) -> PersonServer<Keys, MemoryStore, Host, BoxedClock, BoxedTokenIds> {
    harness(RevocationLimits::default(), Some(directory.clone()))
        .server
        .with_federation(CountingAs {
            calls: Arc::new(AtomicUsize::new(0)),
            jtis,
        })
}
fn exchange(
    server: &PersonServer<Keys, MemoryStore, Host, BoxedClock, BoxedTokenIds>,
    agent: &Agent,
    challenge: &str,
    presented: &str,
) -> String {
    let granted = server.handle(&signed_agent(
        agent,
        "/token",
        json!({"resource_token": challenge, "presented_token": presented}),
    ));
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    value(&granted)["auth_token"].as_str().unwrap().to_owned()
}
fn calls_at_access_server(directory: &Scripted) -> Vec<(String, String, i64)> {
    let mut calls: Vec<_> = directory
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.0 == AS)
        .cloned()
        .collect();
    calls.sort();
    calls
}

#[test]
fn agent_revocation_revokes_each_person_token_presented_to_an_access_server() {
    // Both of the Agent's person tokens were presented to the same AS. Each
    // is revoked there, not only the first.
    let directory = Arc::new(Scripted {
        calls: Mutex::new(Vec::new()),
        deferred: AtomicBool::new(false),
    });
    let server = federated(&directory, &["as-auth-1", "as-auth-2"]);
    let (agent, _) = agent_token("agent-1");
    let mut expected = Vec::new();
    for challenge in ["resource-1", "resource-2"] {
        let person = server.handle(&signed_agent(
            &agent,
            "/person",
            json!({"resource": RESOURCE}),
        ));
        let person = value(&person)["person_token"].as_str().unwrap().to_owned();
        exchange(
            &server,
            &agent,
            &resource_token_for(&agent, &person, AS, challenge),
            &person,
        );
        let claims = PersonToken::parse(&person).unwrap();
        let claims = claims.unverified_claims();
        expected.push((AS.to_owned(), claims.jti.clone(), claims.exp));
    }
    let response = server.handle(&revoke(ap_key(), json!({"jti":"agent-1","exp":2000})));
    assert_eq!(response.status(), 200);
    expected.sort();
    assert_eq!(calls_at_access_server(&directory), expected);
}

#[test]
fn agent_revocation_names_the_person_token_at_the_access_server_after_a_step_up() {
    // The step-up's Auth token, `as-a`, sorts before the one it replaced,
    // `as-z`. The AS still receives the person token both were obtained with,
    // never the jti of its own Auth token.
    let directory = Arc::new(Scripted {
        calls: Mutex::new(Vec::new()),
        deferred: AtomicBool::new(false),
    });
    let server = federated(&directory, &["as-z", "as-a"]);
    let (agent, _) = agent_token("agent-1");
    let person = server.handle(&signed_agent(
        &agent,
        "/person",
        json!({"resource": RESOURCE}),
    ));
    let person = value(&person)["person_token"].as_str().unwrap().to_owned();
    let first = exchange(
        &server,
        &agent,
        &resource_token_for(&agent, &person, AS, "resource-1"),
        &person,
    );
    exchange(
        &server,
        &agent,
        &step_up_token_for(&agent, &first, "resource-2"),
        &first,
    );
    let response = server.handle(&revoke(ap_key(), json!({"jti":"agent-1","exp":2000})));
    assert_eq!(response.status(), 200);
    let claims = PersonToken::parse(&person).unwrap();
    let claims = claims.unverified_claims();
    assert_eq!(
        calls_at_access_server(&directory),
        vec![(AS.to_owned(), claims.jti.clone(), claims.exp)]
    );
    for jti in ["as-z", "as-a"] {
        assert!(server.revocation_exp(AS, jti).is_some(), "{jti}");
    }
}

#[test]
fn disabled_revocation_is_not_advertised() {
    let (_agent, ap) = agent_token("agent-1");
    let server = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
            access: SigningKey::from_seed([7; 32]).public_jwk(),
        },
        MemoryStore::default(),
        Host {
            bound: Arc::new(AtomicUsize::new(0)),
            authorized: Arc::new(AtomicUsize::new(0)),
        },
        || 1000,
        || "issued".into(),
    )
    .unwrap();
    let published: Value = serde_json::from_slice(&server.metadata()).unwrap();
    assert!(published.get("revocation_endpoint").is_none());
    assert_eq!(
        server
            .handle(&revoke(ap_key(), json!({"jti":"a","exp":1500})))
            .status(),
        404
    );
}
