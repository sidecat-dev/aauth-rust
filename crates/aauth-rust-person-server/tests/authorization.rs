use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonToken, ResourceClaims,
    TokenError, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Binding, BoxedClock, BoxedPolicy, BoxedTokenIds, Config,
    Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError, Store,
    StoreError, TokenRecord, TokenReference,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
};

const PS: &str = "https://ps.example";
const ORDERS: &str = "https://orders.example";
const INVENTORY: &str = "https://inventory.example";
#[derive(Clone)]
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap-key") => {
                Ok(SigningKey::from_seed([1; 32]).public_jwk())
            }
            (ORDERS, "aauth-resource.json" | "aauth-agent.json", "orders-key") => {
                Ok(SigningKey::from_seed([4; 32]).public_jwk())
            }
            (INVENTORY, "aauth-resource.json", "inventory-key") => {
                Ok(SigningKey::from_seed([5; 32]).public_jwk())
            }
            (PS, "aauth-person.json", "ps-key") => Ok(SigningKey::from_seed([3; 32]).public_jwk()),
            _ => Err(TokenError::UntrustedIssuer),
        }
    }
}
fn agent(intermediary: bool) -> Agent {
    let (issuer, kid, provider, seed, subject) = if intermediary {
        (ORDERS, "orders-key", 4, 6, "aauth:Orders@orders.example")
    } else {
        (
            "https://ap.example",
            "ap-key",
            1,
            2,
            "aauth:Caller@ap.example",
        )
    };
    let key = SigningKey::from_seed([seed; 32]);
    let token = AgentProvider::new(issuer, kid, SigningKey::from_seed([provider; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: issuer.into(),
            dwk: "aauth-agent.json".into(),
            sub: subject.into(),
            jti: format!("agent-{seed}"),
            iat: 1000,
            exp: 5000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: (!intermediary).then(|| PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}
#[derive(Clone)]
struct TestStore {
    inner: MemoryStore,
    now: Arc<AtomicI64>,
    stall: Arc<AtomicI64>,
    fail: Arc<AtomicBool>,
}
impl Store for TestStore {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.inner.binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.inner.token(reference)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        self.inner.revoke_binding(issuer, agent)
    }
    fn commit(&self, record: TokenRecord, establish: bool) -> Result<(), StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.commit(record, establish)?;
        let stall = self.stall.load(Ordering::SeqCst);
        if stall > 0 {
            self.now.store(stall, Ordering::SeqCst);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Host {
    mode: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
    bind_calls: Arc<AtomicUsize>,
    auth_calls: Arc<AtomicUsize>,
    chain_calls: Arc<AtomicUsize>,
}
impl Host {
    fn person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        if self.mode.load(Ordering::SeqCst) == 7 {
            self.now.store(5000, Ordering::SeqCst);
        }
        Ok(Person {
            id: "internal-person".into(),
            subject: if request.resource == ORDERS {
                "orders-person".into()
            } else {
                "inventory-person".into()
            },
            tenant: Some("team".into()),
        })
    }
    fn grant(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(PolicyError::Denied),
            2 => Err(PolicyError::Unavailable),
            3 => Ok(Grant {
                scopes: vec!["admin".into()],
                lifetime: 600,
            }),
            4 => {
                self.now.store(1300, Ordering::SeqCst);
                Ok(Grant {
                    scopes: request.scopes.clone(),
                    lifetime: 600,
                })
            }
            5 => Ok(Grant {
                scopes: request.scopes.clone(),
                lifetime: 10,
            }),
            6 => Ok(Grant {
                scopes: vec![],
                lifetime: 600,
            }),
            _ => Ok(Grant {
                scopes: request.scopes.clone(),
                lifetime: 600,
            }),
        }
    }
}
impl Policy for Host {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.bind_calls.fetch_add(1, Ordering::SeqCst);
        self.person(request)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.auth_calls.fetch_add(1, Ordering::SeqCst);
        self.grant(request)
    }
    fn bind_upstream(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.chain_calls.fetch_add(1, Ordering::SeqCst);
        assert!(request.binding.is_none());
        assert_eq!(
            request.upstream.as_ref().unwrap().record.person_id,
            "internal-person"
        );
        self.person(request)
    }
    fn authorize_upstream(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.chain_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            request.upstream.as_ref().unwrap().record.principal.subject,
            "aauth:Caller@ap.example"
        );
        self.grant(request)
    }
}
struct Fixture {
    store: TestStore,
    host: Host,
    ids: Arc<AtomicUsize>,
}
type Server = PersonServer<Keys, TestStore, BoxedPolicy, BoxedClock, BoxedTokenIds>;
impl Fixture {
    fn new() -> Self {
        let now = Arc::new(AtomicI64::new(1000));
        Self {
            store: TestStore {
                inner: MemoryStore::default(),
                now: now.clone(),
                stall: Arc::new(AtomicI64::new(0)),
                fail: Arc::new(AtomicBool::new(false)),
            },
            host: Host {
                mode: Arc::new(AtomicUsize::new(0)),
                now,
                bind_calls: Arc::new(AtomicUsize::new(0)),
                auth_calls: Arc::new(AtomicUsize::new(0)),
                chain_calls: Arc::new(AtomicUsize::new(0)),
            },
            ids: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn server(&self, lifetime: i64) -> Server {
        let now = self.host.now.clone();
        let ids = self.ids.clone();
        let mut config = Config::new(PS, "ps-key", SigningKey::from_seed([3; 32]));
        config.person_lifetime = lifetime;
        PersonServer::new(
            config,
            Keys,
            self.store.clone(),
            Box::new(self.host.clone()) as BoxedPolicy,
            Box::new(move || now.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || format!("token-{}", ids.fetch_add(1, Ordering::SeqCst)))
                as BoxedTokenIds,
        )
        .unwrap()
    }
    fn call(&self, server: &Server, agent: &Agent, path: &str, body: Value) -> Response<Vec<u8>> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}{path}"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        agent
            .sign(&mut request, self.host.now.load(Ordering::SeqCst))
            .unwrap();
        server.handle(&request)
    }
    fn person(
        &self,
        server: &Server,
        agent: &Agent,
        resource: &str,
        upstream: Option<&str>,
    ) -> Response<Vec<u8>> {
        let mut body = json!({"resource":resource});
        if let Some(upstream) = upstream {
            body["upstream_token"] = json!(upstream);
        }
        self.call(server, agent, "/person", body)
    }
    fn exchange(
        &self,
        server: &Server,
        agent: &Agent,
        resource: &str,
        presented: &str,
        upstream: Option<&str>,
    ) -> Response<Vec<u8>> {
        let mut body = json!({"resource_token":resource,"presented_token":presented});
        if let Some(upstream) = upstream {
            body["upstream_token"] = json!(upstream);
        }
        self.call(server, agent, "/token", body)
    }
}
fn output(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}
fn compact(response: &Response<Vec<u8>>, field: &str) -> String {
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    output(response)[field].as_str().unwrap().into()
}
fn resource(
    holder: &Agent,
    presented: &str,
    scope: &str,
    change: impl FnOnce(&mut ResourceClaims),
) -> String {
    let parsed = aauth_rust_jose::Jws::parse(presented).unwrap();
    let value: Value = serde_json::from_slice(parsed.payload()).unwrap();
    let resource = value["aud"].as_str().unwrap();
    let (seed, kid) = if resource == ORDERS {
        (4, "orders-key")
    } else {
        (5, "inventory-key")
    };
    let mut claims = ResourceClaims {
        iss: resource.into(),
        dwk: "aauth-resource.json".into(),
        aud: PS.into(),
        ps: PS.into(),
        sub: value["sub"].as_str().unwrap().into(),
        jti: "resource-challenge".into(),
        presented_jti: value["jti"].as_str().unwrap().into(),
        agent_jkt: holder.public_jwk().thumbprint().unwrap(),
        iat: 1000,
        exp: 1300,
        scope: Some(scope.into()),
        account: None,
        login_hint: None,
        nbf: None,
        tenant: value
            .get("tenant")
            .and_then(Value::as_str)
            .map(str::to_owned),
        mission_s256: None,
        extra: Default::default(),
    };
    change(&mut claims);
    mint_resource_token(&SigningKey::from_seed([seed; 32]), kid, &claims).unwrap()
}
fn original(f: &Fixture, s: &Server) -> (String, String) {
    let a = agent(false);
    let p = compact(&f.person(s, &a, ORDERS, None), "person_token");
    let r = resource(&a, &p, "orders.read", |_| {});
    let auth = compact(&f.exchange(s, &a, &r, &p, None), "auth_token");
    (p, auth)
}

#[test]
fn downstream_person_and_auth_use_original_binding_across_server_recomposition() {
    let f = Fixture::new();
    let s = f.server(900);
    let (_, up) = original(&f, &s);
    let intermediary = agent(true);
    let person = compact(
        &f.person(&f.server(900), &intermediary, INVENTORY, Some(&up)),
        "person_token",
    );
    let pc = PersonToken::parse(&person)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(pc.claims().sub, "inventory-person");
    assert_eq!(pc.claims().exp, 1600);
    assert_eq!(
        pc.claims().cnf.jwk.thumbprint().unwrap(),
        intermediary.public_jwk().thumbprint().unwrap()
    );
    let challenge = resource(&intermediary, &person, "inventory.write", |_| {});
    let auth = compact(
        &f.exchange(
            &f.server(900),
            &intermediary,
            &challenge,
            &person,
            Some(&up),
        ),
        "auth_token",
    );
    let ac = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(ac.claims().exp, 1600);
    assert_eq!(ac.claims().scope.as_deref(), Some("inventory.write"));
    assert!(
        f.store
            .binding(
                PS,
                &AgentIdentity {
                    issuer: ORDERS.into(),
                    subject: "aauth:Orders@orders.example".into()
                }
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(f.host.bind_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.host.chain_calls.load(Ordering::SeqCst), 2);
    let stepup = resource(&intermediary, &auth, "inventory.admin", |_| {});
    assert_eq!(
        output(&f.exchange(&s, &intermediary, &stepup, &auth, None))["error"],
        "invalid_upstream_token"
    );
    compact(
        &f.exchange(&s, &intermediary, &stepup, &auth, Some(&up)),
        "auth_token",
    );
}

#[test]
fn chaining_refuses_omission_substitution_foreign_audience_and_revoked_original() {
    let f = Fixture::new();
    let s = f.server(900);
    let (person, up) = original(&f, &s);
    let intermediary = agent(true);
    let downstream = compact(
        &f.person(&s, &intermediary, INVENTORY, Some(&up)),
        "person_token",
    );
    let challenge = resource(&intermediary, &downstream, "inventory.read", |_| {});
    assert_eq!(
        output(&f.exchange(&s, &intermediary, &challenge, &downstream, None))["error"],
        "invalid_upstream_token"
    );
    // A different authentic upstream Person token still does not match the retained exact tie.
    assert_eq!(
        output(&f.exchange(&s, &intermediary, &challenge, &downstream, Some(&person)))["error"],
        "invalid_upstream_token"
    );
    assert_eq!(
        output(&f.person(&s, &agent(false), INVENTORY, Some(&up)))["error"],
        "invalid_upstream_token"
    );
    f.store
        .revoke_binding(
            PS,
            &AgentIdentity {
                issuer: "https://ap.example".into(),
                subject: "aauth:Caller@ap.example".into(),
            },
        )
        .unwrap();
    assert_eq!(
        output(&f.person(&s, &intermediary, INVENTORY, Some(&up)))["error"],
        "revoked_upstream_token"
    );
}

#[test]
fn token_parameter_lineage_failures_are_typed_and_precede_policy() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    for (change, code) in [
        (0, "invalid_resource_token"),
        (1, "invalid_resource_token"),
        (2, "invalid_resource_token"),
        (3, "clock_skew"),
        (4, "expired_resource_token"),
    ] {
        let r = resource(&a, &p, "orders.read", |r| match change {
            0 => r.presented_jti = "other".into(),
            1 => r.sub = "other".into(),
            2 => r.tenant = None,
            3 => {
                r.iat = 1061;
                r.exp = 1300;
            }
            _ => {
                r.iat = 700;
                r.exp = 1000;
            }
        });
        let response = f.exchange(&s, &a, &r, &p, None);
        assert_eq!(response.status(), 400);
        assert_eq!(output(&response)["error"], code);
        assert!(!response.headers().contains_key("signature-error"));
        if code == "clock_skew" {
            assert!(response.headers().contains_key("date"));
        }
    }
    let r = resource(&a, &p, "orders.read", |_| {});
    let response = f.exchange(&s, &a, &r, "malformed", None);
    assert_eq!(output(&response)["error"], "invalid_presented_token");
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn refusal_bad_grants_and_policy_expiry_never_release_credentials() {
    for (mode, status, code) in [
        (1, 403, "access_denied"),
        (2, 500, "server_error"),
        (3, 500, "server_error"),
        (4, 400, "expired_resource_token"),
        (6, 500, "server_error"),
    ] {
        let f = Fixture::new();
        let s = f.server(900);
        let a = agent(false);
        let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
        let r = resource(&a, &p, "orders.read", |_| {});
        f.host.mode.store(mode, Ordering::SeqCst);
        let response = f.exchange(&s, &a, &r, &p, None);
        assert_eq!(response.status(), status);
        assert_eq!(output(&response)["error"], code);
        assert!(output(&response).get("auth_token").is_none());
    }
}

#[test]
fn storage_failure_and_elapsed_issued_lifetime_never_release_a_token() {
    let f = Fixture::new();
    let s = f.server(10);
    let a = agent(false);
    f.store.fail.store(true, Ordering::SeqCst);
    let failure = f.person(&s, &a, ORDERS, None);
    assert_eq!(failure.status(), 500);
    assert!(output(&failure).get("person_token").is_none());
    f.store.fail.store(false, Ordering::SeqCst);
    f.store.stall.store(1010, Ordering::SeqCst);
    let expired = f.person(&s, &a, ORDERS, None);
    assert_eq!(expired.status(), 500);
    assert!(output(&expired).get("person_token").is_none());
}

#[test]
fn response_expires_in_accounts_for_time_spent_committing() {
    let f = Fixture::new();
    let s = f.server(10);
    f.store.stall.store(1005, Ordering::SeqCst);
    let response = f.person(&s, &agent(false), ORDERS, None);
    assert_eq!(response.status(), 200);
    assert_eq!(output(&response)["expires_in"], 5);
}

#[test]
fn auth_commit_failure_or_expiry_never_releases_an_unusable_grant() {
    for fail in [true, false] {
        let f = Fixture::new();
        let s = f.server(900);
        let a = agent(false);
        let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
        let r = resource(&a, &p, "orders.read", |_| {});
        f.host.mode.store(5, Ordering::SeqCst);
        f.store.fail.store(fail, Ordering::SeqCst);
        if !fail {
            f.store.stall.store(1010, Ordering::SeqCst);
        }
        let response = f.exchange(&s, &a, &r, &p, None);
        assert_eq!(response.status(), 500);
        assert!(output(&response).get("auth_token").is_none());
    }
}

#[test]
fn direct_binding_revocation_prevents_rebinding_and_exchange() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    let r = resource(&a, &p, "orders.read", |_| {});
    f.store
        .revoke_binding(
            PS,
            &AgentIdentity {
                issuer: "https://ap.example".into(),
                subject: "aauth:Caller@ap.example".into(),
            },
        )
        .unwrap();
    for response in [
        f.person(&s, &a, ORDERS, None),
        f.exchange(&s, &a, &r, &p, None),
    ] {
        assert_eq!(response.status(), 403);
        assert_eq!(output(&response)["error"], "access_denied");
    }
    assert_eq!(f.host.bind_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn person_policy_expiry_is_a_caller_credential_failure() {
    let f = Fixture::new();
    let s = f.server(900);
    f.host.mode.store(7, Ordering::SeqCst);
    let response = f.person(&s, &agent(false), ORDERS, None);
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["signature-error"], "error=expired_jwt");
    assert!(output(&response).get("person_token").is_none());
}

#[test]
fn a_collocated_agent_provider_uses_host_trust_in_its_own_discovery_role() {
    struct CollocatedKeys;
    impl AgentKeyResolver for CollocatedKeys {
        fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
            if issuer == PS && dwk == "aauth-agent.json" && kid == "ap-key" {
                Ok(SigningKey::from_seed([1; 32]).public_jwk())
            } else {
                Keys.key(issuer, dwk, kid)
            }
        }
    }
    let f = Fixture::new();
    let key = SigningKey::from_seed([2; 32]);
    let raw = AgentProvider::new(PS, "ap-key", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: PS.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Caller@ps.example".into(),
            jti: "collocated-agent".into(),
            iat: 1000,
            exp: 5000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    let agent = Agent::new(key, raw).unwrap();
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        CollocatedKeys,
        f.store.clone(),
        f.host.clone(),
        || 1000,
        || "person-collocated".into(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"resource":ORDERS})).unwrap())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    let response = server.handle(&request);
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
}

#[test]
fn upstream_requires_the_exact_retained_bytes_and_current_expiry() {
    let f = Fixture::new();
    let server = f.server(900);
    let (_, upstream) = original(&f, &server);
    let intermediary = agent(true);
    let parsed = aauth_rust_jose::Jws::parse(&upstream).unwrap();
    let reordered: Value = serde_json::from_slice(parsed.payload()).unwrap();
    let rewritten = aauth_rust_jose::Jws::sign(
        parsed.header(),
        &serde_json::to_vec(&reordered).unwrap(),
        &SigningKey::from_seed([3; 32]),
    )
    .unwrap();
    assert_ne!(rewritten, upstream);
    assert_eq!(
        output(&f.person(&server, &intermediary, INVENTORY, Some(&rewritten)))["error"],
        "invalid_upstream_token"
    );
    f.host.now.store(1600, Ordering::SeqCst);
    assert_eq!(
        output(&f.person(&server, &intermediary, INVENTORY, Some(&upstream)))["error"],
        "expired_upstream_token"
    );
    assert_eq!(f.host.chain_calls.load(Ordering::SeqCst), 0);
}
