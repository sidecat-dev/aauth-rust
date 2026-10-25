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
    Arc, Mutex,
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
            ("https://as.example", "aauth-access.json", "as-key") => {
                Ok(SigningKey::from_seed([7; 32]).public_jwk())
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
    revoke_after_commit: Arc<AtomicBool>,
    after_commit: Arc<AtomicBool>,
    delay_binding_after_commit: Arc<AtomicI64>,
    delayed_binding: Arc<Mutex<Option<(usize, i64)>>>,
}
impl Store for TestStore {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        let binding = self.inner.binding(issuer, agent)?;
        let mut delay = self.delayed_binding.lock().unwrap();
        if let Some((remaining, at)) = delay.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                self.now.store(*at, Ordering::SeqCst);
                *delay = None;
            }
        }
        Ok(binding)
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
        let principal = record.principal.clone();
        self.inner.commit(record, establish)?;
        self.after_commit.store(true, Ordering::SeqCst);
        let delay = self.delay_binding_after_commit.swap(0, Ordering::SeqCst);
        if delay > 0 {
            *self.delayed_binding.lock().unwrap() = Some((1, delay));
        }
        if self.revoke_after_commit.swap(false, Ordering::SeqCst) {
            self.inner.revoke_binding(PS, &principal)?;
        }
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
        if self.mode.load(Ordering::SeqCst) == 8 {
            return Err(PolicyError::UserUnreachable);
        }
        if self.mode.load(Ordering::SeqCst) == 7 {
            self.now.store(5000, Ordering::SeqCst);
        }
        Ok(Person {
            id: "internal-person".into(),
            subject: if self.mode.load(Ordering::SeqCst) == 9 {
                request.upstream.as_ref().unwrap().record.subject.clone()
            } else if request.resource == ORDERS {
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
            8 => Err(PolicyError::UserUnreachable),
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
    fn consent(&self, request: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.grant(request).map(|_| ())
    }
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
type Server<K = Keys> = PersonServer<K, TestStore, BoxedPolicy, BoxedClock, BoxedTokenIds>;
impl Fixture {
    fn new() -> Self {
        let now = Arc::new(AtomicI64::new(1000));
        Self {
            store: TestStore {
                inner: MemoryStore::default(),
                now: now.clone(),
                stall: Arc::new(AtomicI64::new(0)),
                fail: Arc::new(AtomicBool::new(false)),
                revoke_after_commit: Arc::new(AtomicBool::new(false)),
                after_commit: Arc::new(AtomicBool::new(false)),
                delay_binding_after_commit: Arc::new(AtomicI64::new(0)),
                delayed_binding: Arc::new(Mutex::new(None)),
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
        self.server_with_keys(lifetime, Keys)
    }
    fn server_with_keys<K: AgentKeyResolver>(&self, lifetime: i64, keys: K) -> Server<K> {
        let now = self.host.now.clone();
        let ids = self.ids.clone();
        let mut config = Config::new(PS, "ps-key", SigningKey::from_seed([3; 32]));
        config.person_lifetime = lifetime;
        PersonServer::new(
            config,
            keys,
            self.store.clone(),
            Box::new(self.host.clone()) as BoxedPolicy,
            Box::new(move || now.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || format!("token-{}", ids.fetch_add(1, Ordering::SeqCst)))
                as BoxedTokenIds,
        )
        .unwrap()
    }
    fn call<K: AgentKeyResolver>(
        &self,
        server: &Server<K>,
        agent: &Agent,
        path: &str,
        body: Value,
    ) -> Response<Vec<u8>> {
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
    fn person<K: AgentKeyResolver>(
        &self,
        server: &Server<K>,
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
    fn exchange<K: AgentKeyResolver>(
        &self,
        server: &Server<K>,
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
fn an_expired_presented_token_is_refused_before_policy() {
    let f = Fixture::new();
    let s = f.server(1);
    let a = agent(false);
    let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    let r = resource(&a, &p, "orders.read", |_| {});
    f.host.now.store(1001, Ordering::SeqCst);
    let response = f.exchange(&s, &a, &r, &p, None);
    assert_eq!(response.status(), 400);
    assert_eq!(output(&response)["error"], "expired_presented_token");
    assert!(!response.headers().contains_key("signature-error"));
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
    let denied = f.person(&s, &a, ORDERS, None);
    assert_eq!(denied.status(), 403);
    assert_eq!(output(&denied)["error"], "denied");
    let revoked = f.exchange(&s, &a, &r, &p, None);
    assert_eq!(revoked.status(), 400);
    assert_eq!(output(&revoked)["error"], "revoked_presented_token");
    assert!(!revoked.headers().contains_key("signature-error"));
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

#[test]
fn rewritten_presented_bytes_are_not_a_resource_challenge_failure() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let (person, auth) = original(&f, &s);
    for presented in [person, auth] {
        let parsed = aauth_rust_jose::Jws::parse(&presented).unwrap();
        let sorted: Value = serde_json::from_slice(parsed.payload()).unwrap();
        let rewritten = aauth_rust_jose::Jws::sign(
            parsed.header(),
            &serde_json::to_vec(&sorted).unwrap(),
            &SigningKey::from_seed([3; 32]),
        )
        .unwrap();
        assert_ne!(rewritten, presented);
        let r = resource(&a, &rewritten, "orders.read", |_| {});
        let response = f.exchange(&s, &a, &r, &rewritten, None);
        assert_eq!(response.status(), 400);
        assert_eq!(output(&response)["error"], "invalid_presented_token");
        assert!(!response.headers().contains_key("signature-error"));
        assert!(output(&response).get("auth_token").is_none());
    }
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn presented_issuance_for_another_agent_with_the_same_key_is_invalid_presented() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    let mut claims = aauth_rust_core::AgentToken::parse(a.token())
        .unwrap()
        .unverified_claims()
        .clone();
    claims.sub = "aauth:Other@ap.example".into();
    claims.jti = "other-agent".into();
    let provider = AgentProvider::new(
        "https://ap.example",
        "ap-key",
        SigningKey::from_seed([1; 32]),
    )
    .unwrap();
    let other = a.with_token(provider.issue(&claims).unwrap()).unwrap();
    let r = resource(&other, &p, "orders.read", |_| {});
    let response = f.exchange(&s, &other, &r, &p, None);
    assert_eq!(response.status(), 400);
    assert_eq!(output(&response)["error"], "invalid_presented_token");
    assert!(!response.headers().contains_key("signature-error"));
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn revocation_during_policy_or_after_commit_preserves_the_parameter_error_context() {
    struct RevokingPolicy(Host, TestStore);
    impl RevokingPolicy {
        fn revoke(&self) {
            self.1
                .revoke_binding(
                    PS,
                    &AgentIdentity {
                        issuer: "https://ap.example".into(),
                        subject: "aauth:Caller@ap.example".into(),
                    },
                )
                .unwrap();
        }
    }
    impl Policy for RevokingPolicy {
        fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
            self.revoke();
            self.0.bind_person(request)
        }
        fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
            self.revoke();
            self.0.authorize(request)
        }
    }
    for during_policy in [true, false] {
        for path in ["/person", "/token"] {
            let f = Fixture::new();
            let a = agent(false);
            let p = compact(&f.person(&f.server(900), &a, ORDERS, None), "person_token");
            let r = resource(&a, &p, "orders.read", |_| {});
            let policy: BoxedPolicy = if during_policy {
                Box::new(RevokingPolicy(f.host.clone(), f.store.clone()))
            } else {
                f.store.revoke_after_commit.store(true, Ordering::SeqCst);
                Box::new(f.host.clone())
            };
            let clock = f.host.now.clone();
            let ids = f.ids.clone();
            let s: Server = PersonServer::new(
                Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
                Keys,
                f.store.clone(),
                policy,
                Box::new(move || clock.load(Ordering::SeqCst)) as BoxedClock,
                Box::new(move || format!("token-{}", ids.fetch_add(1, Ordering::SeqCst)))
                    as BoxedTokenIds,
            )
            .unwrap();
            let body = if path == "/person" {
                json!({"resource":ORDERS})
            } else {
                json!({"resource_token":r,"presented_token":p})
            };
            let response = f.call(&s, &a, path, body);
            if path == "/person" {
                assert_eq!(response.status(), 403);
                assert_eq!(output(&response)["error"], "denied");
            } else {
                assert_eq!(response.status(), 400);
                assert_eq!(output(&response)["error"], "revoked_presented_token");
            }
            assert!(!response.headers().contains_key("signature-error"));
            assert!(output(&response).get("person_token").is_none());
            assert!(output(&response).get("auth_token").is_none());
        }
    }
}

#[test]
fn copied_upstream_subject_is_refused_before_a_downstream_token_is_released() {
    let f = Fixture::new();
    let s = f.server(900);
    let (_, upstream) = original(&f, &s);
    f.host.mode.store(9, Ordering::SeqCst);
    let response = f.person(&s, &agent(true), INVENTORY, Some(&upstream));
    assert_eq!(response.status(), 403);
    assert_eq!(output(&response)["error"], "access_denied");
    assert!(!response.headers().contains_key("signature-error"));
    assert!(output(&response).get("person_token").is_none());
    assert_eq!(f.host.chain_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.ids.load(Ordering::SeqCst), 2);
    assert!(
        f.store
            .binding(
                PS,
                &AgentIdentity {
                    issuer: ORDERS.into(),
                    subject: "aauth:Orders@orders.example".into(),
                }
            )
            .unwrap()
            .is_none()
    );
}

fn signed_json(agent: &Agent, path: &str, body: Value, content_type: &str) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", content_type)
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

#[test]
fn json_media_type_is_case_insensitive_without_normalizing_signed_header_bytes() {
    for media_type in ["Application/JSON", "APPLICATION/json; charset=UTF-8"] {
        let f = Fixture::new();
        let s = f.server(900);
        let a = agent(false);
        let request = signed_json(&a, "/person", json!({"resource":ORDERS}), media_type);
        let person = compact(&s.handle(&request), "person_token");
        let challenge = resource(&a, &person, "orders.read", |_| {});
        let request = signed_json(
            &a,
            "/token",
            json!({"resource_token":challenge,"presented_token":person}),
            media_type,
        );
        compact(&s.handle(&request), "auth_token");
        assert_eq!(f.host.bind_calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 1);
        let mut changed = request;
        changed
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        let refused = s.handle(&changed);
        assert_eq!(refused.status(), 401);
        assert_eq!(
            refused.headers()["signature-error"],
            "error=invalid_signature"
        );
        assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn identical_auth_exchange_can_issue_distinct_retained_tokens_for_one_resource_challenge() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let person = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    let challenge = resource(&a, &person, "orders.read", |_| {});
    let request = signed_json(
        &a,
        "/token",
        json!({"resource_token":challenge,"presented_token":person}),
        "application/json",
    );
    let first = compact(&s.handle(&request), "auth_token");
    let second = compact(&s.handle(&request), "auth_token");
    let first = AuthToken::parse(&first)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    let second = AuthToken::parse(&second)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_ne!(first.claims().jti, second.claims().jti);
    assert_eq!(first.claims().aud, second.claims().aud);
    assert_eq!(first.claims().scope, second.claims().scope);
    for auth in [first, second] {
        assert!(
            f.store
                .token(&TokenReference {
                    issuer: PS.into(),
                    jti: auth.claims().jti.clone()
                })
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn user_unreachable_is_explicit_at_both_token_endpoints() {
    let f = Fixture::new();
    let s = f.server(900);
    let a = agent(false);
    let p = compact(&f.person(&s, &a, ORDERS, None), "person_token");
    let r = resource(&a, &p, "orders.read", |_| {});
    f.host.mode.store(8, Ordering::SeqCst);
    for response in [
        f.person(&s, &a, ORDERS, None),
        f.exchange(&s, &a, &r, &p, None),
    ] {
        assert_eq!(response.status(), 403);
        assert_eq!(output(&response)["error"], "user_unreachable");
        assert!(!response.headers().contains_key("signature-error"));
        assert!(output(&response).get("person_token").is_none());
        assert!(output(&response).get("auth_token").is_none());
    }
}

struct AccessTransport {
    mode: usize,
    calls: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
}
impl aauth_rust_person_server::Federation for AccessTransport {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        if issuer != "https://as.example" {
            return Err(aauth_rust_person_server::FederationError);
        }
        Ok(match self.mode {
            11 => "http://as.example/token",
            28 => "https://as.example/token?x=1",
            29 => "https://as.example/token#fragment",
            _ => "https://as.example/token",
        }
        .into())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode == 25 {
            return Err(aauth_rust_person_server::FederationError);
        }
        let server = aauth_rust_access_server::AccessServer::new(
            aauth_rust_access_server::Config::new(
                "https://as.example",
                "as-key",
                SigningKey::from_seed([7; 32]),
            ),
            Keys,
            |_: &aauth_rust_access_server::AuthorizationRequest| {
                Ok(aauth_rust_access_server::Decision {
                    scopes: vec!["read".into()],
                    lifetime: if self.mode == 26 { 10 } else { 600 },
                })
            },
            || 1000,
            || format!("access-auth-{call}"),
        )
        .unwrap();
        let mut altered;
        let incoming = if self.mode == 24 || self.mode == 27 {
            altered = request.clone();
            if self.mode == 24 {
                *altered.uri_mut() = "https://as.example:9443/token".parse().unwrap();
            } else {
                let key = SigningKey::from_seed([3; 32]);
                aauth_rust_signature_key::sign_request(
                    &mut altered,
                    &key,
                    aauth_rust_signature_key::KeyMaterial::Hwk(key.public_jwk()),
                    1000,
                )
                .unwrap();
            }
            &altered
        } else {
            request
        };
        let mut response = server.handle(incoming);
        if self.mode != 24 && self.mode != 27 {
            assert_eq!(
                response.status(),
                200,
                "{}",
                String::from_utf8_lossy(response.body())
            );
        } else {
            assert_eq!(response.status(), 401);
            let mut body = output(&response);
            body["detail"] = json!("private AS proof diagnostic");
            *response.body_mut() = body.to_string().into_bytes();
        }
        match self.mode {
            1 => *response.body_mut() = b"not json".to_vec(),
            2 | 3 | 5 | 6 | 15..=22 => {
                let compact = output(&response)["auth_token"].as_str().unwrap().to_owned();
                let parsed = AuthToken::parse(&compact).unwrap();
                let mut claims = parsed.unverified_claims().clone();
                match self.mode {
                    2 => claims.cnf.jwk = SigningKey::from_seed([9; 32]).public_jwk(),
                    3 => claims.scope = Some("admin".into()),
                    5 => claims.exp = 4000,
                    15 => claims.sub = "different-person".into(),
                    16 => claims.aud = PS.into(),
                    17 => claims.ps = "https://other-ps.example".into(),
                    18 => claims.tenant = Some("different-tenant".into()),
                    19 => claims.account = Some("invented-account".into()),
                    20 => claims.iss = "https://foreign-as.example".into(),
                    21 => claims.iat = 1061,
                    22 => {
                        claims
                            .extra
                            .insert("r3_uri".into(), json!("https://resource.example/classes"));
                    }
                    _ => {
                        claims.iss = PS.into();
                        claims.dwk = "aauth-person.json".into();
                    }
                }
                let (key, kid) = if self.mode == 6 {
                    (3, "ps-key")
                } else {
                    (7, "as-key")
                };
                let compact = aauth_rust_core::mint_auth_token(
                    &SigningKey::from_seed([key; 32]),
                    kid,
                    &claims,
                )
                .unwrap();
                *response.body_mut() = json!({"auth_token":compact}).to_string().into_bytes();
            }
            4 | 7 => {
                *response.status_mut() = if self.mode == 4 {
                    http::StatusCode::FORBIDDEN
                } else {
                    http::StatusCode::INTERNAL_SERVER_ERROR
                };
                response
                    .headers_mut()
                    .insert("content-type", "application/problem+json".parse().unwrap());
                *response.body_mut() =
                    json!({"error":if self.mode==4 {"access_denied"}else{"server_error"}})
                        .to_string()
                        .into_bytes();
            }
            13 | 14 => {
                *response.status_mut() = if self.mode == 13 {
                    http::StatusCode::UNAUTHORIZED
                } else {
                    http::StatusCode::BAD_REQUEST
                };
                response
                    .headers_mut()
                    .insert("content-type", "application/problem+json".parse().unwrap());
                response
                    .headers_mut()
                    .insert("date", "Thu, 01 Jan 1970 00:16:40 GMT".parse().unwrap());
                *response.body_mut() = json!({"error": "clock_skew"}).to_string().into_bytes();
            }
            23 => {
                *response.status_mut() = http::StatusCode::PAYMENT_REQUIRED;
                response
                    .headers_mut()
                    .insert("content-type", "application/problem+json".parse().unwrap());
                response.headers_mut().insert(
                    "location",
                    "https://as.example/pending/payment".parse().unwrap(),
                );
                response
                    .headers_mut()
                    .insert("www-authenticate", "Payment id=demo".parse().unwrap());
                *response.body_mut() = json!({"error":"payment_required"}).to_string().into_bytes();
            }
            8 => *response.status_mut() = http::StatusCode::ACCEPTED,
            9 => self.now.store(4000, Ordering::SeqCst),
            _ => {}
        }
        Ok(response)
    }
}
#[test]
fn federated_delivery_verifies_as_result_and_retains_exact_step_up_ancestry() {
    // Core ps-as-federation, auth-token-delivery and resource-token-verification.
    let f = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = f.server(2000).with_federation(AccessTransport {
        mode: 0,
        calls: calls.clone(),
        now: f.host.now.clone(),
    });
    let holder = agent(false);
    let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let challenge = resource(&holder, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let response = f.exchange(&server, &holder, &challenge, &person, None);
    let auth = compact(&response, "auth_token");
    let token = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().dwk, "aauth-access.json");
    let record = f
        .store
        .token(&TokenReference {
            issuer: "https://as.example".into(),
            jti: token.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(record.person_server.as_deref(), Some(PS));
    let step = resource(&holder, &auth, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let second = compact(
        &f.exchange(&server, &holder, &step, &auth, None),
        "auth_token",
    );
    let second = AuthToken::parse(&second)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    let step_record = f
        .store
        .token(&TokenReference {
            issuer: "https://as.example".into(),
            jti: second.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(step_record.presented, Some(record.token.clone()));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(
        f.store
            .binding("https://as.example", &record.principal)
            .unwrap()
            .is_none()
    );
}
#[test]
fn federation_never_releases_unverified_or_unretained_as_tokens() {
    for mode in [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    ] {
        let f = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = f.server(2000).with_federation(AccessTransport {
            mode,
            calls: calls.clone(),
            now: f.host.now.clone(),
        });
        let holder = agent(false);
        let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
        let challenge = resource(&holder, &person, "read", |r| {
            r.aud = "https://as.example".into()
        });
        if mode == 12 {
            f.store.fail.store(true, Ordering::SeqCst);
        }
        let response = f.exchange(&server, &holder, &challenge, &person, None);
        let v = output(&response);
        assert!(v.get("auth_token").is_none(), "mode{mode}");
        let (status, code) = match mode {
            4 => (403, "access_denied"),
            7 | 12 => (500, "server_error"),
            9 => (400, "expired_resource_token"),
            13 => (401, "clock_skew"),
            14 => (400, "clock_skew"),
            _ => (502, "as_unreachable"),
        };
        assert_eq!(
            (response.status().as_u16(), v["error"].as_str().unwrap()),
            (status, code),
            "mode{mode}"
        );
        if mode == 13 || mode == 14 {
            assert_eq!(
                response.headers().get("date").map(|v| v.to_str().unwrap()),
                Some("Thu, 01 Jan 1970 00:16:40 GMT")
            );
        }
        if mode == 11 {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        // Person issuance remains; no unverified/unretained AS Auth row exists.
        for issuer in ["https://as.example", "https://foreign-as.example", PS] {
            assert!(
                f.store
                    .token(&TokenReference {
                        issuer: issuer.into(),
                        jti: "access-auth-0".into()
                    })
                    .unwrap()
                    .is_none(),
                "mode{mode}: unexpected Auth receipt under {issuer}"
            );
        }
    }
}

#[test]
fn federated_consent_denial_prevents_any_as_dispatch() {
    let f = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = f.server(2000).with_federation(AccessTransport {
        mode: 0,
        calls: calls.clone(),
        now: f.host.now.clone(),
    });
    let holder = agent(false);
    let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let challenge = resource(&holder, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    for (mode, reason, status) in [
        (1, PolicyError::Denied, 403),
        (2, PolicyError::Unavailable, 500),
        (8, PolicyError::UserUnreachable, 403),
    ] {
        f.host.mode.store(mode, Ordering::SeqCst);
        let response = f.exchange(&server, &holder, &challenge, &person, None);
        assert_eq!(response.status(), status);
        if mode == 1 {
            assert_eq!(output(&response)["error"], "access_denied");
        }
        let diagnostic = response
            .extensions()
            .get::<aauth_rust_person_server::FederationFailure>()
            .expect("host must learn consent refused before AS contact");
        assert_eq!(diagnostic.access_server, "https://as.example");
        assert_eq!(diagnostic.status, None);
        assert_eq!(
            diagnostic.reason,
            aauth_rust_person_server::FederationFailureReason::ConsentRefused(reason)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn terminal_as_service_proof_refusal_relays_status_error_without_federation_retry_code() {
    // Core auth-token-delivery: a well-formed terminal AS error is relayed.
    let f = Fixture::new();
    let server = f.server(2000).with_federation(AccessTransport {
        mode: 24,
        calls: Arc::new(AtomicUsize::new(0)),
        now: f.host.now.clone(),
    });
    let holder = agent(false);
    let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let challenge = resource(&holder, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let response = f.exchange(&server, &holder, &challenge, &person, None);
    assert_eq!(
        response.status(),
        401,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(output(&response)["error"], "invalid_signature");
    assert!(
        !response.headers().contains_key("signature-error"),
        "the Agent proof at the PS did not fail"
    );
    assert!(!String::from_utf8_lossy(response.body()).contains("private AS proof diagnostic"));
}

#[test]
fn federation_diagnostics_remain_host_visible_and_distinguish_failure_phases() {
    use aauth_rust_person_server::{FederationFailure, FederationFailureReason as Reason};
    for mode in [1, 2, 8, 11, 23, 24, 25, 27] {
        let f = Fixture::new();
        let server = f.server(2000).with_federation(AccessTransport {
            mode,
            calls: Arc::new(AtomicUsize::new(0)),
            now: f.host.now.clone(),
        });
        let holder = agent(false);
        let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
        let challenge = resource(&holder, &person, "read", |r| {
            r.aud = "https://as.example".into()
        });
        let response = f.exchange(&server, &holder, &challenge, &person, None);
        let diagnostic = response
            .extensions()
            .get::<FederationFailure>()
            .expect("host diagnostic on federation failure");
        assert_eq!(diagnostic.access_server, "https://as.example");
        match mode {
            1 => {
                assert_eq!(diagnostic.status, Some(http::StatusCode::OK));
                assert!(matches!(diagnostic.reason, Reason::MalformedResponse(_)));
            }
            2 => assert_eq!(diagnostic.reason, Reason::InvalidGrant),
            8 | 23 => assert_eq!(diagnostic.reason, Reason::UnsupportedResponse),
            11 => {
                assert_eq!(diagnostic.status, None);
                assert_eq!(diagnostic.reason, Reason::InvalidEndpoint);
            }
            25 => {
                assert_eq!(diagnostic.status, None);
                assert_eq!(diagnostic.reason, Reason::TransportUnavailable);
            }
            24 | 27 => {
                assert_eq!(diagnostic.status, Some(http::StatusCode::UNAUTHORIZED));
                let Reason::TerminalError {
                    error,
                    signature_error,
                    detail,
                } = &diagnostic.reason
                else {
                    panic!("terminal diagnostic expected")
                };
                let expected = if mode == 24 {
                    "invalid_signature"
                } else {
                    "unsupported_scheme"
                };
                assert_eq!(error, expected);
                assert_eq!(
                    signature_error.as_deref(),
                    Some(format!("error={expected}").as_str())
                );
                assert_eq!(detail.as_deref(), Some("private AS proof diagnostic"));
            }
            _ => unreachable!(),
        }
        assert!(output(&response).get("auth_token").is_none());
        assert!(!String::from_utf8_lossy(response.body()).contains("private AS proof diagnostic"));
        assert!(!response.headers().contains_key("signature-error"));
        assert!(!response.headers().contains_key("accept-signature-scheme"));
        assert!(!response.headers().contains_key("accept-signature-alg"));
    }
}

#[test]
fn direct_and_federated_expiry_after_commit_keep_the_row_and_report_local_failure() {
    // Core auth-token-delivery; identical local issuance/release disposition.
    for federated in [false, true] {
        let f = Fixture::new();
        let mut server = f.server(2000);
        if federated {
            server = server.with_federation(AccessTransport {
                mode: 26,
                calls: Arc::new(AtomicUsize::new(0)),
                now: f.host.now.clone(),
            });
        }
        let holder = agent(false);
        let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
        let challenge = resource(&holder, &person, "read", |r| {
            if federated {
                r.aud = "https://as.example".into()
            }
        });
        if !federated {
            f.host.mode.store(5, Ordering::SeqCst);
        }
        f.store.stall.store(1010, Ordering::SeqCst);
        let response = f.exchange(&server, &holder, &challenge, &person, None);
        assert_eq!(
            response.status(),
            500,
            "federated={federated}, {}",
            String::from_utf8_lossy(response.body())
        );
        assert_eq!(output(&response)["error"], "server_error");
        assert!(output(&response).get("auth_token").is_none());
        let reference = TokenReference {
            issuer: if federated { "https://as.example" } else { PS }.into(),
            jti: if federated {
                "access-auth-0"
            } else {
                "token-1"
            }
            .into(),
        };
        let retained = f
            .store
            .token(&reference)
            .unwrap()
            .expect("already committed row remains acknowledged");
        assert_eq!(retained.expires_at, 1010);
        if federated {
            let diagnostic = response
                .extensions()
                .get::<aauth_rust_person_server::FederationFailure>()
                .unwrap();
            assert_eq!(
                diagnostic.reason,
                aauth_rust_person_server::FederationFailureReason::ExpiredBeforeRelease
            );
            assert_eq!(diagnostic.status, Some(http::StatusCode::OK));
        }
    }
}

struct AliasAccessKeys;
impl AgentKeyResolver for AliasAccessKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if (issuer, dwk, kid) == ("https://foreign-as.example", "aauth-access.json", "as-key") {
            Ok(SigningKey::from_seed([7; 32]).public_jwk())
        } else {
            Keys.key(issuer, dwk, kid)
        }
    }
}
#[test]
fn delivery_rejects_foreign_as_issuer_even_when_its_resigned_token_verifies() {
    use aauth_rust_person_server::{FederationFailure, FederationFailureReason};
    let f = Fixture::new();
    let server = f
        .server_with_keys(2000, AliasAccessKeys)
        .with_federation(AccessTransport {
            mode: 20,
            calls: Arc::new(AtomicUsize::new(0)),
            now: f.host.now.clone(),
        });
    let holder = agent(false);
    let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let challenge = resource(&holder, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let response = f.exchange(&server, &holder, &challenge, &person, None);
    assert_eq!(response.status(), 502);
    assert_eq!(output(&response)["error"], "as_unreachable");
    assert_eq!(
        response
            .extensions()
            .get::<FederationFailure>()
            .unwrap()
            .reason,
        FederationFailureReason::InvalidGrant,
        "trusted foreign signature must reach the exact expected-issuer comparison"
    );
    for issuer in ["https://as.example", "https://foreign-as.example"] {
        assert!(
            f.store
                .token(&TokenReference {
                    issuer: issuer.into(),
                    jti: "access-auth-0".into()
                })
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn auth_token_endpoint_must_be_https_without_query_or_fragment() {
    use aauth_rust_person_server::{FederationFailure, FederationFailureReason as Reason};
    let f = Fixture::new();
    let published: Value = serde_json::from_slice(&f.server(2000).metadata()).unwrap();
    for field in ["person_token_endpoint", "auth_token_endpoint", "jwks_uri"] {
        let url = published[field].as_str().unwrap();
        assert!(url.starts_with("https://"), "{field} {url}");
        assert!(!url.contains('?') && !url.contains('#'), "{field} {url}");
    }
    for mode in [11, 28, 29] {
        let calls = Arc::new(AtomicUsize::new(0));
        let server = f.server(2000).with_federation(AccessTransport {
            mode,
            calls: calls.clone(),
            now: f.host.now.clone(),
        });
        let holder = agent(false);
        let person = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
        let challenge = resource(&holder, &person, "read", |r| {
            r.aud = "https://as.example".into()
        });
        let response = f.exchange(&server, &holder, &challenge, &person, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "mode{mode}");
        assert_eq!(
            response
                .extensions()
                .get::<FederationFailure>()
                .expect("host diagnostic")
                .reason,
            Reason::InvalidEndpoint,
            "mode{mode}"
        );
    }
}

#[path = "support/deferred.rs"]
mod deferred;

#[path = "support/subagents.rs"]
mod subagents;

#[path = "support/release_fences.rs"]
mod release_fences;
