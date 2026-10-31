use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, ApprovedMission, AuthToken, Confirmation, PersonToken,
    ResourceClaims, TokenError, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Binding, Config, Grant, MemoryStore, MissionRecord,
    MissionState, MissionStore, MissionStoreError, Person, PersonRequest, PersonServer, Policy,
    PolicyError, Store, StoreError, TokenKind, TokenRecord, TokenReference, TokenTie,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};

const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
/// Reached by `RESOURCE` acting as an intermediary.
const DOWNSTREAM: &str = "https://downstream.example";
fn owner() -> AgentIdentity {
    AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:Reader@ap.example".into(),
    }
}
fn approved() -> MissionRecord {
    let bytes = br#"{ "agent":"aauth:Reader@ap.example","approved_at":"1970-01-01T00:16:39Z","expires_at":"1970-01-01T00:17:25.9Z","description":"Read revision A","extension":{"retained":true}}"#;
    MissionRecord {
        person_server: PS.into(),
        owner: owner(),
        person_id: "private-person".into(),
        state: MissionState::Active,
        document: ApprovedMission::decode(
            &URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
            &URL_SAFE_NO_PAD.encode(bytes),
        )
        .unwrap(),
    }
}
#[derive(Clone)]
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap") => 1,
            (PS, "aauth-person.json", "ps") => 3,
            (RESOURCE, "aauth-resource.json", "resource") => 4,
            (RESOURCE, "aauth-agent.json", "resource-agent") => 6,
            (DOWNSTREAM, "aauth-resource.json", "downstream") => 8,
            ("https://as.example", "aauth-access.json", "as") => 9,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}
fn agent(ps: &str) -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let compact = AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: owner().issuer,
            dwk: "aauth-agent.json".into(),
            sub: owner().subject,
            jti: "agent".into(),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(ps.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, compact).unwrap()
}
/// `RESOURCE` as its own Agent Provider, signing downstream requests.
fn intermediary() -> Agent {
    let key = SigningKey::from_seed([7; 32]);
    let compact = AgentProvider::new(RESOURCE, "resource-agent", SigningKey::from_seed([6; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Chain@resource.example".into(),
            jti: "chain".into(),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: None,
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, compact).unwrap()
}
fn request(agent: &Agent, path: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}
fn value(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}

#[derive(Clone)]
struct RacingStore {
    inner: MemoryStore,
    mode: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
}
impl Store for RacingStore {
    fn missions(&self) -> Option<&dyn MissionStore> {
        Some(self)
    }
    fn binding(&self, ps: &str, a: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.inner.binding(ps, a)
    }
    fn token(&self, r: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.inner.token(r)
    }
    fn commit(&self, r: TokenRecord, e: bool) -> Result<(), StoreError> {
        self.inner.commit(r, e)
    }
    fn revoke_binding(&self, ps: &str, a: &AgentIdentity) -> Result<(), StoreError> {
        self.inner.revoke_binding(ps, a)
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        self.inner.retained()
    }
}
impl MissionStore for RacingStore {
    fn load_mission(
        &self,
        ps: &str,
        a: &AgentIdentity,
        s: &str,
        at: i64,
    ) -> Result<MissionRecord, MissionStoreError> {
        self.inner.load_mission(ps, a, s, at)
    }
    fn commit_mission_token(
        &self,
        m: &MissionRecord,
        at: i64,
        r: TokenRecord,
        e: bool,
    ) -> Result<(), MissionStoreError> {
        self.inner.commit_mission_token(m, at, r, e)?;
        match self.mode.load(Ordering::SeqCst) {
            10 => {
                self.inner
                    .terminate_mission(PS, &owner(), m.document.s256(), "revoked")?;
            }
            11 => self.now.store(1045, Ordering::SeqCst),
            12 => self.inner.revoke_binding(PS, &owner())?,
            _ => {}
        };
        Ok(())
    }
}
#[derive(Clone)]
struct Host {
    store: RacingStore,
    calls: Arc<AtomicUsize>,
}
impl Host {
    fn race(&self, m: &MissionRecord) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.store.mode.load(Ordering::SeqCst) {
            1 => self
                .store
                .inner
                .terminate_mission(PS, &owner(), m.document.s256(), "revoked")
                .unwrap(),
            2 => self.store.now.store(1045, Ordering::SeqCst),
            3 => self.store.inner.revoke_binding(PS, &owner()).unwrap(),
            _ => {}
        }
    }
}
impl Policy for Host {
    fn bind_person(&self, r: &PersonRequest) -> Result<Person, PolicyError> {
        let m = r.mission.as_ref().expect("verified host mission context");
        self.race(m);
        Ok(Person {
            id: if self.store.mode.load(Ordering::SeqCst) == 4 {
                "different-person"
            } else {
                "private-person"
            }
            .into(),
            subject: "directed-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, r: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.race(r.mission.as_ref().expect("verified host mission context"));
        Ok(Grant {
            scopes: if self.store.mode.load(Ordering::SeqCst) == 5 {
                vec!["admin".into()]
            } else {
                r.scopes.clone()
            },
            lifetime: 600,
        })
    }
    fn bind_upstream(&self, r: &PersonRequest) -> Result<Person, PolicyError> {
        self.race(r.mission.as_ref().expect("the upstream token's mission"));
        Ok(Person {
            id: "private-person".into(),
            subject: "downstream-person".into(),
            tenant: None,
        })
    }
    fn authorize_upstream(&self, r: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.authorize(r)
    }
    fn consent(&self, r: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.authorize(r).map(|_| ())
    }
    fn consent_upstream(&self, r: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.authorize(r).map(|_| ())
    }
}
type Server = PersonServer<
    Keys,
    RacingStore,
    Host,
    Box<dyn Fn() -> i64 + Send + Sync>,
    Box<dyn Fn() -> String + Send + Sync>,
>;
fn fixture() -> (Server, RacingStore, Arc<AtomicUsize>, MissionRecord) {
    let store = RacingStore {
        inner: MemoryStore::default(),
        mode: Arc::new(AtomicUsize::new(0)),
        now: Arc::new(AtomicI64::new(1000)),
    };
    let m = approved();
    store.inner.install_approved_mission(m.clone()).unwrap();
    let now = store.now.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let ids = AtomicUsize::new(0);
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        store.clone(),
        Host {
            store: store.clone(),
            calls: calls.clone(),
        },
        Box::new(move || now.load(Ordering::SeqCst)) as _,
        Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))) as _,
    )
    .unwrap();
    (server, store, calls, m)
}
fn person(server: &Server, a: &Agent, m: &MissionRecord) -> Response<Vec<u8>> {
    server.handle(&request(
        a,
        "/person",
        json!({"resource":RESOURCE,"mission_s256":m.document.s256()}),
    ))
}
fn resource(a: &Agent, person: &str, mission: Option<&str>) -> String {
    let p = PersonToken::parse(person).unwrap();
    let p = p.unverified_claims();
    mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            ps: PS.into(),
            sub: p.sub.clone(),
            jti: "resource".into(),
            presented_jti: p.jti.clone(),
            agent_jkt: a.public_jwk().thumbprint().unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some("revision.a.read".into()),
            mission_s256: mission.map(str::to_owned),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn auth(server: &Server, a: &Agent, p: &str, r: &str) -> Response<Vec<u8>> {
    server.handle(&request(
        a,
        "/token",
        json!({"presented_token":p,"resource_token":r}),
    ))
}

#[test]
fn an_upstream_tokens_mission_is_carried_down_the_chain_and_ends_it() {
    let (s, store, calls, m) = fixture();
    let upstream = value(&person(&s, &agent(PS), &m))["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let chain = intermediary();
    // The upstream token carries the mission; the intermediary sends none.
    let own =
        json!({"resource":DOWNSTREAM,"upstream_token":upstream,"mission_s256":m.document.s256()});
    assert_eq!(
        value(&s.handle(&request(&chain, "/person", own)))["error"],
        "invalid_request"
    );
    let chained = json!({"resource":DOWNSTREAM,"upstream_token":upstream});
    let response = s.handle(&request(&chain, "/person", chained.clone()));
    assert_eq!(response.status(), 200, "{:?}", value(&response));
    let downstream = value(&response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims = PersonToken::parse(&downstream)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap()
        .claims()
        .clone();
    assert_eq!(claims.mission_s256.as_deref(), Some(m.document.s256()));
    assert_eq!(
        (claims.sub.as_str(), claims.exp),
        ("downstream-person", 1045)
    );
    let retained = store
        .inner
        .token(&TokenReference {
            issuer: PS.into(),
            jti: claims.jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(retained.principal, owner());
    assert_eq!(retained.agent.subject, "aauth:Chain@resource.example");
    let challenge = mint_resource_token(
        &SigningKey::from_seed([8; 32]),
        "downstream",
        &ResourceClaims {
            iss: DOWNSTREAM.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            ps: PS.into(),
            sub: claims.sub.clone(),
            jti: "downstream".into(),
            presented_jti: claims.jti.clone(),
            agent_jkt: chain.public_jwk().thumbprint().unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some("stock.read".into()),
            mission_s256: claims.mission_s256.clone(),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            extra: Default::default(),
        },
    )
    .unwrap();
    let exchange =
        json!({"resource_token":challenge,"presented_token":downstream,"upstream_token":upstream});
    let response = s.handle(&request(&chain, "/token", exchange.clone()));
    assert_eq!(response.status(), 200, "{:?}", value(&response));
    let auth = AuthToken::parse(value(&response)["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        auth.claims().mission_s256.as_deref(),
        Some(m.document.s256())
    );
    assert_eq!(auth.claims().exp, 1045);
    // The caller's Person token, then bind_upstream and authorize_upstream.
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    // Terminating the calling Agent's mission ends the chain at both endpoints.
    store
        .inner
        .terminate_mission(PS, &owner(), m.document.s256(), "revoked")
        .unwrap();
    for (path, body) in [("/person", chained), ("/token", exchange)] {
        let refused = value(&s.handle(&request(&chain, path, body)));
        assert_eq!(refused["error"], "mission_terminated", "{path}");
        assert_eq!(refused["termination_reason"], "revoked", "{path}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn current_mission_person_and_auth_consume_verified_host_record_and_cap_expiry() {
    let (s, store, calls, m) = fixture();
    let a = agent(PS);
    let response = person(&s, &a, &m);
    assert_eq!(response.status(), 200, "{:?}", value(&response));
    let p = value(&response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let verified = PersonToken::parse(&p).unwrap().verify(&Keys, 1000).unwrap();
    assert_eq!(
        verified.claims().mission_s256.as_deref(),
        Some(m.document.s256())
    );
    assert_eq!(verified.claims().exp, 1045);
    assert_eq!(
        store
            .inner
            .load_mission(PS, &owner(), m.document.s256(), 1000)
            .unwrap()
            .document
            .exact_json(),
        m.document.exact_json()
    );
    let r = resource(&a, &p, Some(m.document.s256()));
    let response = auth(&s, &a, &p, &r);
    assert_eq!(response.status(), 200, "{:?}", value(&response));
    let compact = value(&response)["auth_token"].as_str().unwrap().to_owned();
    let verified = AuthToken::parse(&compact)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        verified.claims().mission_s256.as_deref(),
        Some(m.document.s256())
    );
    assert_eq!(verified.claims().exp, 1045);
    assert_eq!(verified.claims().scope.as_deref(), Some("revision.a.read"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn current_mission_wrong_owner_digest_ps_and_terminal_state_never_reach_policy() {
    for mode in 0..5 {
        let (s, store, calls, m) = fixture();
        let a = agent(if mode == 2 {
            "https://other.example"
        } else {
            PS
        });
        let digest = if mode == 0 {
            URL_SAFE_NO_PAD.encode([9; 32])
        } else {
            m.document.s256().into()
        };
        if mode == 1 {
            let mut other = m.clone();
            other.owner.subject = "aauth:Other@ap.example".into();
            assert!(store.inner.install_approved_mission(other).is_err());
            // A real second Agent cannot learn the first Agent's mission state.
            let mut other_owner = owner();
            other_owner.subject = "aauth:Other@ap.example".into();
            assert_eq!(
                store
                    .inner
                    .load_mission(PS, &other_owner, m.document.s256(), 1000),
                Err(MissionStoreError::NotFound)
            );
            continue;
        }
        if mode == 3 {
            store.now.store(1045, Ordering::SeqCst);
        }
        if mode == 4 {
            store
                .inner
                .terminate_mission(PS, &owner(), m.document.s256(), "revoked")
                .unwrap();
        }
        let response = s.handle(&request(
            &a,
            "/person",
            json!({"resource":RESOURCE,"mission_s256":digest}),
        ));
        assert_ne!(response.status(), 200, "mode {mode}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        if mode >= 3 {
            let body = value(&response);
            assert_eq!(response.status(), 403);
            assert_eq!(body["error"], "mission_terminated");
            assert_eq!(body["mission_status"], "terminated");
            assert_eq!(
                body["termination_reason"],
                if mode == 3 { "expired" } else { "revoked" }
            );
            assert_ne!(body["mission_status"], body["termination_reason"]);
        }
    }
}

#[test]
fn current_mission_policy_and_commit_races_release_no_credential() {
    for stage in ["person", "auth"] {
        for mode in [1, 2, 3, 4, 10, 11, 12] {
            if stage == "auth" && mode == 4 {
                continue;
            }
            let (s, store, _, m) = fixture();
            let a = agent(PS);
            let p = if stage == "auth" {
                let response = person(&s, &a, &m);
                value(&response)["person_token"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            } else {
                String::new()
            };
            store.mode.store(mode, Ordering::SeqCst);
            let response = if stage == "person" {
                person(&s, &a, &m)
            } else {
                auth(&s, &a, &p, &resource(&a, &p, Some(m.document.s256())))
            };
            assert_ne!(response.status(), 200, "stage {stage}, mode {mode}");
            assert!(
                value(&response).get("person_token").is_none()
                    && value(&response).get("auth_token").is_none()
            );
        }
    }
}

#[test]
fn current_mission_auth_refuses_stripping_substitution_and_broadened_grant() {
    let (s, store, calls, m) = fixture();
    let a = agent(PS);
    let response = person(&s, &a, &m);
    let p = value(&response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = URL_SAFE_NO_PAD.encode([9; 32]);
    for digest in [None, Some(other.as_str())] {
        let response = auth(&s, &a, &p, &resource(&a, &p, digest));
        assert_eq!(response.status(), 400);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    store.mode.store(5, Ordering::SeqCst);
    let response = auth(&s, &a, &p, &resource(&a, &p, Some(m.document.s256())));
    assert_eq!(response.status(), 500);
}

#[test]
fn empty_termination_reason_leaves_the_active_mission_unchanged() {
    let store = MemoryStore::default();
    let owner = owner();
    store
        .commit(
            TokenRecord {
                parent_agent: None,
                person_server: None,
                token: TokenTie {
                    reference: TokenReference {
                        issuer: PS.into(),
                        jti: "person-1".into(),
                    },
                    compact_sha256: "digest".into(),
                },
                kind: TokenKind::Person,
                resource: RESOURCE.into(),
                subject: "directed-person".into(),
                person_id: "private-person".into(),
                tenant: None,
                agent: owner.clone(),
                principal: owner.clone(),
                binding_generation: 0,
                agent_token_jti: "agent".into(),
                agent_jkt: "thumbprint".into(),
                issued_at: 1000,
                expires_at: 2000,
                retain_until: 3000,
                presented: None,
                upstream: None,
                r3: None,
            },
            true,
        )
        .unwrap();
    let bytes = br#"{"agent":"aauth:Reader@ap.example","approved_at":"1970-01-01T00:16:39Z","description":"still active"}"#;
    let mission = MissionRecord {
        person_server: PS.into(),
        owner: owner.clone(),
        person_id: "private-person".into(),
        state: MissionState::Active,
        document: ApprovedMission::decode(
            &URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
            &URL_SAFE_NO_PAD.encode(bytes),
        )
        .unwrap(),
    };
    store.install_approved_mission(mission.clone()).unwrap();
    let digest = mission.document.s256();
    assert_eq!(
        store.terminate_mission(PS, &owner, digest, ""),
        Err(MissionStoreError::Conflict)
    );
    assert_eq!(
        store.load_mission(PS, &owner, digest, 1000).unwrap().state,
        MissionState::Active
    );
    store.terminate_mission(PS, &owner, digest, "user").unwrap();
    assert!(matches!(
        store.load_mission(PS, &owner, digest, 1000),
        Err(MissionStoreError::Terminated(reason)) if reason == "user"
    ));
}

#[test]
fn current_mission_termination_is_permanent_and_wrong_owner_hides_state() {
    let (_, store, _, m) = fixture();
    let digest = m.document.s256();
    assert!(matches!(
        store.inner.load_mission(PS, &owner(), digest, 1045),
        Err(MissionStoreError::Terminated(_))
    ));
    assert!(matches!(
        store.inner.load_mission(PS, &owner(), digest, 1000),
        Err(MissionStoreError::Terminated(_))
    ));
    assert!(store.inner.install_approved_mission(m.clone()).is_err());
    let mut other = owner();
    other.subject = "aauth:Other@ap.example".into();
    assert_eq!(
        store.inner.load_mission(PS, &other, digest, 1045),
        Err(MissionStoreError::NotFound)
    );
}

#[test]
fn current_mission_without_expiry_still_obeys_agent_ceiling() {
    let (server, store, _, mut mission) = fixture();
    let bytes=br#"{"agent":"aauth:Reader@ap.example","approved_at":"1970-01-01T00:16:39Z","description":"Host approved without expiry"}"#;
    mission.document = ApprovedMission::decode(
        &URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        &URL_SAFE_NO_PAD.encode(bytes),
    )
    .unwrap();
    store
        .inner
        .install_approved_mission(mission.clone())
        .unwrap();
    let response = person(&server, &agent(PS), &mission);
    assert_eq!(response.status(), 200);
    let token = value(&response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        PersonToken::parse(&token)
            .unwrap()
            .verify(&Keys, 1000)
            .unwrap()
            .claims()
            .exp,
        2000
    );
}

struct NoMissions(RacingStore);
impl Store for NoMissions {
    fn binding(&self, ps: &str, a: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.0.binding(ps, a)
    }
    fn token(&self, r: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.0.token(r)
    }
    fn commit(&self, r: TokenRecord, e: bool) -> Result<(), StoreError> {
        self.0.commit(r, e)
    }
    fn revoke_binding(&self, ps: &str, a: &AgentIdentity) -> Result<(), StoreError> {
        self.0.revoke_binding(ps, a)
    }
}
#[test]
fn current_mission_store_extension_is_closed_by_default() {
    let (_, store, calls, m) = fixture();
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        NoMissions(store.clone()),
        Host {
            store,
            calls: calls.clone(),
        },
        || 1000,
        || "not-issued".into(),
    )
    .unwrap();
    let response = server.handle(&request(
        &agent(PS),
        "/person",
        json!({"resource":RESOURCE,"mission_s256":m.document.s256()}),
    ));
    assert_eq!(response.status(), 400);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn install_rejects_a_mission_that_is_not_active_before_writing_a_binding() {
    let store = MemoryStore::default();
    for state in [
        MissionState::Terminated("revoked".into()),
        MissionState::Terminated(String::new()),
    ] {
        let mut record = approved();
        record.state = state;
        assert_eq!(
            store.install_approved_mission(record),
            Err(MissionStoreError::Conflict)
        );
        assert!(store.binding(PS, &owner()).unwrap().is_none());
    }
    store.install_approved_mission(approved()).unwrap();
    let binding = store.binding(PS, &owner()).unwrap().unwrap();
    assert_eq!(binding.person_id, "private-person");
    assert!(!binding.revoked);
}

#[path = "support/federated_missions.rs"]
mod federated_missions;
