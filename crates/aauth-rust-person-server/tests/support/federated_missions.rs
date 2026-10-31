//! Missions through the four-party path: a federated Person Server evaluates
//! the mission and retains the Access Server's Auth token through the
//! `MissionStore`, and the Access Server copies `mission_s256`.
use super::*;
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_person_server::{DeferredConfig, FederationError, FederationInput};
use std::sync::Mutex;

const AS: &str = "https://as.example";
const OTHER_MISSION: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// What the in-process Access Server does with a token request.
const ISSUE: usize = 0;
/// Answer `202` with `requirement=approval` until the mode changes.
const DEFER: usize = 1;
/// Re-sign its Auth token for another mission.
const OTHER: usize = 2;
/// End the mission while its policy decides.
const TERMINATE: usize = 3;

#[derive(Clone)]
struct MissionAs {
    store: MemoryStore,
    now: Arc<AtomicI64>,
    mode: Arc<AtomicUsize>,
    /// `mission_s256` of each Resource token the AS policy saw.
    seen: Arc<Mutex<Vec<Option<String>>>>,
    /// Each PS-to-AS token request body.
    bodies: Arc<Mutex<Vec<Value>>>,
    pending: Arc<MemoryContinuations>,
    ids: Arc<AtomicUsize>,
}
impl MissionAs {
    fn new(store: &RacingStore) -> Self {
        Self {
            store: store.inner.clone(),
            now: store.now.clone(),
            mode: Arc::new(AtomicUsize::new(ISSUE)),
            seen: Arc::default(),
            bodies: Arc::default(),
            pending: Arc::new(MemoryContinuations::new(16)),
            ids: Arc::default(),
        }
    }
    fn seen(&self) -> Vec<Option<String>> {
        self.seen.lock().unwrap().clone()
    }
}
impl aauth_rust_person_server::Federation for MissionAs {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        assert_eq!(issuer, AS);
        Ok(format!("{AS}/token"))
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        if request.method() == "POST" && request.uri().path() == "/token" {
            self.bodies
                .lock()
                .unwrap()
                .push(serde_json::from_slice(request.body()).unwrap());
        }
        let mut deferred = aauth_rust_access_server::DeferredConfig::new(self.pending.clone());
        deferred.retry_after = 0;
        let (mode, store, seen) = (self.mode.clone(), self.store.clone(), self.seen.clone());
        let (now, ids) = (self.now.clone(), self.ids.clone());
        let server = aauth_rust_access_server::AccessServer::new(
            aauth_rust_access_server::Config::new(AS, "as", SigningKey::from_seed([9; 32])),
            Keys,
            move |r: &aauth_rust_access_server::AuthorizationRequest| {
                let mission = r.resource.claims().mission_s256.clone();
                if mode.load(Ordering::SeqCst) == TERMINATE {
                    store
                        .terminate_mission(PS, &owner(), mission.as_deref().unwrap(), "revoked")
                        .unwrap();
                }
                seen.lock().unwrap().push(mission);
                Ok(aauth_rust_access_server::Decision {
                    scopes: r.scopes.clone(),
                    lifetime: 3600,
                })
            },
            move || now.load(Ordering::SeqCst),
            move || format!("as-{}", ids.fetch_add(1, Ordering::SeqCst)),
        )
        .unwrap()
        .with_deferred(deferred, {
            let mode = self.mode.clone();
            move |_: &aauth_rust_access_server::DeferredContext| {
                Ok((mode.load(Ordering::SeqCst) == DEFER).then_some(Requirement::Approval))
            }
        })
        .unwrap();
        let mut response = server.handle(request);
        if self.mode.load(Ordering::SeqCst) == OTHER && response.status() == 200 {
            let compact = value(&response)["auth_token"].as_str().unwrap().to_owned();
            let mut claims = AuthToken::parse(&compact)
                .unwrap()
                .unverified_claims()
                .clone();
            claims.mission_s256 = Some(OTHER_MISSION.into());
            let compact =
                aauth_rust_core::mint_auth_token(&SigningKey::from_seed([9; 32]), "as", &claims)
                    .unwrap();
            *response.body_mut() = json!({"auth_token":compact,"expires_in":45})
                .to_string()
                .into_bytes();
        }
        Ok(response)
    }
}

/// A Resource challenge addressed to the Access Server.
fn challenge(holder: &Agent, presented: &str, mission: Option<&str>) -> String {
    let p = aauth_rust_jose::Jws::parse(presented).unwrap();
    let p: Value = serde_json::from_slice(p.payload()).unwrap();
    let (resource, seed, kid, scope) = if p["aud"] == RESOURCE {
        (RESOURCE, 4, "resource", "revision.a.read")
    } else {
        (DOWNSTREAM, 8, "downstream", "stock.read")
    };
    mint_resource_token(
        &SigningKey::from_seed([seed; 32]),
        kid,
        &ResourceClaims {
            iss: resource.into(),
            dwk: "aauth-resource.json".into(),
            aud: AS.into(),
            ps: PS.into(),
            sub: p["sub"].as_str().unwrap().into(),
            jti: "as-challenge".into(),
            presented_jti: p["jti"].as_str().unwrap().into(),
            agent_jkt: holder.public_jwk().thumbprint().unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some(scope.into()),
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
fn federated() -> (
    Server,
    RacingStore,
    Arc<AtomicUsize>,
    MissionRecord,
    MissionAs,
) {
    let (server, store, calls, m) = fixture();
    let access = MissionAs::new(&store);
    (
        server.with_federation(access.clone()),
        store,
        calls,
        m,
        access,
    )
}
fn person_token(server: &Server, a: &Agent, m: &MissionRecord) -> String {
    let response = person(server, a, m);
    assert_eq!(response.status(), 200, "{:?}", value(&response));
    value(&response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn auth_claims(response: &Response<Vec<u8>>) -> aauth_rust_core::AuthClaims {
    assert_eq!(response.status(), 200, "{:?}", value(response));
    AuthToken::parse(value(response)["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap()
        .claims()
        .clone()
}
/// Access Server Auth tokens this Person Server retained.
fn receipts(store: &RacingStore) -> Vec<TokenRecord> {
    let mut receipts = store.inner.retained().unwrap();
    receipts.retain(|record| record.person_server.is_some());
    receipts
}
fn poll(server: &Server, a: &Agent, location: &str) -> Response<Vec<u8>> {
    let mut request = Request::builder()
        .method("GET")
        .uri(location)
        .body(Vec::new())
        .unwrap();
    a.sign(&mut request, 1000).unwrap();
    server.handle(&request)
}

#[test]
fn a_federated_mission_reaches_the_access_server_and_bounds_its_receipt() {
    let (s, store, calls, m, access) = federated();
    let a = agent(PS);
    let p = person_token(&s, &a, &m);
    // Stripping or substituting the mission is refused before consent and
    // before the Access Server is contacted.
    for digest in [None, Some(OTHER_MISSION)] {
        let refused = auth(&s, &a, &p, &challenge(&a, &p, digest));
        assert_eq!(value(&refused)["error"], "invalid_resource_token");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(access.bodies.lock().unwrap().is_empty());

    let r = challenge(&a, &p, Some(m.document.s256()));
    let claims = auth_claims(&auth(&s, &a, &p, &r));
    assert_eq!(claims.iss, AS);
    assert_eq!(claims.mission_s256.as_deref(), Some(m.document.s256()));
    // The Person token the PS capped at the mission's expiry bounds the grant.
    assert_eq!(claims.exp, 1045);
    assert_eq!(access.seen(), [Some(m.document.s256().to_owned())]);
    // PS-to-AS Token Request: the mission travels only inside the tokens.
    let sent = access.bodies.lock().unwrap()[0].clone();
    let mut members: Vec<_> = sent.as_object().unwrap().keys().collect();
    members.sort();
    assert_eq!(
        members,
        ["agent_token", "presented_token", "resource_token"]
    );
    let receipt = &receipts(&store)[0];
    assert_eq!(receipt.token.reference.jti, claims.jti);
    assert_eq!(receipt.person_server.as_deref(), Some(PS));
    assert_eq!(receipt.principal, owner());
    // bind_person, then consent with the mission.
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    store
        .inner
        .terminate_mission(PS, &owner(), m.document.s256(), "revoked")
        .unwrap();
    let refused = value(&auth(&s, &a, &p, &r));
    assert_eq!(refused["error"], "mission_terminated");
    assert_eq!(refused["termination_reason"], "revoked");
    assert_eq!(access.seen().len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_mission_that_ends_or_an_auth_token_for_another_mission_releases_nothing() {
    // (where the mission ends or the token changes, Host mode, AS mode)
    for (case, host, as_mode) in [
        ("terminated while consent waited", 1, ISSUE),
        ("binding revoked while consent waited", 3, ISSUE),
        ("terminated while the AS decided", 0, TERMINATE),
        ("terminated after the receipt committed", 10, ISSUE),
        ("auth token for another mission", 0, OTHER),
    ] {
        let (s, store, _, m, access) = federated();
        let a = agent(PS);
        let p = person_token(&s, &a, &m);
        store.mode.store(host, Ordering::SeqCst);
        access.mode.store(as_mode, Ordering::SeqCst);
        let response = auth(&s, &a, &p, &challenge(&a, &p, Some(m.document.s256())));
        assert!(value(&response).get("auth_token").is_none(), "{case}");
        let expected = match as_mode {
            OTHER => (502, "as_unreachable"),
            _ if host == 3 => (400, "revoked_presented_token"),
            _ => (403, "mission_terminated"),
        };
        assert_eq!(
            (
                response.status().as_u16(),
                value(&response)["error"].as_str()
            ),
            (expected.0, Some(expected.1)),
            "{case}"
        );
        // Consent is final before the AS is contacted; the store refuses a
        // receipt for a mission that ended while the AS decided.
        let contacted = !case.ends_with("consent waited");
        assert_eq!(access.seen().len(), usize::from(contacted), "{case}");
        assert_eq!(receipts(&store).len(), usize::from(host == 10), "{case}");
    }
}

#[test]
fn a_waiting_mission_bound_request_is_delivered_or_ends_with_its_mission() {
    for ending in ["delivered", "terminated"] {
        let (s, store, _, m, access) = federated();
        let mut config = DeferredConfig::new(Arc::new(MemoryContinuations::new(16)));
        config.retry_after = 0;
        let s = s.with_deferred(config).unwrap();
        let a = agent(PS);
        let p = person_token(&s, &a, &m);
        access.mode.store(DEFER, Ordering::SeqCst);
        let first = auth(&s, &a, &p, &challenge(&a, &p, Some(m.document.s256())));
        assert_eq!(first.status(), 202, "{:?}", value(&first));
        let pending = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        assert_eq!(pending.requirement, Requirement::Approval);
        if ending == "terminated" {
            store
                .inner
                .terminate_mission(PS, &owner(), m.document.s256(), "revoked")
                .unwrap();
            let ended = poll(&s, &a, &pending.location);
            assert_eq!(ended.status(), 403);
            assert_eq!(value(&ended)["error"], "mission_terminated");
            assert_eq!(value(&ended)["termination_reason"], "revoked");
            assert_eq!(poll(&s, &a, &pending.location).status(), 410);
            assert!(receipts(&store).is_empty());
            continue;
        }
        access.mode.store(ISSUE, Ordering::SeqCst);
        assert_eq!(
            s.advance_federation(&pending.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        let claims = auth_claims(&poll(&s, &a, &pending.location));
        assert_eq!(claims.mission_s256.as_deref(), Some(m.document.s256()));
        assert_eq!(receipts(&store)[0].token.reference.jti, claims.jti);
    }
}

#[test]
fn a_mission_travels_a_four_party_chain_until_the_callers_person_token_is_revoked() {
    let (s, store, calls, m, access) = federated();
    let s = s.with_revocation();
    let caller = agent(PS);
    let p = person_token(&s, &caller, &m);
    // The calling Agent was served on an AS Auth token for the mission.
    let upstream = value(&auth(
        &s,
        &caller,
        &p,
        &challenge(&caller, &p, Some(m.document.s256())),
    ))["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let chain = intermediary();
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
    assert_eq!(claims.exp, 1045);

    let exchange = json!({
        "resource_token": challenge(&chain, &downstream, Some(m.document.s256())),
        "presented_token": downstream,
        "upstream_token": upstream,
    });
    let granted = auth_claims(&s.handle(&request(&chain, "/token", exchange.clone())));
    assert_eq!(
        (
            granted.iss.as_str(),
            granted.aud.as_str(),
            granted.mission_s256.as_deref()
        ),
        (AS, DOWNSTREAM, Some(m.document.s256()))
    );
    assert_eq!(
        access.bodies.lock().unwrap()[1]["upstream_token"],
        upstream.as_str()
    );
    let receipt = receipts(&store)
        .into_iter()
        .find(|record| record.token.reference.jti == granted.jti)
        .unwrap();
    assert_eq!(receipt.principal, owner());
    assert_eq!(receipt.agent.subject, "aauth:Chain@resource.example");
    assert_eq!(
        receipt.upstream.map(|tie| tie.reference.jti),
        AuthToken::parse(&upstream)
            .ok()
            .map(|t| t.unverified_claims().jti.clone())
    );
    // bind_person and consent for the caller; bind_upstream and
    // consent_upstream for the intermediary, each with the mission.
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    // Revoking the caller's Person token refuses its AS Auth token as
    // upstream evidence at both endpoints.
    let jti = PersonToken::parse(&p)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    s.revoke_person_token(&jti);
    for (path, body) in [("/person", chained), ("/token", exchange)] {
        let refused = value(&s.handle(&request(&chain, path, body)));
        assert_eq!(refused["error"], "revoked_upstream_token", "{path}");
    }
    assert_eq!(access.seen().len(), 2);
}
