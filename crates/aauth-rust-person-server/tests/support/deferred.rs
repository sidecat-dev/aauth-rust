use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement,
};
use aauth_rust_person_server::{DeferredConfig, FederationInput};
use std::sync::Mutex;
#[derive(Clone)]
pub(super) struct NativeTransport {
    pub(super) stage: Arc<AtomicUsize>,
    pending: Arc<MemoryContinuations>,
    ids: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
    calls: Arc<AtomicUsize>,
    pub(super) original: Arc<Mutex<Vec<Value>>>,
    fault: usize,
}
impl NativeTransport {
    pub(super) fn new(f: &Fixture, stage: usize, fault: usize) -> Self {
        Self {
            stage: Arc::new(AtomicUsize::new(stage)),
            pending: Arc::new(MemoryContinuations::new(16)),
            ids: Arc::new(AtomicUsize::new(0)),
            now: f.host.now.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
            original: Arc::new(Mutex::new(Vec::new())),
            fault,
        }
    }
}
impl aauth_rust_person_server::Federation for NativeTransport {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        assert_eq!(issuer, "https://as.example");
        Ok("https://as.example/token".into())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.method() == "POST" && request.uri().path() == "/token" {
            self.original
                .lock()
                .unwrap()
                .push(serde_json::from_slice(request.body()).unwrap());
        }
        let mut cfg = aauth_rust_access_server::DeferredConfig::new(self.pending.clone());
        cfg.lifetime = 60;
        cfg.retry_after = 0;
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
                    lifetime: 600,
                })
            },
            || self.now.load(Ordering::SeqCst),
            || format!("as-{}", self.ids.fetch_add(1, Ordering::SeqCst)),
        )
        .unwrap()
        .with_deferred(cfg, {
            let stage = self.stage.clone();
            move |c: &aauth_rust_access_server::DeferredContext| {
                Ok(match stage.load(Ordering::SeqCst) {
                    0 => Some(Requirement::Payment {
                        authenticate: "Payment id=\"native-bill\", method=\"example\"".into(),
                    }),
                    1 => Some(Requirement::Approval),
                    3 => return Err(aauth_rust_access_server::PolicyError::Denied),
                    4 if !c.claims.contains_key("email") => {
                        Some(Requirement::Claims(vec!["email".into()]))
                    }
                    5 if c.clarifications.is_empty() => Some(Requirement::Clarification {
                        question: "Why read?".into(),
                        timeout: Some(30),
                        options: vec![],
                    }),
                    6 => Some(Requirement::Interaction {
                        url: "https://as.example/consent".into(),
                        code: c.interaction_code.clone(),
                    }),
                    _ => None,
                })
            }
        })
        .unwrap();
        let mut response = server.handle(request);
        if self.fault == 1 && [202, 402].contains(&response.status().as_u16()) {
            response.headers_mut().insert(
                "location",
                "https://foreign.example/pending/stolen".parse().unwrap(),
            );
        }
        if self.fault == 2 && response.status() == 200 && request.method() != "DELETE" {
            *response.body_mut() = json!({"auth_token":"forged.jwt.bytes"})
                .to_string()
                .into_bytes();
        }
        Ok(response)
    }
}
fn config(store: Arc<MemoryContinuations>) -> DeferredConfig {
    let mut c = DeferredConfig::new(store);
    c.lifetime = 60;
    c.retry_after = 0;
    c
}
pub(super) fn poll<K: AgentKeyResolver>(
    server: &Server<K>,
    holder: &Agent,
    location: &str,
    method: &str,
    body: Option<Value>,
    now: i64,
) -> Response<Vec<u8>> {
    let mut builder = Request::builder().method(method).uri(location);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut r = builder
        .body(body.map(|v| v.to_string().into_bytes()).unwrap_or_default())
        .unwrap();
    holder.sign(&mut r, now).unwrap();
    server.handle(&r)
}
fn initial<K: AgentKeyResolver>(
    f: &Fixture,
    server: &Server<K>,
    holder: &Agent,
) -> (String, String, Response<Vec<u8>>) {
    let person = compact(&f.person(server, holder, ORDERS, None), "person_token");
    let challenge = resource(holder, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let result = f.exchange(server, holder, &challenge, &person, None);
    (person, challenge, result)
}
#[test]
fn native_payment_approval_delivery_recomposes_without_replaying_post() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 0, 0);
    let store = Arc::new(MemoryContinuations::new(16));
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(store.clone()))
        .unwrap();
    let holder = agent(false);
    let (person, challenge, response) = initial(&f, &server, &holder);
    assert_eq!(
        response.status(),
        202,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    assert!(pending.location.starts_with(PS));
    // Both pending URLs carry 128 random bits, not the hosts' token-ID sources.
    let as_pending = server.federation_pending(&pending.location).unwrap();
    for (location, origin) in [
        (&pending.location, PS),
        (&as_pending.location, "https://as.example"),
    ] {
        let id = location
            .strip_prefix(&format!("{origin}/token/pending/"))
            .unwrap();
        assert_eq!(id.len(), 22, "{location}");
        assert!(!id.starts_with("token-") && !id.starts_with("as-"));
    }
    assert!(matches!(
        as_pending.requirement,
        Requirement::Payment { .. }
    ));
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        202
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    drop(server);
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(store))
        .unwrap();
    transport.stage.store(1, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap()
            .status(),
        202
    );
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        202
    );
    transport.stage.store(2, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap()
            .status(),
        200
    );
    let result = poll(&server, &holder, &pending.location, "GET", None, 1000);
    let auth = compact(&result, "auth_token");
    let verified = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(verified.claims().iss, "https://as.example");
    assert!(
        f.store
            .token(&TokenReference {
                issuer: "https://as.example".into(),
                jti: verified.claims().jti.clone()
            })
            .unwrap()
            .is_some()
    );
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        410
    );
    let forwarded = transport.original.lock().unwrap();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(
        forwarded[0],
        json!({"agent_token":holder.token(),"resource_token":challenge,"presented_token":person})
    );
}
#[test]
fn native_claims_clarification_and_interaction_use_one_ps_pending_url() {
    for stage in [4, 5, 6] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, stage, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, response) = initial(&f, &server, &holder);
        assert_eq!(response.status(), 202);
        let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
        match stage {
            4 => {
                assert!(
                    server
                        .advance_federation(
                            &pending.location,
                            FederationInput::Claims(
                                serde_json::from_value(json!({"sub":"forged"})).unwrap()
                            )
                        )
                        .is_err()
                );
                server
                    .advance_federation(
                        &pending.location,
                        FederationInput::Claims(
                            serde_json::from_value(json!({"email":"person@example"})).unwrap(),
                        ),
                    )
                    .unwrap();
            }
            5 => {
                assert!(matches!(
                    pending.requirement,
                    Requirement::Clarification { .. }
                ));
                assert_eq!(poll(&server,&holder,&pending.location,"POST",Some(json!({"action":"clarification_response","clarification_response":"The person asked"})),1000).status(),202);
                assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
                server
                    .advance_federation(&pending.location, FederationInput::Poll)
                    .unwrap();
            }
            6 => {
                assert!(matches!(
                    pending.requirement,
                    Requirement::Interaction { .. }
                ));
                transport.stage.store(2, Ordering::SeqCst);
                server
                    .advance_federation(&pending.location, FederationInput::Poll)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
            200
        );
    }
}
#[test]
fn invalid_as_location_grant_and_local_store_failure_never_release_auth() {
    for fault in [1, 2, 3] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, fault);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, response) = initial(&f, &server, &holder);
        if fault == 1 {
            assert_eq!(response.status(), 502);
            continue;
        }
        let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
        transport.stage.store(2, Ordering::SeqCst);
        if fault == 3 {
            f.store.fail.store(true, Ordering::SeqCst);
        }
        let result = server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap();
        assert_eq!(result.status(), if fault == 2 { 502 } else { 500 });
        let result = poll(&server, &holder, &pending.location, "GET", None, 1000);
        assert_eq!(result.status(), if fault == 2 { 502 } else { 500 });
        assert!(
            !output(&result)
                .as_object()
                .unwrap()
                .contains_key("auth_token")
        );
        assert!(
            f.store
                .token(&TokenReference {
                    issuer: "https://as.example".into(),
                    jti: "as-1".into()
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(
            poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
            410
        );
    }
}
#[test]
fn another_agent_or_key_cannot_poll_and_cancellation_consumes_both_roles() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, response) = initial(&f, &server, &holder);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    assert_eq!(
        poll(&server, &agent(true), &pending.location, "GET", None, 1000).status(),
        403
    );
    let mut claims = aauth_rust_core::AgentToken::parse(holder.token())
        .unwrap()
        .unverified_claims()
        .clone();
    let key = SigningKey::from_seed([98; 32]);
    claims.cnf.jwk = key.public_jwk();
    let token = AgentProvider::new(
        "https://ap.example",
        "ap-key",
        SigningKey::from_seed([1; 32]),
    )
    .unwrap()
    .issue(&claims)
    .unwrap();
    let rotated = Agent::new(key, token).unwrap();
    assert_eq!(
        poll(&server, &rotated, &pending.location, "GET", None, 1000).status(),
        403
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        poll(&server, &holder, &pending.location, "DELETE", None, 1000).status(),
        200
    );
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        410
    );
    assert!(transport.pending.load("as-0").unwrap().is_none());
}

#[test]
fn a_revoked_binding_or_resource_token_ends_a_waiting_agent_poll_without_as_io() {
    for revoked in ["binding", "resource token"] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_revocation()
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, response) = initial(&f, &server, &holder);
        let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
        let (status, error) = if revoked == "binding" {
            f.store
                .inner
                .revoke_binding(
                    PS,
                    &AgentIdentity {
                        issuer: "https://ap.example".into(),
                        subject: "aauth:Caller@ap.example".into(),
                    },
                )
                .unwrap();
            (400, "revoked_presented_token")
        } else {
            // The Resource withdraws the challenge the request was started for.
            let mut withdraw = Request::builder()
                .method("POST")
                .uri(format!("{PS}/revoke"))
                .header("content-type", "application/json")
                .body(
                    serde_json::to_vec(&json!({"jti": "resource-challenge", "exp": 1300})).unwrap(),
                )
                .unwrap();
            sign_request(
                &mut withdraw,
                &SigningKey::from_seed([4; 32]),
                KeyMaterial::JwksUri {
                    id: ORDERS.into(),
                    dwk: "aauth-resource.json".into(),
                    kid: "orders-key".into(),
                },
                1000,
            )
            .unwrap();
            assert_eq!(server.handle(&withdraw).status(), 200);
            // Presenting a Revoked Token: the waiting request ends with the
            // polling error `revoked`, with detail naming the resource token.
            (403, "revoked")
        };
        let result = poll(&server, &holder, &pending.location, "GET", None, 1000);
        assert_eq!(result.status(), status, "{revoked}");
        assert_eq!(output(&result)["error"], error, "{revoked}");
        if revoked == "resource token" {
            assert!(
                output(&result)["detail"]
                    .as_str()
                    .unwrap()
                    .contains("resource token")
            );
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
            410
        );
    }
}
#[test]
fn expiry_during_as_call_is_reported_consistently_to_host_and_agent() {
    #[derive(Clone)]
    struct Slow(NativeTransport);
    impl aauth_rust_person_server::Federation for Slow {
        fn endpoint(&self, i: &str) -> Result<String, aauth_rust_person_server::FederationError> {
            aauth_rust_person_server::Federation::endpoint(&self.0, i)
        }
        fn send(
            &self,
            r: &Request<Vec<u8>>,
        ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
            let result = aauth_rust_person_server::Federation::send(&self.0, r);
            if r.method() == "GET" {
                self.0.now.store(1060, Ordering::SeqCst);
            }
            result
        }
    }
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let server = f
        .server(2000)
        .with_federation(Slow(transport.clone()))
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, response) = initial(&f, &server, &holder);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    transport.stage.store(2, Ordering::SeqCst);
    let host = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(host.status(), 408);
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1060).status(),
        408
    );
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1060).status(),
        410
    );
}
#[test]
fn concurrent_terminal_agent_delivery_has_one_consumer() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let server = Arc::new(
        f.server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap(),
    );
    let holder = agent(false);
    let (_, _, response) = initial(&f, &server, &holder);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    transport.stage.store(2, Ordering::SeqCst);
    server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let server = server.clone();
            let holder = holder.with_token(holder.token().into()).unwrap();
            let location = pending.location.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                poll(&server, &holder, &location, "GET", None, 1000)
            })
        })
        .collect();
    barrier.wait();
    let statuses: Vec<_> = workers
        .into_iter()
        .map(|w| w.join().unwrap().status().as_u16())
        .collect();
    assert_eq!(statuses.iter().filter(|s| **s == 200).count(), 1);
    assert!(statuses.iter().all(|s| [200, 410, 429].contains(s)));
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        410
    );
}

const DELIVERY_GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

struct ReleaseDelivery(Option<std::sync::mpsc::SyncSender<()>>);
impl ReleaseDelivery {
    fn release(&mut self) {
        if let Some(release) = self.0.take() {
            // One slot is sufficient for this single-use gate. A disconnected
            // receiver already means the owner cannot remain blocked here.
            let _ = release.try_send(());
        }
    }
}
impl Drop for ReleaseDelivery {
    fn drop(&mut self) {
        self.release();
    }
}

// Pause only after the successful delivery claim has reached custody, without
// holding MemoryContinuations' lock. Both gate waits are bounded test-harness
// safeguards; they do not advance or replace the injected protocol clock.
struct DeliveryClaimStore {
    inner: MemoryContinuations,
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    gate_failed: AtomicBool,
    claims: AtomicUsize,
    removals: AtomicUsize,
    fail_removal: AtomicBool,
}
impl DeliveryClaimStore {
    fn new() -> (Self, std::sync::mpsc::Receiver<()>, ReleaseDelivery) {
        let (entered, ready) = std::sync::mpsc::sync_channel(1);
        let (release, released) = std::sync::mpsc::sync_channel(1);
        (
            Self {
                inner: MemoryContinuations::new(16),
                entered,
                release: Mutex::new(released),
                gate_failed: AtomicBool::new(false),
                claims: AtomicUsize::new(0),
                removals: AtomicUsize::new(0),
                fail_removal: AtomicBool::new(false),
            },
            ready,
            ReleaseDelivery(Some(release)),
        )
    }
}
impl ContinuationStore for DeliveryClaimStore {
    fn insert(
        &self,
        id: &str,
        value: Value,
    ) -> Result<(), aauth_rust_core::continuation::StoreError> {
        self.inner.insert(id, value)
    }
    fn load(
        &self,
        id: &str,
    ) -> Result<
        Option<aauth_rust_core::continuation::Snapshot>,
        aauth_rust_core::continuation::StoreError,
    > {
        self.inner.load(id)
    }
    fn replace(
        &self,
        id: &str,
        revision: u64,
        value: Option<Value>,
    ) -> Result<bool, aauth_rust_core::continuation::StoreError> {
        let claiming = value.as_ref().is_some_and(|v| v["state"] == "delivering");
        let removing = value.is_none();
        if removing && self.fail_removal.load(Ordering::SeqCst) {
            return Err(aauth_rust_core::continuation::StoreError::Unavailable);
        }
        let changed = self.inner.replace(id, revision, value)?;
        if changed && removing {
            self.removals.fetch_add(1, Ordering::SeqCst);
        }
        if changed && claiming && self.claims.fetch_add(1, Ordering::SeqCst) == 0 {
            let announced = self.entered.try_send(()).is_ok();
            let released = announced
                && self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(DELIVERY_GATE_TIMEOUT)
                    .is_ok();
            if !released {
                self.gate_failed.store(true, Ordering::SeqCst);
                return Err(aauth_rust_core::continuation::StoreError::Unavailable);
            }
        }
        Ok(changed)
    }
}

#[derive(Clone)]
struct DeliveryResourceTrust(Arc<AtomicBool>);
impl AgentKeyResolver for DeliveryResourceTrust {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        // Fresh Agent proof remains verifiable. Only the retained Resource's
        // trust changes, so the competing poll reaches pending cleanup.
        if issuer == ORDERS && dwk == "aauth-resource.json" && !self.0.load(Ordering::SeqCst) {
            return Err(TokenError::UntrustedIssuer);
        }
        Keys.key(issuer, dwk, kid)
    }
}

#[derive(Clone, Copy)]
enum DeliveryInterference {
    Expiry,
    ResourceTrust,
    Cancellation,
    StoreFailure,
}

fn claimed_delivery(interference: DeliveryInterference) {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let (custody, ready, release) = DeliveryClaimStore::new();
    let custody = Arc::new(custody);
    let trusted_resource = Arc::new(AtomicBool::new(true));
    let mut cfg = DeferredConfig::new(custody.clone());
    cfg.lifetime = 60;
    cfg.retry_after = 0;
    let server = Arc::new(
        f.server_with_keys(2000, DeliveryResourceTrust(trusted_resource.clone()))
            .with_federation(transport.clone())
            .with_deferred(cfg)
            .unwrap(),
    );
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    let id = pending.location.rsplit('/').next().unwrap();
    transport.stage.store(2, Ordering::SeqCst);
    let host = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(host.status(), 200);
    let issued = AuthToken::parse(output(&host)["auth_token"].as_str().unwrap()).unwrap();
    let issued_reference = TokenReference {
        issuer: "https://as.example".into(),
        jti: issued.unverified_claims().jti.clone(),
    };
    assert!(f.store.token(&issued_reference).unwrap().is_some());
    let calls_before = transport.calls.load(Ordering::SeqCst);
    let worker = server.clone();
    let owner = holder.with_token(holder.token().into()).unwrap();
    let location = pending.location.clone();
    let (held_before, held_after, now, competing, cancellation, completed) = std::thread::scope(
        |scope| {
            // Move the release guard into this scope: unwinding a rival poll
            // releases the owner before scope's mandatory thread join.
            let mut release = release;
            let thread = scope.spawn(move || poll(&worker, &owner, &location, "GET", None, 1000));
            if let Err(error) = ready.recv_timeout(DELIVERY_GATE_TIMEOUT) {
                release.release();
                let owner_status = match thread.join() {
                    Ok(response) => format!("HTTP {}", response.status().as_u16()),
                    Err(_) => "thread panicked".into(),
                };
                panic!(
                    "delivery claim gate was not reached within 10 seconds: {error}; owner status: {owner_status}"
                );
            }
            let held_before = custody.load(id);
            let now = match interference {
                DeliveryInterference::Expiry => {
                    // All signed credentials outlive the 1060 custody deadline.
                    f.host.now.store(1060, Ordering::SeqCst);
                    1060
                }
                DeliveryInterference::ResourceTrust => {
                    trusted_resource.store(false, Ordering::SeqCst);
                    1000
                }
                DeliveryInterference::StoreFailure => {
                    custody.fail_removal.store(true, Ordering::SeqCst);
                    1000
                }
                DeliveryInterference::Cancellation => 1000,
            };
            let competing = poll(&server, &holder, &pending.location, "GET", None, now);
            let cancellation = poll(&server, &holder, &pending.location, "DELETE", None, now);
            let held_after = custody.load(id);
            release.release();
            let completed = thread.join().unwrap();
            (
                held_before,
                held_after,
                now,
                competing,
                cancellation,
                completed,
            )
        },
    );
    assert!(
        !custody.gate_failed.load(Ordering::SeqCst),
        "the delivery release gate timed out or disconnected"
    );

    // Join before asserting: the historical bug is observed as the owner's
    // 500, rather than leaving a blocked worker behind after the rival fails.
    let (status, code) = match interference {
        DeliveryInterference::Expiry => (408, Some("expired")),
        DeliveryInterference::ResourceTrust => (400, Some("invalid_resource_token")),
        DeliveryInterference::Cancellation => (200, None),
        DeliveryInterference::StoreFailure => (500, Some("server_error")),
    };
    assert_eq!(
        completed.status(),
        status,
        "a competing poll stole delivery custody: owner status {}, rival status {}",
        completed.status(),
        competing.status()
    );
    if let Some(code) = code {
        assert_eq!(output(&completed)["error"], code);
        assert!(output(&completed).get("auth_token").is_none());
    } else {
        assert!(
            output(&completed)["auth_token"] == output(&host)["auth_token"],
            "delivery must preserve the verified host token's exact bytes"
        );
    }
    for rival in [&competing, &cancellation] {
        assert_eq!(rival.status(), 429);
        assert_eq!(output(rival)["error"], "slow_down");
        assert_eq!(rival.headers()["retry-after"], "1");
        assert!(output(rival).get("auth_token").is_none());
    }
    let held_before = held_before.unwrap().unwrap();
    let held_after = held_after
        .unwrap()
        .expect("the rival consumed the owner's row");
    assert_eq!(held_before.value["state"], "delivering");
    assert_eq!(held_after.value["state"], "delivering");
    assert_eq!(held_after.revision, held_before.revision);
    assert_eq!(custody.claims.load(Ordering::SeqCst), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), calls_before);
    assert_eq!(transport.original.lock().unwrap().len(), 1);
    assert!(f.store.token(&issued_reference).unwrap().is_some());

    if matches!(interference, DeliveryInterference::StoreFailure) {
        assert_eq!(custody.removals.load(Ordering::SeqCst), 0);
        assert_eq!(
            custody.load(id).unwrap().unwrap().value["state"],
            "delivering"
        );
        custody.fail_removal.store(false, Ordering::SeqCst);
        let retry = poll(&server, &holder, &pending.location, "GET", None, now);
        assert_eq!(
            retry.status(),
            429,
            "storage recovery must not replay delivery"
        );
        assert!(output(&retry).get("auth_token").is_none());
        assert_eq!(custody.claims.load(Ordering::SeqCst), 1);
    } else {
        assert_eq!(custody.removals.load(Ordering::SeqCst), 1);
        assert!(custody.load(id).unwrap().is_none());
        let consumed = poll(&server, &holder, &pending.location, "GET", None, now);
        assert_eq!(consumed.status(), 410);
        assert_eq!(output(&consumed)["error"], "gone");
        assert!(output(&consumed).get("auth_token").is_none());
    }
}

#[test]
fn claimed_delivery_survives_expired_competing_poll() {
    claimed_delivery(DeliveryInterference::Expiry);
}

#[test]
fn claimed_delivery_survives_untrusted_resource_competing_poll() {
    claimed_delivery(DeliveryInterference::ResourceTrust);
}

#[test]
fn claimed_delivery_rejects_competing_cancellation_and_delivers_once() {
    claimed_delivery(DeliveryInterference::Cancellation);
}

#[test]
fn claimed_delivery_store_failure_remains_local_500() {
    claimed_delivery(DeliveryInterference::StoreFailure);
}

struct BoundaryStore {
    inner: MemoryContinuations,
    on_publish: bool,
    mutate: Box<dyn Fn() + Send + Sync>,
}
impl ContinuationStore for BoundaryStore {
    fn insert(
        &self,
        id: &str,
        value: Value,
    ) -> Result<(), aauth_rust_core::continuation::StoreError> {
        self.inner.insert(id, value)
    }
    fn load(
        &self,
        id: &str,
    ) -> Result<
        Option<aauth_rust_core::continuation::Snapshot>,
        aauth_rust_core::continuation::StoreError,
    > {
        self.inner.load(id)
    }
    fn replace(
        &self,
        id: &str,
        revision: u64,
        value: Option<Value>,
    ) -> Result<bool, aauth_rust_core::continuation::StoreError> {
        let boundary = if self.on_publish {
            value.as_ref().is_some_and(|v| v["state"] == "ready")
        } else {
            value.is_none()
        };
        let changed = self.inner.replace(id, revision, value)?;
        if changed && boundary {
            (self.mutate)();
        }
        Ok(changed)
    }
}
fn boundary_config(f: &Fixture, publish: bool, revoke: bool, release_at: i64) -> DeferredConfig {
    let store = f.store.clone();
    let now = f.host.now.clone();
    let mut cfg = DeferredConfig::new(BoundaryStore {
        inner: MemoryContinuations::new(16),
        on_publish: publish,
        mutate: Box::new(move || {
            if revoke {
                store
                    .inner
                    .revoke_binding(
                        PS,
                        &AgentIdentity {
                            issuer: "https://ap.example".into(),
                            subject: "aauth:Caller@ap.example".into(),
                        },
                    )
                    .unwrap();
            } else {
                now.store(release_at, Ordering::SeqCst);
            }
        }),
    });
    cfg.lifetime = 60;
    cfg.retry_after = 0;
    cfg
}
#[test]
fn agent_terminal_release_rechecks_after_continuation_removal() {
    for revoke in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(boundary_config(&f, false, revoke, 1061))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        transport.stage.store(2, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        let result = poll(&server, &holder, &p.location, "GET", None, 1000);
        assert_eq!(result.status(), if revoke { 400 } else { 408 });
        assert!(
            !output(&result)
                .as_object()
                .unwrap()
                .contains_key("auth_token")
        );
        assert_eq!(
            poll(
                &server,
                &holder,
                &p.location,
                "GET",
                None,
                f.host.now.load(Ordering::SeqCst)
            )
            .status(),
            410
        );
    }
}
#[test]
fn host_terminal_result_rechecks_after_continuation_publication() {
    for revoke in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(boundary_config(&f, true, revoke, 1061))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        transport.stage.store(2, Ordering::SeqCst);
        let result = server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap();
        assert_eq!(result.status(), if revoke { 400 } else { 408 });
        assert!(
            !output(&result)
                .as_object()
                .unwrap()
                .contains_key("auth_token")
        );
        assert_eq!(
            poll(
                &server,
                &holder,
                &p.location,
                "GET",
                None,
                f.host.now.load(Ordering::SeqCst)
            )
            .status(),
            if revoke { 400 } else { 408 }
        );
    }
}
#[derive(Clone)]
struct ScriptedTransport {
    replies: Arc<Mutex<std::collections::VecDeque<Response<Vec<u8>>>>>,
    calls: Arc<AtomicUsize>,
}
impl ScriptedTransport {
    fn new(replies: Vec<Response<Vec<u8>>>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl aauth_rust_person_server::Federation for ScriptedTransport {
    fn endpoint(&self, _: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        Ok("https://as.example/token".into())
    }
    fn send(
        &self,
        _: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected AS I/O"))
    }
}
fn question(text: &str, timeout: u64) -> Response<Vec<u8>> {
    PendingResponse::new(
        "https://as.example/token",
        "/token/pending/scripted",
        0,
        Requirement::Clarification {
            question: text.into(),
            timeout: Some(timeout),
            options: vec![],
        },
    )
    .unwrap()
    .response()
    .unwrap()
}
#[test]
fn external_as_question_timeout_is_retained_across_unchanged_polls() {
    for host_answer in [false, true] {
        let f = Fixture::new();
        let transport = ScriptedTransport::new(vec![question("Why?", 10), question("Why?", 10)]);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        f.host.now.store(1005, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap()
                .status(),
            202
        );
        let repeated = poll(&server, &holder, &p.location, "GET", None, 1005);
        assert_eq!(output(&repeated)["timeout"], 5);
        f.host.now.store(1010, Ordering::SeqCst);
        if host_answer {
            assert_eq!(
                server
                    .advance_federation(&p.location, FederationInput::Clarification("late".into()))
                    .unwrap_err(),
                aauth_rust_person_server::AdvanceError::Expired
            );
        } else {
            assert_eq!(
                poll(
                    &server,
                    &holder,
                    &p.location,
                    "POST",
                    Some(
                        json!({"action":"clarification_response","clarification_response":"late"})
                    ),
                    1010
                )
                .status(),
                408
            );
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }
}
#[test]
fn ps_enforces_five_clarification_rounds_independently_of_the_as() {
    for same_question in [false, true] {
        let f = Fixture::new();
        let replies = (0..6)
            .map(|round| {
                question(
                    &if same_question {
                        "same".into()
                    } else {
                        format!("question{round}")
                    },
                    30,
                )
            })
            .collect();
        let transport = ScriptedTransport::new(replies);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        for round in 0..5 {
            let result = server
                .advance_federation(
                    &p.location,
                    FederationInput::Clarification(format!("answer{round}")),
                )
                .unwrap();
            assert_eq!(
                result.status(),
                if round == 4 { 403 } else { 202 },
                "round={round},same_question={same_question}"
            );
        }
        assert_eq!(
            poll(&server, &holder, &p.location, "GET", None, 1000).status(),
            403
        );
        assert_eq!(
            poll(&server, &holder, &p.location, "GET", None, 1000).status(),
            410
        );
    }
}
#[test]
fn as_refusals_accumulate_backoff_and_delay_queued_answers() {
    for status in [429, 503] {
        let f = Fixture::new();
        let refusal = || {
            Response::builder()
                .status(status)
                .header("retry-after", "5")
                .body(Vec::new())
                .unwrap()
        };
        let transport = ScriptedTransport::new(vec![
            question("Why?", 60),
            refusal(),
            refusal(),
            question("Next?", 30),
        ]);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        assert_eq!(
            poll(
                &server,
                &holder,
                &p.location,
                "POST",
                Some(json!({"action":"clarification_response","clarification_response":"answer"})),
                1000
            )
            .status(),
            202
        );
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap()
                .status(),
            status
        );
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap_err(),
            aauth_rust_person_server::AdvanceError::NotReady
        );
        f.host.now.store(1005, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap()
                .status(),
            status
        );
        let next = if status == 429 { 1015 } else { 1010 };
        f.host.now.store(next - 1, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(
                    &p.location,
                    FederationInput::Clarification("manual retry".into())
                )
                .unwrap_err(),
            aauth_rust_person_server::AdvanceError::NotReady
        );
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap_err(),
            aauth_rust_person_server::AdvanceError::NotReady
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
        f.host.now.store(next, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&p.location, FederationInput::Poll)
                .unwrap()
                .status(),
            202
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
    }
}

#[test]
fn expires_in_uses_the_clock_after_final_custody_io() {
    for publish in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(boundary_config(&f, publish, false, 1005))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        transport.stage.store(2, Ordering::SeqCst);
        let host = server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap();
        assert_eq!(output(&host)["expires_in"], if publish { 595 } else { 600 });
        let result = poll(
            &server,
            &holder,
            &p.location,
            "GET",
            None,
            f.host.now.load(Ordering::SeqCst),
        );
        assert_eq!(result.status(), 200);
        assert_eq!(output(&result)["expires_in"], 595);
    }
}

#[test]
fn queued_answer_ack_allows_an_identical_question_in_the_next_as_round() {
    let f = Fixture::new();
    let transport = ScriptedTransport::new(vec![question("Why?", 10), question("Why?", 10)]);
    let server = f
        .server(2000)
        .with_federation(transport)
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let mut session =
        aauth_rust_agent::PollSession::new(&format!("{PS}/token"), &first, 1000, 1060).unwrap();
    f.host.now.store(1001, Ordering::SeqCst);
    let acknowledgement = server.handle(&session.answer(&holder, "first answer", 1001).unwrap());
    let acknowledged = PendingResponse::parse(&format!("{PS}/token"), &acknowledgement).unwrap();
    assert!(matches!(acknowledged.requirement, Requirement::Approval));
    session.accept(acknowledgement, 1001).unwrap();
    f.host.now.store(1005, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&session.pending().location, FederationInput::Poll)
            .unwrap()
            .status(),
        202
    );
    let next = server.handle(&session.request(&holder, 1005).unwrap());
    session.accept(next, 1005).unwrap();
    f.host.now.store(1014, Ordering::SeqCst);
    let response = server.handle(&session.answer(&holder, "second answer", 1014).unwrap());
    assert_eq!(response.status(), 202);
}

#[test]
fn forwarded_answer_survives_agent_polls_after_its_old_question_timeout() {
    #[derive(Clone)]
    struct Blocking {
        inner: ScriptedTransport,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    }
    impl aauth_rust_person_server::Federation for Blocking {
        fn endpoint(&self, i: &str) -> Result<String, aauth_rust_person_server::FederationError> {
            aauth_rust_person_server::Federation::endpoint(&self.inner, i)
        }
        fn send(
            &self,
            r: &Request<Vec<u8>>,
        ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
            if r.uri().path().starts_with("/token/pending/") {
                self.entered.wait();
                self.release.wait();
            }
            aauth_rust_person_server::Federation::send(&self.inner, r)
        }
    }
    let f = Fixture::new();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let transport = Blocking {
        inner: ScriptedTransport::new(vec![question("Why?", 10), question("Why?", 10)]),
        entered: entered.clone(),
        release: release.clone(),
    };
    let server = Arc::new(
        f.server(2000)
            .with_federation(transport)
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap(),
    );
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    f.host.now.store(1001, Ordering::SeqCst);
    assert_eq!(
        poll(
            &server,
            &holder,
            &p.location,
            "POST",
            Some(json!({"action":"clarification_response","clarification_response":"on time"})),
            1001
        )
        .status(),
        202
    );
    f.host.now.store(1005, Ordering::SeqCst);
    let worker = server.clone();
    let location = p.location.clone();
    let thread =
        std::thread::spawn(move || worker.advance_federation(&location, FederationInput::Poll));
    entered.wait();
    f.host.now.store(1010, Ordering::SeqCst);
    let competing = poll(&server, &holder, &p.location, "GET", None, 1010);
    let cancellation = poll(&server, &holder, &p.location, "DELETE", None, 1010);
    release.wait();
    let completed = thread.join().unwrap();
    assert_eq!(competing.status(), 202);
    assert_eq!(
        cancellation.status(),
        429,
        "in-flight cancellation must request a retry"
    );
    assert_eq!(completed.unwrap().status(), 202);
    let latest = poll(&server, &holder, &p.location, "GET", None, 1010);
    assert!(matches!(
        PendingResponse::parse(&p.location, &latest)
            .unwrap()
            .requirement,
        Requirement::Clarification { .. }
    ));
}

#[test]
fn updated_request_verifies_the_pair_before_replacing_the_pending_request() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 5, 0);
    let store = Arc::new(MemoryContinuations::new(16));
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(store.clone()))
        .unwrap();
    let holder = agent(false);
    let (person, challenge, response) = initial(&f, &server, &holder);
    assert_eq!(response.status(), 202);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    let id = pending.location.rsplit('/').next().unwrap();
    let stored = |store: &MemoryContinuations| {
        store.load(id).unwrap().unwrap().value["parameters"]["resource_token"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(stored(&store), challenge);
    let rejected = poll(
        &server,
        &holder,
        &pending.location,
        "POST",
        Some(json!({"action":"updated_request","resource_token":challenge})),
        1000,
    );
    assert_eq!(rejected.status(), 400);
    assert_eq!(output(&rejected)["error"], "invalid_request");
    assert_eq!(stored(&store), challenge);
    let mismatched_jti = resource(&holder, &person, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.presented_jti = "other".into();
    });
    let step3 = poll(
        &server,
        &holder,
        &pending.location,
        "POST",
        Some(json!({
            "action": "updated_request",
            "resource_token": mismatched_jti,
            "presented_token": person
        })),
        1000,
    );
    assert_eq!(step3.status(), 400);
    assert_eq!(output(&step3)["error"], "invalid_resource_token");
    assert_eq!(stored(&store), challenge);
    let other_person = compact(&f.person(&server, &holder, INVENTORY, None), "person_token");
    let other_resource = resource(&holder, &other_person, "read", |claims| {
        claims.aud = "https://as.example".into();
    });
    let different_resource = poll(
        &server,
        &holder,
        &pending.location,
        "POST",
        Some(json!({
            "action": "updated_request",
            "resource_token": other_resource,
            "presented_token": other_person,
            "justification": "a different resource"
        })),
        1000,
    );
    assert_eq!(different_resource.status(), 400);
    assert_eq!(
        output(&different_resource)["error"],
        "invalid_resource_token"
    );
    assert_eq!(stored(&store), challenge);
    let refuse = |token: String| {
        let response = poll(
            &server,
            &holder,
            &pending.location,
            "POST",
            Some(json!({
                "action": "updated_request",
                "resource_token": token,
                "presented_token": person
            })),
            1000,
        );
        assert_eq!(
            response.status(),
            400,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        assert_eq!(output(&response)["error"], "invalid_resource_token");
        assert_eq!(stored(&store), challenge);
    };
    refuse(resource(&holder, &person, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.ps = "https://other.example".into();
    }));
    refuse(resource(&holder, &person, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.agent_jkt = SigningKey::from_seed([9; 32])
            .public_jwk()
            .thumbprint()
            .unwrap();
    }));
    refuse(resource(&holder, &person, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.mission_s256 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    }));
    refuse(resource(&holder, &person, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.tenant = Some("other-tenant".into());
    }));
    let person2 = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let replacement = resource(&holder, &person2, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.account = Some("reduced".into());
    });
    let accepted = poll(
        &server,
        &holder,
        &pending.location,
        "POST",
        Some(json!({
            "action": "updated_request",
            "resource_token": replacement,
            "presented_token": person2,
            "justification": "read only"
        })),
        1000,
    );
    assert_eq!(
        accepted.status(),
        202,
        "{}",
        String::from_utf8_lossy(accepted.body())
    );
    assert_eq!(stored(&store), replacement);
    let payload = |token: &str| -> Value {
        serde_json::from_slice(aauth_rust_jose::Jws::parse(token).unwrap().payload()).unwrap()
    };
    assert_ne!(
        payload(&challenge)["presented_jti"],
        payload(&replacement)["presented_jti"]
    );
    assert_eq!(
        payload(&replacement)["presented_jti"],
        payload(&person2)["jti"]
    );
    assert_eq!(payload(&replacement)["account"], "reduced");
    let forwarded = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(forwarded.status(), 202);
    transport.stage.store(2, Ordering::SeqCst);
    let granted = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    let auth = aauth_rust_core::AuthToken::parse(output(&granted)["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(auth.claims().account.as_deref(), Some("reduced"));
}

#[test]
fn updated_request_consent_denial_keeps_the_stored_request() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 5, 0);
    let store = Arc::new(MemoryContinuations::new(16));
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(store.clone()))
        .unwrap();
    let holder = agent(false);
    let (_person, challenge, response) = initial(&f, &server, &holder);
    assert_eq!(response.status(), 202);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    let id = pending.location.rsplit('/').next().unwrap();
    let stored = store.load(id).unwrap().unwrap().value["parameters"]["resource_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(stored, challenge);
    let calls = transport.calls.load(Ordering::SeqCst);
    f.host.mode.store(1, Ordering::SeqCst);
    let person2 = compact(&f.person(&server, &holder, ORDERS, None), "person_token");
    let replacement = resource(&holder, &person2, "read", |claims| {
        claims.aud = "https://as.example".into();
        claims.account = Some("reduced".into());
    });
    let denied = poll(
        &server,
        &holder,
        &pending.location,
        "POST",
        Some(json!({
            "action": "updated_request",
            "resource_token": replacement,
            "presented_token": person2,
            "justification": "narrower account"
        })),
        1000,
    );
    assert_eq!(
        denied.status(),
        403,
        "{}",
        String::from_utf8_lossy(denied.body())
    );
    assert_eq!(output(&denied)["error"], "access_denied");
    assert_eq!(
        store.load(id).unwrap().unwrap().value["parameters"]["resource_token"]
            .as_str()
            .unwrap(),
        challenge
    );
    assert!(store.load(id).unwrap().unwrap().value["queued"].is_null());
    assert_eq!(transport.calls.load(Ordering::SeqCst), calls);
}

#[path = "post_gate.rs"]
mod post_gate;

#[path = "subagent_deferred.rs"]
mod subagent_deferred;
