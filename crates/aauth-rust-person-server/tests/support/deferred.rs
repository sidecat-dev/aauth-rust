use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement,
};
use aauth_rust_person_server::{DeferredConfig, FederationInput};
use std::sync::Mutex;
#[derive(Clone)]
struct NativeTransport {
    stage: Arc<AtomicUsize>,
    pending: Arc<MemoryContinuations>,
    ids: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
    calls: Arc<AtomicUsize>,
    original: Arc<Mutex<Vec<Value>>>,
    fault: usize,
}
impl NativeTransport {
    fn new(f: &Fixture, stage: usize, fault: usize) -> Self {
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
                        code: "host-single-use".into(),
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
fn poll(
    server: &Server,
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
fn initial(f: &Fixture, server: &Server, holder: &Agent) -> (String, String, Response<Vec<u8>>) {
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
    assert!(matches!(
        server
            .federation_pending(&pending.location)
            .unwrap()
            .requirement,
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
fn revoked_binding_terminates_a_waiting_agent_poll_without_as_io() {
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
    let result = poll(&server, &holder, &pending.location, "GET", None, 1000);
    assert_eq!(result.status(), 400);
    assert_eq!(output(&result)["error"], "revoked_presented_token");
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        410
    );
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
