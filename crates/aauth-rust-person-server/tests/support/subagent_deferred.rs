use super::super::subagents as kids;
use super::*;

fn begin(f: &Fixture, server: &Server, parent: &Agent, child: &Agent) -> PendingResponse {
    let person = compact(
        &kids::person(f, server, parent, child.token()),
        "person_token",
    );
    let challenge = resource(child, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let response = kids::exchange(f, server, parent, child.token(), &challenge, &person);
    assert_eq!(
        response.status(),
        202,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    PendingResponse::parse(&format!("{PS}/token"), &response).unwrap()
}

#[test]
fn immediate_as_exchange_preserves_parent_child_compacts_and_child_bound_grant() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 2, 0);
    let server = f.server(2000).with_federation(transport.clone());
    let parent = agent(false);
    let child = kids::child();
    let person = compact(
        &kids::person(&f, &server, &parent, child.token()),
        "person_token",
    );
    let challenge = resource(&child, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let auth = compact(
        &kids::exchange(&f, &server, &parent, child.token(), &challenge, &person),
        "auth_token",
    );
    let token = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().iss, "https://as.example");
    assert_eq!(token.claims().exp, 1250);
    assert_eq!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        child.public_jwk().thumbprint().unwrap()
    );
    let record = f
        .store
        .token(&TokenReference {
            issuer: token.claims().iss.clone(),
            jti: token.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        record.parent_agent.as_ref().unwrap().subject,
        "aauth:Caller@ap.example"
    );
    assert_eq!(record.agent.subject, "aauth:Caller+worker@ap.example");
    assert_eq!(
        transport.original.lock().unwrap()[0],
        json!({"agent_token":parent.token(),"subagent_token":child.token(),"resource_token":challenge,"presented_token":person})
    );
}

#[test]
fn child_payment_and_approval_recompose_with_parent_only_single_delivery() {
    for stage in [0, 1] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, stage, 0);
        let custody = Arc::new(MemoryContinuations::new(16));
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(custody.clone()))
            .unwrap();
        let parent = agent(false);
        let child = kids::child();
        let pending = begin(&f, &server, &parent, &child);
        assert_eq!(
            poll(&server, &child, &pending.location, "GET", None, 1000).status(),
            403
        );
        assert_eq!(
            poll(&server, &child, &pending.location, "DELETE", None, 1000).status(),
            403
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        drop(server);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(custody))
            .unwrap();
        if stage == 0 {
            assert!(matches!(
                server
                    .federation_pending(&pending.location)
                    .unwrap()
                    .requirement,
                Requirement::Payment { .. }
            ));
            transport.stage.store(1, Ordering::SeqCst);
            assert_eq!(
                server
                    .advance_federation(&pending.location, FederationInput::Poll)
                    .unwrap()
                    .status(),
                202
            );
        }
        transport.stage.store(2, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&pending.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            poll(&server, &child, &pending.location, "GET", None, 1000).status(),
            403
        );
        let responses = std::thread::scope(|scope| {
            let joins: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| poll(&server, &parent, &pending.location, "GET", None, 1000))
                })
                .collect();
            joins
                .into_iter()
                .map(|j| j.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(responses.iter().filter(|r| r.status() == 200).count(), 1);
        for response in &responses {
            if response.status() != 200 {
                assert!([410, 429].contains(&response.status().as_u16()));
                assert!(output(response).get("auth_token").is_none());
            }
        }
        let delivered = responses.iter().find(|r| r.status() == 200).unwrap();
        let auth = AuthToken::parse(&compact(delivered, "auth_token"))
            .unwrap()
            .verify(&Keys, 1000)
            .unwrap();
        assert_eq!(
            auth.claims().cnf.jwk.thumbprint().unwrap(),
            child.public_jwk().thumbprint().unwrap()
        );
        assert_eq!(
            poll(&server, &parent, &pending.location, "GET", None, 1000).status(),
            410
        );
    }
}

#[test]
fn parent_cancellation_consumes_both_child_continuations() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let parent = agent(false);
    let child = kids::child();
    let pending = begin(&f, &server, &parent, &child);
    assert_eq!(
        poll(&server, &parent, &pending.location, "DELETE", None, 1000).status(),
        200
    );
    assert_eq!(
        poll(&server, &parent, &pending.location, "GET", None, 1000).status(),
        410
    );
    assert_eq!(
        server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap_err(),
        aauth_rust_person_server::AdvanceError::Gone
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn parent_or_child_expiry_caps_pending_wait_without_another_as_call() {
    for parent_first in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let parent = if parent_first {
            let original = agent(false);
            let mut claims = aauth_rust_core::AgentToken::parse(original.token())
                .unwrap()
                .unverified_claims()
                .clone();
            claims.exp = 1005;
            Agent::new(
                SigningKey::from_seed([2; 32]),
                AgentProvider::new(
                    "https://ap.example",
                    "ap-key",
                    SigningKey::from_seed([1; 32]),
                )
                .unwrap()
                .issue(&claims)
                .unwrap(),
            )
            .unwrap()
        } else {
            agent(false)
        };
        let child = if parent_first {
            kids::child()
        } else {
            Agent::new(
                SigningKey::from_seed([11; 32]),
                kids::child_token(|c| c.exp = 1005),
            )
            .unwrap()
        };
        let pending = begin(&f, &server, &parent, &child);
        f.host.now.store(1005, Ordering::SeqCst);
        // A fresh parent credential can authenticate the poll, but cannot extend
        // the exact original parent/child credentials retained by this request.
        let fresh_parent = agent(false);
        let response = poll(&server, &fresh_parent, &pending.location, "GET", None, 1005);
        assert_eq!(response.status(), 408);
        assert!(output(&response).get("auth_token").is_none());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            poll(&server, &fresh_parent, &pending.location, "GET", None, 1005).status(),
            410
        );
    }
}

#[test]
fn revoked_parent_withholds_waiting_and_ready_child_delivery() {
    for ready in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let parent = agent(false);
        let child = kids::child();
        let pending = begin(&f, &server, &parent, &child);
        if ready {
            transport.stage.store(2, Ordering::SeqCst);
            assert_eq!(
                server
                    .advance_federation(&pending.location, FederationInput::Poll)
                    .unwrap()
                    .status(),
                200
            );
        }
        let calls = transport.calls.load(Ordering::SeqCst);
        f.store
            .revoke_binding(
                PS,
                &AgentIdentity {
                    issuer: "https://ap.example".into(),
                    subject: "aauth:Caller@ap.example".into(),
                },
            )
            .unwrap();
        let response = poll(&server, &parent, &pending.location, "GET", None, 1000);
        assert_eq!(response.status(), 400);
        assert_eq!(output(&response)["error"], "revoked_presented_token");
        assert_eq!(transport.calls.load(Ordering::SeqCst), calls);
        assert_eq!(
            poll(&server, &parent, &pending.location, "GET", None, 1000).status(),
            410
        );
    }
}

struct ExpireChildAfterConsume {
    inner: MemoryContinuations,
    now: Arc<AtomicI64>,
}
impl ContinuationStore for ExpireChildAfterConsume {
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
        let delivering = value.is_none()
            && self
                .inner
                .load(id)?
                .is_some_and(|s| s.value["state"] == "delivering");
        let changed = self.inner.replace(id, revision, value)?;
        if changed && delivering {
            self.now.store(1005, Ordering::SeqCst);
        }
        Ok(changed)
    }
}
#[test]
fn child_expiry_during_final_consume_withholds_already_prepared_grant() {
    let f = Fixture::new();
    let transport = NativeTransport::new(&f, 1, 0);
    let mut cfg = DeferredConfig::new(ExpireChildAfterConsume {
        inner: MemoryContinuations::new(16),
        now: f.host.now.clone(),
    });
    cfg.retry_after = 0;
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(cfg)
        .unwrap();
    let parent = agent(false);
    let child = Agent::new(
        SigningKey::from_seed([11; 32]),
        kids::child_token(|c| c.exp = 1005),
    )
    .unwrap();
    let pending = begin(&f, &server, &parent, &child);
    transport.stage.store(2, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap()
            .status(),
        200
    );
    let response = poll(&server, &parent, &pending.location, "GET", None, 1000);
    assert_eq!(response.status(), 408);
    assert!(output(&response).get("auth_token").is_none());
    assert_eq!(
        poll(&server, &parent, &pending.location, "GET", None, 1005).status(),
        410
    );
}

#[test]
fn same_key_different_child_identity_cannot_reuse_retained_person() {
    let f = Fixture::new();
    let server = f.server(2000);
    let parent = agent(false);
    let child = kids::child();
    let person = compact(
        &kids::person(&f, &server, &parent, child.token()),
        "person_token",
    );
    let challenge = resource(&child, &person, "read", |_| {});
    let other = kids::child_token(|c| c.sub = "aauth:Caller+other@ap.example".into());
    let response = kids::exchange(&f, &server, &parent, &other, &challenge, &person);
    assert_eq!(response.status(), 400);
    assert_eq!(output(&response)["error"], "invalid_presented_token");
    assert_eq!(f.host.auth_calls.load(Ordering::SeqCst), 0);
}

struct ArmFinalLookup {
    inner: MemoryContinuations,
    armed: Arc<AtomicBool>,
}
impl ContinuationStore for ArmFinalLookup {
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
        let delivering = value.is_none()
            && self
                .inner
                .load(id)?
                .is_some_and(|s| s.value["state"] == "delivering");
        let changed = self.inner.replace(id, revision, value)?;
        if changed && delivering {
            self.armed.store(true, Ordering::SeqCst);
        }
        Ok(changed)
    }
}
#[test]
fn deferred_delivery_fences_final_key_lookup_and_recomputes_remaining_lifetime() {
    for expires in [1005, 1050] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 1, 0);
        let armed = Arc::new(AtomicBool::new(false));
        let store = Arc::new(ArmFinalLookup {
            inner: MemoryContinuations::new(16),
            armed: armed.clone(),
        });
        let mut cfg = DeferredConfig::new(store.clone());
        cfg.retry_after = 0;
        let server = f
            .server(2000)
            .with_federation(transport.clone())
            .with_deferred(cfg)
            .unwrap();
        let parent = agent(false);
        let child = Agent::new(
            SigningKey::from_seed([11; 32]),
            kids::child_token(|c| c.exp = expires),
        )
        .unwrap();
        let pending = begin(&f, &server, &parent, &child);
        transport.stage.store(2, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&pending.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        drop(server);
        let mut cfg = DeferredConfig::new(store);
        cfg.retry_after = 0;
        let server = f
            .server_with_keys(
                2000,
                kids::DelayedKeys {
                    now: f.host.now.clone(),
                    committed: armed,
                    lookups: AtomicUsize::new(0),
                    // Original parent, preparation parent+child, final parent+parent+child.
                    delay_on: 6,
                },
            )
            .with_federation(transport)
            .with_deferred(cfg)
            .unwrap();
        let response = poll(&server, &parent, &pending.location, "GET", None, 1000);
        let body = output(&response);
        assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
        if expires == 1005 {
            assert_eq!(response.status(), 400, "{body}");
            assert_eq!(body["error"], "expired_subagent_token");
            assert!(body.get("auth_token").is_none());
        } else {
            assert_eq!(response.status(), 200, "{body}");
            assert_eq!(body["expires_in"], 45);
            assert!(body.get("auth_token").is_some());
        }
        assert_eq!(
            poll(&server, &parent, &pending.location, "GET", None, 1005).status(),
            410
        );
    }
}
