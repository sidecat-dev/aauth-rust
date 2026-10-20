use super::*;
use aauth_rust_access_server::{DeferredConfig, DeferredContext};
use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement,
};
fn poll(location: &str, method: &str, value: Option<Value>, now: i64) -> Request<Vec<u8>> {
    let mut builder = Request::builder().uri(location).method(method);
    if value.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder
        .body(
            value
                .map(|v| v.to_string().into_bytes())
                .unwrap_or_default(),
        )
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        now,
    )
    .unwrap();
    request
}
fn grant(_: &aauth_rust_access_server::AuthorizationRequest) -> Result<Decision, PolicyError> {
    Ok(Decision {
        scopes: vec!["read".into()],
        lifetime: 3600,
    })
}
fn config(store: Arc<MemoryContinuations>) -> DeferredConfig {
    let mut c = DeferredConfig::new(store);
    c.lifetime = 60;
    c.retry_after = 0;
    c
}
#[test]
fn payment_approval_grant_is_authenticated_and_consumed_once() {
    let stage = Arc::new(AtomicUsize::new(0));
    let policy = stage.clone();
    let store = Arc::new(MemoryContinuations::new(4));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "opaque-pending".into(),
    )
    .unwrap()
    .with_deferred(config(store.clone()), move |_: &DeferredContext| {
        Ok(match policy.load(Ordering::SeqCst) {
            0 => Some(Requirement::Payment {
                authenticate: "Payment id=\"bill\", method=\"example\"".into(),
            }),
            1 => Some(Requirement::Approval),
            _ => None,
        })
    })
    .unwrap();
    let first = server.handle(&request(good()));
    assert_eq!(first.status(), 402);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    stage.store(1, Ordering::SeqCst);
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        202
    );
    stage.store(2, Ordering::SeqCst);
    let result = server.handle(&poll(&pending.location, "GET", None, 1000));
    assert_eq!(result.status(), 200);
    let value: Value = serde_json::from_slice(result.body()).unwrap();
    let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().exp, 2000);
    assert_eq!(token.claims().sub, "directed-person");
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        410
    );
    assert!(store.load("opaque-pending").unwrap().is_none());
}
#[test]
fn claims_and_clarification_are_signed_inputs_to_policy() {
    let store = Arc::new(MemoryContinuations::new(4));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(config(store), |c: &DeferredContext| {
        Ok(if !c.claims.contains_key("email") {
            Some(Requirement::Claims(vec!["email".into()]))
        } else if c.clarifications.is_empty() {
            Some(Requirement::Clarification {
                question: "Why read?".into(),
                timeout: Some(30),
                options: vec![],
            })
        } else {
            assert_eq!(c.claims["email"], "person@example");
            assert_eq!(c.clarifications, ["To answer the person"]);
            None
        })
    })
    .unwrap();
    let response = server.handle(&request(good()));
    assert_eq!(response.status(), 202);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    assert_eq!(
        server
            .handle(&poll(
                &pending.location,
                "POST",
                Some(json!({"sub":"someone-else"})),
                1000
            ))
            .status(),
        400
    );
    let clarification = server.handle(&poll(
        &pending.location,
        "POST",
        Some(json!({"email":"person@example"})),
        1000,
    ));
    assert!(matches!(
        PendingResponse::parse(&pending.location, &clarification)
            .unwrap()
            .requirement,
        Requirement::Clarification { .. }
    ));
    assert_eq!(
        server
            .handle(&poll(
                &pending.location,
                "POST",
                Some(json!({"action":"unknown"})),
                1000
            ))
            .status(),
        400
    );
    assert_eq!(server.handle(&poll(&pending.location,"POST",Some(json!({"action":"clarification_response","clarification_response":"To answer the person"})),1000)).status(),200);
}
#[test]
fn unsigned_or_tampered_polls_never_advance_policy_and_cancel_is_terminal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(
        config(Arc::new(MemoryContinuations::new(4))),
        move |_: &DeferredContext| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Requirement::Interaction {
                url: format!("{AS}/consent"),
                code: "single-use-host-code".into(),
            }))
        },
    )
    .unwrap();
    let response = server.handle(&request(good()));
    let p = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    assert_eq!(
        server
            .handle(
                &Request::builder()
                    .uri(&p.location)
                    .body(Vec::new())
                    .unwrap()
            )
            .status(),
        401
    );
    let mut changed = poll(
        &p.location,
        "POST",
        Some(json!({"action":"clarification_response","clarification_response":"original"})),
        1000,
    );
    *changed.body_mut() = b"tampered".to_vec();
    assert_eq!(server.handle(&changed).status(), 401);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        server
            .handle(&poll(&p.location, "DELETE", None, 1000))
            .status(),
        200
    );
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1000))
            .status(),
        410
    );
}
#[test]
fn pending_survives_recomposition_and_expiry_is_a_terminal_408() {
    let store = Arc::new(MemoryContinuations::new(4));
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        move || clock.load(Ordering::SeqCst),
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(config(store.clone()), |_: &DeferredContext| {
        Ok(Some(Requirement::Approval))
    })
    .unwrap();
    let first = server.handle(&request(good()));
    let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    drop(server);
    let clock = now.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        move || clock.load(Ordering::SeqCst),
        || "unused".into(),
    )
    .unwrap()
    .with_deferred(config(store), |_: &DeferredContext| Ok(None))
    .unwrap();
    now.store(1060, Ordering::SeqCst);
    let result = server.handle(&poll(&p.location, "GET", None, 1060));
    assert_eq!(result.status(), 408);
    assert_eq!(
        serde_json::from_slice::<Value>(result.body()).unwrap()["error"],
        "expired"
    );
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1060))
            .status(),
        410
    );
}

#[test]
fn concurrent_poll_or_cancellation_cannot_release_two_grants() {
    for cancel in [false, true] {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let stage = Arc::new(AtomicUsize::new(0));
        let state = stage.clone();
        let e = entered.clone();
        let r = release.clone();
        let server = Arc::new(
            AccessServer::new(
                Config::new(AS, "as", SigningKey::from_seed([4; 32])),
                Keys,
                grant,
                || 1000,
                || "opaque".into(),
            )
            .unwrap()
            .with_deferred(
                config(Arc::new(MemoryContinuations::new(4))),
                move |_: &DeferredContext| {
                    if state.load(Ordering::SeqCst) == 0 {
                        Ok(Some(Requirement::Approval))
                    } else {
                        e.wait();
                        r.wait();
                        Ok(None)
                    }
                },
            )
            .unwrap(),
        );
        let response = server.handle(&request(good()));
        let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
        stage.store(1, Ordering::SeqCst);
        let worker = server.clone();
        let location = pending.location.clone();
        let thread = std::thread::spawn(move || worker.handle(&poll(&location, "GET", None, 1000)));
        entered.wait();
        let competing = server.handle(&poll(
            &pending.location,
            if cancel { "DELETE" } else { "GET" },
            None,
            1000,
        ));
        assert_eq!(competing.status(), if cancel { 200 } else { 429 });
        release.wait();
        let result = thread.join().unwrap();
        assert_eq!(result.status(), if cancel { 500 } else { 200 });
        assert_eq!(
            server
                .handle(&poll(&pending.location, "GET", None, 1000))
                .status(),
            410
        );
    }
}
#[test]
fn refreshed_trust_failure_is_terminal_for_a_pending_request() {
    struct RevokingKeys(Arc<std::sync::atomic::AtomicBool>);
    impl AgentKeyResolver for RevokingKeys {
        fn key(&self, i: &str, d: &str, k: &str) -> Result<Jwk, TokenError> {
            if i == RESOURCE && self.0.load(Ordering::SeqCst) {
                Err(TokenError::UntrustedIssuer)
            } else {
                Keys.key(i, d, k)
            }
        }
    }
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        RevokingKeys(revoked.clone()),
        grant,
        || 1000,
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(
        config(Arc::new(MemoryContinuations::new(4))),
        |_: &DeferredContext| Ok(Some(Requirement::Approval)),
    )
    .unwrap();
    let response = server.handle(&request(good()));
    let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        400
    );
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        410
    );
}
#[test]
fn exhausted_custody_and_early_polls_do_not_issue() {
    for capacity in [0, 1] {
        let mut cfg = config(Arc::new(MemoryContinuations::new(capacity)));
        cfg.retry_after = 5;
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            || 1000,
            || "opaque".into(),
        )
        .unwrap()
        .with_deferred(cfg, |_: &DeferredContext| Ok(Some(Requirement::Approval)))
        .unwrap();
        let response = server.handle(&request(good()));
        if capacity == 0 {
            assert_eq!(response.status(), 500);
            assert!(!String::from_utf8_lossy(response.body()).contains("auth_token"));
        } else {
            let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
            assert_eq!(
                server
                    .handle(&poll(&pending.location, "GET", None, 1000))
                    .status(),
                429
            );
        }
    }
}
