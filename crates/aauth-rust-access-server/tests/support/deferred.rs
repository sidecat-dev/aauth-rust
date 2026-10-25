use super::*;
use aauth_rust_access_server::{DeferredConfig, DeferredContext};
use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement,
};
fn poll(location: &str, method: &str, value: Option<Value>, now: i64) -> Request<Vec<u8>> {
    poll_as(location, method, value, now, PS, 3)
}
fn poll_as(
    location: &str,
    method: &str,
    value: Option<Value>,
    now: i64,
    owner: &str,
    seed: u8,
) -> Request<Vec<u8>> {
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
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::JwksUri {
            id: owner.into(),
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
fn subagent_payment_approval_retains_exact_tokens_and_recomposes_child_grant() {
    let stage = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(MemoryContinuations::new(4));
    let original = super::subagent::child_body(agent_claims(), super::subagent::child_claims());
    let make_server = || {
        let stage = stage.clone();
        AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            || 1000,
            || "child-pending".into(),
        )
        .unwrap()
        .with_deferred(config(store.clone()), move |c: &DeferredContext| {
            assert_eq!(
                c.authorization.agent.claims().sub,
                "aauth:Caller@ap.example"
            );
            assert_eq!(
                c.authorization.subagent.as_ref().unwrap().claims().sub,
                "aauth:Caller+worker@ap.example"
            );
            Ok(match stage.load(Ordering::SeqCst) {
                0 => Some(Requirement::Payment {
                    authenticate: "Payment id=\"child-bill\", method=\"example\"".into(),
                }),
                1 => Some(Requirement::Approval),
                _ => None,
            })
        })
        .unwrap()
    };
    let first = make_server().handle(&request(original.clone()));
    assert_eq!(
        first.status(),
        402,
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    assert_eq!(
        store.load("child-pending").unwrap().unwrap().value["request"],
        original
    );
    for method in ["GET", "DELETE"] {
        assert_eq!(
            make_server()
                .handle(&poll_as(&pending.location, method, None, 1000, OTHER_PS, 6))
                .status(),
            403
        );
    }
    let mut child_poll = Request::builder()
        .uri(&pending.location)
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut child_poll,
        &SigningKey::from_seed([7; 32]),
        KeyMaterial::Jwt(original["subagent_token"].as_str().unwrap().into()),
        1000,
    )
    .unwrap();
    assert_eq!(make_server().handle(&child_poll).status(), 401);
    stage.store(1, Ordering::SeqCst);
    assert_eq!(
        make_server()
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        202
    );
    assert_eq!(
        store.load("child-pending").unwrap().unwrap().value["request"],
        original
    );
    stage.store(2, Ordering::SeqCst);
    let final_response = make_server().handle(&poll(&pending.location, "GET", None, 1000));
    assert_eq!(final_response.status(), 200);
    let body: Value = serde_json::from_slice(final_response.body()).unwrap();
    let token = AuthToken::parse(body["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        SigningKey::from_seed([7; 32])
            .public_jwk()
            .thumbprint()
            .unwrap()
    );
    assert_eq!(token.claims().exp, 1600);
    assert_eq!(
        make_server()
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        410
    );
}
#[test]
fn subagent_claims_cannot_replace_the_original_credentials() {
    let store = Arc::new(MemoryContinuations::new(4));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "child-pending".into(),
    )
    .unwrap()
    .with_deferred(config(store.clone()), |c: &DeferredContext| {
        Ok(if c.claims.contains_key("email") {
            None
        } else {
            Some(Requirement::Claims(vec!["email".into()]))
        })
    })
    .unwrap();
    let original = super::subagent::child_body(agent_claims(), super::subagent::child_claims());
    let response = server.handle(&request(original));
    assert_eq!(response.status(), 202);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    let original = store.load("child-pending").unwrap();
    for name in [
        "agent_token",
        "subagent_token",
        "presented_token",
        "resource_token",
    ] {
        let mut body = json!({"email":"parent@example"});
        body[name] = json!("replacement-credential");
        let response = server.handle(&poll(&pending.location, "POST", Some(body), 1000));
        assert_eq!(response.status(), 400, "{name}");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
            "invalid_request"
        );
        assert_eq!(store.load("child-pending").unwrap(), original);
    }
}
#[test]
fn subagent_pending_release_rechecks_expiry_after_initial_waiting_and_terminal_store_writes() {
    struct PersistClock {
        inner: MemoryContinuations,
        now: Arc<AtomicI64>,
        phase: &'static str,
    }
    impl ContinuationStore for PersistClock {
        fn insert(
            &self,
            id: &str,
            value: Value,
        ) -> Result<(), aauth_rust_core::continuation::StoreError> {
            self.inner.insert(id, value)?;
            if self.phase == "initial" {
                self.now.store(1010, Ordering::SeqCst);
            }
            Ok(())
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
            let pause = (self.phase == "waiting"
                && value.as_ref().is_some_and(|v| v["state"] == "waiting"))
                || (self.phase == "terminal" && value.is_none());
            let changed = self.inner.replace(id, revision, value)?;
            if changed && pause {
                self.now.store(1010, Ordering::SeqCst);
            }
            Ok(changed)
        }
    }
    for (phase, question) in [
        ("initial", false),
        ("waiting", false),
        ("terminal", false),
        ("initial", true),
        ("waiting", true),
        ("terminal", true),
    ] {
        let now = Arc::new(AtomicI64::new(1000));
        let clock = now.clone();
        let store = Arc::new(PersistClock {
            inner: MemoryContinuations::new(4),
            now,
            phase,
        });
        let mut cfg = DeferredConfig::new(store.clone());
        cfg.retry_after = 0;
        let stage = Arc::new(AtomicUsize::new(0));
        let state = stage.clone();
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            move || clock.load(Ordering::SeqCst),
            || "child-pending".into(),
        )
        .unwrap()
        .with_deferred(cfg, move |_: &DeferredContext| {
            Ok(
                if phase == "terminal" && state.load(Ordering::SeqCst) == 1 {
                    None
                } else {
                    Some(if question {
                        Requirement::Clarification {
                            question: "Why?".into(),
                            timeout: Some(10),
                            options: vec![],
                        }
                    } else {
                        Requirement::Approval
                    })
                },
            )
        })
        .unwrap();
        let mut child = super::subagent::child_claims();
        child.exp = if question { 1600 } else { 1010 };
        let first = server.handle(&request(super::subagent::child_body(agent_claims(), child)));
        let response = if phase == "initial" {
            first
        } else {
            assert_eq!(first.status(), 202);
            stage.store(1, Ordering::SeqCst);
            let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
            server.handle(&poll(&pending.location, "GET", None, 1000))
        };
        assert_eq!(response.status(), 408, "phase={phase}");
        assert!(!String::from_utf8_lossy(response.body()).contains("auth_token"));
        assert!(
            store.load("child-pending").unwrap().is_none(),
            "phase={phase}"
        );
    }
}
#[test]
fn subagent_pending_deadline_is_capped_by_parent_and_child_expiry() {
    for parent_expires in [false, true] {
        let now = Arc::new(AtomicI64::new(1000));
        let clock = now.clone();
        let store = Arc::new(MemoryContinuations::new(4));
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            move || clock.load(Ordering::SeqCst),
            || "child-pending".into(),
        )
        .unwrap()
        .with_deferred(config(store.clone()), |_: &DeferredContext| {
            Ok(Some(Requirement::Approval))
        })
        .unwrap();
        let mut parent = agent_claims();
        let mut child = super::subagent::child_claims();
        if parent_expires {
            parent.exp = 1010;
        } else {
            child.exp = 1010;
        }
        let first = server.handle(&request(super::subagent::child_body(parent, child)));
        assert_eq!(first.status(), 202);
        let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
        assert_eq!(
            store.load("child-pending").unwrap().unwrap().value["deadline"],
            1010
        );
        now.store(1010, Ordering::SeqCst);
        let response = server.handle(&poll(&pending.location, "GET", None, 1010));
        assert_eq!(response.status(), 408);
        assert!(!String::from_utf8_lossy(response.body()).contains("auth_token"));
        assert!(store.load("child-pending").unwrap().is_none());
    }
}
#[test]
fn subagent_child_trust_is_refreshed_on_each_poll_and_after_final_custody() {
    struct ChildKeys(Arc<std::sync::atomic::AtomicBool>);
    impl AgentKeyResolver for ChildKeys {
        fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
            if issuer == "https://ap.example" && dwk == "aauth-agent.json" && kid == "child-ap" {
                if self.0.load(Ordering::SeqCst) {
                    return Err(TokenError::UntrustedIssuer);
                }
                return Ok(SigningKey::from_seed([1; 32]).public_jwk());
            }
            Keys.key(issuer, dwk, kid)
        }
    }
    struct FinalTrustStore {
        inner: MemoryContinuations,
        revoked: Arc<std::sync::atomic::AtomicBool>,
        final_revoke: bool,
    }
    impl ContinuationStore for FinalTrustStore {
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
            let final_write = value.is_none();
            let result = self.inner.replace(id, revision, value)?;
            if result && final_write && self.final_revoke {
                self.revoked.store(true, Ordering::SeqCst);
            }
            Ok(result)
        }
    }
    for final_revoke in [false, true] {
        let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let store = Arc::new(FinalTrustStore {
            inner: MemoryContinuations::new(4),
            revoked: revoked.clone(),
            final_revoke,
        });
        let stage = Arc::new(AtomicUsize::new(0));
        let state = stage.clone();
        let mut cfg = DeferredConfig::new(store.clone());
        cfg.retry_after = 0;
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            ChildKeys(revoked.clone()),
            grant,
            || 1000,
            || "child-pending".into(),
        )
        .unwrap()
        .with_deferred(cfg, move |_: &DeferredContext| {
            Ok(if state.load(Ordering::SeqCst) == 0 {
                Some(Requirement::Approval)
            } else {
                None
            })
        })
        .unwrap();
        let mut body = super::subagent::child_body(agent_claims(), super::subagent::child_claims());
        body["subagent_token"] = json!(super::subagent::agent_compact(
            &super::subagent::child_claims(),
            1,
            "child-ap"
        ));
        let first = server.handle(&request(body));
        assert_eq!(first.status(), 202);
        let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
        stage.store(1, Ordering::SeqCst);
        if !final_revoke {
            revoked.store(true, Ordering::SeqCst);
        }
        let response = server.handle(&poll(&p.location, "GET", None, 1000));
        assert_eq!(response.status(), 400);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_subagent_token");
        assert!(body.get("auth_token").is_none());
        assert!(store.load("child-pending").unwrap().is_none());
    }
}
#[test]
fn subagent_early_poll_refreshes_child_trust_and_consumes_invalid_custody() {
    struct ChildKeys(Arc<std::sync::atomic::AtomicBool>);
    impl AgentKeyResolver for ChildKeys {
        fn key(&self, i: &str, d: &str, k: &str) -> Result<Jwk, TokenError> {
            if k == "child-ap" {
                if self.0.load(Ordering::SeqCst) {
                    return Err(TokenError::UntrustedIssuer);
                }
                return Keys.key(i, d, "ap");
            }
            Keys.key(i, d, k)
        }
    }
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let store = Arc::new(MemoryContinuations::new(4));
    let mut cfg = config(store.clone());
    cfg.retry_after = 5;
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        ChildKeys(revoked.clone()),
        grant,
        move || clock.load(Ordering::SeqCst),
        || "child-pending".into(),
    )
    .unwrap()
    .with_deferred(cfg, |_: &DeferredContext| Ok(Some(Requirement::Approval)))
    .unwrap();
    let mut body = super::subagent::child_body(agent_claims(), super::subagent::child_claims());
    body["subagent_token"] = json!(super::subagent::agent_compact(
        &super::subagent::child_claims(),
        1,
        "child-ap"
    ));
    let first = server.handle(&request(body));
    assert_eq!(first.status(), 202);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    now.store(1001, Ordering::SeqCst);
    revoked.store(true, Ordering::SeqCst);
    let response = server.handle(&poll(&pending.location, "GET", None, 1001));
    assert_eq!(response.status(), 400);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
        "invalid_subagent_token"
    );
    assert!(store.load("child-pending").unwrap().is_none());
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
                code: "C0DE8X42".into(),
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
fn authenticated_foreign_ps_cannot_advance_or_cancel_the_owners_pending_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let store = Arc::new(MemoryContinuations::new(4));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(config(store.clone()), move |_: &DeferredContext| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Requirement::Claims(vec!["email".into()])))
    })
    .unwrap();
    let response = server.handle(&request(good()));
    let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    let original = store.load("opaque").unwrap();
    for method in ["GET", "POST", "DELETE"] {
        let value = (method == "POST").then(|| json!({"email":"foreign@example"}));
        let response = server.handle(&poll_as(
            &pending.location,
            method,
            value,
            1000,
            OTHER_PS,
            6,
        ));
        assert_eq!(response.status(), 403, "{method}");
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "wrong_poller", "{method}");
        assert!(body.get("auth_token").is_none());
        assert_eq!(store.load("opaque").unwrap(), original);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        202
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        server
            .handle(&poll(&pending.location, "DELETE", None, 1000))
            .status(),
        200
    );
    for location in [&pending.location, &format!("{AS}/token/pending/missing")] {
        let response = server.handle(&poll_as(location, "GET", None, 1000, OTHER_PS, 6));
        assert_eq!(response.status(), 410);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
            "gone"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
#[test]
fn actual_deferred_policy_denial_is_denied_and_consumes_the_request() {
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
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Some(Requirement::Approval))
            } else {
                Err(PolicyError::Denied)
            }
        },
    )
    .unwrap();
    let first = server.handle(&request(good()));
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    let response = server.handle(&poll(&pending.location, "GET", None, 1000));
    assert_eq!(response.status(), 403);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "denied");
    assert!(body.get("auth_token").is_none());
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1000))
            .status(),
        410
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
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
        if !cancel {
            assert_eq!(competing.headers()["retry-after"], "1");
        }
        release.wait();
        let result = thread.join().unwrap();
        assert_eq!(result.status(), if cancel { 410 } else { 200 });
        if cancel {
            let body: Value = serde_json::from_slice(result.body()).unwrap();
            assert_eq!(body["error"], "gone");
            assert!(body.get("auth_token").is_none());
        }
        assert_eq!(
            server
                .handle(&poll(&pending.location, "GET", None, 1000))
                .status(),
            410
        );
    }
}
#[test]
fn cancellation_winning_final_cas_refuses_prepared_grants_and_pending_responses() {
    for (waiting, child) in [(false, false), (true, false), (false, true), (true, true)] {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let store = Arc::new(FinalizationStore {
            inner: MemoryContinuations::new(4),
            replacements: AtomicUsize::new(0),
            entered: entered.clone(),
            release: release.clone(),
            fail: false,
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let mut cfg = DeferredConfig::new(store.clone());
        cfg.retry_after = 0;
        let server = Arc::new(
            AccessServer::new(
                Config::new(AS, "as", SigningKey::from_seed([4; 32])),
                Keys,
                grant,
                || 1000,
                || "opaque".into(),
            )
            .unwrap()
            .with_deferred(cfg, move |_: &DeferredContext| {
                Ok(if seen.fetch_add(1, Ordering::SeqCst) == 0 || waiting {
                    Some(Requirement::Approval)
                } else {
                    None
                })
            })
            .unwrap(),
        );
        let body = if child {
            super::subagent::child_body(agent_claims(), super::subagent::child_claims())
        } else {
            good()
        };
        let first = server.handle(&request(body));
        let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
        let worker = server.clone();
        let location = pending.location.clone();
        let thread = std::thread::spawn(move || worker.handle(&poll(&location, "GET", None, 1000)));
        // The response is prepared and final custody replacement has started.
        entered.wait();
        let cancelled = server.handle(&poll(&pending.location, "DELETE", None, 1000));
        release.wait();
        let response = thread.join().unwrap();
        assert_eq!(cancelled.status(), 200);
        assert_eq!(response.status(), 410, "waiting={waiting}");
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "gone");
        assert!(body.get("auth_token").is_none());
        assert!(store.load("opaque").unwrap().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            server
                .handle(&poll(&pending.location, "GET", None, 1000))
                .status(),
            410
        );
    }
}
struct FinalizationStore {
    inner: MemoryContinuations,
    replacements: AtomicUsize,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
    fail: bool,
}
impl ContinuationStore for FinalizationStore {
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
        if self.replacements.fetch_add(1, Ordering::SeqCst) == 1 {
            self.entered.wait();
            self.release.wait();
            if self.fail {
                return Err(aauth_rust_core::continuation::StoreError::Unavailable);
            }
        }
        self.inner.replace(id, revision, value)
    }
}
#[test]
fn final_custody_persistence_failure_remains_500_and_withholds_the_grant() {
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let store = Arc::new(FinalizationStore {
        inner: MemoryContinuations::new(4),
        replacements: AtomicUsize::new(0),
        entered: entered.clone(),
        release: release.clone(),
        fail: true,
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut cfg = DeferredConfig::new(store.clone());
    cfg.retry_after = 0;
    let server = Arc::new(
        AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            || 1000,
            || "opaque".into(),
        )
        .unwrap()
        .with_deferred(cfg, move |_: &DeferredContext| {
            Ok(if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                Some(Requirement::Approval)
            } else {
                None
            })
        })
        .unwrap(),
    );
    let first = server.handle(&request(good()));
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    let worker = server.clone();
    let location = pending.location.clone();
    let thread = std::thread::spawn(move || worker.handle(&poll(&location, "GET", None, 1000)));
    entered.wait();
    release.wait();
    let response = thread.join().unwrap();
    assert_eq!(response.status(), 500);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "server_error");
    assert!(body.get("auth_token").is_none());
    assert!(store.load("opaque").unwrap().is_some());
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

#[test]
fn early_get_advertises_remaining_wait_without_advancing_or_renewing() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let store = Arc::new(MemoryContinuations::new(4));
    let mut cfg = config(store.clone());
    cfg.retry_after = 10;
    cfg.lifetime = 11;
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        move || clock.load(Ordering::SeqCst),
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(cfg, move |_: &DeferredContext| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Requirement::Approval))
    })
    .unwrap();
    let first = server.handle(&request(good()));
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    let original = store.load("opaque").unwrap();
    assert_eq!(first.headers()["retry-after"], "10");
    for (time, retry) in [(1003, "7"), (1009, "1")] {
        now.store(time, Ordering::SeqCst);
        let response = server.handle(&poll(&pending.location, "GET", None, time));
        assert_eq!(response.status(), 429);
        assert_eq!(response.headers()["retry-after"], retry);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "slow_down");
        assert!(body.get("auth_token").is_none());
        assert_eq!(store.load("opaque").unwrap(), original);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    now.store(1010, Ordering::SeqCst);
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1010))
            .status(),
        202
    );
    let renewed = store.load("opaque").unwrap().unwrap();
    assert_eq!(renewed.value["next"], 1020);
    assert_eq!(renewed.value["deadline"], 1011);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // The global deadline still expires during the next scheduled wait.
    now.store(1011, Ordering::SeqCst);
    let response = server.handle(&poll(&pending.location, "GET", None, 1011));
    assert_eq!(response.status(), 408);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
        "expired"
    );
    assert!(store.load("opaque").unwrap().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        server
            .handle(&poll(&pending.location, "GET", None, 1011))
            .status(),
        410
    );
}
#[test]
fn pending_deadline_is_rechecked_after_both_policy_callbacks() {
    for slow_grant in [false, true] {
        let now = Arc::new(AtomicI64::new(1000));
        let clock = now.clone();
        let grant_clock = now.clone();
        let deferred_clock = now.clone();
        let stage = Arc::new(AtomicUsize::new(0));
        let state = stage.clone();
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            move |c: &aauth_rust_access_server::AuthorizationRequest| {
                if slow_grant {
                    grant_clock.store(1061, Ordering::SeqCst);
                }
                grant(c)
            },
            move || clock.load(Ordering::SeqCst),
            || "opaque".into(),
        )
        .unwrap()
        .with_deferred(
            config(Arc::new(MemoryContinuations::new(4))),
            move |_: &DeferredContext| {
                if state.load(Ordering::SeqCst) == 0 {
                    Ok(Some(Requirement::Approval))
                } else {
                    if !slow_grant {
                        deferred_clock.store(1061, Ordering::SeqCst);
                    }
                    Ok(None)
                }
            },
        )
        .unwrap();
        let first = server.handle(&request(good()));
        let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
        stage.store(1, Ordering::SeqCst);
        now.store(1059, Ordering::SeqCst);
        let result = server.handle(&poll(&p.location, "GET", None, 1059));
        assert_eq!(result.status(), 408, "slow_grant={slow_grant}");
        assert!(!String::from_utf8_lossy(result.body()).contains("auth_token"));
        assert_eq!(
            server
                .handle(&poll(&p.location, "GET", None, 1061))
                .status(),
            410
        );
    }
}
struct RemovalClock {
    inner: MemoryContinuations,
    now: Arc<AtomicI64>,
}
impl ContinuationStore for RemovalClock {
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
        let terminal = value.is_none();
        let changed = self.inner.replace(id, revision, value)?;
        if changed && terminal {
            self.now.store(1061, Ordering::SeqCst);
        }
        Ok(changed)
    }
}
#[test]
fn terminal_store_removal_must_finish_before_the_pending_deadline() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let stage = Arc::new(AtomicUsize::new(0));
    let state = stage.clone();
    let mut cfg = DeferredConfig::new(RemovalClock {
        inner: MemoryContinuations::new(4),
        now: now.clone(),
    });
    cfg.lifetime = 60;
    cfg.retry_after = 0;
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        move || clock.load(Ordering::SeqCst),
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(cfg, move |_: &DeferredContext| {
        Ok(if state.load(Ordering::SeqCst) == 0 {
            Some(Requirement::Approval)
        } else {
            None
        })
    })
    .unwrap();
    let first = server.handle(&request(good()));
    let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    stage.store(1, Ordering::SeqCst);
    let result = server.handle(&poll(&p.location, "GET", None, 1000));
    assert_eq!(result.status(), 408);
    assert!(!String::from_utf8_lossy(result.body()).contains("auth_token"));
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1061))
            .status(),
        410
    );
}
#[test]
fn unchanged_clarification_get_does_not_extend_its_timeout() {
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
    .with_deferred(
        config(Arc::new(MemoryContinuations::new(4))),
        |_: &DeferredContext| {
            Ok(Some(Requirement::Clarification {
                question: "Why?".into(),
                timeout: Some(10),
                options: vec![],
            }))
        },
    )
    .unwrap();
    let first = server.handle(&request(good()));
    let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    now.store(1005, Ordering::SeqCst);
    let repeated = server.handle(&poll(&p.location, "GET", None, 1005));
    assert_eq!(repeated.status(), 202);
    assert_eq!(
        serde_json::from_slice::<Value>(repeated.body()).unwrap()["timeout"],
        5
    );
    now.store(1010, Ordering::SeqCst);
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1010))
            .status(),
        408
    );
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1010))
            .status(),
        410
    );
}

#[test]
fn accepted_answer_retires_its_question_deadline_during_policy_processing() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let (e, r) = (entered.clone(), release.clone());
    let server = Arc::new(
        AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            move || clock.load(Ordering::SeqCst),
            || "opaque".into(),
        )
        .unwrap()
        .with_deferred(
            config(Arc::new(MemoryContinuations::new(4))),
            move |c: &DeferredContext| {
                if c.clarifications.is_empty() {
                    Ok(Some(Requirement::Clarification {
                        question: "Why?".into(),
                        timeout: Some(10),
                        options: vec![],
                    }))
                } else {
                    e.wait();
                    r.wait();
                    Ok(None)
                }
            },
        )
        .unwrap(),
    );
    let first = server.handle(&request(good()));
    let p = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    now.store(1005, Ordering::SeqCst);
    let worker = server.clone();
    let location = p.location.clone();
    let thread = std::thread::spawn(move || {
        worker.handle(&poll(
            &location,
            "POST",
            Some(json!({"action":"clarification_response","clarification_response":"on time"})),
            1005,
        ))
    });
    entered.wait();
    now.store(1010, Ordering::SeqCst);
    let competing = server.handle(&poll(&p.location, "GET", None, 1010));
    release.wait();
    let completed = thread.join().unwrap();
    assert_eq!(competing.status(), 429);
    assert_eq!(completed.status(), 200);
    assert_eq!(
        server
            .handle(&poll(&p.location, "GET", None, 1010))
            .status(),
        410
    );
}

#[test]
fn updated_request_verifies_the_pair_before_replacing_the_pending_request() {
    let store = Arc::new(MemoryContinuations::new(4));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        || 1000,
        || "opaque".into(),
    )
    .unwrap()
    .with_deferred(config(store.clone()), |context: &DeferredContext| {
        Ok(if context.clarifications.is_empty() {
            Some(Requirement::Clarification {
                question: "Why read?".into(),
                timeout: Some(30),
                options: vec![],
            })
        } else {
            None
        })
    })
    .unwrap();
    let response = server.handle(&request(good()));
    assert_eq!(response.status(), 202);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &response).unwrap();
    let stored = || {
        store.load("opaque").unwrap().unwrap().value["request"]["resource_token"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let original = stored();
    let error = |body: Value| {
        let response = server.handle(&poll(&pending.location, "POST", Some(body), 1000));
        assert_eq!(
            response.status(),
            400,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        serde_json::from_slice::<Value>(response.body()).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        error(json!({"action":"updated_request","resource_token":original})),
        "invalid_request"
    );
    assert_eq!(stored(), original);
    let mut resource = super::resource_claims();
    resource.presented_jti = "other".into();
    let mismatched = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &resource,
    )
    .unwrap();
    let presented = good()["presented_token"].as_str().unwrap().to_owned();
    assert_eq!(
        error(json!({
            "action": "updated_request",
            "resource_token": mismatched,
            "presented_token": presented
        })),
        "invalid_resource_token"
    );
    assert_eq!(stored(), original);
    let mut person = super::person_claims();
    person.sub = "other-person".into();
    let mut resource = super::resource_claims();
    resource.sub = "other-person".into();
    let other_presented =
        aauth_rust_core::mint_person_token(&SigningKey::from_seed([3; 32]), "ps", &person).unwrap();
    let other_resource = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &resource,
    )
    .unwrap();
    assert_eq!(
        error(json!({
            "action": "updated_request",
            "resource_token": other_resource,
            "presented_token": other_presented
        })),
        "invalid_resource_token"
    );
    assert_eq!(stored(), original);
    for mutate in [
        |claims: &mut ResourceClaims| claims.ps = "https://other.example".into(),
        |claims: &mut ResourceClaims| {
            claims.agent_jkt = SigningKey::from_seed([9; 32])
                .public_jwk()
                .thumbprint()
                .unwrap();
        },
        |claims: &mut ResourceClaims| {
            claims.mission_s256 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        },
        |claims: &mut ResourceClaims| claims.tenant = Some("other-tenant".into()),
    ] {
        let mut claims = super::resource_claims();
        mutate(&mut claims);
        let token = aauth_rust_core::mint_resource_token(
            &SigningKey::from_seed([5; 32]),
            "resource",
            &claims,
        )
        .unwrap();
        assert_eq!(
            error(json!({
                "action": "updated_request",
                "resource_token": token,
                "presented_token": presented
            })),
            "invalid_resource_token"
        );
        assert_eq!(stored(), original);
    }
    let mut person = super::person_claims();
    person.jti = "person-tenant".into();
    person.tenant = Some("other-tenant".into());
    let mut resource = super::resource_claims();
    resource.presented_jti = "person-tenant".into();
    resource.tenant = Some("other-tenant".into());
    let tenant_presented =
        aauth_rust_core::mint_person_token(&SigningKey::from_seed([3; 32]), "ps", &person).unwrap();
    let tenant_resource = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &resource,
    )
    .unwrap();
    assert_eq!(
        error(json!({
            "action": "updated_request",
            "resource_token": tenant_resource,
            "presented_token": tenant_presented
        })),
        "invalid_resource_token"
    );
    assert_eq!(stored(), original);
    let mut person = super::person_claims();
    person.jti = "person-2".into();
    let mut resource = super::resource_claims();
    resource.presented_jti = "person-2".into();
    resource.account = Some("reduced".into());
    let next_presented =
        aauth_rust_core::mint_person_token(&SigningKey::from_seed([3; 32]), "ps", &person).unwrap();
    let next_resource = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &resource,
    )
    .unwrap();
    let accepted = server.handle(&poll(
        &pending.location,
        "POST",
        Some(json!({
            "action": "updated_request",
            "resource_token": next_resource,
            "presented_token": next_presented,
            "justification": "read only"
        })),
        1000,
    ));
    assert_eq!(
        accepted.status(),
        202,
        "{}",
        String::from_utf8_lossy(accepted.body())
    );
    assert_eq!(stored(), next_resource);
    let granted = server.handle(&poll(
        &pending.location,
        "POST",
        Some(json!({"action":"clarification_response","clarification_response":"read only"})),
        1000,
    ));
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    let token = AuthToken::parse(
        serde_json::from_slice::<Value>(granted.body()).unwrap()["auth_token"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .verify(&Keys, 1000)
    .unwrap();
    assert_eq!(token.claims().account.as_deref(), Some("reduced"));
}
