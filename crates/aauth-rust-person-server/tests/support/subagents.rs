use super::*;
use aauth_rust_jose::Jws;

fn child_claims() -> AgentClaims {
    AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Caller+worker@ap.example".into(),
        jti: "worker-token".into(),
        iat: 1000,
        exp: 1250,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([11; 32]).public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: Some("aauth:Caller@ap.example".into()),
        nbf: None,
        extra: Default::default(),
    }
}
pub(super) fn child_token(change: impl FnOnce(&mut AgentClaims)) -> String {
    let mut claims = child_claims();
    change(&mut claims);
    let (kid, seed) = if claims.iss == ORDERS {
        ("orders-key", 4)
    } else {
        ("ap-key", 1)
    };
    Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":kid}),
        &serde_json::to_vec(&claims).unwrap(),
        &SigningKey::from_seed([seed; 32]),
    )
    .unwrap()
}
pub(super) fn child() -> Agent {
    Agent::new(SigningKey::from_seed([11; 32]), child_token(|_| {})).unwrap()
}
pub(super) fn person(
    f: &Fixture,
    server: &Server,
    parent: &Agent,
    child: &str,
) -> Response<Vec<u8>> {
    f.call(
        server,
        parent,
        "/person",
        json!({"resource":ORDERS,"subagent_token":child}),
    )
}
pub(super) fn exchange(
    f: &Fixture,
    server: &Server,
    parent: &Agent,
    child: &str,
    challenge: &str,
    presented: &str,
) -> Response<Vec<u8>> {
    f.call(
        server,
        parent,
        "/token",
        json!({"resource_token":challenge,"presented_token":presented,"subagent_token":child}),
    )
}

#[test]
fn parent_mediated_person_establishes_only_parent_binding_and_retains_child_holder() {
    let f = Fixture::new();
    let parent = agent(false);
    let worker = child();
    let response = person(&f, &f.server(2000), &parent, worker.token());
    let compact = compact(&response, "person_token");
    let token = PersonToken::parse(&compact)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().exp, 1250);
    assert_eq!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        worker.public_jwk().thumbprint().unwrap()
    );
    assert_ne!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        parent.public_jwk().thumbprint().unwrap()
    );
    assert!(!token.claims().extra.contains_key("parent_agent"));
    let record = f
        .store
        .token(&TokenReference {
            issuer: PS.into(),
            jti: token.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(record.agent.subject, "aauth:Caller+worker@ap.example");
    assert_eq!(record.principal.subject, "aauth:Caller@ap.example");
    assert_eq!(
        serde_json::to_value(&record).unwrap()["parent_agent"]["subject"],
        "aauth:Caller@ap.example"
    );
    assert!(f.store.binding(PS, &record.principal).unwrap().is_some());
    assert!(f.store.binding(PS, &record.agent).unwrap().is_none());
}

#[test]
fn parent_mediated_direct_auth_and_step_up_bind_child_and_recheck_parent_revocation() {
    let f = Fixture::new();
    let parent = agent(false);
    let worker = child();
    let p = compact(
        &person(&f, &f.server(2000), &parent, worker.token()),
        "person_token",
    );
    let challenge = resource(&worker, &p, "read", |_| {});
    let issued = exchange(&f, &f.server(2000), &parent, worker.token(), &challenge, &p);
    let auth = compact(&issued, "auth_token");
    let token = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().exp, 1250);
    assert_eq!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        worker.public_jwk().thumbprint().unwrap()
    );
    let step_up = resource(&worker, &auth, "read write", |_| {});
    compact(
        &exchange(
            &f,
            &f.server(2000),
            &parent,
            worker.token(),
            &step_up,
            &auth,
        ),
        "auth_token",
    );
    let principal = AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:Caller@ap.example".into(),
    };
    f.store.revoke_binding(PS, &principal).unwrap();
    let denied = exchange(&f, &f.server(2000), &parent, worker.token(), &challenge, &p);
    assert_eq!(denied.status(), 400);
    assert_eq!(output(&denied)["error"], "revoked_presented_token");
    assert!(output(&denied).get("auth_token").is_none());
    assert_eq!(
        person(&f, &f.server(2000), &parent, worker.token()).status(),
        403
    );
}

#[test]
fn malformed_or_unrelated_child_is_rejected_before_person_policy() {
    for (change, expected) in [
        (
            (|c: &mut AgentClaims| c.parent_agent = Some("aauth:Other@ap.example".into()))
                as fn(&mut AgentClaims),
            "invalid_subagent_token",
        ),
        (
            |c| {
                c.iss = ORDERS.into();
                c.sub = "aauth:Orders+worker@orders.example".into();
            },
            "invalid_subagent_token",
        ),
        (|c| c.exp = 1000, "expired_subagent_token"),
        (
            |c| c.ps = Some("https://other-ps.example".into()),
            "invalid_subagent_token",
        ),
        (
            |c| c.parent_agent = Some("aauth:Caller+worker@ap.example".into()),
            "invalid_subagent_token",
        ),
        (
            |c| c.cnf.jwk = SigningKey::from_seed([2; 32]).public_jwk(),
            "invalid_subagent_token",
        ),
    ] {
        let f = Fixture::new();
        let response = person(&f, &f.server(2000), &agent(false), &child_token(change));
        assert_eq!(response.status(), 400);
        assert_eq!(output(&response)["error"], expected);
        assert_eq!(f.host.bind_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn optional_child_ps_is_allowed_and_child_cannot_sign_ps_requests() {
    let f = Fixture::new();
    let server = f.server(2000);
    let parent = agent(false);
    let worker = child();
    compact(
        &person(&f, &server, &parent, &child_token(|c| c.ps = None)),
        "person_token",
    );
    let before = f.host.bind_calls.load(Ordering::SeqCst);
    for body in [
        json!({"resource":ORDERS}),
        json!({"resource":ORDERS,"subagent_token":worker.token()}),
    ] {
        let response = f.call(&server, &worker, "/person", body);
        assert_eq!(response.status(), 401);
        assert!(output(&response).get("person_token").is_none());
    }
    assert_eq!(f.host.bind_calls.load(Ordering::SeqCst), before);
}

pub(super) struct DelayedKeys {
    pub now: Arc<AtomicI64>,
    pub committed: Arc<AtomicBool>,
    pub lookups: AtomicUsize,
    pub delay_on: usize,
}
impl AgentKeyResolver for DelayedKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let key = Keys.key(issuer, dwk, kid)?;
        if issuer == "https://ap.example"
            && self.committed.load(Ordering::SeqCst)
            && self.lookups.fetch_add(1, Ordering::SeqCst) + 1 == self.delay_on
            && self.committed.swap(false, Ordering::SeqCst)
        {
            self.now.store(1005, Ordering::SeqCst);
        }
        Ok(key)
    }
}

#[test]
fn final_child_key_lookup_fences_expiry_and_recomputes_remaining_lifetime() {
    for kind in ["person", "local_auth", "as_auth"] {
        for expires in [1005, 1050] {
            let f = Fixture::new();
            let parent = agent(false);
            let token = child_token(|c| c.exp = expires);
            let presented = (kind != "person").then(|| {
                compact(
                    &person(&f, &f.server(2000), &parent, &token),
                    "person_token",
                )
            });
            f.store.after_commit.store(false, Ordering::SeqCst);
            let mut server = f.server_with_keys(
                2000,
                DelayedKeys {
                    now: f.host.now.clone(),
                    committed: f.store.after_commit.clone(),
                    lookups: AtomicUsize::new(0),
                    // Final parent recheck, verified parent, then child key.
                    delay_on: 3,
                },
            );
            if kind == "as_auth" {
                server = server.with_federation(super::deferred::NativeTransport::new(&f, 2, 0));
            }
            let response = if let Some(presented) = presented {
                let worker = Agent::new(SigningKey::from_seed([11; 32]), token.clone()).unwrap();
                let challenge = resource(&worker, &presented, "read", |r| {
                    if kind == "as_auth" {
                        r.aud = "https://as.example".into();
                    }
                });
                f.call(&server, &parent, "/token", json!({
                    "resource_token": challenge, "presented_token": presented, "subagent_token": token
                }))
            } else {
                f.call(
                    &server,
                    &parent,
                    "/person",
                    json!({"resource": ORDERS, "subagent_token": token}),
                )
            };
            let body = output(&response);
            assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
            if expires == 1005 {
                assert_eq!(response.status(), 400, "kind={kind}: {body}");
                assert_eq!(body["error"], "expired_subagent_token");
                assert!(body.get("person_token").is_none());
                assert!(body.get("auth_token").is_none());
            } else {
                assert_eq!(response.status(), 200, "kind={kind}: {body}");
                assert_eq!(body["expires_in"], 45, "kind={kind}");
                assert!(
                    body.get(if kind == "person" {
                        "person_token"
                    } else {
                        "auth_token"
                    })
                    .is_some()
                );
            }
        }
    }
}
