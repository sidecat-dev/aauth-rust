use super::*;
use aauth_rust_jose::Jws;

pub(super) fn child_claims() -> AgentClaims {
    let mut child = agent_claims();
    child.sub = "aauth:Caller+worker@ap.example".into();
    child.parent_agent = Some("aauth:Caller@ap.example".into());
    child.jti = "child".into();
    child.cnf.jwk = SigningKey::from_seed([7; 32]).public_jwk();
    child.exp = 1600;
    child
}
pub(super) fn agent_compact(claims: &AgentClaims, seed: u8, kid: &str) -> String {
    // Raw AP-signed fixtures let hostile relationships reach the AS verifier.
    Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":kid}),
        &serde_json::to_vec(claims).unwrap(),
        &SigningKey::from_seed([seed; 32]),
    )
    .unwrap()
}
pub(super) fn child_body(parent: AgentClaims, child: AgentClaims) -> Value {
    let mut p = person_claims();
    p.cnf = child.cnf.clone();
    let mut r = resource_claims();
    r.agent_jkt = child.cnf.jwk.thumbprint().unwrap();
    let mut value = body(parent, p, r);
    value["subagent_token"] = json!(agent_compact(&child, 1, "ap"));
    value
}
fn grant(r: &aauth_rust_access_server::AuthorizationRequest) -> Result<Decision, PolicyError> {
    assert_eq!(r.agent.claims().sub, "aauth:Caller@ap.example");
    let child = r
        .subagent
        .as_ref()
        .expect("policy receives the independently verified child");
    assert_eq!(child.claims().sub, "aauth:Caller+worker@ap.example");
    Ok(Decision {
        scopes: vec!["read".into()],
        lifetime: 3600,
    })
}
#[test]
fn subagent_optional_ps_and_auth_step_up_preserve_child_binding() {
    for child_ps in [None, Some(PS.into())] {
        let mut child = child_claims();
        child.ps = child_ps;
        let mut value = child_body(agent_claims(), child.clone());
        let auth = aauth_rust_core::AuthClaims {
            iss: AS.into(),
            dwk: "aauth-access.json".into(),
            aud: RESOURCE.into(),
            ps: PS.into(),
            sub: "directed-person".into(),
            cnf: child.cnf.clone(),
            jti: "person".into(),
            iat: 1000,
            exp: 1500,
            scope: Some("read".into()),
            account: Some("".into()),
            tenant: Some("team".into()),
            mission_s256: None,
            nbf: None,
            extra: Default::default(),
        };
        value["presented_token"] = json!(
            aauth_rust_core::mint_auth_token(&SigningKey::from_seed([4; 32]), "as", &auth).unwrap()
        );
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            || 1000,
            || "step-up".into(),
        )
        .unwrap();
        let response = server.handle(&request(value));
        assert_eq!(
            response.status(),
            200,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
            .unwrap()
            .verify(&Keys, 1000)
            .unwrap();
        assert_eq!(token.claims().exp, 1500);
        assert_eq!(
            token.claims().cnf.jwk.thumbprint().unwrap(),
            child.cnf.jwk.thumbprint().unwrap()
        );
    }
}
#[test]
fn subagent_immediate_grant_uses_child_holder_and_each_credential_lifetime() {
    // Missing child handling or use of the parent key/expiry breaks this exchange.
    for (parent_exp, child_exp, presented_exp, expected_exp) in [
        (5000, 1600, 2000, 1600),
        (1450, 1600, 2000, 1450),
        (5000, 2100, 1500, 1500),
    ] {
        let mut parent = agent_claims();
        parent.exp = parent_exp;
        let mut child = child_claims();
        child.exp = child_exp;
        let mut p = person_claims();
        p.cnf = child.cnf.clone();
        p.exp = presented_exp;
        let mut r = resource_claims();
        r.agent_jkt = child.cnf.jwk.thumbprint().unwrap();
        let mut value = body(parent, p, r);
        value["subagent_token"] = json!(agent_compact(&child, 1, "ap"));
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            grant,
            || 1000,
            || "child-auth".into(),
        )
        .unwrap();
        let response = server.handle(&request(value));
        assert_eq!(
            response.status(),
            200,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
            .unwrap()
            .verify(&Keys, 1000)
            .unwrap();
        assert_eq!(
            token.claims().cnf.jwk.thumbprint().unwrap(),
            child.cnf.jwk.thumbprint().unwrap()
        );
        assert_eq!(token.claims().exp, expected_exp);
        assert_eq!(token.claims().scope.as_deref(), Some("read"));
        assert!(
            token.claims().exp > 1300,
            "challenge expiry does not cap a released grant"
        );
        assert_eq!(value["expires_in"], expected_exp - 1000);
    }
}
#[test]
fn subagent_hostile_relationships_and_holder_swaps_fail_before_policy() {
    let seen = Arc::new(AtomicUsize::new(0));
    let calls = seen.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |r: &aauth_rust_access_server::AuthorizationRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            grant(r)
        },
        || 1000,
        || "unused".into(),
    )
    .unwrap();
    for (case, expected) in [
        (0, "invalid_subagent_token"),
        (1, "invalid_subagent_token"),
        (2, "invalid_subagent_token"),
        (3, "invalid_subagent_token"),
        (4, "invalid_subagent_token"),
        (5, "expired_subagent_token"),
        (6, "invalid_subagent_token"),
        (7, "invalid_subagent_token"),
        (8, "invalid_resource_token"),
        (9, "invalid_presented_token"),
        (10, "invalid_subagent_token"),
        (11, "invalid_subagent_token"),
        (12, "invalid_subagent_token"),
        (13, "invalid_subagent_token"),
        (14, "clock_skew"),
        (15, "invalid_agent_token"),
    ] {
        let mut child = child_claims();
        match case {
            0 => child.parent_agent = Some("aauth:Other@ap.example".into()),
            1 => child.parent_agent = None,
            2 => child.sub = "aauth:Caller+worker+deeper@ap.example".into(),
            3 => child.sub = "aauth:Other+worker@ap.example".into(),
            4 => child.cnf = agent_claims().cnf,
            5 => {
                child.iat = 999;
                child.exp = 1000;
            }
            6 => {
                child.iss = "https://other-ap.example".into();
                child.sub = "aauth:Caller+worker@other-ap.example".into();
            }
            7 => child.ps = Some(OTHER_PS.into()),
            14 => child.iat = 1061,
            _ => {}
        }
        let mut b = child_body(agent_claims(), child);
        match case {
            8 => {
                let mut r = resource_claims();
                r.agent_jkt = agent_claims().cnf.jwk.thumbprint().unwrap();
                b["resource_token"] = json!(
                    mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &r).unwrap()
                );
            }
            9 => b["presented_token"] = good()["presented_token"].clone(),
            10 => b["subagent_token"] = json!("broken"),
            11 => b["subagent_token"] = Value::Null,
            12 => b["subagent_token"] = json!(""),
            13 => b["subagent_token"] = json!(agent_compact(&child_claims(), 9, "ap")),
            15 => b["agent_token"] = b["subagent_token"].clone(),
            _ => {}
        }
        let response = server.handle(&request(b));
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(response.status(), 400, "case {case}: {value}");
        assert_eq!(value["error"], expected, "case {case}");
        assert!(value.get("auth_token").is_none());
    }
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}
#[test]
fn subagent_expiry_after_grant_policy_withholds_the_auth_token() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |r: &aauth_rust_access_server::AuthorizationRequest| {
            now.store(1100, Ordering::SeqCst);
            grant(r)
        },
        move || clock.load(Ordering::SeqCst),
        || "unused".into(),
    )
    .unwrap();
    let mut child = child_claims();
    child.exp = 1100;
    let response = server.handle(&request(child_body(agent_claims(), child)));
    assert_eq!(response.status(), 400);
    let value: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(value["error"], "expired_subagent_token");
    assert!(value.get("auth_token").is_none());
}
#[test]
fn subagent_expiry_during_signing_and_unsigned_child_swaps_withhold() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        grant,
        move || clock.load(Ordering::SeqCst),
        move || {
            now.store(1100, Ordering::SeqCst);
            "late-auth".into()
        },
    )
    .unwrap();
    let mut child = child_claims();
    child.exp = 1100;
    let mut request = request(child_body(agent_claims(), child));
    let original = request.body().clone();
    let mut swapped: Value = serde_json::from_slice(&original).unwrap();
    swapped["subagent_token"] = json!(agent_compact(&child_claims(), 1, "ap"));
    *request.body_mut() = swapped.to_string().into_bytes();
    assert_eq!(server.handle(&request).status(), 401);
    *request.body_mut() = original;
    let result = server.handle(&request);
    assert_eq!(result.status(), 400);
    assert_eq!(
        serde_json::from_slice::<Value>(result.body()).unwrap()["error"],
        "expired_subagent_token"
    );
}
