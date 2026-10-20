use aauth_rust_access_server::{AccessServer, Config, Decision, PolicyError};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonClaims, ResourceClaims,
    TokenError, mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};
const AS: &str = "https://as.example";
const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
#[derive(Clone)]
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            (PS, "aauth-person.json", "ps") => 3,
            (AS, "aauth-access.json", "as") => 4,
            (RESOURCE, "aauth-resource.json", "resource") => 5,
            ("https://ap.example", "aauth-agent.json", "ap") => 1,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}
fn agent_claims() -> AgentClaims {
    AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Caller@ap.example".into(),
        jti: "agent".into(),
        iat: 1000,
        exp: 5000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    }
}
fn person_claims() -> PersonClaims {
    PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "person".into(),
        iat: 1000,
        exp: 2000,
        cnf: agent_claims().cnf,
        nbf: None,
        tenant: Some("team".into()),
        mission_s256: None,
        extra: Default::default(),
    }
}
fn resource_claims() -> ResourceClaims {
    ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: AS.into(),
        sub: "directed-person".into(),
        jti: "challenge".into(),
        iat: 1000,
        exp: 1300,
        ps: PS.into(),
        presented_jti: "person".into(),
        agent_jkt: agent_claims().cnf.jwk.thumbprint().unwrap(),
        nbf: None,
        tenant: Some("team".into()),
        mission_s256: None,
        scope: Some("read write".into()),
        account: Some("".into()),
        login_hint: None,
        extra: Default::default(),
    }
}
fn body(a: AgentClaims, p: PersonClaims, r: ResourceClaims) -> Value {
    let agent = AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&a)
        .unwrap();
    json!({"agent_token":agent,"presented_token":mint_person_token(&SigningKey::from_seed([3;32]),"ps",&p).unwrap(),"resource_token":mint_resource_token(&SigningKey::from_seed([5;32]),"resource",&r).unwrap()})
}
fn request(body: Value) -> Request<Vec<u8>> {
    let mut r = Request::builder()
        .method("POST")
        .uri(format!("{AS}/token"))
        .header("content-type", "Application/JSON")
        .body(body.to_string().into_bytes())
        .unwrap();
    sign_request(
        &mut r,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        1000,
    )
    .unwrap();
    r
}
fn good() -> Value {
    body(agent_claims(), person_claims(), resource_claims())
}
#[test]
fn core_four_party_grant_is_bound_and_challenge_expiry_does_not_cap_it() {
    // Core ps-to-as-token-request, resource-token-verification, auth-token-structure.
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |r: &aauth_rust_access_server::AuthorizationRequest| {
            count.fetch_add(1, Ordering::SeqCst);
            assert_eq!(r.person_server, PS);
            assert_eq!(r.agent.claims().sub, "aauth:Caller@ap.example");
            assert_eq!(r.resource.claims().sub, "directed-person");
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 3600,
            })
        },
        || 1000,
        || "auth-1".into(),
    )
    .unwrap();
    let response = server.handle(&request(good()));
    assert_eq!(
        response.status(),
        200,
        "{:?}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: Value = serde_json::from_slice(response.body()).unwrap();
    let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    let c = token.claims();
    assert_eq!(
        (
            c.iss.as_str(),
            c.dwk.as_str(),
            c.aud.as_str(),
            c.ps.as_str()
        ),
        (AS, "aauth-access.json", RESOURCE, PS)
    );
    assert_eq!(
        c.cnf.jwk.thumbprint().unwrap(),
        agent_claims().cnf.jwk.thumbprint().unwrap()
    );
    assert_eq!(c.scope.as_deref(), Some("read"));
    assert_eq!(c.exp, 2000);
    assert_eq!(c.tenant.as_deref(), Some("team"));
    assert_eq!(c.account, Some("".into()));
}
#[test]
fn verified_lineage_and_proof_precede_policy() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |_: &aauth_rust_access_server::AuthorizationRequest| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 600,
            })
        },
        || 1000,
        || "auth".into(),
    )
    .unwrap();
    for (case, expected) in [
        (0, "invalid_resource_token"),
        (1, "invalid_resource_token"),
        (2, "invalid_resource_token"),
        (3, "invalid_presented_token"),
        (4, "invalid_agent_token"),
        (5, "expired_presented_token"),
        (6, "clock_skew"),
        (7, "invalid_resource_token"),
        (8, "invalid_request"),
    ] {
        let mut a = agent_claims();
        let mut p = person_claims();
        let mut r = resource_claims();
        match case {
            0 => r.aud = PS.into(),
            1 => r.presented_jti = "other".into(),
            2 => r.ps = "https://other.example".into(),
            3 => p.aud = AS.into(),
            4 => a.ps = Some(AS.into()),
            5 => {
                p.iat = 999;
                p.exp = 1000
            }
            6 => r.iat = 1061,
            7 => {
                r.agent_jkt = SigningKey::from_seed([9; 32])
                    .public_jwk()
                    .thumbprint()
                    .unwrap()
            }
            _ => {}
        }
        let mut b = body(a, p, r);
        if case == 8 {
            b["upstream_token"] = json!("not-supported");
        }
        let response = server.handle(&request(b));
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(value["error"], expected, "case{case}");
        assert_eq!(response.status(), 400, "case{case}");
        if case == 6 {
            assert!(response.headers().contains_key("date"));
            assert!(!response.headers().contains_key("signature-error"));
        }
    }
    let mut r = request(good());
    r.body_mut().push(b' ');
    let response = server.handle(&r);
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["signature-error"],
        "error=invalid_signature"
    );
    let mut r = request(good());
    *r.uri_mut() = "https://foreign.example/token".parse().unwrap();
    assert_eq!(server.handle(&r).status(), 401);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}
#[test]
fn policy_denial_operational_failure_widening_and_time_resampling_are_distinct() {
    for mode in 0..5 {
        let now = Arc::new(AtomicI64::new(1000));
        let clock = now.clone();
        let server = AccessServer::new(
            Config::new(AS, "as", SigningKey::from_seed([4; 32])),
            Keys,
            move |_: &aauth_rust_access_server::AuthorizationRequest| match mode {
                0 => Err(PolicyError::Denied),
                1 => Err(PolicyError::Unavailable),
                _ => {
                    if mode == 4 {
                        now.store(1300, Ordering::SeqCst);
                    }
                    Ok(Decision {
                        scopes: vec![if mode == 2 { "admin" } else { "read" }.into()],
                        lifetime: if mode == 3 { 3601 } else { 600 },
                    })
                }
            },
            move || clock.load(Ordering::SeqCst),
            || "id".into(),
        )
        .unwrap();
        let response = server.handle(&request(good()));
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(
            (response.status().as_u16(), value["error"].as_str().unwrap()),
            match mode {
                0 => (403, "access_denied"),
                4 => (400, "expired_resource_token"),
                _ => (500, "server_error"),
            }
        );
    }
}
#[test]
fn metadata_and_signed_listener_origin_are_separate() {
    let mut config = Config::new(AS, "as", SigningKey::from_seed([4; 32]));
    config.signed_origin = "https://as.example:9443".into();
    let server = AccessServer::new(
        config,
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| Err(PolicyError::Denied),
        || 1000,
        || "id".into(),
    )
    .unwrap();
    let req = Request::builder()
        .uri("https://as.example:9443/.well-known/aauth-access.json")
        .body(vec![])
        .unwrap();
    let response = server.handle(&req);
    assert_eq!(response.status(), 200);
    let v: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(v["issuer"], AS);
    assert_eq!(v["auth_token_endpoint"], format!("{AS}/token"));
}
