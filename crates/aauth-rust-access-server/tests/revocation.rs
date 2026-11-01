//! Access Server revocation, cascade, and pre-policy refusal.
use aauth_rust_access_server::{AccessServer, Config, Decision, DeferredConfig, DeferredContext};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, CallOutcome, Confirmation, PersonClaims,
    ResourceClaims, RevocationDirectory, RevocationSender, RevocationTarget, TokenError,
    mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
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
struct Recording(Mutex<Vec<(String, String, i64)>>);
impl RevocationDirectory for Recording {
    fn revoke(&self, sender: &RevocationSender<'_>, target: &RevocationTarget<'_>) -> CallOutcome {
        assert_eq!((sender.issuer, sender.dwk), (AS, "aauth-access.json"));
        assert_eq!(target.dwk, "aauth-resource.json");
        self.0.lock().expect("directory").push((
            target.recipient.to_owned(),
            target.jti.to_owned(),
            target.exp,
        ));
        CallOutcome::Recorded
    }
}
struct Deferring(AtomicBool);
impl RevocationDirectory for Deferring {
    fn revoke(&self, _: &RevocationSender<'_>, _: &RevocationTarget<'_>) -> CallOutcome {
        if self.0.load(Ordering::SeqCst) {
            CallOutcome::Deferred
        } else {
            CallOutcome::Recorded
        }
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
fn person_claims(exp: i64) -> PersonClaims {
    PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "person".into(),
        iat: 1000,
        exp,
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
fn token_body(person_exp: i64) -> Value {
    let agent = AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&agent_claims())
        .unwrap();
    json!({
        "agent_token": agent,
        "presented_token": mint_person_token(&SigningKey::from_seed([3; 32]), "ps", &person_claims(person_exp)).unwrap(),
        "resource_token": mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &resource_claims()).unwrap()
    })
}
fn token_request(body: Value, now: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{AS}/token"))
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
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
fn revoke(seed: u8, id: &str, dwk: &str, kid: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{AS}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::JwksUri {
            id: id.into(),
            dwk: dwk.into(),
            kid: kid.into(),
        },
        1000,
    )
    .unwrap();
    request
}
fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// A step-up of `auth`: the same exchange, presenting that Auth token to a
/// fresh challenge that names it.
fn step_up_body(auth: &str) -> Value {
    let claims = AuthToken::parse(auth).unwrap().unverified_claims().clone();
    let mut challenge = resource_claims();
    challenge.jti = format!("step-up-of-{}", claims.jti);
    challenge.presented_jti = claims.jti;
    let mut body = token_body(1200);
    body["presented_token"] = json!(auth);
    body["resource_token"] = json!(
        mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &challenge).unwrap()
    );
    body
}

#[test]
fn person_token_revocation_reaches_step_ups_reports_downstream_and_refuses_further_grants() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let ids = AtomicUsize::new(0);
    let directory = Arc::new(Recording(Mutex::new(Vec::new())));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |_: &aauth_rust_access_server::AuthorizationRequest| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 3600,
            })
        },
        move || clock.load(Ordering::SeqCst),
        move || format!("auth-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap()
    .with_revocation_directory(directory.clone());
    let published: Value = serde_json::from_slice(&server.metadata()).unwrap();
    assert_eq!(published["revocation_endpoint"], format!("{AS}/revoke"));
    let granted = server.handle(&token_request(token_body(1200), 1000));
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    let first = value(granted.body())["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    // An AS-local step-up: issued against the first Auth token, not the
    // person token.
    let stepped = server.handle(&token_request(step_up_body(&first), 1000));
    assert_eq!(
        stepped.status(),
        200,
        "{}",
        String::from_utf8_lossy(stepped.body())
    );
    let step = value(stepped.body())["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let issued: Vec<(String, String, i64)> = [&first, &step]
        .iter()
        .map(|compact| {
            let claims = AuthToken::parse(compact)
                .unwrap()
                .unverified_claims()
                .clone();
            (RESOURCE.to_owned(), claims.jti, claims.exp)
        })
        .collect();
    let cascade = server.handle(&revoke(
        3,
        PS,
        "aauth-person.json",
        "ps",
        json!({"jti":"person","exp":1200,"iss":"https://evil.example"}),
    ));
    assert_eq!(
        cascade.status(),
        200,
        "{}",
        String::from_utf8_lossy(cascade.body())
    );
    assert_eq!(cascade.headers()["content-type"], "application/json");
    let body = value(cascade.body());
    assert!(body.get("downstream").is_some());
    assert_eq!(body["downstream"][0]["recipient"], RESOURCE);
    assert!(body["downstream"][0].get("error").is_none());
    // Revocation Cascade: every Auth token issued from the person token, the
    // step-up included, is revoked at its Resource.
    assert_eq!(directory.0.lock().unwrap().as_slice(), issued.as_slice());
    for (_, jti, exp) in &issued {
        assert_eq!(server.revocation_exp(AS, jti), Some(*exp));
    }
    // Neither is accepted again as the presented token of a further step-up.
    for presented in [&first, &step] {
        let refused = server.handle(&token_request(step_up_body(presented), 1000));
        assert_eq!(refused.status(), 400);
        assert_eq!(value(refused.body())["error"], "revoked_presented_token");
    }
    assert_eq!(server.revocation_exp(PS, "person"), Some(1200));
    assert!(
        server
            .revocation_exp("https://evil.example", "person")
            .is_none()
    );
    let refused = server.handle(&token_request(token_body(1200), 1000));
    assert_eq!(refused.status(), 400);
    assert_eq!(value(refused.body())["error"], "revoked_presented_token");
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    now.store(1200, Ordering::SeqCst);
    let expired = server.handle(&token_request(token_body(1200), 1200));
    assert_eq!(
        expired.status(),
        400,
        "{}",
        String::from_utf8_lossy(expired.body())
    );
    assert_eq!(value(expired.body())["error"], "revoked_presented_token");
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}

/// The PS's signed poll of an AS pending URL.
fn poll(location: &str) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("GET")
        .uri(location)
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        1000,
    )
    .unwrap();
    request
}

#[test]
fn resource_token_revocation_does_not_defer_ends_waiting_requests_and_refuses_the_challenge() {
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
        || "auth-1".into(),
    )
    .unwrap()
    .with_revocation()
    .with_deferred(
        {
            let mut config = DeferredConfig::new(MemoryContinuations::new(4));
            config.retry_after = 0;
            config
        },
        |_: &DeferredContext| Ok(Some(Requirement::Approval)),
    )
    .unwrap();
    // A request started before the Resource withdraws its challenge.
    let started = server.handle(&token_request(token_body(2000), 1000));
    assert_eq!(started.status(), 202);
    let pending = PendingResponse::parse(&format!("{AS}/token"), &started).unwrap();
    let mut request = revoke(
        5,
        RESOURCE,
        "aauth-resource.json",
        "resource",
        json!({"jti":"challenge","exp":1300}),
    );
    request
        .headers_mut()
        .insert("prefer", "wait=0".parse().unwrap());
    let recorded = server.handle(&request);
    assert_eq!(recorded.status(), 200);
    assert!(recorded.body().is_empty());
    assert!(!recorded.headers().contains_key("content-type"));
    assert!(!recorded.headers().contains_key("location"));
    // Presenting a Revoked Token: the waiting request ends at its next poll
    // with the polling error `revoked`, with detail naming the resource token.
    let ended = server.handle(&poll(&pending.location));
    assert_eq!(ended.status(), 403);
    assert_eq!(value(ended.body())["error"], "revoked");
    assert!(
        value(ended.body())["detail"]
            .as_str()
            .unwrap()
            .contains("resource token")
    );
    assert_eq!(server.handle(&poll(&pending.location)).status(), 410);
    // A new request naming the challenge gets the parameter error.
    let refused = server.handle(&token_request(token_body(2000), 1000));
    assert_eq!(
        refused.status(),
        400,
        "{}",
        String::from_utf8_lossy(refused.body())
    );
    assert_eq!(value(refused.body())["error"], "revoked_resource_token");
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[test]
fn deferred_downstream_revocation_pending_url_is_random_and_gone_after_the_answer() {
    let directory = Arc::new(Deferring(AtomicBool::new(true)));
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 3600,
            })
        },
        || 1000,
        || "auth-1".into(),
    )
    .unwrap()
    .with_revocation_directory(directory.clone());
    let granted = server.handle(&token_request(token_body(1200), 1000));
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    let pending = server.handle(&revoke(
        3,
        PS,
        "aauth-person.json",
        "ps",
        json!({"jti":"person","exp":1200}),
    ));
    assert_eq!(
        pending.status(),
        202,
        "{}",
        String::from_utf8_lossy(pending.body())
    );
    let location = pending.headers()["location"].to_str().unwrap();
    let id = location
        .strip_prefix(&format!("{AS}/revoke/pending/"))
        .unwrap();
    // 128 random bits, not the host's token-ID source.
    assert_eq!(id.len(), 22, "{location}");
    assert_ne!(id, "auth-1");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    let poll = || {
        let mut request = Request::builder()
            .method("GET")
            .uri(location)
            .body(Vec::new())
            .unwrap();
        sign_request(
            &mut request,
            &SigningKey::from_seed([3; 32]),
            KeyMaterial::JwksUri {
                id: PS.into(),
                dwk: "aauth-person.json".into(),
                kid: "ps".into(),
            },
            1000,
        )
        .unwrap();
        server.handle(&request)
    };
    directory.0.store(false, Ordering::SeqCst);
    assert_eq!(poll().status(), 200);
    let gone = poll();
    assert_eq!(gone.status(), 410);
    assert_eq!(value(gone.body())["error"], "gone");
}
