//! Call chaining at the Access Server: a passed-through `upstream_token` is
//! verified per Upstream Token Verification before policy and bounds the grant.
use aauth_rust_access_server::{
    AccessServer, AuthorizationRequest, Config, Decision, DeferredConfig, DeferredContext,
    UpstreamToken,
};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, AuthToken, Confirmation, PersonClaims,
    ResourceClaims, TokenError, mint_auth_token, mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};

const AS: &str = "https://as.example";
const PS: &str = "https://ps.example";
const OTHER_PS: &str = "https://other-ps.example";
const OTHER_AS: &str = "https://other-as.example";
const RESOURCE: &str = "https://resource.example";
/// The intermediary: a resource that is its own Agent Provider.
const ORDERS: &str = "https://orders.example";

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            (PS, "aauth-person.json", "ps") => 3,
            (OTHER_PS, "aauth-person.json", "ps") => 6,
            (AS, "aauth-access.json", "as") => 4,
            (OTHER_AS, "aauth-access.json", "other-as") => 10,
            (RESOURCE, "aauth-resource.json", "resource") => 5,
            (ORDERS, "aauth-agent.json", "orders") => 9,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}

/// The calling Agent's key: the upstream token is bound to it.
fn caller_key() -> Jwk {
    SigningKey::from_seed([2; 32]).public_jwk()
}
/// The intermediary's own key, which signs downstream requests.
fn intermediary_key() -> Jwk {
    SigningKey::from_seed([8; 32]).public_jwk()
}

fn intermediary_agent(ps: Option<&str>) -> String {
    AgentProvider::new(ORDERS, "orders", SigningKey::from_seed([9; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: ORDERS.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:chain@orders.example".into(),
            jti: "orders-agent".into(),
            iat: 1000,
            exp: 5000,
            cnf: Confirmation {
                jwk: intermediary_key(),
            },
            ps: ps.map(str::to_owned),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap()
}

/// The person token the calling Agent presented to the intermediary.
fn upstream_person() -> PersonClaims {
    PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: ORDERS.into(),
        sub: "person-at-orders".into(),
        jti: "upstream-person".into(),
        iat: 1000,
        exp: 1500,
        cnf: Confirmation { jwk: caller_key() },
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra: Default::default(),
    }
}

/// An auth token the calling Agent presented to the intermediary, from another AS.
fn upstream_auth() -> AuthClaims {
    AuthClaims {
        iss: OTHER_AS.into(),
        dwk: "aauth-access.json".into(),
        aud: ORDERS.into(),
        ps: PS.into(),
        sub: "person-at-orders".into(),
        jti: "upstream-auth".into(),
        iat: 1000,
        exp: 1400,
        cnf: Confirmation { jwk: caller_key() },
        scope: Some("orders.read".into()),
        account: None,
        tenant: None,
        mission_s256: None,
        nbf: None,
        extra: Default::default(),
    }
}

fn person_compact(claims: &PersonClaims, seed: u8) -> String {
    mint_person_token(&SigningKey::from_seed([seed; 32]), "ps", claims).unwrap()
}

/// The downstream exchange: the intermediary's own Person token and challenge.
fn chained_body(upstream: Value) -> Value {
    let presented = PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "person-at-resource".into(),
        jti: "downstream-person".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: intermediary_key(),
        },
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra: Default::default(),
    };
    let resource = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: AS.into(),
        sub: "person-at-resource".into(),
        jti: "challenge".into(),
        iat: 1000,
        exp: 1300,
        ps: PS.into(),
        presented_jti: "downstream-person".into(),
        agent_jkt: intermediary_key().thumbprint().unwrap(),
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: Some("read".into()),
        account: None,
        login_hint: None,
        extra: Default::default(),
    };
    json!({
        "agent_token": intermediary_agent(None),
        "presented_token": person_compact(&presented, 3),
        "resource_token": mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &resource).unwrap(),
        "upstream_token": upstream,
    })
}

fn signed(method: &str, uri: &str, body: Option<&Value>, now: i64) -> Request<Vec<u8>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder
        .body(body.map(|b| b.to_string().into_bytes()).unwrap_or_default())
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

fn token_request(body: &Value) -> Request<Vec<u8>> {
    signed("POST", &format!("{AS}/token"), Some(body), 1000)
}

type Seen = Arc<Mutex<Vec<Option<UpstreamToken>>>>;

fn server(
    seen: &Seen,
) -> AccessServer<
    Keys,
    impl Fn(&AuthorizationRequest) -> Result<Decision, aauth_rust_access_server::PolicyError>,
    impl Fn() -> i64,
    impl Fn() -> String,
> {
    let seen = seen.clone();
    AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |request: &AuthorizationRequest| {
            seen.lock().unwrap().push(request.upstream.clone());
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 3600,
            })
        },
        || 1000,
        || "downstream-auth".into(),
    )
    .unwrap()
}

fn error(response: &http::Response<Vec<u8>>) -> String {
    serde_json::from_slice::<Value>(response.body()).unwrap()["error"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn granted(response: &http::Response<Vec<u8>>) -> AuthClaims {
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    AuthToken::parse(body["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap()
        .claims()
        .clone()
}

#[test]
fn upstream_person_token_is_verified_and_bounds_the_downstream_grant() {
    let seen = Seen::default();
    let server = server(&seen);
    let upstream = person_compact(&upstream_person(), 3);
    let claims = granted(&server.handle(&token_request(&chained_body(json!(upstream)))));
    // Ends no later than the upstream token; directed to the downstream
    // Resource; bound to the intermediary's key, not the caller's.
    assert_eq!(claims.exp, 1500);
    assert_eq!(claims.sub, "person-at-resource");
    assert_eq!(claims.aud, RESOURCE);
    assert_eq!(claims.ps, PS);
    assert_eq!(
        claims.cnf.jwk.thumbprint().unwrap(),
        intermediary_key().thumbprint().unwrap()
    );
    let seen = seen.lock().unwrap();
    let Some(Some(UpstreamToken::Person(token))) = seen.first() else {
        panic!("policy did not see the verified upstream person token");
    };
    assert_eq!(token.compact(), upstream);
    assert_eq!(token.claims().aud, ORDERS);
    assert_eq!(seen[0].as_ref().unwrap().person_server(), PS);
}

#[test]
fn upstream_auth_token_names_the_signing_person_server_whatever_its_issuer() {
    let seen = Seen::default();
    let server = server(&seen);
    let upstream = mint_auth_token(
        &SigningKey::from_seed([10; 32]),
        "other-as",
        &upstream_auth(),
    )
    .unwrap();
    let claims = granted(&server.handle(&token_request(&chained_body(json!(upstream)))));
    assert_eq!(claims.exp, 1400);
    assert_eq!(claims.sub, "person-at-resource");
    let seen = seen.lock().unwrap();
    let Some(Some(UpstreamToken::Auth(token))) = seen.first() else {
        panic!("policy did not see the verified upstream auth token");
    };
    assert_eq!(token.claims().iss, OTHER_AS);
    assert_eq!(token.claims().ps, PS);
}

#[test]
fn unverifiable_upstream_tokens_are_refused_before_policy() {
    let seen = Seen::default();
    let server = server(&seen);
    let person = |edit: fn(&mut PersonClaims), seed: u8| {
        let mut claims = upstream_person();
        edit(&mut claims);
        json!(person_compact(&claims, seed))
    };
    let auth = |edit: fn(&mut AuthClaims)| {
        let mut claims = upstream_auth();
        edit(&mut claims);
        json!(mint_auth_token(&SigningKey::from_seed([10; 32]), "other-as", &claims).unwrap())
    };
    let resource_token = chained_body(json!("x"))["resource_token"].clone();
    let cases: Vec<(&str, Value, &str)> = vec![
        ("malformed", json!("not-a-token"), "invalid_upstream_token"),
        (
            "resource token typ",
            resource_token,
            "invalid_upstream_token",
        ),
        (
            "signature from another key",
            person(|_| {}, 7),
            "invalid_upstream_token",
        ),
        (
            "person token from another PS",
            person(|c| c.iss = OTHER_PS.into(), 6),
            "invalid_upstream_token",
        ),
        (
            "auth token for another PS",
            auth(|c| c.ps = OTHER_PS.into()),
            "invalid_upstream_token",
        ),
        (
            "person token for another audience",
            person(|c| c.aud = "https://elsewhere.example".into(), 3),
            "invalid_upstream_token",
        ),
        (
            "auth token for another audience",
            auth(|c| c.aud = RESOURCE.into()),
            "invalid_upstream_token",
        ),
        (
            "expired person token",
            person(
                |c| {
                    c.iat = 900;
                    c.exp = 1000;
                },
                3,
            ),
            "expired_upstream_token",
        ),
        (
            "expired auth token",
            auth(|c| {
                c.iat = 900;
                c.exp = 1000;
            }),
            "expired_upstream_token",
        ),
        (
            "issued in the future",
            person(
                |c| {
                    c.iat = 1100;
                    c.exp = 1600;
                },
                3,
            ),
            "clock_skew",
        ),
        ("not a string", json!(7), "invalid_request"),
    ];
    for (case, upstream, expected) in cases {
        let response = server.handle(&token_request(&chained_body(upstream)));
        assert_eq!(response.status(), 400, "{case}");
        assert_eq!(error(&response), expected, "{case}");
    }
    let mut with_child = chained_body(json!(person_compact(&upstream_person(), 3)));
    with_child["subagent_token"] = json!(intermediary_agent(None));
    let response = server.handle(&token_request(&with_child));
    assert_eq!(error(&response), "invalid_request");
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn only_a_chained_request_relaxes_the_agent_ps_profile() {
    let seen = Seen::default();
    let server = server(&seen);
    // Without upstream_token the intermediary's Agent token must name the PS.
    let mut unchained = chained_body(json!("x"));
    unchained.as_object_mut().unwrap().remove("upstream_token");
    let response = server.handle(&token_request(&unchained));
    assert_eq!(error(&response), "invalid_agent_token");
    // With it, the intermediary's own `ps` names its Person Server, not the person's.
    let mut chained = chained_body(json!(person_compact(&upstream_person(), 3)));
    chained["agent_token"] = json!(intermediary_agent(Some(OTHER_PS)));
    granted(&server.handle(&token_request(&chained)));
}

#[test]
fn revoked_upstream_token_is_refused() {
    let seen = Seen::default();
    let server = server(&seen).with_revocation();
    let upstream = person_compact(&upstream_person(), 3);
    let revoked = server.handle(&signed(
        "POST",
        &format!("{AS}/revoke"),
        Some(&json!({"jti": "upstream-person", "exp": 1500})),
        1000,
    ));
    assert!(
        revoked.status().is_success(),
        "{}",
        String::from_utf8_lossy(revoked.body())
    );
    let response = server.handle(&token_request(&chained_body(json!(upstream))));
    assert_eq!(response.status(), 400);
    assert_eq!(error(&response), "revoked_upstream_token");
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn pending_chained_request_ends_when_its_upstream_token_expires() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let mut config = DeferredConfig::new(MemoryContinuations::new(4));
    config.lifetime = 3600;
    config.retry_after = 0;
    let server = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        move |_: &AuthorizationRequest| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 3600,
            })
        },
        move || clock.load(Ordering::SeqCst),
        || "downstream-auth".into(),
    )
    .unwrap()
    .with_deferred(config, |context: &DeferredContext| {
        assert!(context.authorization.upstream.is_some());
        Ok(Some(Requirement::Approval))
    })
    .unwrap();
    // The upstream token ends before every other input of the request.
    let mut short = upstream_person();
    short.exp = 1200;
    let upstream = person_compact(&short, 3);
    let first = server.handle(&token_request(&chained_body(json!(upstream))));
    assert_eq!(
        first.status(),
        202,
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let pending = PendingResponse::parse(&format!("{AS}/token"), &first).unwrap();
    now.store(1199, Ordering::SeqCst);
    let waiting = server.handle(&signed("GET", &pending.location, None, 1199));
    assert_eq!(waiting.status(), 202);
    now.store(1200, Ordering::SeqCst);
    let ended = server.handle(&signed("GET", &pending.location, None, 1200));
    assert_eq!(ended.status(), 408);
    assert_eq!(error(&ended), "expired");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
