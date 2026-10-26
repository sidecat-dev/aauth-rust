//! Three-party issuance copies the resource unit and narrows the amount.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{IssuerPolicy, UnitDeclaration, parse_budget};
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, AuthToken, Confirmation, ResourceClaims, TokenError,
    mint_auth_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, DeferredConfig, Federation, FederationError, FederationFailure,
    FederationInput, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError,
    Store,
};
use http::{Method, Request, Response};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const RESOURCE: &str = "https://orders.example";

#[derive(Clone)]
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap") => 1,
            (PS, "aauth-person.json", "ps") => 3,
            (AS, "aauth-access.json", "as") => 4,
            (RESOURCE, "aauth-resource.json", "resource") => 5,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed".into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}

fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Caller@ap.example".into(),
            jti: "agent".into(),
            iat: 1000,
            exp: 5000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}

static IDS: AtomicUsize = AtomicUsize::new(0);
fn clock() -> i64 {
    1000
}
fn ids() -> String {
    format!("id-{}", IDS.fetch_add(1, Ordering::SeqCst))
}
fn fed_ids() -> String {
    "fed-id".to_owned()
}

type Server = PersonServer<Keys, MemoryStore, Host, fn() -> i64, fn() -> String>;

fn dollars() -> Vec<UnitDeclaration> {
    vec![UnitDeclaration::with_max("USD", 6, 10_000_000, "dollars").unwrap()]
}

fn server_with(policy: IssuerPolicy) -> Server {
    PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        clock as fn() -> i64,
        ids as fn() -> String,
    )
    .unwrap()
    .with_budgets(policy)
    .unwrap()
}

fn server() -> Server {
    server_with(IssuerPolicy::capped(2_000_000, dollars()))
}

fn call(server: &Server, path: &str, body: Value) -> http::Response<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent().sign(&mut request, 1000).unwrap();
    server.handle(&request)
}

#[test]
fn person_server_narrows_amount_without_changing_unit_or_decimals() {
    let declared = UnitDeclaration::with_max(
        "USD",
        6,
        10_000_000,
        "pay <b>now</b> [x](javascript:alert(1))",
    )
    .unwrap();
    let server = server_with(IssuerPolicy::capped(2_000_000, vec![declared.clone()]));
    let person = call(
        &server,
        "/person",
        json!({"resource": RESOURCE, "capabilities": ["budget", "not-a-real-capability"]}),
    );
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let parsed = aauth_rust_jose::Jws::parse(&person_token).unwrap();
    let claims: Value = serde_json::from_slice(parsed.payload()).unwrap();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": 5_000_000, "unit": "USD", "decimals": 6}),
    );
    let resource = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: PS.into(),
        ps: PS.into(),
        sub: "directed".into(),
        jti: "challenge".into(),
        presented_jti: claims["jti"].as_str().unwrap().into(),
        agent_jkt: agent().public_jwk().thumbprint().unwrap(),
        iat: 1000,
        exp: 1300,
        scope: Some("read".into()),
        account: None,
        login_hint: None,
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra,
    };
    let resource_token =
        mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &resource).unwrap();
    let response = call(
        &server,
        "/token",
        json!({
            "resource_token": resource_token,
            "presented_token": person_token,
            "capabilities": ["budget", "not-a-real-capability"]
        }),
    );
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let auth = serde_json::from_slice::<Value>(response.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    let got = &token.claims().extra["budget"];
    assert_eq!(got["amount"], 2_000_000);
    assert_eq!(got["unit"], "USD");
    assert_eq!(got["decimals"], 6);
    assert_eq!(server.budget_accounted(), Some(2_000_000));
    let offer = parse_budget(resource.extra.get("budget").unwrap()).unwrap();
    assert_eq!(
        (offer.amount(), offer.unit(), offer.decimals()),
        (5_000_000, "USD", 6)
    );
    let figure = server
        .budget_consent(&offer, declared.description())
        .unwrap();
    assert_eq!(figure.amount, "$5.00");
    assert_ne!(figure.amount, figure.description);
    assert!(!figure.description.contains('<'));
    assert!(
        !figure
            .description
            .to_ascii_lowercase()
            .contains("javascript:")
    );
    assert!(!figure.description.contains("$5.00"));
    assert!(!figure.description.contains("5000000"));
}

fn person_token(server: &Server) -> String {
    let person = call(
        server,
        "/person",
        json!({"resource": RESOURCE, "capabilities": ["budget"]}),
    );
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn issue(
    server: &Server,
    person_token: &str,
    challenge: &str,
) -> aauth_rust_core::VerifiedAuthToken {
    issue_offer(server, person_token, challenge, 5_000_000)
}

fn issue_offer(
    server: &Server,
    person_token: &str,
    challenge: &str,
    amount: i64,
) -> aauth_rust_core::VerifiedAuthToken {
    let parsed = aauth_rust_jose::Jws::parse(person_token).unwrap();
    let claims: Value = serde_json::from_slice(parsed.payload()).unwrap();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": amount, "unit": "USD", "decimals": 6}),
    );
    let resource = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: PS.into(),
        ps: PS.into(),
        sub: "directed".into(),
        jti: challenge.into(),
        presented_jti: claims["jti"].as_str().unwrap().into(),
        agent_jkt: agent().public_jwk().thumbprint().unwrap(),
        iat: 1000,
        exp: 1300,
        scope: Some("read".into()),
        account: None,
        login_hint: None,
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra,
    };
    let resource_token =
        mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &resource).unwrap();
    let response = call(
        server,
        "/token",
        json!({
            "resource_token": resource_token,
            "presented_token": person_token,
            "capabilities": ["budget"]
        }),
    );
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let auth = serde_json::from_slice::<Value>(response.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap()
}

fn issued_amount(server: &Server, person_token: &str, challenge: &str) -> i64 {
    issue(server, person_token, challenge).claims().extra["budget"]["amount"]
        .as_i64()
        .unwrap()
}

#[test]
fn a_second_grant_for_the_same_person_stays_inside_the_ceiling() {
    let server = server();
    let first = issued_amount(&server, &person_token(&server), "challenge-a");
    let second = issued_amount(&server, &person_token(&server), "challenge-b");
    assert_eq!(first, 2_000_000);
    assert_eq!(second, 0);
    assert_eq!(server.budget_accounted(), Some(2_000_000));
}

#[test]
fn clearing_outstanding_budgets_opens_the_cap_for_the_next_exchange() {
    let server = server();
    assert_eq!(
        issued_amount(&server, &person_token(&server), "challenge-a"),
        2_000_000
    );
    server.clear_outstanding_budgets();
    assert_eq!(
        issued_amount(&server, &person_token(&server), "challenge-b"),
        2_000_000
    );
    assert_eq!(
        issued_amount(&server, &person_token(&server), "challenge-c"),
        0
    );
}

#[test]
fn an_offer_above_the_host_limit_is_still_narrowed_in_three_party_access() {
    let server = server_with(IssuerPolicy::capped(2_000_000, dollars()).omit_above(5_000_000));
    let fitted = issue_offer(&server, &person_token(&server), "challenge-fit", 5_000_000);
    assert_eq!(fitted.claims().extra["budget"]["amount"], 2_000_000);
    let wide_server = server_with(IssuerPolicy::capped(2_000_000, dollars()).omit_above(5_000_000));
    let wide = issue_offer(
        &wide_server,
        &person_token(&wide_server),
        "challenge-wide",
        9_000_000,
    );
    assert_eq!(wide.claims().extra["budget"]["amount"], 2_000_000);
    assert_eq!(wide_server.budget_accounted(), Some(2_000_000));
}

struct CapturedParameter(Arc<Mutex<Vec<Option<i64>>>>);
impl Federation for CapturedParameter {
    fn endpoint(&self, access_server: &str) -> Result<String, FederationError> {
        if access_server == AS {
            Ok(format!("{AS}/token"))
        } else {
            Err(FederationError)
        }
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        let body: Value = serde_json::from_slice(request.body()).expect("ps request is json");
        let amount = body
            .get("budget")
            .and_then(|budget| budget.get("amount"))
            .and_then(|amount| amount.as_i64());
        self.0.lock().unwrap().push(amount);
        Err(FederationError)
    }
}

#[test]
fn omit_above_drops_only_the_four_party_parameter() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        clock as fn() -> i64,
        ids as fn() -> String,
    )
    .unwrap()
    .with_federation(CapturedParameter(Arc::clone(&seen)))
    .with_budgets(IssuerPolicy::capped(2_000_000, dollars()).omit_above(5_000_000))
    .unwrap();
    let person = person_token(&server);
    for (challenge, amount) in [("omit-wide", 9_000_000), ("omit-fit", 5_000_000)] {
        let claims: Value =
            serde_json::from_slice(aauth_rust_jose::Jws::parse(&person).unwrap().payload())
                .unwrap();
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            "budget".into(),
            json!({"amount": amount, "unit": "USD", "decimals": 6}),
        );
        let resource_token = mint_resource_token(
            &SigningKey::from_seed([5; 32]),
            "resource",
            &ResourceClaims {
                iss: RESOURCE.into(),
                dwk: "aauth-resource.json".into(),
                aud: AS.into(),
                ps: PS.into(),
                sub: "directed".into(),
                jti: challenge.into(),
                presented_jti: claims["jti"].as_str().unwrap().into(),
                agent_jkt: agent().public_jwk().thumbprint().unwrap(),
                iat: 1000,
                exp: 1300,
                scope: Some("read".into()),
                account: None,
                login_hint: None,
                nbf: None,
                tenant: None,
                mission_s256: None,
                extra,
            },
        )
        .unwrap();
        let _ = call(
            &server,
            "/token",
            json!({
                "resource_token": resource_token,
                "presented_token": person
            }),
        );
    }
    assert_eq!(*seen.lock().unwrap(), vec![None, Some(2_000_000)]);
}

#[test]
fn a_calendar_boundary_ends_the_grant() {
    let open_server = server();
    let open = issue(&open_server, &person_token(&open_server), "open");
    assert!(open.claims().exp > 1_100, "{}", open.claims().exp);
    let bounded = server_with(IssuerPolicy::capped(2_000_000, dollars()).until(1_100));
    let token = issue(&bounded, &person_token(&bounded), "bounded");
    assert_eq!(token.claims().exp, 1_100);
    assert_eq!(token.claims().extra["budget"]["amount"], 2_000_000);
}

struct RaisedGrant;
impl Federation for RaisedGrant {
    fn endpoint(&self, access_server: &str) -> Result<String, FederationError> {
        if access_server == AS {
            Ok(format!("{AS}/token"))
        } else {
            Err(FederationError)
        }
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        let body: Value = serde_json::from_slice(request.body()).expect("ps request is json");
        assert_eq!(body["budget"]["amount"], 2_000_000);
        assert_eq!(body["budget"]["decimals"], 6);
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            "budget".into(),
            json!({"amount": 5_000_000, "unit": "USD", "decimals": 6}),
        );
        let compact = mint_auth_token(
            &SigningKey::from_seed([4; 32]),
            "as",
            &AuthClaims {
                iss: AS.into(),
                dwk: "aauth-access.json".into(),
                aud: RESOURCE.into(),
                sub: "directed".into(),
                jti: "forged".into(),
                iat: 1000,
                exp: 1200,
                ps: PS.into(),
                cnf: Confirmation {
                    jwk: SigningKey::from_seed([2; 32]).public_jwk(),
                },
                scope: Some("read".into()),
                account: None,
                nbf: None,
                tenant: None,
                mission_s256: None,
                extra,
            },
        )
        .expect("forged auth token");
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"auth_token": compact})).unwrap())
            .unwrap())
    }
}

#[test]
fn a_delivered_budget_above_the_parameter_is_a_delivery_failure() {
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        clock as fn() -> i64,
        fed_ids as fn() -> String,
    )
    .unwrap()
    .with_federation(RaisedGrant)
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 6, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = call(
        &server,
        "/person",
        json!({"resource": RESOURCE, "capabilities": ["budget"]}),
    );
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims: Value = serde_json::from_slice(
        aauth_rust_jose::Jws::parse(&person_token)
            .unwrap()
            .payload(),
    )
    .unwrap();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": 5_000_000, "unit": "USD", "decimals": 6}),
    );
    let resource_token = mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: AS.into(),
            ps: PS.into(),
            sub: "directed".into(),
            jti: "challenge".into(),
            presented_jti: claims["jti"].as_str().unwrap().into(),
            agent_jkt: SigningKey::from_seed([2; 32])
                .public_jwk()
                .thumbprint()
                .unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra,
        },
    )
    .unwrap();
    let response = call(
        &server,
        "/token",
        json!({
            "resource_token": resource_token,
            "presented_token": person_token
        }),
    );
    assert_eq!(
        response.status(),
        502,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "as_unreachable");
    assert!(
        matches!(
            response
                .extensions()
                .get::<FederationFailure>()
                .map(|failure| &failure.reason),
            Some(aauth_rust_person_server::FederationFailureReason::InvalidGrant)
        ),
        "{:?}",
        response.extensions().get::<FederationFailure>()
    );
    assert_eq!(server.budget_accounted(), Some(0));
}

fn post_json<S, P, C, I>(
    server: &PersonServer<Keys, S, P, C, I>,
    path: &str,
    body: Value,
    now: i64,
) -> Response<Vec<u8>>
where
    S: Store,
    P: Policy,
    C: Fn() -> i64,
    I: Fn() -> String,
{
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent().sign(&mut request, now).unwrap();
    server.handle(&request)
}

fn issued_person<S, P, C, I>(server: &PersonServer<Keys, S, P, C, I>, now: i64) -> String
where
    S: Store,
    P: Policy,
    C: Fn() -> i64,
    I: Fn() -> String,
{
    let person = post_json(
        server,
        "/person",
        json!({"resource": RESOURCE, "capabilities": ["budget"]}),
        now,
    );
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn resource_offer(person_token: &str, challenge: &str, amount: i64) -> String {
    let claims: Value =
        serde_json::from_slice(aauth_rust_jose::Jws::parse(person_token).unwrap().payload())
            .unwrap();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": amount, "unit": "USD", "decimals": 6}),
    );
    mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: AS.into(),
            ps: PS.into(),
            sub: "directed".into(),
            jti: challenge.into(),
            presented_jti: claims["jti"].as_str().unwrap().into(),
            agent_jkt: agent().public_jwk().thumbprint().unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra,
        },
    )
    .unwrap()
}

fn auth_body(amount: i64, iat: i64, exp: i64) -> Response<Vec<u8>> {
    static JTI: AtomicUsize = AtomicUsize::new(0);
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": amount, "unit": "USD", "decimals": 6}),
    );
    let compact = mint_auth_token(
        &SigningKey::from_seed([4; 32]),
        "as",
        &AuthClaims {
            iss: AS.into(),
            dwk: "aauth-access.json".into(),
            aud: RESOURCE.into(),
            sub: "directed".into(),
            jti: format!("as-{}", JTI.fetch_add(1, Ordering::SeqCst)),
            iat,
            exp,
            ps: PS.into(),
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            scope: Some("read".into()),
            account: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra,
        },
    )
    .unwrap();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"auth_token": compact})).unwrap())
        .unwrap()
}

fn accepted() -> Response<Vec<u8>> {
    Response::builder()
        .status(202)
        .header("location", format!("{AS}/token/pending/as-wait"))
        .header("retry-after", "0")
        .header("cache-control", "no-store")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"status": "pending"})).unwrap())
        .unwrap()
}

#[derive(Clone, Copy)]
enum Script {
    Shrink,
    Grow,
}

struct Scripted {
    script: Script,
    posts: AtomicUsize,
    sent: Mutex<Vec<i64>>,
}

impl Federation for Scripted {
    fn endpoint(&self, access_server: &str) -> Result<String, FederationError> {
        if access_server == AS {
            Ok(format!("{AS}/token"))
        } else {
            Err(FederationError)
        }
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        if *request.method() == Method::GET {
            return Ok(match self.script {
                Script::Shrink => auth_body(2_000_000, 1000, 1200),
                Script::Grow => auth_body(4_000_000, 1101, 1200),
            });
        }
        let body: Value = serde_json::from_slice(request.body()).expect("ps request is json");
        let sent = body["budget"]["amount"].as_i64().expect("sent amount");
        self.sent.lock().unwrap().push(sent);
        let turn = self.posts.fetch_add(1, Ordering::SeqCst);
        Ok(match (self.script, turn) {
            (Script::Shrink, 0) => {
                assert_eq!(sent, 2_000_000);
                accepted()
            }
            (Script::Shrink, 1) => {
                assert_eq!(sent, 2_000_000);
                auth_body(sent, 1000, 1200)
            }
            (Script::Grow, 0) => {
                assert_eq!(sent, 3_000_000);
                auth_body(sent, 1000, 1100)
            }
            (Script::Grow, 1) => {
                assert_eq!(sent, 2_000_000);
                accepted()
            }
            _ => panic!("unexpected federation post {turn}"),
        })
    }
}

fn deferred_config(lifetime: i64) -> DeferredConfig {
    let mut config = DeferredConfig::new(MemoryContinuations::new(16));
    config.lifetime = lifetime;
    config.retry_after = 0;
    config
}

static DEFERRED_IDS: AtomicUsize = AtomicUsize::new(0);
fn deferred_ids() -> String {
    format!("d{}", DEFERRED_IDS.fetch_add(1, Ordering::SeqCst))
}

#[test]
fn a_decimals_mismatch_on_the_resource_token_is_rejected() {
    let server = server();
    let person = person_token(&server);
    let claims: Value =
        serde_json::from_slice(aauth_rust_jose::Jws::parse(&person).unwrap().payload()).unwrap();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "budget".into(),
        json!({"amount": 5_000_000, "unit": "USD", "decimals": 2}),
    );
    let resource = mint_resource_token(
        &SigningKey::from_seed([5; 32]),
        "resource",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            ps: PS.into(),
            sub: "directed".into(),
            jti: "decimals-off".into(),
            presented_jti: claims["jti"].as_str().unwrap().into(),
            agent_jkt: agent().public_jwk().thumbprint().unwrap(),
            iat: 1000,
            exp: 1300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra,
        },
    )
    .unwrap();
    let response = call(
        &server,
        "/token",
        json!({"resource_token": resource, "presented_token": person}),
    );
    assert_eq!(
        response.status(),
        400,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "invalid_budget");
    assert_eq!(server.budget_accounted(), Some(0));
    assert_eq!(
        issued_amount(&server, &person_token(&server), "decimals-ok"),
        2_000_000
    );
}

#[test]
fn a_deferred_delivery_is_checked_against_the_budget_that_was_sent() {
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        clock as fn() -> i64,
        deferred_ids,
    )
    .unwrap()
    .with_federation(Scripted {
        script: Script::Shrink,
        posts: AtomicUsize::new(0),
        sent: Mutex::new(Vec::new()),
    })
    .with_budgets(IssuerPolicy::capped(3_000_000, dollars()))
    .unwrap()
    .with_deferred(deferred_config(60))
    .unwrap();
    let first_person = issued_person(&server, 1000);
    let first = post_json(
        &server,
        "/token",
        json!({
            "resource_token": resource_offer(&first_person, "shrink-a", 2_000_000),
            "presented_token": first_person,
            "capabilities": ["budget"]
        }),
        1000,
    );
    assert_eq!(
        first.status(),
        202,
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let pending = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    let second_person = issued_person(&server, 1000);
    let second = post_json(
        &server,
        "/token",
        json!({
            "resource_token": resource_offer(&second_person, "shrink-b", 2_000_000),
            "presented_token": second_person,
            "capabilities": ["budget"]
        }),
        1000,
    );
    assert_eq!(
        second.status(),
        200,
        "{}",
        String::from_utf8_lossy(second.body())
    );
    let second_body: Value = serde_json::from_slice(second.body()).unwrap();
    let second_token = AuthToken::parse(second_body["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(second_token.claims().extra["budget"]["amount"], 2_000_000);
    assert_eq!(server.budget_accounted(), Some(2_000_000));
    let advanced = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(
        advanced.status(),
        200,
        "{}",
        String::from_utf8_lossy(advanced.body())
    );
    let advanced_body: Value = serde_json::from_slice(advanced.body()).unwrap();
    let completed = AuthToken::parse(advanced_body["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(completed.claims().extra["budget"]["amount"], 2_000_000);
    assert_eq!(server.budget_accounted(), Some(4_000_000));
}

struct FlexLifetime(AtomicI64);
impl Policy for FlexLifetime {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed".into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        let lifetime = self.0.swap(600, Ordering::SeqCst);
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime,
        })
    }
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}

#[test]
fn a_deferred_delivery_above_the_sent_budget_is_refused_after_the_room_grows() {
    let now = Arc::new(AtomicI64::new(1000));
    let clock_now = Arc::clone(&now);
    let ids = Arc::new(AtomicUsize::new(0));
    let clock_ids = Arc::clone(&ids);
    let server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        FlexLifetime(AtomicI64::new(100)),
        move || clock_now.load(Ordering::SeqCst),
        move || format!("g{}", clock_ids.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap()
    .with_federation(Scripted {
        script: Script::Grow,
        posts: AtomicUsize::new(0),
        sent: Mutex::new(Vec::new()),
    })
    .with_budgets(IssuerPolicy::capped(5_000_000, dollars()))
    .unwrap()
    .with_deferred(deferred_config(3600))
    .unwrap();
    let filler_person = issued_person(&server, 1000);
    let filler = post_json(
        &server,
        "/token",
        json!({
            "resource_token": resource_offer(&filler_person, "grow-fill", 3_000_000),
            "presented_token": filler_person,
            "capabilities": ["budget"]
        }),
        1000,
    );
    assert_eq!(
        filler.status(),
        200,
        "{}",
        String::from_utf8_lossy(filler.body())
    );
    assert_eq!(server.budget_accounted(), Some(3_000_000));
    let deferred_person = issued_person(&server, 1000);
    let deferred = post_json(
        &server,
        "/token",
        json!({
            "resource_token": resource_offer(&deferred_person, "grow-wait", 4_000_000),
            "presented_token": deferred_person,
            "capabilities": ["budget"]
        }),
        1000,
    );
    assert_eq!(
        deferred.status(),
        202,
        "{}",
        String::from_utf8_lossy(deferred.body())
    );
    let pending = PendingResponse::parse(&format!("{PS}/token"), &deferred).unwrap();
    now.store(1101, Ordering::SeqCst);
    let advanced = server
        .advance_federation(&pending.location, FederationInput::Poll)
        .unwrap();
    assert_eq!(
        advanced.status(),
        502,
        "{}",
        String::from_utf8_lossy(advanced.body())
    );
    let body: Value = serde_json::from_slice(advanced.body()).unwrap();
    assert_eq!(body["error"], "as_unreachable");
    assert_eq!(server.budget_accounted(), Some(3_000_000));
}
