//! Three-party issuance copies the resource unit and narrows the amount.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, AuthToken, Confirmation, ResourceClaims, TokenError,
    mint_auth_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Federation, FederationError, FederationFailure, Grant,
    MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn server() -> Server {
    PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        clock as fn() -> i64,
        ids as fn() -> String,
    )
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 6, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap()
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
    let server = server();
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
    let figure = server
        .budget_consent(&Budget::new(2_000_000, "USD", 6).unwrap(), "pay <b>now</b>")
        .unwrap();
    assert_eq!(figure.amount, "$2.00");
    assert!(!figure.description.contains('<'));
    assert_ne!(figure.amount, figure.description);
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

fn issued_amount(server: &Server, person_token: &str, challenge: &str) -> i64 {
    let parsed = aauth_rust_jose::Jws::parse(person_token).unwrap();
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
    let token = AuthToken::parse(&auth)
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    token.claims().extra["budget"]["amount"].as_i64().unwrap()
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
