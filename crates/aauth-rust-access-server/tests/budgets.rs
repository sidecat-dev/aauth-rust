//! Access Server budget parameter: copy the resource's unit, never exceed it,
//! and issue nothing when the person server omits the parameter.
use aauth_rust_access_server::{AccessServer, Config, Decision, PolicyError};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonClaims, ResourceClaims,
    TokenError, mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn budget(amount: i64, decimals: i64) -> Value {
    json!({"amount": amount, "unit": "USD", "decimals": decimals})
}

fn resource_claims(extra: BTreeMap<String, Value>) -> ResourceClaims {
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
        agent_jkt: SigningKey::from_seed([2; 32])
            .public_jwk()
            .thumbprint()
            .unwrap(),
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: Some("read".into()),
        account: None,
        login_hint: None,
        extra,
    }
}

fn request(
    resource_extra: BTreeMap<String, Value>,
    budget_param: Option<Value>,
) -> Request<Vec<u8>> {
    let agent = AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
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
        })
        .unwrap();
    let person = PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "person".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra: Default::default(),
    };
    let mut body = json!({
        "agent_token": agent,
        "presented_token": mint_person_token(&SigningKey::from_seed([3; 32]), "ps", &person).unwrap(),
        "resource_token": mint_resource_token(&SigningKey::from_seed([5; 32]), "resource", &resource_claims(resource_extra)).unwrap(),
    });
    if let Some(budget_param) = budget_param {
        body["budget"] = budget_param;
    }
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
        1000,
    )
    .unwrap();
    request
}

fn server() -> AccessServer<
    Keys,
    impl Fn(&aauth_rust_access_server::AuthorizationRequest) -> Result<Decision, PolicyError>,
    impl Fn() -> i64,
    impl Fn() -> String,
> {
    AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 600,
            })
        },
        || 1000,
        || "auth-budget".into(),
    )
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000,
        vec![UnitDeclaration::with_max("USD", 6, 10_000, "dollars").unwrap()],
    ))
    .unwrap()
}

fn error(response: &http::Response<Vec<u8>>) -> String {
    serde_json::from_slice::<Value>(response.body()).unwrap()["error"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn access_server_narrows_to_its_cap_and_copies_unit_and_decimals() {
    let mut extra = BTreeMap::new();
    extra.insert("budget".into(), budget(5_000, 6));
    let response = server().handle(&request(extra, Some(budget(3_000, 6))));
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
    let got = Budget::new(
        token.claims().extra["budget"]["amount"].as_i64().unwrap(),
        token.claims().extra["budget"]["unit"].as_str().unwrap(),
        token.claims().extra["budget"]["decimals"].as_i64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        (got.amount(), got.unit(), got.decimals()),
        (2_000, "USD", 6)
    );
}

#[test]
fn omitting_the_parameter_issues_no_budget_claim() {
    let mut extra = BTreeMap::new();
    extra.insert("budget".into(), budget(5_000, 6));
    let response = server().handle(&request(extra, None));
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
    assert!(!token.claims().extra.contains_key("budget"));
}

#[test]
fn decimals_mismatch_amount_above_offer_and_a_budget_without_an_offer_are_rejected() {
    let mut offer = BTreeMap::new();
    offer.insert("budget".into(), budget(5_000, 6));
    let mismatch = server().handle(&request(offer.clone(), Some(budget(3_000, 2))));
    assert_eq!(mismatch.status(), 400);
    assert_eq!(error(&mismatch), "invalid_budget");
    let above = server().handle(&request(offer.clone(), Some(budget(6_000, 6))));
    assert_eq!(above.status(), 400);
    assert_eq!(error(&above), "invalid_budget");
    let invented = server().handle(&request(BTreeMap::new(), Some(budget(3_000, 6))));
    assert_eq!(invented.status(), 400);
    assert_eq!(error(&invented), "invalid_budget");
    let malformed = server().handle(&request(offer, Some(json!({"amount": 1}))));
    assert_eq!(malformed.status(), 400);
    assert_eq!(error(&malformed), "invalid_budget");
}

#[test]
fn a_calendar_boundary_ends_the_access_server_grant() {
    let bounded = AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 600,
            })
        },
        || 1000,
        || "auth-period".into(),
    )
    .unwrap()
    .with_budgets(
        IssuerPolicy::capped(
            2_000,
            vec![UnitDeclaration::with_max("USD", 6, 10_000, "dollars").unwrap()],
        )
        .until(1_100),
    )
    .unwrap();
    let mut extra = BTreeMap::new();
    extra.insert("budget".into(), budget(5_000, 6));
    let response = bounded.handle(&request(extra, Some(budget(3_000, 6))));
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
    assert_eq!(token.claims().exp, 1_100);
    assert_eq!(token.claims().extra["budget"]["amount"], 2_000);
}

static BELOW_CAP: AtomicUsize = AtomicUsize::new(0);

fn below_cap_ids() -> String {
    format!("below-{}", BELOW_CAP.fetch_add(1, Ordering::SeqCst))
}

fn issued_amount(response: &http::Response<Vec<u8>>) -> i64 {
    let value: Value = serde_json::from_slice(response.body()).unwrap();
    let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    token.claims().extra["budget"]["amount"].as_i64().unwrap()
}

fn wide_server() -> AccessServer<
    Keys,
    impl Fn(&aauth_rust_access_server::AuthorizationRequest) -> Result<Decision, PolicyError>,
    impl Fn() -> i64,
    impl Fn() -> String,
> {
    AccessServer::new(
        Config::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 600,
            })
        },
        || 1000,
        below_cap_ids,
    )
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        4_000,
        vec![UnitDeclaration::with_max("USD", 6, 10_000, "dollars").unwrap()],
    ))
    .unwrap()
}

#[test]
fn access_server_does_not_exceed_a_parameter_below_its_cap() {
    let mut extra = BTreeMap::new();
    extra.insert("budget".into(), budget(8_000, 6));
    let below = wide_server().handle(&request(extra.clone(), Some(budget(1_500, 6))));
    assert_eq!(
        below.status(),
        200,
        "{}",
        String::from_utf8_lossy(below.body())
    );
    let value: Value = serde_json::from_slice(below.body()).unwrap();
    let token = AuthToken::parse(value["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(token.claims().extra["budget"]["amount"], 1_500);
    assert_eq!(token.claims().extra["budget"]["unit"], "USD");
    assert_eq!(token.claims().extra["budget"]["decimals"], 6);
    assert_ne!(issued_amount(&below), 4_000);

    let at_cap = wide_server().handle(&request(extra.clone(), Some(budget(6_000, 6))));
    assert_eq!(
        at_cap.status(),
        200,
        "{}",
        String::from_utf8_lossy(at_cap.body())
    );
    assert_eq!(issued_amount(&at_cap), 4_000);

    let above_offer = wide_server().handle(&request(extra, Some(budget(9_000, 6))));
    assert_eq!(above_offer.status(), 400);
    assert_eq!(error(&above_offer), "invalid_budget");
}
