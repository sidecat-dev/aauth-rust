//! Resource metering and the four-party narrowing chain.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use aauth_rust_access_server::{AccessServer, Config as AsConfig, Decision};
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{ChargeError, IssuerPolicy, Refusal, UnitDeclaration, UsageQuery};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, AuthToken, Confirmation, ResourceToken, TokenError,
    mint_auth_token,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest as PsAuthorization, Config as PsConfig, Federation, FederationError,
    Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError as PsPolicyError,
};
use aauth_rust_resource::{AuthDecision, Deny, PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};

const NOW: i64 = 1000;
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

fn units(decimals: i64) -> Vec<UnitDeclaration> {
    vec![UnitDeclaration::with_max("USD", decimals, 10_000_000, "dollars <b>cash</b>").unwrap()]
}

type Admit = fn(&aauth_rust_core::VerifiedAuthToken, &Request<Vec<u8>>) -> Result<String, Deny>;

fn admit(
    _token: &aauth_rust_core::VerifiedAuthToken,
    _request: &Request<Vec<u8>>,
) -> Result<String, Deny> {
    Ok("admitted".into())
}

fn resource() -> PsAuthorizationResource<Keys, Admit> {
    PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: RESOURCE.into(),
            signed_origin: RESOURCE.into(),
            kid: "resource".into(),
            signing_key: SigningKey::from_seed([5; 32]),
            scopes: vec!["read".into()],
            scope_descriptions: BTreeMap::from([(
                "read".into(),
                "Read the metered records".into(),
            )]),
        },
        Keys,
        admit as Admit,
    )
    .unwrap()
    .with_budgets(units(6), "https://orders.example/usage", 1_000, 5_000_000)
    .unwrap()
}

fn auth(jti: &str, amount: Option<i64>, scope: &str) -> String {
    let mut extra = std::collections::BTreeMap::new();
    if let Some(amount) = amount {
        extra.insert(
            "budget".into(),
            json!({"amount": amount, "unit": "USD", "decimals": 6}),
        );
    }
    mint_auth_token(
        &SigningKey::from_seed([3; 32]),
        "ps",
        &AuthClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "directed".into(),
            jti: jti.into(),
            iat: NOW,
            exp: 4_000,
            ps: PS.into(),
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            scope: Some(scope.into()),
            account: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra,
        },
    )
    .unwrap()
}

fn present(token: &str, max_cost: Option<i64>) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{RESOURCE}/records"))
        .body(Vec::new())
        .unwrap();
    if let Some(max_cost) = max_cost {
        request
            .headers_mut()
            .insert("aauth-max-cost", max_cost.to_string().parse().unwrap());
    }
    sign_request(
        &mut request,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt {
            jwt: token.into(),
            cache: false,
        },
        NOW,
    )
    .unwrap();
    request
}

fn payload(compact: &str) -> Value {
    let parsed = Jws::parse(compact).unwrap_or_else(|error| {
        panic!(
            "{error:?} len={} dots={} head={:?}",
            compact.len(),
            compact.bytes().filter(|byte| *byte == b'.').count(),
            compact.chars().take(80).collect::<String>()
        )
    });
    serde_json::from_slice(parsed.payload()).unwrap()
}

#[test]
fn buffered_requests_meter_the_token_cap_and_keep_its_signed_scale() {
    let resource = resource();
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(metadata["budget_units"][0]["unit"], "USD");
    assert_eq!(metadata["budget_units"][0]["decimals"], 6);
    assert_eq!(metadata["usage_endpoint"], "https://orders.example/usage");
    assert_eq!(metadata["access_mode"], "auth-token");

    let open = resource
        .authorize(
            &present(&auth("plain", None, "read"), None),
            NOW,
            "plain-challenge",
        )
        .into_response();
    assert_eq!(open.status(), 200);
    assert!(!open.headers().contains_key("aauth-budget"));

    let first = resource
        .authorize(
            &present(&auth("meter", Some(2_000), "read"), None),
            NOW,
            "c1",
        )
        .into_response();
    assert_eq!(
        first.status(),
        200,
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let header = first.headers()["aauth-budget"].to_str().unwrap().to_owned();
    assert!(header.contains("cost=1000"), "{header}");
    assert!(header.contains("remaining=1000"), "{header}");
    assert!(header.contains("decimals=6"), "{header}");
    assert!(!first.headers().contains_key("aauth-capabilities"));

    resource.replace_budget_units(units(2)).unwrap();
    let second = resource
        .authorize(
            &present(&auth("meter", Some(2_000), "read"), Some(500)),
            NOW,
            "c2",
        )
        .into_response();
    assert_eq!(
        second.status(),
        200,
        "{}",
        String::from_utf8_lossy(second.body())
    );
    let header = second.headers()["aauth-budget"].to_str().unwrap();
    assert!(header.contains("decimals=6"), "{header}");
    assert!(header.contains("cost=500"), "{header}");
    assert!(header.contains("remaining=500"), "{header}");

    let wrong = resource
        .authorize(
            &present(&auth("wrong", Some(2_000), "other"), None),
            NOW,
            "c-wrong",
        )
        .into_response();
    assert_eq!(wrong.status(), 403);
    assert!(wrong.headers().contains_key("aauth-budget"));
    let wrong_token = AuthToken::parse(&auth("wrong", Some(2_000), "other"))
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    assert!(resource.budget_reserve(&wrong_token, 2_000).is_ok());

    let tight = resource
        .authorize(
            &present(&auth("meter", Some(2_000), "read"), Some(1_500)),
            NOW,
            "c3",
        )
        .into_response();
    assert_eq!(tight.status(), 401);
    let requirement = tight.headers()["aauth-requirement"].to_str().unwrap();
    assert!(
        requirement.contains("reason=insufficient-budget"),
        "{requirement}"
    );
    let refusal = tight.headers()["aauth-budget"].to_str().unwrap();
    assert!(refusal.contains("remaining=500"), "{refusal}");
    assert!(refusal.contains("required=1000"), "{refusal}");
    assert!(!refusal.contains("cost="), "{refusal}");
    let challenge = requirement
        .split("resource-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let challenge_claims = payload(challenge);
    assert!(challenge_claims.get("budget_consumed").is_none());
    assert_eq!(challenge_claims["budget"]["unit"], "USD");
    assert_eq!(challenge_claims["budget"]["decimals"], 2);
    assert_eq!(challenge_claims["budget"]["amount"], 5_000_000);
    assert_ne!(challenge_claims["budget"]["amount"], 1_500);

    let finish = resource
        .authorize(
            &present(&auth("meter", Some(2_000), "read"), Some(500)),
            NOW,
            "c4",
        )
        .into_response();
    assert_eq!(
        finish.status(),
        200,
        "{}",
        String::from_utf8_lossy(finish.body())
    );
    let spent = resource
        .authorize(
            &present(&auth("meter", Some(2_000), "read"), Some(1)),
            NOW,
            "c5",
        )
        .into_response();
    assert_eq!(spent.status(), 401);
    assert!(
        spent.headers()["aauth-requirement"]
            .to_str()
            .unwrap()
            .contains("reason=budget-exhausted")
    );
    let exhausted = spent.headers()["aauth-budget"].to_str().unwrap();
    assert!(exhausted.contains("remaining=0"), "{exhausted}");
    assert!(!exhausted.contains("required="), "{exhausted}");
    assert!(!exhausted.contains("cost="), "{exhausted}");
}

#[test]
fn a_conflicting_grant_for_the_same_jti_is_500_and_omits_the_budget_header() {
    let resource = resource();
    let first = resource
        .authorize(
            &present(&auth("clash", Some(2_000), "read"), None),
            NOW,
            "clash-1",
        )
        .into_response();
    assert_eq!(first.status(), 200);
    assert!(first.headers().contains_key("aauth-budget"));

    let conflict = resource
        .authorize(
            &present(&auth("clash", Some(5_000), "read"), None),
            NOW,
            "clash-2",
        )
        .into_response();
    assert_eq!(
        conflict.status(),
        500,
        "{}",
        String::from_utf8_lossy(conflict.body())
    );
    assert!(!conflict.headers().contains_key("aauth-budget"));
    assert_eq!(
        serde_json::from_slice::<Value>(conflict.body()).unwrap()["error"],
        "server_error"
    );

    let again = resource
        .authorize(
            &present(&auth("clash", Some(2_000), "read"), None),
            NOW,
            "clash-3",
        )
        .into_response();
    assert_eq!(
        again.status(),
        200,
        "{}",
        String::from_utf8_lossy(again.body())
    );
    let header = again.headers()["aauth-budget"].to_str().unwrap();
    assert!(header.contains("cost=1000"), "{header}");
}

#[test]
fn a_revoked_budgeted_token_is_refused_with_what_its_grant_has_left() {
    let resource = resource().with_revocation();
    let mut revoke = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"jti": "revoked", "exp": 4_000})).unwrap())
        .unwrap();
    sign_request(
        &mut revoke,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        NOW,
    )
    .unwrap();
    assert_eq!(resource.revoke(&revoke, NOW).status(), 200);
    let refused = resource
        .authorize(
            &present(&auth("revoked", Some(2_000), "read"), None),
            NOW,
            "c-revoked",
        )
        .into_response();
    assert_eq!(refused.status(), 401);
    assert_eq!(refused.headers()["signature-error"], "error=revoked_jwt");
    let header = refused.headers()["aauth-budget"].to_str().unwrap();
    assert!(header.contains("remaining=2000"), "{header}");
}

#[test]
fn an_insufficient_refusal_can_omit_required() {
    let resource = resource().without_stated_required();
    let refused = resource
        .authorize(
            &present(&auth("quiet", Some(400), "read"), Some(2_500)),
            NOW,
            "quiet-1",
        )
        .into_response();
    assert_eq!(refused.status(), 401);
    let requirement = refused.headers()["aauth-requirement"].to_str().unwrap();
    assert!(
        requirement.contains("reason=insufficient-budget"),
        "{requirement}"
    );
    let header = refused.headers()["aauth-budget"].to_str().unwrap();
    assert!(header.contains("remaining=400"), "{header}");
    assert!(!header.contains("required="), "{header}");
    assert!(!header.contains("cost="), "{header}");
    let again = resource
        .authorize(
            &present(&auth("quiet-ok", Some(2_000), "read"), Some(1_000)),
            NOW,
            "quiet-2",
        )
        .into_response();
    assert_eq!(
        again.status(),
        200,
        "{}",
        String::from_utf8_lossy(again.body())
    );
}

#[test]
fn streaming_hold_and_replay_do_not_pass_the_grant() {
    let resource = resource();
    let token = AuthToken::parse(&auth("stream", Some(5_000), "read"))
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    let before = resource.budget_held_header(&token).unwrap();
    assert!(before.contains("remaining=5000"), "{before}");
    assert_eq!(resource.budget_held_header(&token).unwrap(), before);
    let reservation = resource.budget_reserve(&token, 400).unwrap();
    let preview = resource.budget_stream_header(&reservation).unwrap();
    assert!(preview.contains("reserved=400"), "{preview}");
    assert!(!preview.contains("cost="), "{preview}");
    let done = resource.budget_commit(&reservation, 100, NOW).unwrap();
    assert!(done.contains("cost=100"), "{done}");
    let (listed, name, field) = resource.budget_trailer(&preview, 100).unwrap();
    assert_eq!(listed, "AAuth-Budget");
    assert_eq!(name, "aauth-budget");
    assert_eq!(field, "cost=100");
    let first = resource
        .budget_complete_held("pending", &token, 10, 4, NOW)
        .unwrap();
    assert!(first.contains("cost=4"), "{first}");
    let again = resource
        .budget_complete_held("pending", &token, 10, 4, NOW + 1)
        .unwrap();
    assert!(again.contains("cost=4"), "{again}");
    let remaining = match resource.budget_reserve(&token, 5_000) {
        Err(ChargeError::Refused(Refusal::Insufficient { remaining, .. })) => remaining,
        other => panic!("{other:?}"),
    };
    assert_eq!(remaining, 4_896);
}

#[test]
fn the_process_mutex_lets_only_one_side_spend_the_last_units() {
    let resource = Arc::new(resource());
    let token = auth("race", Some(10), "read");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let resource = Arc::clone(&resource);
        let token = token.clone();
        handles.push(thread::spawn(move || {
            let verified = AuthToken::parse(&token)
                .unwrap()
                .verify(&Keys, NOW)
                .unwrap();
            resource.budget_reserve(&verified, 4).is_ok()
        }));
    }
    let mut wins = 0;
    for handle in handles {
        if handle.join().unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 2);
}

#[test]
fn four_party_chain_narrows_at_each_stage_and_a_figure_replaces_the_assumption() {
    let resource = PsAuthorizationResource::new_federated(
        PsAuthorizationConfig {
            issuer: RESOURCE.into(),
            signed_origin: RESOURCE.into(),
            kid: "resource".into(),
            signing_key: SigningKey::from_seed([5; 32]),
            scopes: vec!["read".into()],
            scope_descriptions: BTreeMap::from([(
                "read".into(),
                "Read the metered records".into(),
            )]),
        },
        AS,
        Keys,
        |_token: &aauth_rust_core::VerifiedAuthToken, _request: &Request<Vec<u8>>| {
            Ok::<_, Deny>("admitted".to_owned())
        },
    )
    .unwrap()
    .with_authorization_endpoint()
    .with_budgets(units(6), "https://orders.example/usage", 1_500, 5_000_000)
    .unwrap();

    let access = AccessServer::new(
        AsConfig::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Ok(Decision {
                scopes: vec!["read".into()],
                lifetime: 600,
            })
        },
        || NOW,
        {
            let ids = AtomicUsize::new(0);
            move || format!("as-{}", ids.fetch_add(1, Ordering::SeqCst))
        },
    )
    .unwrap()
    .with_budgets(IssuerPolicy::capped(2_000, units(6)))
    .unwrap();

    struct Bridge<S>(Mutex<S>);
    impl<S> Federation for Bridge<S>
    where
        S: Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync,
    {
        fn endpoint(&self, access_server: &str) -> Result<String, FederationError> {
            if access_server == AS {
                Ok(format!("{AS}/token"))
            } else {
                Err(FederationError)
            }
        }
        fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
            Ok((self.0.lock().unwrap())(request))
        }
    }

    let person = PersonServer::new(
        PsConfig::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        || NOW,
        {
            let ids = AtomicUsize::new(0);
            move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))
        },
    )
    .unwrap()
    .with_federation(Bridge(Mutex::new(move |request: &Request<Vec<u8>>| {
        access.handle(request)
    })))
    .with_budgets(IssuerPolicy::capped(4_000, units(6)))
    .unwrap();

    let key = SigningKey::from_seed([2; 32]);
    let agent_token =
        AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32]))
            .unwrap()
            .issue(&AgentClaims {
                iss: "https://ap.example".into(),
                dwk: "aauth-agent.json".into(),
                sub: "aauth:Caller@ap.example".into(),
                jti: "agent".into(),
                iat: NOW,
                exp: 5_000,
                cnf: Confirmation {
                    jwk: key.public_jwk(),
                },
                ps: Some(PS.into()),
                parent_agent: None,
                nbf: None,
                extra: Default::default(),
            })
            .unwrap();
    let agent = Agent::new(key, agent_token).unwrap();
    let mut person_request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"resource": RESOURCE, "capabilities": ["budget", "not-a-real-capability"]}),
            )
            .unwrap(),
        )
        .unwrap();
    agent.sign(&mut person_request, NOW).unwrap();
    let person_response = person.handle(&person_request);
    assert_eq!(
        person_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(person_response.body())
    );
    let person_token =
        serde_json::from_slice::<Value>(person_response.body()).unwrap()["person_token"]
            .as_str()
            .unwrap()
            .to_owned();

    let mut high = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/authorize"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"scope": "read", "budget": {"amount": 20_000_000, "unit": "USD", "decimals": 6}})).unwrap())
        .unwrap();
    sign_request(
        &mut high,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt {
            jwt: person_token.clone(),
            cache: false,
        },
        NOW,
    )
    .unwrap();
    let high_response = resource
        .authorize_endpoint(&high, NOW, "offer")
        .into_response();
    assert_eq!(
        high_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(high_response.body())
    );
    let resource_token =
        serde_json::from_slice::<Value>(high_response.body()).unwrap()["resource_token"]
            .as_str()
            .unwrap()
            .to_owned();
    let offer = payload(&resource_token);
    assert_eq!(offer["budget"]["amount"], 10_000_000);
    assert_eq!(offer["budget"]["unit"], "USD");
    assert_eq!(offer["budget"]["decimals"], 6);
    assert!(offer.get("budget_consumed").is_none());

    let mut unknown = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/authorize"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"scope": "read", "budget": {"amount": 1, "unit": "EUR", "decimals": 6}}),
            )
            .unwrap(),
        )
        .unwrap();
    sign_request(
        &mut unknown,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt {
            jwt: person_token.clone(),
            cache: false,
        },
        NOW,
    )
    .unwrap();
    let unknown_response = resource
        .authorize_endpoint(&unknown, NOW, "bad-unit")
        .into_response();
    assert_eq!(unknown_response.status(), 400);
    assert_eq!(
        serde_json::from_slice::<Value>(unknown_response.body()).unwrap()["error"],
        "invalid_budget"
    );

    let mut exchange = Request::builder()
        .method("POST")
        .uri(format!("{PS}/token"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "resource_token": resource_token,
                "presented_token": person_token,
                "capabilities": ["budget", "not-a-real-capability"]
            }))
            .unwrap(),
        )
        .unwrap();
    agent.sign(&mut exchange, NOW).unwrap();
    let exchange_response = person.handle(&exchange);
    assert_eq!(
        exchange_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(exchange_response.body())
    );
    let auth = serde_json::from_slice::<Value>(exchange_response.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let issued = payload(&auth);
    assert_eq!(issued["budget"]["amount"], 2_000);
    assert_eq!(issued["budget"]["unit"], "USD");
    assert_eq!(issued["budget"]["decimals"], 6);
    assert_eq!(person.budget_accounted(), Some(2_000));

    let metered = resource
        .authorize(&present(&auth, None), NOW, "spend")
        .into_response();
    assert_eq!(
        metered.status(),
        200,
        "{}",
        String::from_utf8_lossy(metered.body())
    );
    assert!(
        metered.headers()["aauth-budget"]
            .to_str()
            .unwrap()
            .contains("cost=1500")
    );
    let step = resource
        .authorize(&present(&auth, Some(1_500)), NOW, "step")
        .into_response();
    assert_eq!(step.status(), 401);
    let requirement = step.headers()["aauth-requirement"].to_str().unwrap();
    assert!(
        requirement.contains("reason=insufficient-budget"),
        "{requirement}"
    );
    let step_token = requirement
        .split("resource-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let step_claims = payload(&step_token);
    assert_eq!(step_claims["budget_consumed"]["consumed"], 1_500);
    assert_eq!(step_claims["budget"]["decimals"], 6);
    assert_eq!(step_claims["budget"]["unit"], "USD");
    let verified = ResourceToken::parse(&step_token)
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    assert_eq!(verified.claims().aud, AS);

    let mut report = Request::builder()
        .method("POST")
        .uri(format!("{PS}/token"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({"resource_token": step_token, "presented_token": auth}))
                .unwrap(),
        )
        .unwrap();
    agent.sign(&mut report, NOW).unwrap();
    let report_response = person.handle(&report);
    assert_eq!(
        report_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(report_response.body())
    );
    assert_eq!(person.budget_accounted(), Some(3_500));
}

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PsPolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed".into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &PsAuthorization) -> Result<Grant, PsPolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, _: &PsAuthorization) -> Result<(), PsPolicyError> {
        Ok(())
    }
}

#[test]
fn person_and_access_servers_ask_for_usage_signed_as_themselves() {
    let resource = resource();
    let granted = resource
        .authorize(
            &present(&auth("asked", Some(2_000), "read"), None),
            NOW,
            "asked-c",
        )
        .into_response();
    assert_eq!(granted.status(), 200);
    let person = PersonServer::new(
        PsConfig::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Host,
        || NOW,
        || "ps-id".to_owned(),
    )
    .unwrap();
    let holder = SigningKey::from_seed([2; 32])
        .public_jwk()
        .thumbprint()
        .unwrap();
    let query = UsageQuery {
        sub: Some("directed".into()),
        tenant: None,
        mission: None,
        ps: None,
        jkts: Some(vec![holder.clone()]),
    };
    let asked = person
        .usage_request("https://orders.example/usage", &query)
        .unwrap();
    assert!(
        asked.headers()["signature-key"]
            .to_str()
            .unwrap()
            .contains("jwks_uri;id=\"https://ps.example\";dwk=\"aauth-person.json\"")
    );
    let answer = resource.usage(&asked, NOW);
    assert_eq!(
        answer.status(),
        200,
        "{}",
        String::from_utf8_lossy(answer.body())
    );
    let usage = person.read_usage(&answer, &query).unwrap();
    assert_eq!(usage.aud, PS);
    assert_eq!(usage.scope, Some(("sub", "directed".to_owned())));
    assert_eq!(usage.usage.unwrap().all_time, 1_000);
    assert_eq!(usage.jkts.unwrap()[&holder], 1_000);
    // A person server names no `ps`; it is the caller.
    let named = UsageQuery {
        ps: Some(PS.into()),
        ..query.clone()
    };
    assert!(
        person
            .usage_request("https://orders.example/usage", &named)
            .is_err()
    );
    assert!(
        person
            .usage_request("http://orders.example/usage", &query)
            .is_err()
    );

    let access = AccessServer::new(
        AsConfig::new(AS, "as", SigningKey::from_seed([4; 32])),
        Keys,
        |_: &aauth_rust_access_server::AuthorizationRequest| {
            Err(aauth_rust_access_server::PolicyError::Denied)
        },
        || NOW,
        || "as-id".to_owned(),
    )
    .unwrap();
    // An access server names the person server whose `sub` it asks about.
    assert!(
        access
            .usage_request("https://orders.example/usage", &query)
            .is_err()
    );
    let asked = access
        .usage_request("https://orders.example/usage", &named)
        .unwrap();
    let answer = resource.usage(&asked, NOW);
    assert_eq!(answer.status(), 200);
    let usage = access.read_usage(&answer, &named).unwrap();
    assert_eq!(usage.aud, AS);
    // The access server issued none of these tokens, so it sees no figure.
    assert_eq!(usage.usage, None);
    // An answer produced for one caller is not read as a statement about another.
    assert!(person.read_usage(&answer, &query).is_err());
}

#[test]
fn usage_answers_the_caller_that_appears_on_the_token() {
    let resource = resource();
    let response = resource
        .authorize(
            &present(&auth("usage", Some(2_000), "read"), None),
            NOW,
            "usage-c",
        )
        .into_response();
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"sub": "directed"})).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        NOW,
    )
    .unwrap();
    let usage = resource.usage(&request, NOW);
    assert_eq!(
        usage.status(),
        200,
        "{}",
        String::from_utf8_lossy(usage.body())
    );
    assert!(
        usage.headers()["signature-input"]
            .to_str()
            .unwrap()
            .contains("\"@status\"")
    );
    assert!(
        usage.headers()["signature-input"]
            .to_str()
            .unwrap()
            .contains("\"content-digest\"")
    );
    assert!(
        usage.headers()["signature-key"]
            .to_str()
            .unwrap()
            .contains("dwk=\"aauth-resource.json\"")
    );
    let body: Value = serde_json::from_slice(usage.body()).unwrap();
    assert_eq!(body["aud"], PS);
    assert_eq!(body["unit"], "USD");
    assert_eq!(body["decimals"], 6);
    assert_eq!(body["usage"]["all_time"], 1_000);
    assert_eq!(usage.headers()["cache-control"], "no-store");
    assert!(body["as_of"].as_i64().unwrap() >= NOW);

    let mut unknown = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"sub": "nobody"})).unwrap())
        .unwrap();
    sign_request(
        &mut unknown,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        NOW,
    )
    .unwrap();
    let unknown_response = resource.usage(&unknown, NOW);
    assert_eq!(unknown_response.status(), 200);
    let unknown_body: Value = serde_json::from_slice(unknown_response.body()).unwrap();
    assert!(unknown_body.get("usage").is_none(), "{unknown_body}");

    let unsigned = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"sub": "directed"})).unwrap())
        .unwrap();
    assert_eq!(resource.usage(&unsigned, NOW).status(), 401);

    let mut wrong_scheme = unsigned.clone();
    sign_request(
        &mut wrong_scheme,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::Jwt {
            jwt: auth("usage", Some(2_000), "read"),
            cache: false,
        },
        NOW,
    )
    .unwrap();
    // A refusal is a Signature-Error naming the one scheme this endpoint takes.
    let refused = resource.usage(&wrong_scheme, NOW);
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["signature-error"],
        "error=unsupported_scheme"
    );
    assert_eq!(refused.headers()["accept-signature-scheme"], "jwks_uri");

    let mut missing_digest = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut missing_digest,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        NOW,
    )
    .unwrap();
    *missing_digest.body_mut() = serde_json::to_vec(&json!({"sub": "directed"})).unwrap();
    missing_digest
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    let refused = resource.usage(&missing_digest, NOW);
    assert_eq!(refused.status(), 401);
    assert!(
        refused.headers()["signature-error"]
            .to_str()
            .unwrap()
            .starts_with("error=invalid_input, required_input=(")
    );

    let mut foreign = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"sub": "directed", "ps": PS})).unwrap())
        .unwrap();
    sign_request(
        &mut foreign,
        &SigningKey::from_seed([4; 32]),
        KeyMaterial::JwksUri {
            id: AS.into(),
            dwk: "aauth-access.json".into(),
            kid: "as".into(),
        },
        NOW,
    )
    .unwrap();
    let foreign_response = resource.usage(&foreign, NOW);
    assert_eq!(foreign_response.status(), 200);
    let foreign_body: Value = serde_json::from_slice(foreign_response.body()).unwrap();
    assert!(foreign_body.get("usage").is_none(), "{foreign_body}");
    assert!(
        !foreign_body.to_string().contains("all_time"),
        "{foreign_body}"
    );
    let mut foreign_keys = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"jkts": ["missing-thumbprint"]})).unwrap())
        .unwrap();
    sign_request(
        &mut foreign_keys,
        &SigningKey::from_seed([4; 32]),
        KeyMaterial::JwksUri {
            id: AS.into(),
            dwk: "aauth-access.json".into(),
            kid: "as".into(),
        },
        NOW,
    )
    .unwrap();
    let foreign_keys_response = resource.usage(&foreign_keys, NOW);
    assert_eq!(foreign_keys_response.status(), 200);
    let foreign_keys_body: Value = serde_json::from_slice(foreign_keys_response.body()).unwrap();
    assert!(
        foreign_keys_body
            .get("jkts")
            .is_none_or(|keys| keys.as_object().is_some_and(|keys| keys.is_empty())),
        "{foreign_keys_body}"
    );
    assert!(
        !foreign_keys_body.to_string().contains("all_time"),
        "{foreign_keys_body}"
    );
}

#[test]
fn a_client_cost_cannot_raise_the_host_bound_or_buy_a_free_admission() {
    let resource = resource();
    let zero = resource
        .authorize(
            &present(&auth("priced", Some(2_000), "read"), Some(0)),
            NOW,
            "zero",
        )
        .into_response();
    assert_eq!(zero.status(), 401);
    let requirement = zero.headers()["aauth-requirement"].to_str().unwrap();
    assert!(
        requirement.contains("reason=insufficient-budget"),
        "{requirement}"
    );
    let header = zero.headers()["aauth-budget"].to_str().unwrap();
    assert!(header.contains("remaining=2000"), "{header}");
    // The host bound fits the remainder, so it is not a `required` figure.
    assert!(!header.contains("required="), "{header}");
    assert!(!header.contains("cost="), "{header}");

    let charged = resource
        .authorize(
            &present(&auth("priced", Some(2_000), "read"), None),
            NOW,
            "pay",
        )
        .into_response();
    assert_eq!(charged.status(), 200);
    let charged_header = charged.headers()["aauth-budget"].to_str().unwrap();
    assert!(charged_header.contains("cost=1000"), "{charged_header}");
    assert!(
        charged_header.contains("remaining=1000"),
        "{charged_header}"
    );

    let raised = resource
        .authorize(
            &present(&auth("priced", Some(2_000), "read"), Some(4_000)),
            NOW,
            "raise",
        )
        .into_response();
    assert_eq!(raised.status(), 200);
    let raised_header = raised.headers()["aauth-budget"].to_str().unwrap();
    assert!(raised_header.contains("cost=1000"), "{raised_header}");
    assert!(raised_header.contains("remaining=0"), "{raised_header}");

    let spent = resource
        .authorize(
            &present(&auth("priced", Some(2_000), "read"), Some(0)),
            NOW,
            "spent-zero",
        )
        .into_response();
    assert_eq!(spent.status(), 401);
    assert!(
        spent.headers()["aauth-requirement"]
            .to_str()
            .unwrap()
            .contains("reason=budget-exhausted")
    );

    let lowered = resource
        .authorize(
            &present(&auth("lower", Some(2_000), "read"), Some(250)),
            NOW,
            "lower",
        )
        .into_response();
    assert_eq!(lowered.status(), 200);
    assert!(
        lowered.headers()["aauth-budget"]
            .to_str()
            .unwrap()
            .contains("cost=250")
    );
    let AuthDecision::Granted(admitted) = resource.authorize(
        &present(&auth("cap", Some(2_000), "read"), Some(250)),
        NOW,
        "cap",
    ) else {
        panic!("expected a granted admission");
    };
    assert_eq!(admitted.admitted_maximum(), Some(250));
}

#[test]
fn step_up_offers_the_declared_scale_and_omits_a_stale_consumption_record() {
    let resource = resource();
    let first = resource
        .authorize(
            &present(&auth("scale", Some(1_500), "read"), None),
            NOW,
            "scale-1",
        )
        .into_response();
    assert_eq!(first.status(), 200);
    let step = resource
        .authorize(
            &present(&auth("scale", Some(1_500), "read"), None),
            NOW,
            "scale-2",
        )
        .into_response();
    assert_eq!(step.status(), 401);
    let requirement = step.headers()["aauth-requirement"].to_str().unwrap();
    let challenge = requirement
        .split("resource-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let claims = payload(challenge);
    assert_eq!(claims["budget_consumed"]["consumed"], 1_000);
    assert_eq!(claims["budget"]["unit"], "USD");
    assert_eq!(claims["budget"]["decimals"], 6);
    resource
        .replace_budget_units(vec![
            UnitDeclaration::with_max("EUR", 2, 10_000_000, "euros").unwrap(),
        ])
        .unwrap();
    let relabeled = resource
        .authorize(
            &present(&auth("scale", Some(1_500), "read"), None),
            NOW,
            "scale-3",
        )
        .into_response();
    assert_eq!(relabeled.status(), 401);
    let relabeled_requirement = relabeled.headers()["aauth-requirement"].to_str().unwrap();
    let relabeled_challenge = relabeled_requirement
        .split("resource-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let relabeled_claims = payload(relabeled_challenge);
    assert!(relabeled_claims.get("budget_consumed").is_none());
    assert_eq!(relabeled_claims["budget"]["unit"], "EUR");
    assert_eq!(relabeled_claims["budget"]["decimals"], 2);
    let metered = relabeled.headers()["aauth-budget"].to_str().unwrap();
    assert!(metered.contains("decimals=6"), "{metered}");
}

#[test]
fn observed_admission_meters_once_and_a_buffered_call_does_not() {
    let resource = resource();
    let bare = Request::builder()
        .uri(format!("{RESOURCE}/records"))
        .body(Vec::new())
        .unwrap();
    assert!(matches!(
        resource.authorize_observed(&bare, NOW, "unsigned"),
        AuthDecision::PersonTokenRequired
    ));

    let watched = resource.authorize_observed(
        &present(&auth("watch", Some(5_000), "read"), None),
        NOW,
        "watch",
    );
    let AuthDecision::Observed(observed) = watched else {
        panic!("expected an unmetered admission, got {watched:?}");
    };
    assert_eq!(observed.admitted_maximum(), Some(1_000));
    let followed = resource
        .authorize(
            &present(&auth("watch", Some(5_000), "read"), None),
            NOW,
            "watch-meter",
        )
        .into_response();
    assert_eq!(followed.status(), 200);
    assert!(
        followed.headers()["aauth-budget"]
            .to_str()
            .unwrap()
            .contains("remaining=4000")
    );

    let once = resource.authorize_observed(
        &present(&auth("once", Some(5_000), "read"), None),
        NOW,
        "once",
    );
    let AuthDecision::Observed(once) = once else {
        panic!("expected an unmetered admission, got {once:?}");
    };
    resource
        .budget_complete_held("held-1", once.token(), 100, 35, NOW)
        .unwrap();
    let again = resource
        .budget_complete_held("held-1", once.token(), 100, 35, NOW)
        .unwrap();
    assert!(again.contains("cost=35"), "{again}");
    assert!(resource.budget_reserve(once.token(), 4_965).is_ok());

    let doubled = resource
        .authorize(
            &present(&auth("double", Some(2_000), "read"), None),
            NOW,
            "double",
        )
        .into_response();
    assert_eq!(doubled.status(), 200);
    let token = AuthToken::parse(&auth("double", Some(2_000), "read"))
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    resource
        .budget_complete_held("other-held", &token, 1_000, 1_000, NOW)
        .unwrap();
    let exhausted = resource
        .authorize(
            &present(&auth("double", Some(2_000), "read"), None),
            NOW,
            "double-again",
        )
        .into_response();
    assert_eq!(exhausted.status(), 401);
    assert!(
        exhausted.headers()["aauth-requirement"]
            .to_str()
            .unwrap()
            .contains("reason=budget-exhausted")
    );
}

#[test]
fn a_reserved_stream_commits_once_and_dropping_the_decision_does_not() {
    let resource = resource();
    let held = resource.authorize_reserved(
        &present(&auth("stream", Some(2_000), "read"), Some(400)),
        NOW,
        "stream",
    );
    let AuthDecision::Held(held) = held else {
        panic!("expected a reservation, got {held:?}");
    };
    assert_eq!(held.admitted_maximum(), 400);
    let preview = resource.budget_stream_header(held.reservation()).unwrap();
    assert!(preview.contains("reserved=400"), "{preview}");
    assert!(!preview.contains("cost="), "{preview}");
    let posted = resource.budget_commit(held.reservation(), 30, NOW).unwrap();
    assert!(posted.contains("cost=30"), "{posted}");
    assert!(resource.budget_commit(held.reservation(), 1, NOW).is_err());

    let abandoned = resource.authorize_reserved(
        &present(&auth("drop", Some(1_500), "read"), None),
        NOW,
        "drop",
    );
    let response = abandoned.into_response();
    assert_eq!(response.status(), 500);
    let released = resource
        .authorize(
            &present(&auth("drop", Some(1_500), "read"), None),
            NOW,
            "drop-again",
        )
        .into_response();
    assert_eq!(released.status(), 200);
    let released_header = released.headers()["aauth-budget"].to_str().unwrap();
    assert!(released_header.contains("cost=1000"), "{released_header}");
    assert!(
        released_header.contains("remaining=500"),
        "{released_header}"
    );

    let by_result = resource.authorize_reserved(
        &present(&auth("result", Some(1_500), "read"), None),
        NOW,
        "result",
    );
    let error = by_result
        .into_result()
        .expect_err("a hold is not an HTTP grant");
    assert_eq!(error.status(), 500);
    let result_released = resource
        .authorize(
            &present(&auth("result", Some(1_500), "read"), None),
            NOW,
            "result-again",
        )
        .into_response();
    assert_eq!(result_released.status(), 200);

    let later = NOW + 40;
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"sub": "directed"})).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps".into(),
        },
        later,
    )
    .unwrap();
    let usage = resource.usage(&request, later);
    assert_eq!(usage.status(), 200);
    let body: Value = serde_json::from_slice(usage.body()).unwrap();
    assert_eq!(body["usage"]["all_time"], 30 + 1_000 + 1_000);
    assert_eq!(body["as_of"], later);
}
