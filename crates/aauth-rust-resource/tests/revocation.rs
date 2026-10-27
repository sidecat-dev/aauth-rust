//! Resource revocation endpoint, presentation, and resource-token cascade.
use aauth_rust_core::{
    AgentKeyResolver, AuthClaims, CallOutcome, Confirmation, PersonClaims, RevocationDirectory,
    TokenError, TrustedIssuerKeys, VerifiedAuthToken, mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthAdmissionPolicy, Deny, PsAuthorizationConfig, PsAuthorizationResource,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicUsize, Ordering},
};

const NOW: i64 = 1000;
const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const ORIGIN: &str = "https://resource.example:8443";

#[derive(Clone)]
struct Keys(Vec<TrustedIssuerKeys>);
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        for snapshot in &self.0 {
            match snapshot.key(issuer, dwk, kid) {
                Err(TokenError::UntrustedIssuer | TokenError::InvalidDiscoveryDocument) => continue,
                other => return other,
            }
        }
        Err(TokenError::UntrustedIssuer)
    }
}
fn issuer_key(issuer: &str, dwk: &str, seed: u8, kid: &str) -> TrustedIssuerKeys {
    let mut jwk = serde_json::to_value(SigningKey::from_seed([seed; 32]).public_jwk()).unwrap();
    jwk["kid"] = json!(kid);
    TrustedIssuerKeys::from_documents(
        issuer,
        dwk,
        &serde_json::to_vec(&json!({"issuer": issuer, "jwks_uri": format!("{issuer}/keys")}))
            .unwrap(),
        &serde_json::to_vec(&json!({"keys": [jwk]})).unwrap(),
    )
    .unwrap()
}
fn keys() -> Keys {
    Keys(vec![
        issuer_key(PS, "aauth-person.json", 3, "ps-1"),
        issuer_key(AS, "aauth-access.json", 5, "as-1"),
        issuer_key(RESOURCE, "aauth-resource.json", 4, "resource-1"),
    ])
}
fn config() -> PsAuthorizationConfig {
    PsAuthorizationConfig {
        issuer: RESOURCE.into(),
        signed_origin: ORIGIN.into(),
        kid: "resource-1".into(),
        signing_key: SigningKey::from_seed([4; 32]),
        scopes: vec!["records.read".into()],
    }
}
fn resource(
    calls: Arc<AtomicUsize>,
) -> PsAuthorizationResource<Keys, BoxedAuthAdmissionPolicy<String>> {
    PsAuthorizationResource::new(
        config(),
        keys(),
        Box::new(move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("host".to_owned()) as Result<String, Deny>
        }) as BoxedAuthAdmissionPolicy<String>,
    )
    .unwrap()
    .with_revocation()
}
fn person(jti: &str, iat: i64, exp: i64) -> String {
    mint_person_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "directed-person".into(),
            jti: jti.into(),
            iat,
            exp,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            nbf: None,
            tenant: Some("team".into()),
            mission_s256: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn auth(jti: &str, iat: i64, exp: i64) -> String {
    mint_auth_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &AuthClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "directed-person".into(),
            jti: jti.into(),
            iat,
            exp,
            ps: PS.into(),
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            scope: Some("records.read".into()),
            account: None,
            nbf: None,
            tenant: Some("team".into()),
            mission_s256: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn present(token: &str, seed: u8) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{ORIGIN}/records"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::Jwt(token.into()),
        NOW,
    )
    .unwrap();
    request
}
fn server_post(seed: u8, id: &str, dwk: &str, kid: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{ORIGIN}/revoke"))
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
        NOW,
    )
    .unwrap();
    request
}

#[test]
fn revoked_person_token_is_refused_without_a_resource_token() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone());
    let live = person("person-1", NOW, 3000);
    let recorded = resource.revoke(
        &server_post(
            3,
            PS,
            "aauth-person.json",
            "ps-1",
            json!({"jti":"person-1","exp":3000}),
        ),
        NOW,
    );
    assert_eq!(recorded.status(), 200);
    let response = resource
        .authorize(&present(&live, 2), NOW, "challenge")
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["signature-error"], "error=revoked_jwt");
    assert!(!response.headers().contains_key("aauth-requirement"));
    let requirement = response
        .headers()
        .get("aauth-requirement")
        .map(|value| value.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(!requirement.contains("resource-token"));
    let expired = person("person-old", NOW - 100, NOW);
    resource.revoke(
        &server_post(
            3,
            PS,
            "aauth-person.json",
            "ps-1",
            json!({"jti":"person-old","exp":NOW}),
        ),
        NOW,
    );
    let expired_response = resource
        .authorize(&present(&expired, 2), NOW, "challenge")
        .into_response();
    assert_eq!(
        expired_response.headers()["signature-error"],
        "error=revoked_jwt"
    );
    let mismatched = {
        let mut request = Request::builder()
            .uri(format!("{ORIGIN}/records"))
            .body(Vec::new())
            .unwrap();
        sign_request(
            &mut request,
            &SigningKey::from_seed([9; 32]),
            KeyMaterial::Jwt(live),
            NOW,
        )
        .unwrap();
        request
    };
    let proof = resource
        .authorize(&mismatched, NOW, "challenge")
        .into_response();
    assert_eq!(
        proof.headers()["signature-error"],
        "error=invalid_signature"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn revoked_auth_token_is_revoked_jwt_with_person_requirement() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone());
    let live = auth("auth-1", NOW, 2500);
    assert_eq!(
        resource
            .revoke(
                &server_post(
                    3,
                    PS,
                    "aauth-person.json",
                    "ps-1",
                    json!({"jti":"auth-1","exp":2500})
                ),
                NOW
            )
            .status(),
        200
    );
    let response = resource
        .authorize(&present(&live, 2), NOW, "unused")
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["signature-error"], "error=revoked_jwt");
    assert_eq!(
        response.headers()["aauth-requirement"],
        "requirement=person-token"
    );
    assert!(
        !response.headers()["aauth-requirement"]
            .to_str()
            .unwrap()
            .contains("resource-token")
    );
    let expired = auth("auth-old", NOW - 100, NOW);
    resource.revoke(
        &server_post(
            3,
            PS,
            "aauth-person.json",
            "ps-1",
            json!({"jti":"auth-old","exp":NOW}),
        ),
        NOW,
    );
    let expired_response = resource
        .authorize(&present(&expired, 2), NOW, "unused")
        .into_response();
    assert_eq!(
        expired_response.headers()["aauth-requirement"],
        "requirement=person-token"
    );
    assert_eq!(
        expired_response.headers()["signature-error"],
        "error=revoked_jwt"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

type CoreResource = PsAuthorizationResource<Keys, BoxedAuthAdmissionPolicy<String>>;

#[test]
fn core_revocation_completed_during_host_policy_refuses_admission_without_effect_or_replay() {
    let calls = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let handle: Arc<OnceLock<Weak<CoreResource>>> = Arc::new(OnceLock::new());
    let (policy_calls, policy_recorded, policy_handle) =
        (calls.clone(), recorded.clone(), handle.clone());
    // Plain Core, no R3: the signed revocation completes inside host policy.
    let resource = Arc::new(
        PsAuthorizationResource::new(
            config(),
            keys(),
            Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
                policy_calls.fetch_add(1, Ordering::SeqCst);
                if token.claims().jti == "auth-raced"
                    && let Some(resource) = policy_handle.get().and_then(Weak::upgrade)
                {
                    let response = resource.revoke(
                        &server_post(
                            3,
                            PS,
                            "aauth-person.json",
                            "ps-1",
                            json!({"jti":"auth-raced","exp":2500}),
                        ),
                        NOW,
                    );
                    policy_recorded
                        .lock()
                        .unwrap()
                        .push(response.status().as_u16());
                }
                Ok("host".to_owned()) as Result<String, Deny>
            }) as BoxedAuthAdmissionPolicy<String>,
        )
        .unwrap()
        .with_revocation(),
    );
    handle.set(Arc::downgrade(&resource)).unwrap();

    // Policy admitted, but the post-callback check refuses: no grant reaches the host.
    let raced = auth("auth-raced", NOW, 2500);
    let decision = resource.authorize(&present(&raced, 2), NOW, "unused");
    assert!(
        matches!(decision, AuthDecision::Revoked { auth_token: true }),
        "{decision:?}"
    );
    assert_eq!(*recorded.lock().unwrap(), [200]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let response = decision.into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["signature-error"], "error=revoked_jwt");
    assert_eq!(
        response.headers()["aauth-requirement"],
        "requirement=person-token"
    );

    // No replay: the same token is refused before policy and never admitted.
    let again = resource.authorize(&present(&raced, 2), NOW, "unused");
    assert!(
        matches!(again, AuthDecision::Revoked { auth_token: true }),
        "{again:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*recorded.lock().unwrap(), [200]);

    // Control: an unrevoked Core token on the same Resource is admitted.
    let live = auth("auth-live", NOW, 2500);
    assert!(
        resource
            .authorize(&present(&live, 2), NOW, "unused")
            .into_result()
            .is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(*recorded.lock().unwrap(), [200]);
}

#[test]
fn resource_revocation_endpoint_records_without_deferral() {
    let resource = resource(Arc::new(AtomicUsize::new(0)));
    let published: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        published["revocation_endpoint"],
        format!("{RESOURCE}/revoke")
    );
    let mut request = server_post(
        3,
        PS,
        "aauth-person.json",
        "ps-1",
        json!({"jti":"shared","exp":1500,"iss":"https://evil.example"}),
    );
    request
        .headers_mut()
        .insert("prefer", "wait=0".parse().unwrap());
    let response = resource.revoke(&request, NOW);
    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    assert!(!response.headers().contains_key("content-type"));
    assert!(!response.headers().contains_key("location"));
    assert_eq!(resource.revocation_exp(PS, "shared"), Some(1500));
    assert!(
        resource
            .revocation_exp("https://evil.example", "shared")
            .is_none()
    );
    let repeat = resource.revoke(
        &server_post(
            3,
            PS,
            "aauth-person.json",
            "ps-1",
            json!({"jti":"shared","exp":1800}),
        ),
        NOW,
    );
    assert_eq!(repeat.status(), 200);
    assert_eq!(resource.revocation_exp(PS, "shared"), Some(1500));
    let other = resource.revoke(
        &server_post(
            5,
            AS,
            "aauth-access.json",
            "as-1",
            json!({"jti":"shared","exp":1700}),
        ),
        NOW,
    );
    assert_eq!(other.status(), 200);
    assert_eq!(resource.revocation_exp(AS, "shared"), Some(1700));
    let wrong_role = server_post(
        3,
        PS,
        "aauth-agent.json",
        "ps-1",
        json!({"jti":"nope","exp":1500}),
    );
    assert_eq!(resource.revoke(&wrong_role, NOW).status(), 401);
}

#[test]
fn resource_token_cascade_calls_the_audience_and_the_person_server() {
    struct Recording(Mutex<Vec<(String, String, i64)>>);
    impl RevocationDirectory for Recording {
        fn revoke(&self, recipient: &str, jti: &str, exp: i64) -> CallOutcome {
            self.0
                .lock()
                .unwrap()
                .push((recipient.to_owned(), jti.to_owned(), exp));
            CallOutcome::Recorded
        }
    }
    let recorded = Arc::new(Recording(Mutex::new(Vec::new())));
    let federated = PsAuthorizationResource::new_federated(
        config(),
        AS,
        keys(),
        Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| Ok::<(), Deny>(()))
            as BoxedAuthAdmissionPolicy<()>,
    )
    .unwrap()
    .with_revocation_directory(recorded.clone());
    let missing = federated.revoke_issued_resource_token("challenge-1", 1300, AS, None);
    assert_eq!(missing.status(), 400);
    let response = federated.revoke_issued_resource_token("challenge-1", 1300, AS, Some(PS));
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["downstream"][0]["recipient"], AS);
    assert_eq!(body["downstream"][1]["recipient"], PS);
    assert_eq!(
        recorded.0.lock().unwrap().as_slice(),
        [
            (AS.into(), "challenge-1".into(), 1300),
            (PS.into(), "challenge-1".into(), 1300)
        ]
    );
    let direct = Arc::new(Recording(Mutex::new(Vec::new())));
    let three = resource(Arc::new(AtomicUsize::new(0))).with_revocation_directory(direct.clone());
    let once = three.revoke_issued_resource_token("challenge-2", 1300, PS, None);
    assert_eq!(once.status(), 200);
    assert_eq!(
        direct.0.lock().unwrap().as_slice(),
        [(PS.into(), "challenge-2".into(), 1300)]
    );
}
