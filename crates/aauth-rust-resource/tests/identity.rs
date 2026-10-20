use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, Decision};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;

fn composition() -> (
    Agent,
    AgentIdentityResource<AgentProviderKeys, impl Fn(&aauth_rust_core::VerifiedAgentToken) -> bool>,
) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent@ap.example".into(),
        jti: "agent-1".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let token = ap.issue(&claims).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    (
        Agent::new(key, token).unwrap(),
        AgentIdentityResource::new(
            "https://resource.example/whoami",
            keys,
            |_: &aauth_rust_core::VerifiedAgentToken| true,
        )
        .unwrap(),
    )
}
fn request() -> Request<Vec<u8>> {
    Request::builder()
        .uri("https://resource.example/whoami")
        .body(Vec::new())
        .unwrap()
}

#[test]
fn direct_identity_is_verified_before_policy_sees_it() {
    let (agent, resource) = composition();
    assert!(matches!(
        resource.authorize(&request(), 1000),
        Decision::AgentTokenRequired
    ));
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    let Decision::Granted(token) = resource.authorize(&req, 1000) else {
        panic!("identity denied")
    };
    assert_eq!(token.claims().sub, "aauth:Agent@ap.example");
    assert!(matches!(
        resource.authorize(&req, 2000),
        Decision::SignatureFailure(_)
    ));
}

#[test]
fn non_jwt_schemes_get_the_defined_aauth_scheme_rejection() {
    let (_, resource) = composition();
    let key = SigningKey::from_seed([2; 32]);
    let mut req = request();
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    for header in [
        req.headers()["signature-key"].clone(),
        "sig=future;value=token".parse().unwrap(),
        "sig=hwk".parse().unwrap(),
    ] {
        req.headers_mut().insert("signature-key", header);
        let response = resource.authorize(&req, 1000).into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["signature-error"],
            "error=unsupported_scheme"
        );
        assert_eq!(response.headers()["accept-signature-scheme"], "jwt");
    }
}

#[test]
fn verification_failure_never_invokes_host_policy() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = resource.with_policy(move |_: &aauth_rust_core::VerifiedAgentToken| {
        seen.fetch_add(1, Ordering::SeqCst);
        false
    });
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    *req.uri_mut() = "https://resource.example/tampered".parse().unwrap();
    assert!(matches!(
        resource.authorize(&req, 1000),
        Decision::SignatureFailure(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    *req.uri_mut() = "https://resource.example/whoami".parse().unwrap();
    assert!(matches!(
        resource.authorize(&req, 1000),
        Decision::Forbidden
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn token_cannot_be_reused_with_a_different_request_key() {
    let (agent, resource) = composition();
    let mut req = request();
    sign_request(
        &mut req,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::Jwt(agent.token().into()),
        1000,
    )
    .unwrap();
    assert!(matches!(
        resource.authorize(&req, 1000),
        Decision::SignatureFailure(_)
    ));
    assert!(Agent::new(SigningKey::from_seed([3; 32]), agent.token().into()).is_err());
}

#[test]
fn missing_coverage_feedback_includes_query_and_authorization_requirements() {
    let (agent, resource) = composition();
    let mut req = Request::builder()
        .uri("https://resource.example/whoami?x=1")
        .header("authorization", "AAuth session")
        .body(Vec::new())
        .unwrap();
    agent.sign(&mut req, 1000).unwrap();
    req.headers_mut().insert(
        "signature-input",
        "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1000"
            .parse()
            .unwrap(),
    );
    let response = resource.authorize(&req, 1000).into_response();
    assert_eq!(response.status(), 401);
    let error = response.headers()["signature-error"].to_str().unwrap();
    assert!(error.contains("\"@query\""), "{error}");
    assert!(error.contains("\"authorization\""), "{error}");
}

#[test]
fn wire_failures_have_problem_details_and_safe_recovery_hints() {
    use aauth_rust_core::TokenError;
    use aauth_rust_resource::SignatureFailure;
    for (failure, code, hint) in [
        (
            SignatureFailure::Token(TokenError::UnsupportedAlgorithm),
            "unsupported_algorithm",
            Some(("accept-signature-alg", "Ed25519")),
        ),
        (
            SignatureFailure::Token(TokenError::IssuerMissing),
            "issuer_missing",
            None,
        ),
        (
            SignatureFailure::Token(TokenError::IssuerMismatch),
            "issuer_mismatch",
            None,
        ),
        (
            SignatureFailure::Token(TokenError::UnexpectedTokenType),
            "invalid_jwt",
            Some(("aauth-requirement", "requirement=agent-token")),
        ),
    ] {
        let response = Decision::SignatureFailure(failure).into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
        assert_eq!(
            response.headers()["signature-error"],
            format!("error={code}")
        );
        if let Some((name, value)) = hint {
            assert_eq!(response.headers()[name], value);
        }
        let problem: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(problem["type"], format!("urn:ietf:params:sig-error:{code}"));
        assert_eq!(problem["status"], 401);
        assert_eq!(problem["error"], code);
    }
    let response = Decision::Forbidden.into_response();
    assert_eq!(response.status(), 403);
    assert!(!response.headers().contains_key("signature-error"));
    let problem: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(problem["type"], "about:blank");
}

#[test]
fn provider_refuses_subagent_issuance_in_the_top_level_profile() {
    let (agent, _) = composition();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    claims.sub = "aauth:Agent+Child@ap.example".into();
    assert!(ap.issue(&claims).is_err());
    claims.sub = "aauth:Agent@ap.example".into();
    claims.parent_agent = Some("aauth:Parent@ap.example".into());
    assert!(ap.issue(&claims).is_err());
}

#[test]
fn resource_binds_valid_proofs_to_its_configured_authority_and_path() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = resource.with_policy(move |_: &VerifiedAgentToken| {
        seen.fetch_add(1, Ordering::SeqCst);
        true
    });
    for uri in [
        "https://other.example/whoami",
        "https://resource.example/admin",
        "https://resource.example:8443/whoami",
    ] {
        let mut req = Request::builder().uri(uri).body(Vec::new()).unwrap();
        agent.sign(&mut req, 1000).unwrap();
        assert!(
            !matches!(resource.authorize(&req, 1000), Decision::Granted(_)),
            "accepted {uri}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut req = Request::builder()
        .uri("https://RESOURCE.example:443/whoami?x=1")
        .body(Vec::new())
        .unwrap();
    agent.sign(&mut req, 1000).unwrap();
    assert!(matches!(
        resource.authorize(&req, 1000),
        Decision::Granted(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_honors_the_recommended_24_hour_agent_token_lifetime() {
    let (agent, _) = composition();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    claims.exp = claims.iat + 86400;
    ap.issue(&claims).unwrap();
    claims.exp += 1;
    assert!(ap.issue(&claims).is_err());
    claims.exp = i64::MAX;
    assert!(ap.issue(&claims).is_err());
}

#[test]
fn decision_debug_support_does_not_print_the_compact_credential() {
    let (agent, resource) = composition();
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    let output = format!("{:?}", resource.authorize(&req, 1000));
    assert!(output.contains("Granted"));
    assert!(!output.contains(agent.token()));
}
