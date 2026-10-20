use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, BoxedPolicy, Decision};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;

type TestResource = AgentIdentityResource<AgentProviderKeys, BoxedPolicy>;
fn composition() -> (Agent, TestResource) {
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
            Box::new(|_: &aauth_rust_core::VerifiedAgentToken, _request: &Request<Vec<u8>>| true)
                as BoxedPolicy,
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
    let resource = resource.with_policy(
        move |_: &aauth_rust_core::VerifiedAgentToken, _request: &Request<Vec<u8>>| {
            seen.fetch_add(1, Ordering::SeqCst);
            false
        },
    );
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
        let response = Decision::<()>::SignatureFailure(failure).into_response();
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
    let response = Decision::<()>::Forbidden.into_response();
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
    let resource =
        resource.with_policy(move |_: &VerifiedAgentToken, _request: &Request<Vec<u8>>| {
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
    let parsed = aauth_rust_core::AgentToken::parse(agent.token()).unwrap();
    assert!(!format!("{parsed:?}").contains(agent.token()));
    let prepared =
        aauth_rust_signature_key::PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    assert!(!format!("{prepared:?}").contains(agent.token()));
}

#[test]
fn admission_policy_sees_the_authenticated_method_and_query() {
    let (agent, resource) = composition();
    use aauth_rust_resource::BoxedPolicy;
    use std::sync::Arc;
    let policy: BoxedPolicy = Box::new(|_: &VerifiedAgentToken, req: &Request<Vec<u8>>| {
        req.method() == http::Method::GET && req.uri().query() == Some("scope=read")
    });
    let resource: Arc<AgentIdentityResource<AgentProviderKeys, BoxedPolicy>> =
        Arc::new(resource.with_policy(policy));
    for (method, query, allowed) in [
        ("GET", "scope=read", true),
        ("POST", "scope=read", false),
        ("GET", "scope=write", false),
    ] {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("https://resource.example/whoami?{query}"))
            .body(Vec::new())
            .unwrap();
        agent.sign(&mut req, 1000).unwrap();
        let decision = resource.authorize(&req, 1000);
        assert_eq!(matches!(decision, Decision::Granted(_)), allowed);
        if !allowed {
            assert!(matches!(decision, Decision::Forbidden));
        }
    }
}

#[test]
fn verified_identity_can_be_cloned_into_handler_state() {
    let (agent, resource) = composition();
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    let Decision::Granted(token) = resource.authorize(&req, 1000) else {
        panic!("valid identity refused")
    };
    let owned: VerifiedAgentToken = token.token().clone();
    assert_eq!(owned.compact(), agent.token());
    assert_eq!(owned.claims().sub, token.claims().sub);
}

#[test]
fn origin_form_refusal_explains_the_absolute_https_integration_requirement() {
    let (_, resource) = composition();
    let request = Request::builder().uri("/whoami").body(Vec::new()).unwrap();
    let Decision::SignatureFailure(error) = resource.authorize(&request, 1000) else {
        panic!("relative target accepted")
    };
    assert!(error.to_string().contains("absolute HTTPS"), "{error}");
    assert_eq!(error.code(), "invalid_signature");
}

#[test]
fn a_post_body_added_after_signing_is_refused_before_policy() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = resource.with_policy(move |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
        seen.fetch_add(1, Ordering::SeqCst);
        true
    });
    let mut req = Request::builder()
        .method("POST")
        .uri("https://resource.example/whoami")
        .body(Vec::new())
        .unwrap();
    agent.sign(&mut req, 1000).unwrap();
    *req.body_mut() = br#"{"operation":"tampered"}"#.to_vec();
    let Decision::SignatureFailure(error) = resource.authorize(&req, 1000) else {
        panic!("body accepted")
    };
    assert_eq!(error.code(), "invalid_input");
    assert!(
        matches!(error, aauth_rust_resource::SignatureFailure::Input(ref fields) if fields.contains(&"content-digest"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    req.body_mut().clear();
    assert!(matches!(
        resource.authorize(&req, 1000),
        Decision::Granted(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn future_iat_accepts_exactly_sixty_seconds_and_refuses_sixty_one() {
    let (agent, resource) = composition();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    let provider =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    for (iat, accepted) in [(1060, true), (1061, false)] {
        claims.iat = iat;
        let agent = Agent::new(
            SigningKey::from_seed([2; 32]),
            provider.issue(&claims).unwrap(),
        )
        .unwrap();
        let mut req = request();
        agent.sign(&mut req, 1000).unwrap();
        let decision = resource.authorize(&req, 1000);
        assert_eq!(
            matches!(decision, Decision::Granted(_)),
            accepted,
            "iat={iat}"
        );
        if !accepted {
            let response = decision.into_response();
            assert_eq!(response.status(), 401);
            assert_eq!(response.headers()["signature-error"], "error=clock_skew");
            assert_eq!(response.headers()["date"], "Thu, 01 Jan 1970 00:16:40 GMT");
        }
    }
    let mut req = request();
    agent.sign(&mut req, 1061).unwrap();
    let response = resource.authorize(&req, 1000).into_response();
    assert_eq!(response.headers()["signature-error"], "error=clock_skew");
    assert_eq!(response.headers()["date"], "Thu, 01 Jan 1970 00:16:40 GMT");
}

#[test]
fn foreign_issuer_is_a_terminal_trust_failure_on_the_wire() {
    let (agent, resource) = composition();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    claims.iss = "https://attacker.example".into();
    claims.sub = "aauth:Agent@attacker.example".into();
    let foreign_provider =
        AgentProvider::new(&claims.iss, "ap-1", SigningKey::from_seed([8; 32])).unwrap();
    let agent = Agent::new(
        SigningKey::from_seed([2; 32]),
        foreign_provider.issue(&claims).unwrap(),
    )
    .unwrap();
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    let decision = resource.authorize(&req, 1000);
    assert!(matches!(
        decision,
        Decision::SignatureFailure(aauth_rust_resource::SignatureFailure::Token(
            aauth_rust_core::TokenError::UntrustedIssuer
        ))
    ));
    let response = decision.into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["signature-error"], "error=invalid_key");
    let problem: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(problem["type"], "urn:ietf:params:sig-error:invalid_key");
    assert_eq!(problem["error"], "invalid_key");
}

#[test]
fn ap_issuance_refuses_millisecond_timestamps_before_serializing() {
    let (agent, _) = composition();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    claims.iat = (1_i64 << 33) - 2;
    claims.exp = (1_i64 << 33) - 1;
    ap.issue(&claims).unwrap();
    for (iat, exp) in [
        (1_800_000_000_000, 1_800_000_000_300),
        ((1_i64 << 33) - 1, 1_i64 << 33),
    ] {
        claims.iat = iat;
        claims.exp = exp;
        assert_eq!(
            ap.issue(&claims).unwrap_err(),
            aauth_rust_core::TokenError::InvalidTokenLifetime
        );
    }
}

#[test]
fn refreshing_an_agents_token_reuses_the_key_and_keeps_the_old_agent_usable() {
    let (agent, resource) = composition();
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let mut claims = aauth_rust_core::AgentToken::parse(agent.token())
        .unwrap()
        .unverified_claims()
        .clone();
    claims.jti = "refreshed-2".into();
    claims.exp = 3000;
    let next = agent.with_token(ap.issue(&claims).unwrap()).unwrap();
    for current in [&agent, &next] {
        let mut req = request();
        current.sign(&mut req, 1000).unwrap();
        assert!(matches!(
            resource.authorize(&req, 1000),
            Decision::Granted(_)
        ));
    }
    claims.cnf.jwk = SigningKey::from_seed([9; 32]).public_jwk();
    assert!(agent.with_token(ap.issue(&claims).unwrap()).is_err());
}

#[test]
fn typed_policy_carries_verified_upstream_identity_to_the_handler_once() {
    use aauth_rust_resource::Deny;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let resource = resource.with_policy(
        move |_: &VerifiedAgentToken, req: &Request<Vec<u8>>| -> Result<VerifiedAgentToken, Deny> {
            seen.fetch_add(1, Ordering::SeqCst);
            let compact = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("AAuth-Upstream "))
                .ok_or(Deny)?;
            aauth_rust_core::AgentToken::parse(compact)
                .and_then(|token| token.verify(&keys, 1000))
                .map_err(|_| Deny)
        },
    );
    let mut req = request();
    req.headers_mut().insert(
        "authorization",
        format!("AAuth-Upstream {}", agent.token()).parse().unwrap(),
    );
    agent.sign(&mut req, 1000).unwrap();
    let (caller, upstream) = resource.authorize(&req, 1000).into_result().unwrap();
    assert_eq!(caller.claims().sub, "aauth:Agent@ap.example");
    assert_eq!(upstream.compact(), agent.token());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    req.headers_mut().remove("authorization");
    agent.sign(&mut req, 1000).unwrap();
    let response = resource.authorize(&req, 1000).into_result().unwrap_err();
    assert_eq!(response.status(), 403);
    assert!(!response.headers().contains_key("signature-error"));
}

#[test]
fn identical_proofs_are_accepted_twice_inside_the_window_without_host_replay_policy() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = resource.with_policy(move |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
        seen.fetch_add(1, Ordering::SeqCst);
        true
    });
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    for now in [1000, 1060] {
        assert!(matches!(
            resource.authorize(&req, now),
            Decision::Granted(_)
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        resource.authorize(&req, 1061),
        Decision::SignatureFailure(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn agent_public_jwk_supports_renewal_without_exposing_or_mutating_the_proof_key() {
    let (agent, resource) = composition();
    let public = agent.public_jwk();
    public.validate().unwrap();
    assert_eq!(
        public.thumbprint().unwrap(),
        SigningKey::from_seed([2; 32])
            .public_jwk()
            .thumbprint()
            .unwrap()
    );
    assert_eq!(
        serde_json::to_value(&public)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["alg", "crv", "kty", "x"]
    );
    let mut caller_copy = agent.public_jwk();
    caller_copy.x.clear();
    assert_eq!(
        agent.public_jwk().thumbprint().unwrap(),
        public.thumbprint().unwrap()
    );

    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let renewed_claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent@ap.example".into(),
        jti: "renewal-public-key".into(),
        iat: 1000,
        exp: 3000,
        cnf: Confirmation {
            jwk: agent.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let renewed = agent
        .with_token(ap.issue(&renewed_claims).unwrap())
        .unwrap();
    for signer in [&agent, &renewed] {
        let mut request = request();
        signer.sign(&mut request, 1000).unwrap();
        assert!(matches!(
            resource.authorize(&request, 1000),
            Decision::Granted(_)
        ));
    }
}

#[test]
fn signed_json_content_reaches_policy_only_after_actual_digest_verification() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, resource) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource =
        resource.with_policy(move |_: &VerifiedAgentToken, request: &Request<Vec<u8>>| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok::<_, aauth_rust_resource::Deny>(request.body().clone())
        });
    let mut request = Request::builder()
        .method("POST")
        .uri("https://resource.example/whoami")
        .header("content-type", "application/json")
        .body(br#"{"operation":"reserve"}"#.to_vec())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    let (token, content) = resource.authorize(&request, 1000).into_result().unwrap();
    assert_eq!(token.claims().sub, "aauth:Agent@ap.example");
    assert_eq!(content, request.body().as_slice());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for body in [br#"{"operation":"delete"}"#.to_vec(), Vec::new()] {
        let mut changed = request.clone();
        *changed.body_mut() = body;
        let response = resource.authorize(&changed, 1000).into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["signature-error"],
            "error=invalid_signature"
        );
    }
    let mut changed_type = request.clone();
    changed_type
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    let response = resource.authorize(&changed_type, 1000).into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["signature-error"],
        "error=invalid_signature"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn resource_metadata_describes_only_the_implemented_verifier_profile() {
    let (_, resource) = composition();
    let metadata: serde_json::Value =
        serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata,
        serde_json::json!({
            "issuer":"https://resource.example", "access_mode":"agent-token", "signature_window":60
        })
    );
    for endpoint in [
        "https://resource.example:8443/whoami",
        "https://127.0.0.1/whoami",
    ] {
        let resource = AgentIdentityResource::new(
            endpoint,
            resource_keys(),
            |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
        )
        .unwrap();
        assert!(
            resource.metadata().is_err(),
            "invalid server identifier published: {endpoint}"
        );
    }
}

#[test]
fn metadata_failure_is_a_local_configuration_error() {
    let resource = AgentIdentityResource::for_origin(
        "https://resource.example:8443",
        resource_keys(),
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    let error = resource.metadata().unwrap_err();
    assert_eq!(error.code(), "invalid_configuration");
    assert!(error.to_string().contains("metadata_for"));
}

#[test]
fn published_identity_is_independent_of_the_signed_request_authority() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, _) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = AgentIdentityResource::for_origin(
        "https://resource.example:8443/",
        resource_keys(),
        move |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        },
    )
    .unwrap();
    let metadata: serde_json::Value =
        serde_json::from_slice(&resource.metadata_for("https://resource.example").unwrap())
            .unwrap();
    assert_eq!(metadata["issuer"], "https://resource.example");
    for (authority, accepted) in [
        ("resource.example:8443", true),
        ("resource.example", false),
        ("resource.example:8444", false),
        ("foreign.example:8443", false),
    ] {
        let mut request = Request::builder()
            .uri(format!("https://{authority}/orders"))
            .body(Vec::new())
            .unwrap();
        agent.sign(&mut request, 1000).unwrap();
        assert_eq!(
            matches!(resource.authorize(&request, 1000), Decision::Granted(_)),
            accepted,
            "authority {authority}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_metadata_issuer_is_validated_without_normalizing_server_identifiers() {
    // A root slash is convenient transport syntax, but is not a server identifier.
    let resource = AgentIdentityResource::for_origin(
        "https://127.0.0.1:8443/",
        resource_keys(),
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    assert!(resource.metadata_for("https://resource.example").is_ok());
    for issuer in [
        "http://resource.example",
        "https://Resource.example",
        "https://resource.example/",
        "https://resource.example:443",
        "https://resource.example:8443",
        "https://resource.example/api",
        "https://resource.example?x=1",
        "https://resource.example#part",
        "https://user@resource.example",
        "https://127.0.0.1",
    ] {
        let error = resource.metadata_for(issuer).unwrap_err();
        assert_eq!(error.code(), "invalid_configuration", "issuer {issuer}");
    }
}

#[test]
fn oversized_buffered_content_is_a_request_failure_not_a_bad_signature() {
    let (agent, resource) = composition();
    let mut req = request();
    agent.sign(&mut req, 1000).unwrap();
    *req.body_mut() = vec![0; aauth_rust_signature_key::MAX_BODY_BYTES + 1];
    let response = resource.authorize(&req, 1000).into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["signature-error"],
        "error=invalid_request"
    );
    let problem: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(problem["type"], "urn:ietf:params:sig-error:invalid_request");
}

fn resource_keys() -> AgentProviderKeys {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap()
}

#[test]
fn one_origin_resource_and_its_replaced_policy_serve_distinct_signed_paths() {
    let (agent, _) = composition();
    let resource = AgentIdentityResource::for_origin(
        "https://resource.example",
        resource_keys(),
        |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    let resource = resource.with_policy(|_: &VerifiedAgentToken, request: &Request<Vec<u8>>| {
        Ok::<_, aauth_rust_resource::Deny>(
            request.uri().path_and_query().unwrap().as_str().to_owned(),
        )
    });
    for path in ["/whoami", "/orders/123?sku=cat%2Ftree"] {
        let mut request = Request::builder()
            .uri(format!("https://resource.example{path}"))
            .body(Vec::new())
            .unwrap();
        agent.sign(&mut request, 1000).unwrap();
        let (_, admitted) = resource.authorize(&request, 1000).into_result().unwrap();
        assert_eq!(admitted, path);
    }
}

#[test]
fn origin_binding_still_requires_the_actual_signed_path_and_configured_authority() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (agent, _) = composition();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let resource = AgentIdentityResource::for_origin(
        "https://resource.example/",
        resource_keys(),
        move |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        },
    )
    .unwrap();
    let mut request = request();
    agent.sign(&mut request, 1000).unwrap();
    *request.uri_mut() = "https://resource.example/orders/123".parse().unwrap();
    assert!(matches!(
        resource.authorize(&request, 1000),
        Decision::SignatureFailure(_)
    ));
    *request.uri_mut() = "https://foreign.example/whoami".parse().unwrap();
    agent.sign(&mut request, 1000).unwrap();
    assert!(matches!(
        resource.authorize(&request, 1000),
        Decision::SignatureFailure(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_origin_constructor_rejects_endpoint_paths_queries_and_invalid_origins() {
    for origin in [
        "/whoami",
        "http://resource.example",
        "https://resource.example/api",
        "https://resource.example?x=1",
        "https://resource.example#part",
        "https://user@resource.example",
        "https://resource.example:99999",
        "https://resource.example:0",
        "https://resource.example:0000",
    ] {
        assert!(
            AgentIdentityResource::for_origin(
                origin,
                resource_keys(),
                |_: &VerifiedAgentToken, _: &Request<Vec<u8>>| true
            )
            .is_err(),
            "accepted {origin}"
        );
    }
}
