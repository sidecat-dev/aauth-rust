use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, Confirmation, PersonClaims, ResourceToken,
    TokenError, TrustedIssuerKeys, VerifiedAuthToken, mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::{
    AuthDecision, AuthorizationAsk, BoxedAuthAdmissionPolicy, Deny, PsAuthorizationConfig,
    PsAuthorizationResource,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const NOW: i64 = 1000;
const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";
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
        &serde_json::to_vec(&json!({"issuer":issuer,"jwks_uri":format!("{issuer}/keys")})).unwrap(),
        &serde_json::to_vec(&json!({"keys":[jwk]})).unwrap(),
    )
    .unwrap()
}
fn keys() -> Keys {
    Keys(vec![
        issuer_key("https://ap.example", "aauth-agent.json", 1, "ap-1"),
        issuer_key(PS, "aauth-person.json", 3, "ps-1"),
        issuer_key(RESOURCE, "aauth-resource.json", 4, "resource-1"),
    ])
}
fn agent() -> Agent {
    let proof = SigningKey::from_seed([2; 32]);
    let token = AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:reader@ap.example".into(),
            jti: "agent-1".into(),
            iat: NOW,
            exp: 4000,
            cnf: Confirmation {
                jwk: proof.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(proof, token).unwrap()
}
fn person_claims() -> PersonClaims {
    PersonClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "person-1".into(),
        iat: NOW,
        exp: 3000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        nbf: None,
        tenant: Some("team".into()),
        mission_s256: None,
        extra: Default::default(),
    }
}
fn person() -> String {
    mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &person_claims()).unwrap()
}
fn auth_claims() -> AuthClaims {
    AuthClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "auth-1".into(),
        iat: NOW,
        exp: 2500,
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
    }
}
fn auth(claims: &AuthClaims) -> String {
    mint_auth_token(&SigningKey::from_seed([3; 32]), "ps-1", claims).unwrap()
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
type Policy = BoxedAuthAdmissionPolicy<String>;
type Resource = PsAuthorizationResource<Keys, Policy>;
fn resource(calls: Arc<AtomicUsize>, allow: bool) -> Resource {
    PsAuthorizationResource::new(
        config(),
        keys(),
        Box::new(
            move |token: &VerifiedAuthToken, request: &Request<Vec<u8>>| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(token.claims().sub, "directed-person");
                assert_eq!(request.uri().path(), "/records");
                if allow {
                    Ok("host-context".into())
                } else {
                    Err(Deny)
                }
            },
        ) as Policy,
    )
    .unwrap()
}
fn request() -> Request<Vec<u8>> {
    Request::builder()
        .uri(format!("{ORIGIN}/records"))
        .body(Vec::new())
        .unwrap()
}
fn signed(token: &str) -> Request<Vec<u8>> {
    let mut req = request();
    sign_request(
        &mut req,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(token.into()),
        NOW,
    )
    .unwrap();
    req
}
fn challenge_token(response: &http::Response<Vec<u8>>) -> &str {
    assert_eq!(response.status(), 401);
    assert!(!response.headers().contains_key("signature-error"));
    response.headers()["aauth-requirement"]
        .to_str()
        .unwrap()
        .strip_prefix("requirement=auth-token;resource-token=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap()
}

#[test]
fn no_proof_and_verified_agent_proof_require_person_without_policy() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    for req in [request(), signed(agent().token())] {
        let response = resource.authorize(&req, NOW, "challenge-1").into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["aauth-requirement"],
            "requirement=person-token"
        );
        assert!(!response.headers().contains_key("signature-error"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn verified_person_challenges_without_admission_and_copies_exact_lineage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    let response = resource
        .authorize(&signed(&person()), NOW, "challenge-1")
        .into_response();
    let compact = challenge_token(&response);
    let verified = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    let c = verified.claims();
    assert_eq!(
        (&c.iss, &c.aud, &c.ps, &c.sub, &c.presented_jti),
        (
            &RESOURCE.to_string(),
            &PS.to_string(),
            &PS.to_string(),
            &"directed-person".to_string(),
            &"person-1".to_string()
        )
    );
    assert_eq!(c.agent_jkt, agent().public_jwk().thumbprint().unwrap());
    assert_eq!(c.tenant.as_deref(), Some("team"));
    assert_eq!(c.scope.as_deref(), Some("records.read"));
    assert_eq!((c.iat, c.exp), (1000, 1300));
    assert!(c.mission_s256.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let validated = agent()
        .verify_resource_challenge(compact, RESOURCE, PS, &person(), &keys(), NOW)
        .unwrap();
    assert_eq!(validated.compact(), compact);
}

#[test]
fn auth_admission_carries_verified_auth_and_host_context() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    let compact = auth(&auth_claims());
    let (verified, context) = resource
        .authorize(&signed(&compact), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(verified.compact(), compact);
    assert_eq!(context, "host-context");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let denied = resource::denied_response();
    assert_eq!(denied.status(), 403);
    assert!(!denied.headers().contains_key("signature-error"));
}
mod resource {
    use super::*;
    pub fn denied_response() -> http::Response<Vec<u8>> {
        super::resource(Arc::new(AtomicUsize::new(0)), false)
            .authorize(&signed(&auth(&auth_claims())), NOW, "unused")
            .into_response()
    }
}

#[test]
fn invalid_target_token_key_scope_and_body_never_reach_policy() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    let base = auth_claims();
    for mutate in [
        |c: &mut AuthClaims| c.aud = "https://other.example".into(),
        |c: &mut AuthClaims| c.scope = Some("records.write".into()),
        |c: &mut AuthClaims| c.cnf.jwk = SigningKey::from_seed([9; 32]).public_jwk(),
        |c: &mut AuthClaims| c.iat = 1061,
        |c: &mut AuthClaims| {
            c.iat = 0;
            c.exp = 1000;
        },
        |c: &mut AuthClaims| {
            c.mission_s256 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
        },
        |c: &mut AuthClaims| {
            c.extra.insert("budget".into(), json!({"amount":"1"}));
        },
    ] {
        let mut claims = base.clone();
        mutate(&mut claims);
        assert!(
            resource
                .authorize(&signed(&auth(&claims)), NOW, "unused")
                .into_result()
                .is_err()
        );
    }
    let mut wrong_target = signed(&auth(&base));
    *wrong_target.uri_mut() = "https://other.example/records".parse().unwrap();
    assert!(
        resource
            .authorize(&wrong_target, NOW, "unused")
            .into_result()
            .is_err()
    );
    let mut body = signed(&auth(&base));
    *body.body_mut() = b"tampered".to_vec();
    assert!(
        resource
            .authorize(&body, NOW, "unused")
            .into_result()
            .is_err()
    );
    let mut signature = signed(&auth(&base));
    signature.headers_mut().insert("signature","sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:".parse().unwrap());
    assert!(
        resource
            .authorize(&signature, NOW, "unused")
            .into_result()
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn person_audience_and_default_mission_are_checked_before_challenge() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    for mut claims in [person_claims(), person_claims()].into_iter().enumerate() {
        if claims.0 == 0 {
            claims.1.aud = "https://other.example".into();
        } else {
            claims.1.mission_s256 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        }
        let compact =
            mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &claims.1).unwrap();
        let response = resource
            .authorize(&signed(&compact), NOW, "challenge-1")
            .into_response();
        assert_ne!(response.status(), 200);
        assert!(!response.headers().contains_key("aauth-requirement"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn resource_metadata_and_config_advertise_only_the_implemented_role() {
    let resource = resource(Arc::new(AtomicUsize::new(0)), true);
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(metadata["issuer"], RESOURCE);
    assert_eq!(metadata["access_mode"], "auth-token");
    assert_eq!(
        metadata["jwks_uri"],
        format!("{RESOURCE}/.well-known/jwks.json")
    );
    assert!(metadata.get("authorization_endpoint").is_none());
    assert!(metadata.get("revocation_endpoint").is_none());
    TrustedIssuerKeys::from_documents(
        RESOURCE,
        "aauth-resource.json",
        &resource.metadata().unwrap(),
        &resource.jwks().unwrap(),
    )
    .unwrap();
    for mutate in [
        |c: &mut PsAuthorizationConfig| c.issuer = format!("{RESOURCE}:8443"),
        |c: &mut PsAuthorizationConfig| c.signed_origin = format!("{ORIGIN}/records"),
        |c: &mut PsAuthorizationConfig| c.kid = String::new(),
        |c: &mut PsAuthorizationConfig| c.scopes.clear(),
        |c: &mut PsAuthorizationConfig| c.scopes = vec!["read".into(), "read".into()],
        |c: &mut PsAuthorizationConfig| c.scopes = vec!["read write".into()],
    ] {
        let mut config = config();
        mutate(&mut config);
        assert!(
            PsAuthorizationResource::new(
                config,
                keys(),
                |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true
            )
            .is_err()
        );
    }
}

#[test]
fn configured_scope_descriptions_are_published_without_an_invented_endpoint() {
    use std::collections::BTreeMap;
    let resource = resource(Arc::new(AtomicUsize::new(0)), true)
        .with_scope_descriptions(BTreeMap::from([(
            "records.read".into(),
            "Read the frozen revision".into(),
        )]))
        .unwrap();
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata["scope_descriptions"]["records.read"],
        "Read the frozen revision"
    );
    assert!(metadata.get("authorization_endpoint").is_none());
    assert!(superfluous_scope_descriptions_are_refused());
}
fn superfluous_scope_descriptions_are_refused() -> bool {
    resource(Arc::new(AtomicUsize::new(0)), true)
        .with_scope_descriptions(std::collections::BTreeMap::from([(
            "admin".into(),
            "Unconfigured privilege".into(),
        )]))
        .is_err()
}

// Core70d6737: the Resource consumes authenticated mission context, not the
// mission description or a host's human-review fixture. Existing public APIs
// must preserve that context through the Person challenge and Auth admission.
const CURRENT_MISSION: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn current_mission_person_context_reaches_the_signed_resource_challenge() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true).with_mission_context();
    let mut claims = person_claims();
    claims.mission_s256 = Some(CURRENT_MISSION.into());
    let compact = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &claims).unwrap();
    let response = resource
        .authorize(&signed(&compact), NOW, "mission-challenge")
        .into_response();
    let challenge = challenge_token(&response);
    let verified = ResourceToken::parse(challenge)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(
        verified.claims().mission_s256.as_deref(),
        Some(CURRENT_MISSION)
    );
    assert_eq!(verified.claims().presented_jti, claims.jti);
    assert_eq!(verified.claims().ps, PS);
    assert_eq!(verified.claims().sub, claims.sub);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Person identity is not Auth admission"
    );
    agent()
        .verify_resource_challenge(challenge, RESOURCE, PS, &compact, &keys(), NOW)
        .unwrap();
}

#[test]
fn current_mission_auth_digest_reaches_host_policy() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let policy: Policy = Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
        observed.fetch_add(1, Ordering::SeqCst);
        if token.claims().mission_s256.as_deref() == Some(CURRENT_MISSION) {
            Ok("approved-mission".to_owned())
        } else {
            Err(Deny)
        }
    });
    let resource = PsAuthorizationResource::new(config(), keys(), policy)
        .unwrap()
        .with_mission_context();
    let mut claims = auth_claims();
    claims.mission_s256 = Some(CURRENT_MISSION.into());
    let compact = auth(&claims);
    let (verified, admitted) = resource
        .authorize(&signed(&compact), NOW, "unused")
        .into_result()
        .expect("valid PS-issued mission Auth credential must reach host admission");
    assert_eq!(
        verified.claims().mission_s256.as_deref(),
        Some(CURRENT_MISSION)
    );
    assert_eq!(verified.compact(), compact);
    assert_eq!(admitted, "approved-mission");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for substituted in [
        None,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned()),
    ] {
        let mut changed = claims.clone();
        changed.mission_s256 = substituted;
        let response = resource
            .authorize(&signed(&auth(&changed)), NOW, "unused")
            .into_response();
        assert_eq!(
            response.status(),
            403,
            "host must refuse another/missing mission"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn federated_resource_refuses_a_mission_even_when_direct_context_is_enabled() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut snapshots = keys().0;
    snapshots.push(issuer_key(PS, "aauth-access.json", 3, "ps-1"));
    let resource = PsAuthorizationResource::new_federated(
        config(),
        PS,
        Keys(snapshots),
        Box::new(move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok("should-not-run".to_owned())
        }) as Policy,
    )
    .unwrap()
    .with_mission_context();
    let mut person = person_claims();
    person.mission_s256 = Some(CURRENT_MISSION.into());
    let person = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &person).unwrap();
    let challenged = resource
        .authorize(&signed(&person), NOW, "mission-challenge")
        .into_response();
    assert_eq!(challenged.status(), 401);
    assert!(!challenged.headers().contains_key("aauth-requirement"));
    let mut auth_claims = auth_claims();
    auth_claims.mission_s256 = Some(CURRENT_MISSION.into());
    auth_claims.iss = PS.into();
    auth_claims.dwk = "aauth-access.json".into();
    let admitted = resource
        .authorize(&signed(&auth(&auth_claims)), NOW, "unused")
        .into_result();
    assert!(admitted.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn retained_agent_key_signs_person_and_auth_without_asserting_issuer_trust() {
    let agent = agent();
    for token in [person(), auth(&auth_claims())] {
        let holder = agent.with_token(token.clone()).unwrap();
        assert_eq!(holder.token(), token);
        let resource = resource(Arc::new(AtomicUsize::new(0)), true);
        let mut req = request();
        holder.sign(&mut req, NOW).unwrap();
        assert!(!matches!(
            resource.authorize(&req, NOW, "challenge"),
            AuthDecision::SignatureFailure(_)
        ));
    }
    let mut claims = person_claims();
    claims.cnf.jwk = SigningKey::from_seed([9; 32]).public_jwk();
    let token = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &claims).unwrap();
    assert_eq!(
        agent.with_token(token).err().unwrap(),
        TokenError::ConfirmationKeyMismatch
    );
    assert!(Agent::new(SigningKey::from_seed([2; 32]), person()).is_err());
    let untrusted =
        mint_person_token(&SigningKey::from_seed([9; 32]), "ps-1", &person_claims()).unwrap();
    let holder = agent.with_token(untrusted).unwrap();
    let mut req = request();
    holder.sign(&mut req, NOW).unwrap();
    assert!(matches!(
        resource(Arc::new(AtomicUsize::new(0)), true).authorize(&req, NOW, "challenge"),
        AuthDecision::SignatureFailure(_)
    ));
}

#[test]
fn challenge_and_delivery_bind_the_actual_target_parent_and_proof_key() {
    let agent = agent();
    let parent = person();
    let resource = resource(Arc::new(AtomicUsize::new(0)), true);
    let response = resource
        .authorize(&signed(&parent), NOW, "challenge")
        .into_response();
    let compact = challenge_token(&response);
    let verified = agent
        .verify_resource_challenge(compact, RESOURCE, PS, &parent, &keys(), NOW)
        .unwrap();
    let auth = auth(&auth_claims());
    let delivered = agent
        .verify_auth_delivery(&auth, RESOURCE, &verified, &parent, &keys(), NOW)
        .unwrap();
    assert_eq!(delivered.compact(), auth);
    assert!(
        agent
            .verify_resource_challenge(compact, "https://other.example", PS, &parent, &keys(), NOW)
            .is_err()
    );
    assert!(
        agent
            .verify_resource_challenge(
                compact,
                RESOURCE,
                "https://other.example",
                &parent,
                &keys(),
                NOW
            )
            .is_err()
    );
    let mut replaced = person_claims();
    replaced.jti = "replacement".into();
    let replaced = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &replaced).unwrap();
    assert!(
        agent
            .verify_resource_challenge(compact, RESOURCE, PS, &replaced, &keys(), NOW)
            .is_err()
    );
    assert!(
        agent
            .verify_auth_delivery(
                &auth,
                "https://other.example",
                &verified,
                &parent,
                &keys(),
                NOW
            )
            .is_err()
    );
    for mutate in [
        |c: &mut AuthClaims| c.sub = "other-person".into(),
        |c: &mut AuthClaims| c.exp = 3001,
        |c: &mut AuthClaims| c.scope = Some("records.write".into()),
        |c: &mut AuthClaims| c.tenant = None,
        |c: &mut AuthClaims| c.cnf.jwk = SigningKey::from_seed([9; 32]).public_jwk(),
    ] {
        let mut claims = auth_claims();
        mutate(&mut claims);
        let raw = mint_auth_token(&SigningKey::from_seed([3; 32]), "ps-1", &claims).unwrap();
        assert!(
            agent
                .verify_auth_delivery(&raw, RESOURCE, &verified, &parent, &keys(), NOW)
                .is_err()
        );
    }
}

#[test]
fn valid_auth_from_access_discovery_cannot_enter_ps_authorization_resource() {
    let mut claims = auth_claims();
    claims.dwk = "aauth-access.json".into();
    let mut trusted = keys();
    trusted.0[1] = issuer_key(PS, "aauth-access.json", 3, "ps-1");
    let resource = PsAuthorizationResource::new(
        config(),
        trusted,
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    assert!(
        resource
            .authorize(&signed(&auth(&claims)), NOW, "unused")
            .into_result()
            .is_err()
    );
}

#[test]
fn auth_challenge_debug_does_not_print_forwardable_token_bytes() {
    let resource = resource(Arc::new(AtomicUsize::new(0)), true);
    let decision = resource.authorize(&signed(&person()), NOW, "challenge");
    let AuthDecision::AuthTokenRequired { resource_token } = &decision else {
        panic!("missing challenge")
    };
    assert!(!format!("{decision:?}").contains(resource_token));
}

#[test]
fn boxed_auth_boolean_policy_captures_service_state() {
    use aauth_rust_resource::BoxedAuthPolicy;
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = calls.clone();
    let policy: BoxedAuthPolicy = Box::new(move |token, request| {
        captured.fetch_add(1, Ordering::SeqCst);
        token.claims().sub == "directed-person" && request.uri().path() == "/records"
    });
    let resource: PsAuthorizationResource<Keys, BoxedAuthPolicy> =
        PsAuthorizationResource::new(config(), keys(), policy).unwrap();
    assert!(
        resource
            .authorize(&signed(&auth(&auth_claims())), NOW, "unused")
            .into_result()
            .is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn wrong_audience_has_a_specific_diagnostic_without_challenge_or_policy() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    let mut identity = person_claims();
    identity.aud = "https://other.example".into();
    let mut authorization = auth_claims();
    authorization.aud = "https://other.example".into();
    for compact in [
        mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &identity).unwrap(),
        auth(&authorization),
    ] {
        let decision = resource.authorize(&signed(&compact), NOW, "unused");
        let AuthDecision::SignatureFailure(aauth_rust_resource::SignatureFailure::Token(error)) =
            &decision
        else {
            panic!("expected token refusal, got {decision:?}");
        };
        assert_eq!(*error, TokenError::AudienceMismatch);
        assert!(error.to_string().contains("audience"), "{error}");
        let response = decision.into_response();
        assert_eq!(response.status(), 401);
        // Keep the pinned Signature-Key code while diagnosing the actual fix.
        assert_eq!(response.headers()["signature-error"], "error=invalid_jwt");
        assert!(!response.headers().contains_key("aauth-requirement"));
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_jwt");
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|value| value.contains("audience"))
        );
        assert!(!String::from_utf8_lossy(response.body()).contains(&compact));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn explicit_federation_pins_as_and_role_even_when_collocated() {
    // Core PS-AS Collapse / Auth Token Verification: issuer alone is insufficient.
    let mut snapshots = keys().0;
    snapshots.push(issuer_key(PS, "aauth-access.json", 3, "ps-1"));
    let keys = Keys(snapshots);
    let resource = PsAuthorizationResource::new_federated(
        config(),
        PS,
        keys.clone(),
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    let person = person();
    let response = resource
        .authorize(&signed(&person), NOW, "challenge")
        .into_response();
    let challenge = ResourceToken::parse(challenge_token(&response))
        .unwrap()
        .verify(&keys, NOW)
        .unwrap();
    assert_eq!(challenge.claims().aud, PS);
    assert_eq!(challenge.claims().ps, PS);
    let mut claims = auth_claims();
    assert!(
        resource
            .authorize(&signed(&auth(&claims)), NOW, "unused")
            .into_result()
            .is_err()
    );
    claims.dwk = "aauth-access.json".into();
    assert!(
        resource
            .authorize(&signed(&auth(&claims)), NOW, "unused")
            .into_result()
            .is_ok()
    );
    let direct = PsAuthorizationResource::new(
        config(),
        keys.clone(),
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )
    .unwrap();
    assert!(
        direct
            .authorize(&signed(&auth(&claims)), NOW, "unused")
            .into_result()
            .is_err()
    );
    let context = aauth_rust_agent::FederatedContext {
        resource: RESOURCE,
        person_server: PS,
        access_server: PS,
        presented_token: &person,
    };
    let holder = agent();
    holder
        .verify_federated_resource_challenge(challenge_token(&response), &context, &keys, NOW)
        .unwrap();
    holder
        .verify_federated_auth_delivery(&auth(&claims), &challenge, &context, &keys, NOW)
        .unwrap();
    claims.iss = "https://foreign.example".into();
    assert!(
        holder
            .verify_federated_auth_delivery(&auth(&claims), &challenge, &context, &keys, NOW)
            .is_err()
    );
}

fn assert_verified_mismatch(response: &http::Response<Vec<u8>>) {
    assert_eq!(response.status(), 403);
    assert!(!response.headers().contains_key("signature-error"));
    assert!(!response.headers().contains_key("aauth-requirement"));
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "access_denied");
}

fn asked() -> AuthorizationAsk {
    AuthorizationAsk {
        ps: PS.into(),
        login_hint: Some("alice@example.com".into()),
        sub: "directed-person".into(),
        account: Some("acct-1".into()),
        tenant: Some("team".into()),
    }
}

#[test]
fn resource_checks_auth_claims_against_the_ask_and_not_the_login_hint() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let resource = PsAuthorizationResource::new(
        config(),
        keys(),
        Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            observed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(token.claims().sub, "directed-person");
            assert_ne!(token.claims().sub, "alice@example.com");
            Ok("checked".to_owned())
        }) as Policy,
    )
    .unwrap();
    let response = resource
        .authorize_for(&signed(&person()), NOW, "hint-challenge", &asked())
        .into_response();
    let compact = challenge_token(&response);
    let challenge = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(
        challenge.claims().login_hint.as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(challenge.claims().ps, PS);
    assert_eq!(challenge.claims().sub, "directed-person");
    assert_eq!(challenge.claims().account.as_deref(), Some("acct-1"));
    assert_eq!(challenge.claims().tenant.as_deref(), Some("team"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut matching = auth_claims();
    matching.account = Some("acct-1".into());
    let (verified, admitted) = resource
        .authorize_for(&signed(&auth(&matching)), NOW, "unused", &asked())
        .into_result()
        .unwrap();
    assert_eq!(verified.claims().sub, "directed-person");
    assert_eq!(admitted, "checked");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut hinted_subject = matching.clone();
    hinted_subject.sub = "alice@example.com".into();
    hinted_subject.jti = "auth-hint-subject".into();
    let mut other_account = matching.clone();
    other_account.account = None;
    other_account.jti = "auth-other-account".into();
    let mut replaced_account = matching.clone();
    replaced_account.account = Some("acct-2".into());
    replaced_account.jti = "auth-replaced-account".into();
    let mut other_tenant = matching.clone();
    other_tenant.tenant = None;
    other_tenant.jti = "auth-other-tenant".into();
    let mut replaced_tenant = matching.clone();
    replaced_tenant.tenant = Some("other-team".into());
    replaced_tenant.jti = "auth-replaced-tenant".into();
    for claims in [
        hinted_subject,
        other_account,
        replaced_account,
        other_tenant,
        replaced_tenant,
    ] {
        let response = resource
            .authorize_for(&signed(&auth(&claims)), NOW, "unused", &asked())
            .into_response();
        assert_verified_mismatch(&response);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for ask in [
        AuthorizationAsk {
            ps: String::new(),
            ..asked()
        },
        AuthorizationAsk {
            sub: String::new(),
            ..asked()
        },
        AuthorizationAsk {
            login_hint: Some(String::new()),
            ..asked()
        },
        AuthorizationAsk {
            account: Some(String::new()),
            ..asked()
        },
        AuthorizationAsk {
            tenant: Some(String::new()),
            ..asked()
        },
    ] {
        assert_eq!(
            resource
                .authorize_for(&signed(&auth(&matching)), NOW, "unused", &ask)
                .into_response()
                .status(),
            500
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let no_hint = AuthorizationAsk {
        login_hint: None,
        ..asked()
    };
    let still = resource
        .authorize_for(&signed(&auth(&matching)), NOW, "unused", &no_hint)
        .into_result()
        .unwrap();
    assert_eq!(still.0.claims().sub, "directed-person");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let mut other_person = person_claims();
    other_person.sub = "someone-else".into();
    other_person.jti = "person-else".into();
    let other = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &other_person).unwrap();
    let refused = resource
        .authorize_for(&signed(&other), NOW, "hint-challenge", &asked())
        .into_response();
    assert_verified_mismatch(&refused);
    let mut other_tenant_person = person_claims();
    other_tenant_person.tenant = Some("other-team".into());
    other_tenant_person.jti = "person-other-tenant".into();
    let other_tenant = mint_person_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &other_tenant_person,
    )
    .unwrap();
    let refused_tenant = resource
        .authorize_for(&signed(&other_tenant), NOW, "hint-challenge", &asked())
        .into_response();
    assert_verified_mismatch(&refused_tenant);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn same_subject_from_another_person_server_does_not_match_the_ask() {
    const OTHER: &str = "https://other-ps.example";
    const ACCESS: &str = "https://as.example";
    let mut snapshots = keys().0;
    snapshots.push(issuer_key(OTHER, "aauth-person.json", 5, "other-1"));
    snapshots.push(issuer_key(ACCESS, "aauth-access.json", 6, "as-1"));
    let keyset = Keys(snapshots);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let resource = PsAuthorizationResource::new(
        config(),
        keyset.clone(),
        Box::new(move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok("checked".to_owned())
        }) as Policy,
    )
    .unwrap();
    let mut foreign_person = person_claims();
    foreign_person.iss = OTHER.into();
    foreign_person.jti = "person-other-ps".into();
    let foreign_person =
        mint_person_token(&SigningKey::from_seed([5; 32]), "other-1", &foreign_person).unwrap();
    let refused = resource
        .authorize_for(&signed(&foreign_person), NOW, "hint-challenge", &asked())
        .into_response();
    assert_verified_mismatch(&refused);
    let mut foreign_auth = auth_claims();
    foreign_auth.iss = OTHER.into();
    foreign_auth.ps = OTHER.into();
    foreign_auth.account = Some("acct-1".into());
    foreign_auth.jti = "auth-other-ps".into();
    let foreign_auth =
        mint_auth_token(&SigningKey::from_seed([5; 32]), "other-1", &foreign_auth).unwrap();
    assert_verified_mismatch(
        &resource
            .authorize_for(&signed(&foreign_auth), NOW, "unused", &asked())
            .into_response(),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let federated_calls = Arc::new(AtomicUsize::new(0));
    let federated_observed = federated_calls.clone();
    let federated = PsAuthorizationResource::new_federated(
        config(),
        ACCESS,
        keyset,
        Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            federated_observed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(token.claims().ps, PS);
            Ok("federated".to_owned())
        }) as Policy,
    )
    .unwrap();
    let admitted = federated
        .authorize_for(&signed(&person()), NOW, "fed-challenge", &asked())
        .into_response();
    assert!(admitted.headers().contains_key("aauth-requirement"));
    let mut access = auth_claims();
    access.iss = ACCESS.into();
    access.dwk = "aauth-access.json".into();
    access.account = Some("acct-1".into());
    access.jti = "auth-access".into();
    let (verified, context) = federated
        .authorize_for(
            &signed(&mint_auth_token(&SigningKey::from_seed([6; 32]), "as-1", &access).unwrap()),
            NOW,
            "unused",
            &asked(),
        )
        .into_result()
        .unwrap();
    assert_eq!(verified.claims().ps, PS);
    assert_eq!(context, "federated");
    access.ps = OTHER.into();
    access.jti = "auth-access-other-ps".into();
    assert_verified_mismatch(
        &federated
            .authorize_for(
                &signed(
                    &mint_auth_token(&SigningKey::from_seed([6; 32]), "as-1", &access).unwrap(),
                ),
                NOW,
                "unused",
                &asked(),
            )
            .into_response(),
    );
    assert_eq!(federated_calls.load(Ordering::SeqCst), 1);
}
