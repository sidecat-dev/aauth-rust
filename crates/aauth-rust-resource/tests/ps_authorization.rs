use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::interaction::ResourceInteraction;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, Confirmation, PersonClaims, ResourceToken,
    TokenError, TrustedIssuerKeys, VerifiedAuthToken, mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_resource::{
    AuthDecision, AuthorizationAsk, BoxedAuthAdmissionPolicy, Deny, ProactiveDecision,
    PsAuthorizationConfig, PsAuthorizationResource, PsConfigurationError,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::Request;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
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
        scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
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
        KeyMaterial::Jwt {
            jwt: token.into(),
            cache: false,
        },
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
fn a_resource_that_needs_its_own_flow_names_it_in_the_person_challenge() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true);
    let interaction = ResourceInteraction::open("https://resource.example/connect").unwrap();
    assert!(ResourceInteraction::open("https://resource.example/connect?x=1").is_err());
    let response = resource
        .authorize_with_interaction(&signed(&person()), NOW, "challenge-1", &interaction)
        .into_response();
    let compact = challenge_token(&response);
    let verified = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    let carried = ResourceInteraction::from_claims(verified.claims())
        .unwrap()
        .expect("the challenge carries the interaction claim");
    assert_eq!(carried, interaction);
    assert_eq!(carried.url(), "https://resource.example/connect");
    // The agent passes the challenge on unchanged; its lineage still verifies.
    agent()
        .verify_resource_challenge(compact, RESOURCE, PS, &person(), &keys(), NOW)
        .unwrap();
    // A plain challenge carries no claim, and an Auth token is judged as usual.
    let plain = resource
        .authorize(&signed(&person()), NOW, "challenge-2")
        .into_response();
    let plain = ResourceToken::parse(challenge_token(&plain))
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(
        ResourceInteraction::from_claims(plain.claims()).unwrap(),
        None
    );
    let admitted = resource.authorize_with_interaction(
        &signed(&auth(&auth_claims())),
        NOW,
        "challenge-3",
        &interaction,
    );
    assert!(matches!(admitted, AuthDecision::Granted(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Verified challenge claims, without the identifiers that differ per presentation.
fn challenge_claims(resource: &Resource, person: &str, challenge_jti: &str) -> Value {
    let response = resource
        .authorize(&signed(person), NOW, challenge_jti)
        .into_response();
    let verified = ResourceToken::parse(challenge_token(&response))
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    let mut claims = serde_json::to_value(verified.claims()).unwrap();
    let object = claims.as_object_mut().unwrap();
    assert_eq!(object.remove("jti"), Some(json!(challenge_jti)));
    object.remove("presented_jti");
    claims
}

// Core Person Token and Continuity, Not Identity Proofing: a person token is
// the same `(iss, sub)` again, not evidence of identity proofing, legal
// identity or an assurance level, and it never stands in for an auth token.
#[test]
fn a_person_token_is_continuity_not_identity_proofing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = resource(calls.clone(), true).with_authorization_endpoint();
    // Claims a person server might add about how it established the person.
    let mut proofed = person_claims();
    proofed.jti = "person-proofed".into();
    proofed.extra = BTreeMap::from([
        ("acr".into(), json!("urn:example:assurance:high")),
        ("amr".into(), json!(["hwk", "face"])),
        (
            "verified_claims".into(),
            json!({
                "verification": {"trust_framework": "example", "assurance_level": "high"},
                "claims": {"given_name": "Ada", "family_name": "Lovelace", "birthdate": "1815-12-10"}
            }),
        ),
        ("name".into(), json!("Ada Lovelace")),
    ]);
    let proofed_token =
        mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &proofed).unwrap();

    // The asserted proofing changes nothing the Resource issues: the same
    // person, the same scope and lifetime, and no claim about the person
    // beyond `(iss, sub)` and the organizational `tenant`.
    let plain = challenge_claims(&resource, &person(), "challenge-plain");
    let asserted = challenge_claims(&resource, &proofed_token, "challenge-proofed");
    assert_eq!(asserted, plain);
    for name in ["acr", "amr", "verified_claims", "name"] {
        assert!(asserted.get(name).is_none(), "{name}");
    }
    let proactive = resource
        .authorize_endpoint(
            &authorize_body(Some(&proofed_token), Some("records.read")),
            NOW,
            "proactive-proofed",
        )
        .into_response();
    assert_eq!(proactive.status(), 200);
    let body: Value = serde_json::from_slice(proactive.body()).unwrap();
    let issued = ResourceToken::parse(body["resource_token"].as_str().unwrap())
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    let issued = serde_json::to_value(issued.claims()).unwrap();
    for name in ["acr", "amr", "verified_claims", "name"] {
        assert!(issued.get(name).is_none(), "{name}");
    }

    // Continuity is the pair: the same asserted proofing under another `sub`
    // is another person at this Resource.
    let mut other = proofed.clone();
    other.sub = "another-directed-person".into();
    other.jti = "person-other".into();
    let other = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &other).unwrap();
    let other = challenge_claims(&resource, &other, "challenge-other");
    assert_eq!(other["sub"], "another-directed-person");
    assert_eq!(other["ps"], plain["ps"]);

    // An ask names the person by `(ps, sub)`. Proofing claims satisfy no ask
    // for a different subject.
    let mut ask = asked();
    ask.sub = "another-directed-person".into();
    let response = resource
        .authorize_for(&signed(&proofed_token), NOW, "challenge-ask", &ask)
        .into_response();
    assert_verified_mismatch(&response);

    // A person token is never authorization, whatever it asserts.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
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
        |c: &mut PsAuthorizationConfig| {
            c.scopes.clear();
            c.scope_descriptions.clear();
        },
        |c: &mut PsAuthorizationConfig| {
            c.scopes = vec!["read".into(), "read".into()];
            c.scope_descriptions = BTreeMap::from([("read".into(), "Read".into())]);
        },
        |c: &mut PsAuthorizationConfig| {
            c.scopes = vec!["read write".into()];
            c.scope_descriptions = BTreeMap::from([("read write".into(), "Read".into())]);
        },
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
    let resource = resource(Arc::new(AtomicUsize::new(0)), true);
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata["scope_descriptions"],
        json!({ "records.read": "Read records" })
    );
    assert!(metadata.get("authorization_endpoint").is_none());
}

fn read_write_config() -> PsAuthorizationConfig {
    let mut profile = config();
    profile.scopes = vec!["records.read".into(), "records.write".into()];
    profile
        .scope_descriptions
        .insert("records.write".into(), "Change records".into());
    profile
}

fn scope_values(compact: &str) -> Vec<String> {
    let verified = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    let scope = verified
        .claims()
        .scope
        .clone()
        .expect("resource token scope");
    scope.split(' ').map(str::to_owned).collect()
}

// Core Scopes: a resource token includes only resource scopes the Resource
// has defined in its `scope_descriptions` metadata. The Resource issues no
// identity scopes.
#[test]
fn resource_tokens_carry_only_scopes_defined_in_scope_descriptions() {
    let read = || ("records.read".to_owned(), "Read records".to_owned());
    let write = || ("records.write".to_owned(), "Change records".to_owned());
    for descriptions in [
        BTreeMap::new(),
        BTreeMap::from([read()]),
        BTreeMap::from([read(), ("records.write".into(), " ".into())]),
        BTreeMap::from([read(), write(), ("admin".into(), "Administer".into())]),
        BTreeMap::from([read(), ("admin".into(), "Administer".into())]),
    ] {
        let mut profile = read_write_config();
        profile.scope_descriptions = descriptions;
        assert!(matches!(
            PsAuthorizationResource::new(
                profile,
                keys(),
                |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true
            ),
            Err(PsConfigurationError::InvalidScopes)
        ));
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_policy = calls.clone();
    let resource = PsAuthorizationResource::new(
        read_write_config(),
        keys(),
        Box::new(
            move |_token: &VerifiedAuthToken, _request: &Request<Vec<u8>>| {
                calls_for_policy.fetch_add(1, Ordering::SeqCst);
                Ok("host-context".into())
            },
        ) as Policy,
    )
    .unwrap()
    .with_authorization_endpoint();
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    let defined: BTreeSet<String> = metadata["scope_descriptions"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        defined,
        BTreeSet::from(["records.read".into(), "records.write".into()])
    );

    // The reactive challenge on a verified Person token.
    let challenged = resource
        .authorize(&signed(&person()), NOW, "challenge-defined")
        .into_response();
    let reactive = scope_values(challenge_token(&challenged));
    assert_eq!(reactive, ["records.read", "records.write"]);
    assert!(reactive.iter().all(|scope| defined.contains(scope)));

    // A proactive request names a defined subset, and an undefined scope
    // gets no resource token.
    let response = resource
        .authorize_endpoint(
            &authorize_body(Some(&person()), Some("records.write")),
            NOW,
            "proactive-defined",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let proactive = scope_values(body["resource_token"].as_str().unwrap());
    assert_eq!(proactive, ["records.write"]);
    assert!(proactive.iter().all(|scope| defined.contains(scope)));
    for undefined in ["admin", "records.read admin", "openid"] {
        let refused = resource
            .authorize_endpoint(
                &authorize_body(Some(&person()), Some(undefined)),
                NOW,
                "proactive-undefined",
            )
            .into_response();
        assert_eq!(refused.status(), 400, "{undefined}");
        assert!(
            refused
                .body()
                .windows(13)
                .any(|bytes| bytes == b"invalid_scope"),
            "{undefined}"
        );
        assert!(
            !refused
                .body()
                .windows(14)
                .any(|bytes| bytes == b"resource_token"),
            "{undefined}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
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
fn federated_resource_carries_mission_context_to_its_access_server() {
    const AS: &str = "https://as.example";
    let calls = Arc::new(AtomicUsize::new(0));
    let federated = |mission_context: bool| {
        let observed = calls.clone();
        let mut snapshots = keys().0;
        snapshots.push(issuer_key(AS, "aauth-access.json", 7, "as-1"));
        let resource = PsAuthorizationResource::new_federated(
            config(),
            AS,
            Keys(snapshots),
            Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
                observed.fetch_add(1, Ordering::SeqCst);
                token
                    .claims()
                    .mission_s256
                    .clone()
                    .ok_or(Deny)
                    .map(|mission| format!("admitted {mission}"))
            }) as Policy,
        )
        .unwrap();
        if mission_context {
            resource.with_mission_context()
        } else {
            resource
        }
    };
    let mut person = person_claims();
    person.mission_s256 = Some(CURRENT_MISSION.into());
    let person = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &person).unwrap();
    let mut claims = auth_claims();
    claims.iss = AS.into();
    claims.dwk = "aauth-access.json".into();
    claims.mission_s256 = Some(CURRENT_MISSION.into());
    let as_auth = mint_auth_token(&SigningKey::from_seed([7; 32]), "as-1", &claims).unwrap();

    // The default profile stays missionless with an access server too.
    let missionless = federated(false);
    let refused = missionless
        .authorize(&signed(&person), NOW, "mission-challenge")
        .into_response();
    assert_eq!(refused.status(), 401);
    assert!(!refused.headers().contains_key("aauth-requirement"));
    assert!(
        missionless
            .authorize(&signed(&as_auth), NOW, "unused")
            .into_result()
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let resource = federated(true);
    let response = resource
        .authorize(&signed(&person), NOW, "mission-challenge")
        .into_response();
    let challenge = ResourceToken::parse(challenge_token(&response))
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(challenge.claims().aud, AS);
    assert_eq!(challenge.claims().ps, PS);
    assert_eq!(
        challenge.claims().mission_s256.as_deref(),
        Some(CURRENT_MISSION)
    );
    let (verified, admitted) = resource
        .authorize(&signed(&as_auth), NOW, "unused")
        .into_result()
        .expect("an AS Auth token for the mission reaches host admission");
    assert_eq!(verified.claims().iss, AS);
    assert_eq!(admitted, format!("admitted {CURRENT_MISSION}"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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
    let AuthDecision::AuthTokenRequired { resource_token, .. } = &decision else {
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

fn assert_proactive_failure(response: &http::Response<Vec<u8>>, code: &str) {
    assert_eq!(
        response.status(),
        401,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let error = response.headers()["signature-error"].to_str().unwrap();
    assert!(
        error.split(',').next().unwrap() == format!("error={code}"),
        "{error}"
    );
    assert!(!response.headers().contains_key("aauth-requirement"));
    assert!(
        !response
            .body()
            .windows(15)
            .any(|bytes| bytes == b"resource_token")
    );
}

fn authorize_body(token: Option<&str>, scope: Option<&str>) -> Request<Vec<u8>> {
    let body = match scope {
        Some(scope) => json!({ "scope": scope }),
        None => json!({}),
    };
    authorize_json(token, body)
}

fn authorize_json(token: Option<&str>, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{ORIGIN}/authorize"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    if let Some(token) = token {
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
    }
    request
}

#[test]
fn proactive_authorization_verifies_the_person_token_and_requires_scope() {
    let calls = Arc::new(AtomicUsize::new(0));
    let plain = resource(calls.clone(), true);
    let metadata: Value = serde_json::from_slice(&plain.metadata().unwrap()).unwrap();
    assert!(metadata.get("authorization_endpoint").is_none());
    let resource = plain.with_authorization_endpoint();
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata["authorization_endpoint"],
        format!("{RESOURCE}/authorize")
    );

    for request in [
        authorize_body(None, Some("records.read")),
        authorize_body(Some(agent().token()), Some("records.read")),
    ] {
        let response = resource
            .authorize_endpoint(&request, NOW, "proactive-1")
            .into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["aauth-requirement"],
            "requirement=person-token"
        );
        assert!(
            !response
                .body()
                .windows(15)
                .any(|bytes| bytes == b"resource_token")
        );
    }

    let forged = authorize_body(Some(&person()), Some("records.read"));
    let mut forged = forged;
    forged.headers_mut().insert(
        "signature",
        "sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:".parse().unwrap(),
    );
    let rejected = resource
        .authorize_endpoint(&forged, NOW, "proactive-1")
        .into_response();
    assert_eq!(rejected.status(), 401);
    assert!(rejected.headers().contains_key("signature-error"));
    assert!(!rejected.headers().contains_key("aauth-requirement"));

    let mut tampered = person();
    let (prefix, signature) = tampered.rsplit_once('.').unwrap();
    let mut signature = signature.as_bytes().to_vec();
    signature[0] = if signature[0] == b'A' { b'B' } else { b'A' };
    tampered = format!("{prefix}.{}", std::str::from_utf8(&signature).unwrap());
    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&tampered), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "invalid_jwt",
    );

    let mut expired_claims = person_claims();
    expired_claims.iat = 900;
    expired_claims.exp = NOW;
    expired_claims.jti = "person-expired-forged".into();
    let mut forged_expired =
        mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &expired_claims).unwrap();
    let (prefix, signature) = forged_expired.rsplit_once('.').unwrap();
    let mut signature = signature.as_bytes().to_vec();
    signature[0] = if signature[0] == b'A' { b'B' } else { b'A' };
    forged_expired = format!("{prefix}.{}", std::str::from_utf8(&signature).unwrap());
    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&forged_expired), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "invalid_jwt",
    );

    let mut wrong_audience = person_claims();
    wrong_audience.aud = "https://other.example".into();
    wrong_audience.jti = "person-audience".into();
    let wrong_audience =
        mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &wrong_audience).unwrap();
    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&wrong_audience), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "invalid_jwt",
    );

    let mut expired = person_claims();
    expired.iat = 900;
    expired.exp = NOW;
    expired.jti = "person-expired".into();
    let expired = mint_person_token(&SigningKey::from_seed([3; 32]), "ps-1", &expired).unwrap();
    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&expired), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "expired_jwt",
    );

    let mut untrusted = person_claims();
    untrusted.iss = "https://evil.example".into();
    untrusted.jti = "person-untrusted".into();
    let untrusted =
        mint_person_token(&SigningKey::from_seed([9; 32]), "evil-1", &untrusted).unwrap();
    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&untrusted), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "invalid_key",
    );

    assert_proactive_failure(
        &resource
            .authorize_endpoint(
                &authorize_body(Some(&auth(&auth_claims())), Some("records.read")),
                NOW,
                "proactive-1",
            )
            .into_response(),
        "invalid_jwt",
    );

    let missing = resource
        .authorize_endpoint(&authorize_body(Some(&person()), None), NOW, "proactive-1")
        .into_response();
    assert_eq!(missing.status(), 400);
    assert!(
        missing
            .body()
            .windows(15)
            .any(|bytes| bytes == b"invalid_request")
    );

    let unknown = resource
        .authorize_endpoint(
            &authorize_body(Some(&person()), Some("admin")),
            NOW,
            "proactive-1",
        )
        .into_response();
    assert_eq!(unknown.status(), 400);
    assert!(
        unknown
            .body()
            .windows(13)
            .any(|bytes| bytes == b"invalid_scope")
    );

    let response = resource
        .authorize_endpoint(
            &authorize_body(Some(&person()), Some("records.read")),
            NOW,
            "proactive-1",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let compact = body["resource_token"].as_str().unwrap();
    let verified = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(verified.claims().scope.as_deref(), Some("records.read"));
    assert_eq!(verified.claims().presented_jti, "person-1");
    assert_eq!(verified.claims().ps, PS);
    assert_eq!(verified.claims().sub, "directed-person");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let with_account = resource
        .authorize_endpoint(
            &authorize_json(
                Some(&person()),
                json!({ "scope": "records.read", "account": "ignored-account" }),
            ),
            NOW,
            "proactive-account",
        )
        .into_response();
    assert_eq!(
        with_account.status(),
        200,
        "{}",
        String::from_utf8_lossy(with_account.body())
    );
    let issued: Value = serde_json::from_slice(with_account.body()).unwrap();
    let issued = ResourceToken::parse(issued["resource_token"].as_str().unwrap())
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(issued.claims().scope.as_deref(), Some("records.read"));
    assert!(!issued.claims().extra.contains_key("account"));
    assert!(matches!(
        resource.authorize_endpoint(&authorize_body(Some(&person()), None), NOW, "proactive-1"),
        ProactiveDecision::InvalidRequest
    ));
}

#[test]
fn proactive_scope_may_be_a_subset_while_an_auth_token_must_name_every_scope() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_policy = calls.clone();
    let resource = PsAuthorizationResource::new(
        read_write_config(),
        keys(),
        Box::new(
            move |_token: &VerifiedAuthToken, _request: &Request<Vec<u8>>| {
                calls_for_policy.fetch_add(1, Ordering::SeqCst);
                Ok("host-context".into())
            },
        ) as Policy,
    )
    .unwrap()
    .with_authorization_endpoint();
    let subset = resource
        .authorize_endpoint(
            &authorize_body(Some(&person()), Some("records.read")),
            NOW,
            "subset-1",
        )
        .into_response();
    assert_eq!(
        subset.status(),
        200,
        "{}",
        String::from_utf8_lossy(subset.body())
    );
    let issued: Value = serde_json::from_slice(subset.body()).unwrap();
    let issued = ResourceToken::parse(issued["resource_token"].as_str().unwrap())
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(issued.claims().scope.as_deref(), Some("records.read"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut partial = auth_claims();
    partial.jti = "auth-partial".into();
    partial.scope = Some("records.read".into());
    let refused = resource
        .authorize(&signed(&auth(&partial)), NOW, "unused")
        .into_response();
    assert_eq!(
        refused.status(),
        403,
        "{}",
        String::from_utf8_lossy(refused.body())
    );
    assert!(
        refused
            .body()
            .windows(13)
            .any(|bytes| bytes == b"access_denied")
    );
    assert!(!refused.headers().contains_key("signature-error"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut complete = auth_claims();
    complete.jti = "auth-complete".into();
    complete.scope = Some("records.read records.write".into());
    resource
        .authorize(&signed(&auth(&complete)), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut repeated_member = Request::builder()
        .method("POST")
        .uri(format!("{ORIGIN}/authorize"))
        .header("content-type", "application/json")
        .body(br#"{"scope":"records.read","scope":"records.write"}"#.to_vec())
        .unwrap();
    sign_request(
        &mut repeated_member,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt {
            jwt: person(),
            cache: false,
        },
        NOW,
    )
    .unwrap();
    let repeated_member = resource
        .authorize_endpoint(&repeated_member, NOW, "repeated-member")
        .into_response();
    assert_eq!(repeated_member.status(), 400);
    assert!(
        repeated_member
            .body()
            .windows(15)
            .any(|bytes| bytes == b"invalid_request")
    );
    assert!(
        !repeated_member
            .body()
            .windows(14)
            .any(|bytes| bytes == b"resource_token")
    );

    let repeated_token = resource
        .authorize_endpoint(
            &authorize_body(Some(&person()), Some("records.read records.read")),
            NOW,
            "repeated-token",
        )
        .into_response();
    assert_eq!(repeated_token.status(), 400);
    assert!(
        repeated_token
            .body()
            .windows(15)
            .any(|bytes| bytes == b"invalid_request")
    );
    assert!(
        !repeated_token
            .body()
            .windows(13)
            .any(|bytes| bytes == b"invalid_scope")
    );
}

#[test]
fn listed_signature_components_are_published_and_required_of_agents() {
    let listing = resource(Arc::new(AtomicUsize::new(0)), true)
        .with_additional_signature_components(["x-tenant"])
        .unwrap();
    let metadata: Value = serde_json::from_slice(&listing.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata["additional_signature_components"],
        json!(["x-tenant"])
    );
    let with_tenant = || {
        let mut req = request();
        req.headers_mut()
            .insert("x-tenant", "blue".parse().unwrap());
        req
    };
    // Base coverage only: refused, with the components to add.
    let mut plain = with_tenant();
    agent().sign(&mut plain, NOW).unwrap();
    let refused = listing
        .authorize(&plain, NOW, "challenge-1")
        .into_response();
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["signature-error"],
        "error=invalid_input, required_input=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"x-tenant\")"
    );
    let mut covered = with_tenant();
    agent()
        .with_additional_signature_components(["x-tenant"])
        .sign(&mut covered, NOW)
        .unwrap();
    let response = listing
        .authorize(&covered, NOW, "challenge-1")
        .into_response();
    assert_eq!(
        response.headers()["aauth-requirement"],
        "requirement=person-token"
    );
    // A scheme other than jwt is refused, naming jwt, the one it accepts.
    let mut hwk = request();
    let key = SigningKey::from_seed([2; 32]);
    sign_request(&mut hwk, &key, KeyMaterial::Hwk(key.public_jwk()), NOW).unwrap();
    let refused = resource(Arc::new(AtomicUsize::new(0)), true)
        .authorize(&hwk, NOW, "challenge-1")
        .into_response();
    assert_eq!(
        refused.headers()["signature-error"],
        "error=unsupported_scheme"
    );
    assert_eq!(refused.headers()["accept-signature-scheme"], "jwt");
    assert_eq!(
        listing
            .with_additional_signature_components(["@status"])
            .err(),
        Some(PsConfigurationError::InvalidComponent)
    );
}
