use aauth_rust_core::{
    AgentClaims, AgentProviderKeys, AgentToken, TokenError, validate_agent_identifier,
    validate_server_identifier,
};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::json;

fn fixture() -> (SigningKey, SigningKey, AgentClaims, AgentProviderKeys) {
    let ap = SigningKey::from_seed([1; 32]);
    let agent = SigningKey::from_seed([2; 32]);
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent.7@ap.example".into(),
        jti: "token-1".into(),
        iat: 1000,
        exp: 2000,
        cnf: aauth_rust_core::Confirmation {
            jwk: agent.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let mut jwk = serde_json::to_value(ap.public_jwk()).unwrap();
    jwk["kid"] = json!("ap-1");
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &serde_json::to_vec(
            &json!({"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}),
        )
        .unwrap(),
        &serde_json::to_vec(&json!({"keys":[{"kid":"future","kty":"AKP","alg":"ML-DSA-44"},jwk]}))
            .unwrap(),
    )
    .unwrap();
    (ap, agent, claims, keys)
}
fn mint(ap: &SigningKey, claims: &AgentClaims, typ: &str) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","kid":"ap-1","typ":typ}),
        &serde_json::to_vec(claims).unwrap(),
        ap,
    )
    .unwrap()
}

#[test]
fn agent_token_checks_type_key_and_expiry_without_losing_bytes() {
    let (ap, agent, claims, keys) = fixture();
    let raw = mint(&ap, &claims, "aa-agent+jwt");
    let token = AgentToken::parse(&raw).unwrap();
    let verified = token.verify(&keys, 1000).unwrap();
    assert_eq!(verified.claims().sub, "aauth:Agent.7@ap.example");
    assert_eq!(verified.compact(), raw);
    assert_eq!(
        verified.claims().cnf.jwk.thumbprint().unwrap(),
        agent.public_jwk().thumbprint().unwrap()
    );
    assert_eq!(
        token.verify(&keys, 2000).err().unwrap(),
        TokenError::ExpiredJwt
    );
    assert!(AgentToken::parse(&mint(&ap, &claims, "aa-auth+jwt")).is_err());
    let impostor = SigningKey::from_seed([8; 32]);
    assert!(
        AgentToken::parse(&mint(&impostor, &claims, "aa-agent+jwt"))
            .unwrap()
            .verify(&keys, 1000)
            .is_err()
    );
}

#[test]
fn required_claims_issuer_and_confirmation_are_not_inferred() {
    let (ap, _, claims, keys) = fixture();
    for field in ["iss", "dwk", "sub", "jti", "iat", "exp", "cnf"] {
        let mut value = serde_json::to_value(&claims).unwrap();
        value.as_object_mut().unwrap().remove(field);
        let raw = Jws::sign(
            &json!({"alg":"Ed25519","kid":"ap-1","typ":"aa-agent+jwt"}),
            &serde_json::to_vec(&value).unwrap(),
            &ap,
        )
        .unwrap();
        assert!(AgentToken::parse(&raw).is_err(), "missing {field}");
    }
    for (field, value) in [
        ("iss", json!("https://other.example")),
        ("dwk", json!("aauth-person.json")),
        ("sub", json!("aauth:x@other.example")),
        ("ps", json!("http://ps.example")),
        ("nbf", json!(1500)),
    ] {
        let mut value_claims = serde_json::to_value(&claims).unwrap();
        value_claims[field] = value;
        let raw = Jws::sign(
            &json!({"alg":"Ed25519","kid":"ap-1","typ":"aa-agent+jwt"}),
            &serde_json::to_vec(&value_claims).unwrap(),
            &ap,
        )
        .unwrap();
        assert!(
            AgentToken::parse(&raw)
                .and_then(|t| t.verify(&keys, 1000))
                .is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn identifiers_are_exact_and_do_not_accept_url_normalization() {
    for good in ["https://ap.example", "https://xn--nxasmq6b.example"] {
        validate_server_identifier(good).unwrap();
    }
    for bad in [
        "https://AP.example",
        "https://ap.example/",
        "https://ap.example:443",
        "https://ap.example:8443",
        "http://ap.example",
        "https://user@ap.example",
        "https://ap.example?x=1",
        "https://ap.example#x",
        "https://127.0.0.1",
        "https://ap_example",
        "https://-ap.example",
    ] {
        assert!(validate_server_identifier(bad).is_err(), "{bad}");
    }
    for good in ["aauth:A_b-7.8@ap.example", "aauth:parent+child@ap.example"] {
        validate_agent_identifier(good).unwrap();
    }
    for bad in [
        "aauth:@ap.example",
        "aauth:a b@ap.example",
        "agent@ap.example",
        "aauth:a@AP.example",
        "aauth:+worker@ap.example",
        "aauth:assistant+@ap.example",
        "aauth:parent+worker+leaf@ap.example",
        &format!("aauth:{}@ap.example", "a".repeat(256)),
    ] {
        assert!(validate_agent_identifier(bad).is_err(), "{bad}");
    }
    validate_agent_identifier(&format!("aauth:{}@ap.example", "a".repeat(255))).unwrap();
}

#[test]
fn agent_identifiers_that_differ_only_by_local_case_stay_distinct() {
    let (ap, _, mut claims, keys) = fixture();
    claims.sub = "aauth:Agent@ap.example".into();
    let upper = mint(&ap, &claims, "aa-agent+jwt");
    claims.sub = "aauth:agent@ap.example".into();
    claims.jti = "token-2".into();
    let lower = mint(&ap, &claims, "aa-agent+jwt");
    let upper = AgentToken::parse(&upper)
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    let lower = AgentToken::parse(&lower)
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    assert_eq!(upper.claims().sub, "aauth:Agent@ap.example");
    assert_eq!(lower.claims().sub, "aauth:agent@ap.example");
    assert_ne!(upper.claims().sub, lower.claims().sub);
}

#[test]
fn discovery_binds_exact_issuer_and_selects_only_the_named_key() {
    let (_, _, _, keys) = fixture();
    assert_eq!(
        keys.key("https://other.example", "aauth-agent.json", "ap-1")
            .err()
            .unwrap(),
        TokenError::UntrustedIssuer
    );
    assert_eq!(
        keys.key("https://ap.example", "aauth-agent.json", "absent")
            .err()
            .unwrap(),
        TokenError::UnknownKey
    );
    assert!(
        AgentProviderKeys::from_documents(
            "https://ap.example",
            br#"{"issuer":"https://other.example","jwks_uri":"https://ap.example/keys"}"#,
            br#"{"keys":[]}"#
        )
        .is_err()
    );
    assert!(
        AgentProviderKeys::from_documents(
            "https://ap.example",
            br#"{"jwks_uri":"https://ap.example/keys"}"#,
            br#"{"keys":[]}"#
        )
        .is_err()
    );
}

#[test]
fn iat_is_retained_and_future_refusal_is_explicit_resource_policy() {
    let (ap, _, mut claims, keys) = fixture();
    claims.iat = 1800;
    let verified = AgentToken::parse(&mint(&ap, &claims, "aa-agent+jwt"))
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    assert_eq!(verified.claims().iat, 1800);
}

#[test]
fn selected_unknown_key_algorithm_has_defined_feedback() {
    let (_, _, _, keys) = fixture();
    assert_eq!(
        keys.key("https://ap.example", "aauth-agent.json", "future")
            .err()
            .unwrap(),
        TokenError::UnsupportedAlgorithm
    );
    let x = keys
        .key("https://ap.example", "aauth-agent.json", "ap-1")
        .unwrap()
        .x;
    let ec = AgentProviderKeys::from_documents(
        "https://ap.example",
        br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}"#,
        serde_json::to_vec(&json!({"keys":[{
            "kty":"EC","crv":"P-256","alg":"ES256","kid":"ec",
            "x": x, "y": x
        }]}))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(
        ec.key("https://ap.example", "aauth-agent.json", "ec")
            .err()
            .unwrap(),
        TokenError::UnsupportedAlgorithm
    );
}

#[test]
fn missing_confirmation_algorithm_is_not_inferred_or_misclassified() {
    let (ap, _, claims, _) = fixture();
    let mut value = serde_json::to_value(claims).unwrap();
    value["cnf"]["jwk"].as_object_mut().unwrap().remove("alg");
    let raw = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-1"}),
        &serde_json::to_vec(&value).unwrap(),
        &ap,
    )
    .unwrap();
    assert_eq!(
        AgentToken::parse(&raw).err().unwrap(),
        TokenError::UnsupportedAlgorithm
    );
    value["cnf"]["jwk"]["alg"] = json!("ES256");
    value["cnf"]["jwk"]["kty"] = json!("EC");
    value["cnf"]["jwk"]["crv"] = json!("P-256");
    value["cnf"]["jwk"]["y"] = value["cnf"]["jwk"]["x"].clone();
    let raw = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-1"}),
        &serde_json::to_vec(&value).unwrap(),
        &ap,
    )
    .unwrap();
    assert_eq!(
        AgentToken::parse(&raw).err().unwrap(),
        TokenError::UnsupportedAlgorithm
    );
}

#[test]
fn local_claim_errors_name_the_field_to_fix() {
    let (_, _, claims, _) = fixture();
    let mut bad = claims.clone();
    bad.iss = "http://ap.example".into();
    assert!(bad.validate().unwrap_err().to_string().contains("https://"));
    let mut bad = claims.clone();
    bad.dwk = "wrong.json".into();
    assert!(
        bad.validate()
            .unwrap_err()
            .to_string()
            .contains("aauth-agent.json")
    );
    let mut bad = claims;
    bad.sub = "aauth:Agent@other.example".into();
    assert!(bad.validate().unwrap_err().to_string().contains("sub"));
}

#[test]
fn explicit_null_optional_claims_are_not_absent_claims() {
    let (ap, _, claims, _) = fixture();
    for name in ["ps", "parent_agent", "nbf"] {
        let mut value = serde_json::to_value(&claims).unwrap();
        value[name] = json!(null);
        let raw = Jws::sign(
            &json!({"alg":"Ed25519","kid":"ap-1","typ":"aa-agent+jwt"}),
            &serde_json::to_vec(&value).unwrap(),
            &ap,
        )
        .unwrap();
        assert!(AgentToken::parse(&raw).is_err(), "accepted {name}=null");
    }
}

#[test]
fn missing_kid_and_malformed_selected_keys_have_distinct_codes() {
    let (ap, _, claims, _) = fixture();
    let raw = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt"}),
        &serde_json::to_vec(&claims).unwrap(),
        &ap,
    )
    .unwrap();
    let error = AgentToken::parse(&raw).err().unwrap();
    assert_eq!(error.code(), "invalid_jwt");
    assert!(error.to_string().contains("kid"));
    let metadata = br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}"#;
    assert_eq!(
        AgentProviderKeys::from_documents("https://ap.example", metadata, b"not json")
            .err()
            .unwrap()
            .code(),
        "invalid_key"
    );
    let mut key = serde_json::to_value(ap.public_jwk()).unwrap();
    key["kid"] = json!("ap-1");
    key["crv"] = json!("Ed448");
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        metadata,
        &serde_json::to_vec(&json!({"keys":[key.clone(),key]})).unwrap(),
    )
    .unwrap();
    assert_eq!(
        keys.key("https://ap.example", "aauth-agent.json", "ap-1")
            .err()
            .unwrap()
            .code(),
        "invalid_key"
    );
}

#[test]
fn optional_claims_and_numeric_date_boundaries_are_explicit() {
    let (ap, _, mut claims, keys) = fixture();
    claims.ps = Some("https://ps.example".into());
    claims.parent_agent = Some("aauth:Parent@ap.example".into());
    claims.sub = "aauth:Parent+Child@ap.example".into();
    claims.nbf = Some(1000);
    claims.iat = 0;
    AgentToken::parse(&mint(&ap, &claims, "aa-agent+jwt"))
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    claims.nbf = Some(2000);
    for now in [1999, 2000] {
        assert!(
            AgentToken::parse(&mint(&ap, &claims, "aa-agent+jwt"))
                .unwrap()
                .verify(&keys, now)
                .is_err()
        );
    }
}

#[test]
fn jwks_endpoints_are_https_urls_not_server_identifiers_and_empty_sets_are_valid() {
    for uri in [
        "https://AP.example/keys?v=1",
        "https://127.0.0.1:8443/keys",
        "https://[::1]/keys",
    ] {
        let metadata =
            serde_json::to_vec(&json!({"issuer":"https://ap.example","jwks_uri":uri})).unwrap();
        let keys =
            AgentProviderKeys::from_documents("https://ap.example", &metadata, br#"{"keys":[]}"#)
                .unwrap();
        assert_eq!(keys.jwks_uri(), uri);
        assert_eq!(
            keys.key("https://ap.example", "aauth-agent.json", "absent")
                .err()
                .unwrap(),
            TokenError::UnknownKey
        );
    }
}

#[test]
fn discovery_refuses_non_https_jwks_locations() {
    for uri in [
        "http://ap.example/keys",
        "https://ap.example:notaport/keys",
        "https://ap.example:65536/keys",
        "https://:443/keys",
        "file:///keys",
        "https://user:secret@ap.example/keys",
        "https://ap.example/keys#fragment",
    ] {
        let metadata =
            serde_json::to_vec(&json!({"issuer":"https://ap.example","jwks_uri":uri})).unwrap();
        assert!(
            AgentProviderKeys::from_documents("https://ap.example", &metadata, br#"{"keys":[]}"#)
                .is_err(),
            "{uri}"
        );
    }
}

#[test]
fn a_foreign_issuer_does_not_look_like_a_rotated_key() {
    let (_, _, _, keys) = fixture();
    let foreign = keys
        .key("https://attacker.example", "aauth-agent.json", "ap-1")
        .err()
        .unwrap();
    assert_ne!(foreign, TokenError::UnknownKey);
    assert_eq!(
        keys.key("https://ap.example", "aauth-agent.json", "rotated")
            .err()
            .unwrap(),
        TokenError::UnknownKey
    );
}

#[test]
fn snapshots_can_be_shared_as_references_arcs_and_boxed_resolvers() {
    use aauth_rust_core::AgentKeyResolver;
    use std::sync::Arc;
    let (ap, _, claims, keys) = fixture();
    let compact = mint(&ap, &claims, "aa-agent+jwt");
    let token = AgentToken::parse(&compact).unwrap();
    let cloned = keys.clone();
    let borrowed = &keys;
    token.verify(&borrowed, 1000).unwrap();
    let shared = Arc::new(cloned);
    token.verify(&shared, 1000).unwrap();
    let erased: Box<dyn AgentKeyResolver> = Box::new(shared);
    token.verify(&erased, 1000).unwrap();
}

#[test]
fn supplied_multi_key_jwks_keeps_old_tokens_valid_until_the_key_is_retired() {
    let (old, _, claims, _) = fixture();
    let next = SigningKey::from_seed([8; 32]);
    let old_token = AgentToken::parse(&mint(&old, &claims, "aa-agent+jwt")).unwrap();
    let compact = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-2"}),
        &serde_json::to_vec(&claims).unwrap(),
        &next,
    )
    .unwrap();
    let new_token = AgentToken::parse(&compact).unwrap();
    let mut first = serde_json::to_value(old.public_jwk()).unwrap();
    first["kid"] = json!("ap-1");
    let mut second = serde_json::to_value(next.public_jwk()).unwrap();
    second["kid"] = json!("ap-2");
    let metadata = br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}"#;
    let overlap = AgentProviderKeys::from_documents(
        "https://ap.example",
        metadata,
        &serde_json::to_vec(&json!({"keys":[first,second.clone()]})).unwrap(),
    )
    .unwrap();
    old_token.verify(&overlap, 1000).unwrap();
    new_token.verify(&overlap, 1000).unwrap();
    let retired = AgentProviderKeys::from_documents(
        "https://ap.example",
        metadata,
        &serde_json::to_vec(&json!({"keys":[second]})).unwrap(),
    )
    .unwrap();
    assert_eq!(
        old_token.verify(&retired, 1000).err().unwrap(),
        TokenError::UnknownKey
    );
    new_token.verify(&retired, 1000).unwrap();
}

#[test]
fn invalid_jwks_metadata_never_advertises_a_key_refresh() {
    for location in [
        None,
        Some(json!(null)),
        Some(json!("http://ap.example/keys")),
        Some(json!("https://user@ap.example/keys")),
        Some(json!("https://ap.example/keys#x")),
        Some(json!("https://ap.example:bad/keys")),
    ] {
        let mut metadata = json!({"issuer":"https://ap.example"});
        if let Some(location) = location {
            metadata["jwks_uri"] = location;
        }
        let error = AgentProviderKeys::from_documents(
            "https://ap.example",
            &serde_json::to_vec(&metadata).unwrap(),
            br#"{"keys":[]}"#,
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), "invalid_key");
        assert_ne!(error, TokenError::UnknownKey);
    }
}
