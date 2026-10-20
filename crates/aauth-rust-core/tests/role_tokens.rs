use aauth_rust_core::{
    AuthClaims, AuthToken, PersonClaims, PersonToken, ResourceClaims, ResourceToken, TokenError,
    TrustedIssuerKeys, mint_auth_token, mint_person_token, mint_resource_token,
};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::{Value, json};

const NOW: i64 = 1000;
const DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn payload(role: &str) -> Value {
    let mut value = json!({
        "iss":"https://ps.example", "dwk":"aauth-person.json",
        "aud":"https://resource.example", "sub":"directed-person", "jti":"token-1",
        "iat":1000, "exp":2000, "tenant":"team", "mission_s256":DIGEST,
        "custom":{"attested":true}
    });
    if role == "resource" {
        value["iss"] = json!("https://resource.example");
        value["dwk"] = json!("aauth-resource.json");
        value["aud"] = json!("https://ps.example");
        value["ps"] = json!("https://ps.example");
        value["presented_jti"] = json!("person-token-1");
        value["agent_jkt"] = json!(
            SigningKey::from_seed([2; 32])
                .public_jwk()
                .thumbprint()
                .unwrap()
        );
        value["scope"] = json!("records.read records.write");
        value["account"] = json!("");
        value["login_hint"] = json!("person@example.com");
    } else {
        value["cnf"] = json!({"jwk":SigningKey::from_seed([2; 32]).public_jwk()});
        if role == "auth" {
            value["ps"] = json!("https://ps.example");
            value["scope"] = json!("records.read");
            value["account"] = json!("");
        }
    }
    value
}
fn signed(role: &str, value: &Value, key: &SigningKey) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","typ":format!("aa-{role}+jwt"),"kid":"issuer-1"}),
        &serde_json::to_vec(value).unwrap(),
        key,
    )
    .unwrap()
}
fn keys(issuer: &str, dwk: &str, key: &SigningKey) -> TrustedIssuerKeys {
    let mut jwk = serde_json::to_value(key.public_jwk()).unwrap();
    jwk["kid"] = json!("issuer-1");
    TrustedIssuerKeys::from_documents(
        issuer,
        dwk,
        &serde_json::to_vec(&json!({"issuer":issuer,"jwks_uri":format!("{issuer}/keys")})).unwrap(),
        &serde_json::to_vec(&json!({"keys":[jwk]})).unwrap(),
    )
    .unwrap()
}
fn parse(role: &str, compact: &str) -> Result<(), TokenError> {
    match role {
        "person" => PersonToken::parse(compact).map(|_| ()),
        "resource" => ResourceToken::parse(compact).map(|_| ()),
        "auth" => AuthToken::parse(compact).map(|_| ()),
        _ => unreachable!(),
    }
}
fn verify(
    role: &str,
    compact: &str,
    keys: &TrustedIssuerKeys,
    now: i64,
) -> Result<Value, TokenError> {
    match role {
        "person" => PersonToken::parse(compact)?
            .verify(keys, now)
            .map(|v| serde_json::to_value(v.claims()).unwrap()),
        "resource" => ResourceToken::parse(compact)?
            .verify(keys, now)
            .map(|v| serde_json::to_value(v.claims()).unwrap()),
        "auth" => AuthToken::parse(compact)?
            .verify(keys, now)
            .map(|v| serde_json::to_value(v.claims()).unwrap()),
        _ => unreachable!(),
    }
}
fn mint(role: &str, value: Value, key: &SigningKey, kid: &str) -> Result<String, TokenError> {
    match role {
        "person" => mint_person_token(
            key,
            kid,
            &serde_json::from_value::<PersonClaims>(value).unwrap(),
        ),
        "resource" => mint_resource_token(
            key,
            kid,
            &serde_json::from_value::<ResourceClaims>(value).unwrap(),
        ),
        "auth" => mint_auth_token(
            key,
            kid,
            &serde_json::from_value::<AuthClaims>(value).unwrap(),
        ),
        _ => unreachable!(),
    }
}

#[test]
fn role_tokens_authenticate_exact_bytes_and_preserve_additive_claims() {
    let signer = SigningKey::from_seed([1; 32]);
    let person_raw = mint("person", payload("person"), &signer, "issuer-1").unwrap();
    let person = PersonToken::parse(&person_raw).unwrap();
    assert_eq!(person.unverified_claims().aud, "https://resource.example");
    let person_keys = keys("https://ps.example", "aauth-person.json", &signer);
    let verified = person.verify(&person_keys, NOW).unwrap();
    assert_eq!(verified.compact(), person_raw);
    assert_eq!(verified.claims().extra["custom"], json!({"attested":true}));
    assert!(!format!("{person:?} {verified:?}").contains(&person_raw));

    let auth_raw = mint("auth", payload("auth"), &signer, "issuer-1").unwrap();
    let auth = AuthToken::parse(&auth_raw).unwrap();
    assert_eq!(auth.unverified_claims().ps, "https://ps.example");
    let verified = auth.verify(&person_keys, NOW).unwrap();
    assert_eq!(verified.compact(), auth_raw);
    assert_eq!(verified.claims().account.as_deref(), Some(""));
    assert!(!format!("{auth:?} {verified:?}").contains(&auth_raw));

    let resource_raw = mint("resource", payload("resource"), &signer, "issuer-1").unwrap();
    let resource = ResourceToken::parse(&resource_raw).unwrap();
    assert_eq!(resource.unverified_claims().presented_jti, "person-token-1");
    let verified = resource
        .verify(
            &keys("https://resource.example", "aauth-resource.json", &signer),
            NOW,
        )
        .unwrap();
    assert_eq!(verified.compact(), resource_raw);
    assert_eq!(
        verified.claims().login_hint.as_deref(),
        Some("person@example.com")
    );
    assert!(!format!("{resource:?} {verified:?}").contains(&resource_raw));
}

#[test]
fn role_tokens_refuse_missing_null_and_wrongly_typed_required_claims() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "resource", "auth"] {
        let mut required = vec!["iss", "dwk", "aud", "sub", "jti", "iat", "exp"];
        if role == "resource" {
            required.extend(["ps", "presented_jti", "agent_jkt"]);
        } else {
            required.push("cnf");
        }
        if role == "auth" {
            required.push("ps");
        }
        for field in required {
            for replacement in [None, Some(Value::Null), Some(json!([]))] {
                let mut value = payload(role);
                if let Some(replacement) = replacement {
                    value[field] = replacement;
                } else {
                    value.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    parse(role, &signed(role, &value, &signer)).is_err(),
                    "{role}: accepted invalid {field}"
                );
            }
        }
    }
}

#[test]
fn explicit_null_optional_claims_are_not_silently_treated_as_absent() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "resource", "auth"] {
        let mut fields = vec!["nbf", "tenant", "mission_s256"];
        if role != "person" {
            fields.extend(["scope", "account"]);
        }
        if role == "resource" {
            fields.push("login_hint");
        }
        for field in fields {
            let mut value = payload(role);
            value[field] = Value::Null;
            assert!(
                parse(role, &signed(role, &value, &signer)).is_err(),
                "{role}: null {field}"
            );
        }
    }
}

#[test]
fn token_roles_cannot_be_swapped_or_routed_through_another_discovery_role() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "resource", "auth"] {
        let raw = signed(role, &payload(role), &signer);
        for other in ["person", "resource", "auth"] {
            if other != role {
                assert!(parse(other, &raw).is_err());
            }
        }
        let mut value = payload(role);
        value["dwk"] = json!("aauth-agent.json");
        assert!(parse(role, &signed(role, &value, &signer)).is_err());
        for field in ["iss", "aud", "ps"]
            .into_iter()
            .filter(|field| *field != "ps" || role != "person")
        {
            value = payload(role);
            value[field] = json!("https://PS.example/");
            assert!(
                parse(role, &signed(role, &value, &signer)).is_err(),
                "{role}: noncanonical {field}"
            );
        }
    }
    let mut auth = payload("auth");
    auth["ps"] = json!("https://other.example");
    assert!(parse("auth", &signed("auth", &auth, &signer)).is_err());
    auth["dwk"] = json!("aauth-access.json");
    verify(
        "auth",
        &signed("auth", &auth, &signer),
        &keys("https://ps.example", "aauth-access.json", &signer),
        NOW,
    )
    .unwrap();
}

#[test]
fn person_authorization_and_resource_confirmation_claims_are_forbidden() {
    let signer = SigningKey::from_seed([1; 32]);
    for (role, fields) in [
        ("person", vec!["scope", "account"]),
        ("resource", vec!["cnf"]),
    ] {
        for field in fields {
            let mut value = payload(role);
            value[field] = Value::Null;
            assert!(
                parse(role, &signed(role, &value, &signer)).is_err(),
                "{role}: forbidden {field}"
            );
        }
    }
    let mut person: PersonClaims = serde_json::from_value(payload("person")).unwrap();
    for field in ["scope", "account", "aud", "nbf"] {
        person.extra.insert(field.into(), json!("injected"));
        assert!(mint_person_token(&signer, "issuer-1", &person).is_err());
        person.extra.remove(field);
    }
    let mut auth: AuthClaims = serde_json::from_value(payload("auth")).unwrap();
    auth.extra
        .insert("ps".into(), json!("https://other.example"));
    assert!(mint_auth_token(&signer, "issuer-1", &auth).is_err());
    let mut resource: ResourceClaims = serde_json::from_value(payload("resource")).unwrap();
    resource.extra.insert("agent_jkt".into(), json!(DIGEST));
    assert!(mint_resource_token(&signer, "issuer-1", &resource).is_err());
}

#[test]
fn person_and_auth_one_hour_ceiling_is_enforced_on_external_tokens() {
    let signer = SigningKey::from_seed([1; 32]);
    let trusted = keys("https://ps.example", "aauth-person.json", &signer);
    for role in ["person", "auth"] {
        let mut value = payload(role);
        value["exp"] = json!(4600);
        verify(role, &signed(role, &value, &signer), &trusted, NOW).unwrap();
        value["exp"] = json!(4601);
        assert!(parse(role, &signed(role, &value, &signer)).is_err());
    }
    let mut resource = payload("resource");
    resource["exp"] = json!(5000);
    verify(
        "resource",
        &signed("resource", &resource, &signer),
        &keys("https://resource.example", "aauth-resource.json", &signer),
        NOW,
    )
    .unwrap();
}

#[test]
fn expiry_is_exact_nbf_applies_and_iat_is_not_a_clock_validity_check() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "resource", "auth"] {
        let mut value = payload(role);
        let trusted = keys(
            value["iss"].as_str().unwrap(),
            value["dwk"].as_str().unwrap(),
            &signer,
        );
        let raw = signed(role, &value, &signer);
        assert_eq!(
            verify(role, &raw, &trusted, 2000).unwrap_err(),
            TokenError::ExpiredJwt
        );
        verify(role, &raw, &trusted, 1999).unwrap();
        value["iat"] = json!(1500);
        verify(role, &signed(role, &value, &signer), &trusted, NOW).unwrap();
        value["nbf"] = json!(1001);
        assert!(verify(role, &signed(role, &value, &signer), &trusted, NOW).is_err());
        verify(role, &signed(role, &value, &signer), &trusted, 1001).unwrap();
        for (iat, exp) in [(1000, 1000), (1001, 1000), (-1, 1000)] {
            value = payload(role);
            value["iat"] = json!(iat);
            value["exp"] = json!(exp);
            assert!(parse(role, &signed(role, &value, &signer)).is_err());
        }
    }
}

#[test]
fn local_mint_refuses_millisecond_timestamps_and_empty_key_identifiers() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "resource", "auth"] {
        assert_eq!(
            mint(role, payload(role), &signer, "").unwrap_err(),
            TokenError::InvalidKeyId
        );
        let mut value = payload(role);
        value["iat"] = json!(8589934590_i64);
        value["exp"] = json!(8589934591_i64);
        mint(role, value.clone(), &signer, "issuer-1").unwrap();
        value["iat"] = json!(8589934591_i64);
        value["exp"] = json!(8589934592_i64);
        assert!(mint(role, value.clone(), &signer, "issuer-1").is_err());
        // Verification does not impose this implementation's local issuance horizon.
        let trusted = keys(
            value["iss"].as_str().unwrap(),
            value["dwk"].as_str().unwrap(),
            &signer,
        );
        verify(role, &signed(role, &value, &signer), &trusted, 8589934591).unwrap();
    }
}

#[test]
fn public_only_confirmation_and_canonical_hashes_are_required() {
    let signer = SigningKey::from_seed([1; 32]);
    for role in ["person", "auth"] {
        for (field, bad) in [
            ("d", json!("secret")),
            ("x", json!("missing")),
            ("alg", json!("EdDSA")),
            ("kty", json!("RSA")),
        ] {
            let mut value = payload(role);
            value["cnf"]["jwk"][field] = bad;
            assert!(
                parse(role, &signed(role, &value, &signer)).is_err(),
                "{role}: bad cnf {field}"
            );
        }
    }
    for role in ["person", "resource", "auth"] {
        for hash in [
            "",
            "short",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            let mut value = payload(role);
            value["mission_s256"] = json!(hash);
            assert!(
                parse(role, &signed(role, &value, &signer)).is_err(),
                "{role}: hash {hash}"
            );
            if role == "resource" {
                value = payload(role);
                value["agent_jkt"] = json!(hash);
                assert!(parse(role, &signed(role, &value, &signer)).is_err());
            }
        }
    }
}

#[test]
fn trusted_role_snapshot_never_resolves_an_unconfigured_issuer_or_role() {
    let signer = SigningKey::from_seed([1; 32]);
    let trusted = keys("https://ps.example", "aauth-person.json", &signer);
    assert_eq!(
        trusted
            .key("https://other.example", "aauth-person.json", "issuer-1")
            .unwrap_err(),
        TokenError::UntrustedIssuer
    );
    assert!(
        trusted
            .key("https://ps.example", "aauth-access.json", "issuer-1")
            .is_err()
    );
    assert_eq!(
        trusted
            .key("https://ps.example", "aauth-person.json", "missing")
            .unwrap_err(),
        TokenError::UnknownKey
    );
    assert_eq!(trusted.jwks_uri(), "https://ps.example/keys");
    let impostor = SigningKey::from_seed([9; 32]);
    assert!(
        verify(
            "person",
            &signed("person", &payload("person"), &impostor),
            &trusted,
            NOW
        )
        .is_err()
    );
    assert!(
        TrustedIssuerKeys::from_documents(
            "https://ps.example",
            "other.json",
            br#"{"issuer":"https://ps.example","jwks_uri":"https://ps.example/keys"}"#,
            br#"{"keys":[]}"#
        )
        .is_err()
    );
}
