use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use serde_json::json;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc8032_empty_message_vector() {
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let key = SigningKey::from_seed(seed);
    assert_eq!(
        key.public_jwk().x,
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
    assert_eq!(
        key.sign(b"").as_slice(),
        unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    key.public_jwk().verify(b"", &key.sign(b"")).unwrap();
    assert!(key.public_jwk().verify(b"changed", &key.sign(b"")).is_err());
}

#[test]
fn compact_jws_preserves_original_bytes_and_rejects_substitution() {
    let key = SigningKey::from_seed([7; 32]);
    let compact = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-1"}),
        b"{ \"a\" : 1 }",
        &key,
    )
    .unwrap();
    let parsed = Jws::parse(&compact).unwrap();
    assert_eq!(parsed.compact(), compact);
    assert_eq!(parsed.payload(), b"{ \"a\" : 1 }");
    parsed.verify(&key.public_jwk()).unwrap();
    assert!(
        parsed
            .verify(&SigningKey::from_seed([8; 32]).public_jwk())
            .is_err()
    );
    let mut ec = key.public_jwk();
    ec.kty = "EC".into();
    ec.crv = "P-256".into();
    ec.alg = "ES256".into();
    ec.y = ec.x.clone();
    assert!(matches!(
        parsed.verify(&ec),
        Err(aauth_rust_jose::Error::UnsupportedAlgorithm)
    ));
    for alg in ["EdDSA", "none", "HS256"] {
        assert!(Jws::sign(&json!({"alg":alg}), b"{}", &key).is_err());
    }
    assert!(
        Jws::sign(
            &json!({"alg":"Ed25519","crit":["b64"],"b64":false}),
            b"{}",
            &key
        )
        .is_err()
    );
}

#[test]
fn jwk_algorithm_and_shape_are_checked_at_use() {
    let key = SigningKey::from_seed([7; 32]);
    let original = serde_json::to_value(key.public_jwk()).unwrap();
    for (member, value) in [
        ("alg", json!("EdDSA")),
        ("alg", json!("ES256")),
        ("kty", json!("EC")),
        ("crv", json!("Ed448")),
        ("x", json!("AA")),
        ("d", json!("secret")),
    ] {
        let mut bad = original.clone();
        bad[member] = value;
        let jwk: Jwk = serde_json::from_value(bad).unwrap();
        assert!(jwk.validate().is_err(), "accepted {member}");
    }
    let mut no_alg = original;
    no_alg.as_object_mut().unwrap().remove("alg");
    assert!(matches!(
        serde_json::from_value::<Jwk>(no_alg).unwrap().validate(),
        Err(aauth_rust_jose::Error::UnsupportedAlgorithm)
    ));
}

#[test]
fn unknown_kty_and_symmetric_algs_are_unsupported_not_inconsistent() {
    let key = SigningKey::from_seed([7; 32]);
    let original = serde_json::to_value(key.public_jwk()).unwrap();
    for (member, value) in [
        ("kty", json!("AKP")),
        ("kty", json!("oct")),
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("alg", json!("HS384")),
        ("alg", json!("HS512")),
    ] {
        let mut bad = original.clone();
        bad[member] = value;
        let jwk: Jwk = serde_json::from_value(bad).unwrap();
        assert!(
            matches!(
                jwk.validate(),
                Err(aauth_rust_jose::Error::UnsupportedAlgorithm)
            ),
            "{member}"
        );
    }
    let mut inconsistent = original;
    inconsistent["kty"] = json!("EC");
    let jwk: Jwk = serde_json::from_value(inconsistent).unwrap();
    assert!(matches!(
        jwk.validate(),
        Err(aauth_rust_jose::Error::InvalidKey)
    ));
}

#[test]
fn thumbprint_ignores_optional_jwk_metadata() {
    let key = SigningKey::from_seed([7; 32]);
    let mut jwk = key.public_jwk();
    let before = jwk.thumbprint().unwrap();
    jwk.extra.insert("kid".into(), json!("rotation-2"));
    assert_eq!(jwk.thumbprint().unwrap(), before);
    assert_ne!(
        SigningKey::from_seed([8; 32])
            .public_jwk()
            .thumbprint()
            .unwrap(),
        before
    );
}

#[test]
fn duplicate_json_members_are_rejected_recursively() {
    for bad in [
        r#"{"alg":"none","alg":"Ed25519"}"#,
        r#"{"cnf":{"jwk":{"x":"first","x":"second"}}}"#,
        r#"[ {"x":1,"x":2} ]"#,
    ] {
        assert!(strict_json(bad.as_bytes()).is_err());
    }
    assert_eq!(
        strict_json(br#"{"extension":{"a":[1,true,null]}}"#).unwrap(),
        json!({"extension":{"a":[1,true,null]}})
    );
}

#[test]
fn public_jwk_refuses_all_known_private_members() {
    for name in ["d", "k", "p", "q", "dp", "dq", "qi", "oth"] {
        let mut key = SigningKey::from_seed([7; 32]).public_jwk();
        key.extra.insert(name.into(), json!("private material"));
        assert!(key.validate().is_err(), "accepted private {name}");
    }
}

#[test]
fn noncanonical_base64url_trailing_bits_are_already_refused() {
    let key = SigningKey::from_seed([7; 32]);
    let mut jwk = key.public_jwk();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = jwk.x.pop().unwrap();
    let i = alphabet.iter().position(|b| *b == last as u8).unwrap();
    jwk.x.push(alphabet[i + 1] as char);
    assert!(jwk.validate().is_err());
    let raw = Jws::sign(&json!({"alg":"Ed25519"}), b"arbitrary JWS payload", &key).unwrap();
    let mut parts: Vec<String> = raw.split('.').map(str::to_owned).collect();
    let last = parts[2].pop().unwrap();
    let i = alphabet.iter().position(|b| *b == last as u8).unwrap();
    parts[2].push(alphabet[i + 1] as char);
    assert!(Jws::parse(&parts.join(".")).is_err());
    Jws::parse(&raw).unwrap().verify(&key.public_jwk()).unwrap();
}

#[test]
fn low_order_ed25519_keys_are_not_verification_keys() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut jwk = SigningKey::from_seed([7; 32]).public_jwk();
    jwk.x = URL_SAFE_NO_PAD.encode(identity);
    assert!(jwk.validate().is_err());
}

#[test]
fn parse_rejects_critical_headers_and_nonobject_headers() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    for header in [
        r#"{"alg":"Ed25519","crit":["extension"]}"#,
        r#"{"alg":"Ed25519","b64":false}"#,
        "[1]",
        "null",
    ] {
        let compact = format!(
            "{}.e30.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        );
        assert!(
            matches!(
                Jws::parse(&compact),
                Err(aauth_rust_jose::Error::InvalidJws)
            ),
            "{header}"
        );
    }
}

#[test]
fn thumbprints_match_the_rfc_examples_for_every_key_type() {
    let key = |value: serde_json::Value| serde_json::from_value::<Jwk>(value).unwrap();
    // RFC 8037 Appendix A.3.
    let okp = key(json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }));
    assert_eq!(
        okp.thumbprint().unwrap(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
    // RFC 9449 Section 6.1.
    let ec = key(json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256",
        "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
        "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    }));
    assert_eq!(
        ec.thumbprint().unwrap(),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
    // RFC 7638 Section 3.1. The thumbprint does not depend on `alg`.
    let mut rsa = key(json!({
        "kty": "RSA", "alg": "RS256", "e": "AQAB",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    }));
    assert_eq!(
        rsa.thumbprint().unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    rsa.alg = "PS256".into();
    assert_eq!(
        rsa.thumbprint().unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    rsa.alg = "EdDSA".into();
    assert!(matches!(
        rsa.thumbprint(),
        Err(aauth_rust_jose::Error::UnsupportedAlgorithm)
    ));
}

#[test]
fn pkcs8_keys_sign_only_under_their_own_algorithm() {
    use aauth_rust_jose::Error::{InvalidKey, UnsupportedAlgorithm};
    use p256::pkcs8::EncodePrivateKey;

    let seed = [7u8; 32];
    let mut ed25519 = unhex("302e020100300506032b657004220420");
    ed25519.extend_from_slice(&seed);
    let imported = SigningKey::from_pkcs8_der("Ed25519", &ed25519).unwrap();
    assert_eq!(imported.algorithm(), "Ed25519");
    assert_eq!(imported.sign(b"m"), SigningKey::from_seed(seed).sign(b"m"));

    let es256 = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
        .to_pkcs8_der()
        .unwrap();
    let es384 = p384::ecdsa::SigningKey::random(&mut rand_core::OsRng)
        .to_pkcs8_der()
        .unwrap();
    for (alg, der, crv, len) in [
        ("ES256", es256.as_bytes(), "P-256", 64),
        ("ES384", es384.as_bytes(), "P-384", 96),
    ] {
        let key = SigningKey::from_pkcs8_der(alg, der).unwrap();
        let jwk = key.public_jwk();
        assert_eq!(key.algorithm(), alg);
        assert_eq!((jwk.kty.as_str(), jwk.crv.as_str()), ("EC", crv));
        assert_eq!(jwk.alg, alg);
        let signature = key.sign(b"signature base");
        assert_eq!(signature.len(), len);
        jwk.verify(b"signature base", &signature).unwrap();
        assert!(jwk.verify(b"other base", &signature).is_err());
        assert!(matches!(
            Jws::sign(&json!({"alg": "Ed25519"}), b"{}", &key),
            Err(UnsupportedAlgorithm)
        ));
    }

    for (alg, der) in [
        ("ES384", es256.as_bytes()),
        ("ES256", es384.as_bytes()),
        ("RS256", es256.as_bytes()),
        ("Ed25519", es256.as_bytes()),
        ("ES256", ed25519.as_slice()),
    ] {
        assert!(
            matches!(SigningKey::from_pkcs8_der(alg, der), Err(InvalidKey)),
            "{alg}"
        );
    }
    for alg in ["EdDSA", "ES512", "PS384", "HS256", "none", ""] {
        assert!(
            matches!(
                SigningKey::from_pkcs8_der(alg, es256.as_bytes()),
                Err(UnsupportedAlgorithm)
            ),
            "{alg}"
        );
    }
}
