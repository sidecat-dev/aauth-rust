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
