use aauth_jose::{Jwk, Jws, SigningKey, strict_json};
use serde_json::json;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}

#[test]
fn rfc8032_empty_message_vector() {
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap();
    let key = SigningKey::from_seed(seed);
    assert_eq!(key.public_jwk().x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    assert_eq!(key.sign(b"").as_slice(), unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
    key.public_jwk().verify(b"", &key.sign(b"")).unwrap();
    assert!(key.public_jwk().verify(b"changed", &key.sign(b"")).is_err());
}

#[test]
fn compact_jws_preserves_original_bytes_and_rejects_substitution() {
    let key = SigningKey::from_seed([7; 32]);
    let compact = Jws::sign(&json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-1"}), b"{ \"a\" : 1 }", &key).unwrap();
    let parsed = Jws::parse(&compact).unwrap();
    assert_eq!(parsed.compact(), compact);
    assert_eq!(parsed.payload(), b"{ \"a\" : 1 }");
    parsed.verify(&key.public_jwk()).unwrap();
    assert!(parsed.verify(&SigningKey::from_seed([8;32]).public_jwk()).is_err());
    for alg in ["EdDSA", "none", "HS256"] {
        assert!(Jws::sign(&json!({"alg":alg}), b"{}", &key).is_err());
    }
    assert!(Jws::sign(&json!({"alg":"Ed25519","crit":["b64"],"b64":false}), b"{}", &key).is_err());
}

#[test]
fn jwk_algorithm_and_shape_are_checked_at_use() {
    let key = SigningKey::from_seed([7;32]);
    let original = serde_json::to_value(key.public_jwk()).unwrap();
    for (member,value) in [("alg",json!("EdDSA")),("alg",json!("ES256")),("kty",json!("EC")),("crv",json!("Ed448")),("x",json!("AA")),("d",json!("secret"))] {
        let mut bad = original.clone(); bad[member]=value;
        let jwk: Jwk = serde_json::from_value(bad).unwrap();
        assert!(jwk.validate().is_err(), "accepted {member}");
    }
    let mut no_alg=original; no_alg.as_object_mut().unwrap().remove("alg");
    assert!(serde_json::from_value::<Jwk>(no_alg).is_err());
}

#[test]
fn thumbprint_ignores_optional_jwk_metadata() {
    let key=SigningKey::from_seed([7;32]);
    let mut jwk=key.public_jwk();
    let before=jwk.thumbprint().unwrap();
    jwk.extra.insert("kid".into(),json!("rotation-2"));
    assert_eq!(jwk.thumbprint().unwrap(), before);
    assert_ne!(SigningKey::from_seed([8;32]).public_jwk().thumbprint().unwrap(), before);
}

#[test]
fn duplicate_json_members_are_rejected_recursively() {
    for bad in [r#"{"alg":"none","alg":"Ed25519"}"#,r#"{"cnf":{"jwk":{"x":"first","x":"second"}}}"#, r#"[ {"x":1,"x":2} ]"#] {
        assert!(strict_json(bad.as_bytes()).is_err());
    }
    assert_eq!(strict_json(br#"{"extension":{"a":[1,true,null]}}"#).unwrap(), json!({"extension":{"a":[1,true,null]}}));
}
