use aauth_rust_jose::{Jwk, SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    writer: String,
    message: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    algorithm: String,
    pkcs8: String,
    jwk: Jwk,
    signature: String,
}

#[test]
fn imports_and_verifies_keys_exported_by_the_previous_implementation() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/previous-keys/cases.json")).unwrap();
    assert_eq!(fixture.writer, "5251bc5acf77b4ab3f22832cf805255167b4f89f");
    let algorithms: Vec<_> = fixture
        .cases
        .iter()
        .map(|case| case.algorithm.as_str())
        .collect();
    assert_eq!(algorithms, ["Ed25519", "ES256", "ES384", "RS256", "PS256"]);
    let message = fixture.message.as_bytes();
    for case in fixture.cases {
        let der = STANDARD.decode(case.pkcs8).unwrap();
        let key = SigningKey::from_pkcs8_der(&case.algorithm, &der).unwrap();
        assert_eq!(
            serde_json::to_value(key.public_jwk()).unwrap(),
            serde_json::to_value(&case.jwk).unwrap(),
            "{}",
            case.algorithm
        );
        let old = STANDARD.decode(case.signature).unwrap();
        key.public_jwk().verify(message, &old).unwrap();
        let new = key.sign(message).unwrap();
        case.jwk.verify(message, &new).unwrap();
        if case.algorithm != "PS256" {
            assert_eq!(new, old, "{}", case.algorithm);
        }
    }
}
