// Run as an example in a checkout of 5251bc5a; see README.md beside this file.
use aauth_rust_jose::SigningKey;
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::pkcs8::EncodePrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde_json::json;

fn main() {
    let message = "Sidecat previous-key compatibility fixture";
    let p256 = p256::ecdsa::SigningKey::from_slice(&[2; 32])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let p384 = p384::ecdsa::SigningKey::from_slice(&[3; 48])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let rsa = include_bytes!("../../aauth-rust-signature-key/tests/fixtures/rsa-2048.der");
    let rsa = rsa::RsaPrivateKey::from_pkcs1_der(rsa)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let mut cases = Vec::new();
    for key in [
        SigningKey::from_seed([1; 32]),
        SigningKey::from_pkcs8_der("ES256", p256.as_bytes()).unwrap(),
        SigningKey::from_pkcs8_der("ES384", p384.as_bytes()).unwrap(),
        SigningKey::from_pkcs8_der("RS256", rsa.as_bytes()).unwrap(),
        SigningKey::from_pkcs8_der("PS256", rsa.as_bytes()).unwrap(),
    ] {
        cases.push(json!({
            "algorithm": key.algorithm(),
            "pkcs8": STANDARD.encode(key.export_pkcs8_der().unwrap().as_bytes()),
            "jwk": key.public_jwk(),
            "signature": STANDARD.encode(key.sign(message.as_bytes()).unwrap()),
        }));
    }
    let fixture = json!({"writer": "5251bc5acf77b4ab3f22832cf805255167b4f89f", "message": message, "cases": cases});
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
