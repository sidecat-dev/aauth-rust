//! Signers whose keys the resolver discovers over loopback TLS: a key
//! replaced under the same `kid`, a direct `jwks` URL and a `self-jwt` issuer.
mod support;

use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentToken, Confirmation, TokenError};
use aauth_rust_discovery::KeyResolver;
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{Error, KeyMaterial, PreparedRequest, sign_request};
use http::Request;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use support::{Net, json, now};

const AP: &str = "https://ap.test";
const SIGNER: &str = "https://signer.test";
const SIGNER_JWKS: &str = "https://signer.test/keys.json";

fn agent_token(provider: &AgentProvider, at: i64) -> String {
    provider
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:assistant@ap.test".into(),
            jti: format!("agent-{at}"),
            iat: at,
            exp: at + 3600,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([9; 32]).public_jwk(),
            },
            ps: None,
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap()
}

fn jwks(key: &SigningKey, kid: &str) -> Vec<u8> {
    let mut jwk = serde_json::to_value(key.public_jwk()).unwrap();
    jwk["kid"] = kid.into();
    serde_json::to_vec(&serde_json::json!({ "keys": [jwk] })).unwrap()
}

fn signed(key: &SigningKey, material: KeyMaterial, at: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri("https://resource.test/api")
        .body(Vec::new())
        .unwrap();
    sign_request(&mut request, key, material, at).unwrap();
    request
}

#[test]
fn a_key_replaced_under_its_kid_is_refetched_once_per_minute() {
    let first = || SigningKey::from_seed([1; 32]);
    let replaced = SigningKey::from_seed([2; 32]);
    let issuer = AgentProvider::new(AP, "ap-1", first()).unwrap();
    let metadata = issuer.metadata().unwrap();
    let served = Arc::new(Mutex::new(issuer.jwks().unwrap()));
    let mut net = Net::new(&["ap.test"]);
    let jwks_now = served.clone();
    net.serve("ap.test", move |request| match request.uri().path() {
        "/.well-known/aauth-agent.json" => json(200, metadata.clone()),
        "/.well-known/jwks.json" => json(200, jwks_now.lock().unwrap().clone()),
        _ => json(404, "{}"),
    });
    let start = now();
    let clock = Arc::new(AtomicI64::new(start));
    let time = clock.clone();
    let keys = KeyResolver::new(net.client())
        .trust(AP, "aauth-agent.json")
        .with_clock(move || time.load(Ordering::SeqCst));
    let verify = |token: &str| {
        AgentToken::parse(token)
            .unwrap()
            .verify(&keys, start + 1)
            .map(|_| ())
    };

    verify(&agent_token(&issuer, start)).unwrap();
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 1);

    // The provider replaces its key and keeps the kid. Inside the minute
    // after the last fetch the cached key answers, and the signature fails.
    let rotated = AgentProvider::new(AP, "ap-1", replaced).unwrap();
    *served.lock().unwrap() = rotated.jwks().unwrap();
    let after_rotation = agent_token(&rotated, start);
    clock.store(start + 30, Ordering::SeqCst);
    assert_eq!(verify(&after_rotation).unwrap_err(), TokenError::InvalidJwt);
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 1);

    // After it, the failed signature refetches the set once and verifies.
    clock.store(start + 61, Ordering::SeqCst);
    verify(&after_rotation).unwrap();
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 2);
    verify(&after_rotation).unwrap();
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 2);

    // A signature that fails under the fresh key fails, with no new fetch
    // inside the minute.
    let stranger = AgentProvider::new(AP, "ap-1", first()).unwrap();
    clock.store(start + 62, Ordering::SeqCst);
    assert_eq!(
        verify(&agent_token(&stranger, start)).unwrap_err(),
        TokenError::InvalidJwt
    );
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 2);
}

#[test]
fn direct_jwks_and_self_jwt_signers_resolve_through_trusted_discovery() {
    let signer = SigningKey::generate();
    let replaced = SigningKey::generate_es256();
    let served = Arc::new(Mutex::new(jwks(&signer, "s-1")));
    let mut net = Net::new(&["signer.test"]);
    let keys_now = served.clone();
    net.serve("signer.test", move |request| match request.uri().path() {
        "/keys.json" => json(200, keys_now.lock().unwrap().clone()),
        "/.well-known/aauth-agent.json" => json(
            200,
            serde_json::to_vec(&serde_json::json!({
                "issuer": SIGNER, "jwks_uri": SIGNER_JWKS
            }))
            .unwrap(),
        ),
        _ => json(404, "{}"),
    });
    let start = now();
    let clock = Arc::new(AtomicI64::new(start));
    let time = clock.clone();
    let untrusted = KeyResolver::new(net.client());
    let keys = KeyResolver::new(net.client())
        .trust_jwks(SIGNER_JWKS)
        .trust(SIGNER, "aauth-agent.json")
        .with_clock(move || time.load(Ordering::SeqCst));
    let jwks_member = || KeyMaterial::Jwks {
        url: SIGNER_JWKS.into(),
        kid: "s-1".into(),
    };
    let prepare = |request: &Request<Vec<u8>>, scheme: &str| {
        PreparedRequest::prepare_with_schemes(request, "sig", start, 60, &[scheme]).unwrap()
    };

    // jwks: the URL is the identity, and an untrusted one is never fetched.
    let request = signed(&signer, jwks_member(), start);
    assert_eq!(
        prepare(&request, "jwks")
            .verify_jwks(&untrusted)
            .unwrap_err(),
        Error::InvalidKey
    );
    assert!(net.log().is_empty());
    let identity = prepare(&request, "jwks").verify_jwks(&keys).unwrap();
    assert_eq!(identity.url, SIGNER_JWKS);
    assert_eq!(net.log(), ["GET signer.test/keys.json"]);

    // The signer replaces its key under the same kid; after the minute the
    // failed signature refetches the URL once.
    *served.lock().unwrap() = jwks(&replaced, "s-1");
    let request = signed(&replaced, jwks_member(), start);
    assert_eq!(
        prepare(&request, "jwks").verify_jwks(&keys).unwrap_err(),
        Error::InvalidSignature
    );
    clock.store(start + 61, Ordering::SeqCst);
    let identity = prepare(&request, "jwks").verify_jwks(&keys).unwrap();
    assert_eq!(identity.key.alg, "ES256");
    assert_eq!(net.count("GET signer.test/keys.json"), 2);
    let unknown = signed(
        &replaced,
        KeyMaterial::Jwks {
            url: SIGNER_JWKS.into(),
            kid: "s-2".into(),
        },
        start,
    );
    assert_eq!(
        prepare(&unknown, "jwks").verify_jwks(&keys).unwrap_err(),
        Error::UnknownKey
    );

    // self-jwt: the issuer's metadata names the same JWKS, and the resolver
    // finds both from the assertion's iss, dwk and kid.
    let assertion = Jws::sign(
        &serde_json::json!({"alg":"ES256","typ":"example+jwt","kid":"s-1"}),
        &serde_json::to_vec(&serde_json::json!({
            "iss": SIGNER, "dwk": "aauth-agent.json", "iat": start, "exp": start + 300
        }))
        .unwrap(),
        &replaced,
    )
    .unwrap();
    let request = signed(&replaced, KeyMaterial::SelfJwt { jwt: assertion }, start);
    let verified = keys
        .verify_self_jwt(&prepare(&request, "self-jwt"), start, "example+jwt")
        .unwrap();
    assert_eq!(verified.issuer, SIGNER);
    assert_eq!(verified.key_id, "s-1");
    let fetched = net.log().len();
    assert_eq!(
        untrusted
            .verify_self_jwt(&prepare(&request, "self-jwt"), start, "example+jwt")
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(net.log().len(), fetched);
}
