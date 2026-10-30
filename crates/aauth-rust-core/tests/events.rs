use aauth_rust_core::events::{
    EventClaims, EventToken, SubscribeClaims, SubscribeToken, body_s256, event_endpoint,
    mint_event_token, mint_subscribe_token,
};
use aauth_rust_core::{Confirmation, TokenError, TrustedIssuerKeys};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::{Value, json};

fn ap_keys() -> TrustedIssuerKeys {
    let jwks = json!({"keys":[{"kid":"ap-1",
        "kty":"OKP","crv":"Ed25519","alg":"Ed25519",
        "x":SigningKey::from_seed([1; 32]).public_jwk().x}]});
    TrustedIssuerKeys::from_documents(
        "https://ap.example",
        "aauth-agent.json",
        br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks.json"}"#,
        jwks.to_string().as_bytes(),
    )
    .unwrap()
}
fn resource_keys() -> TrustedIssuerKeys {
    let jwks = json!({"keys":[{"kid":"resource-1",
        "kty":"OKP","crv":"Ed25519","alg":"Ed25519",
        "x":SigningKey::from_seed([5; 32]).public_jwk().x}]});
    TrustedIssuerKeys::from_documents(
        "https://resource.example",
        "aauth-resource.json",
        br#"{"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks.json"}"#,
        jwks.to_string().as_bytes(),
    )
    .unwrap()
}
fn subscribe_claims() -> SubscribeClaims {
    SubscribeClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:k7q3p9n2@ap.example".into(),
        aud: "https://resource.example".into(),
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        eid: "evt_8f3k2n9p".into(),
        jti: "st-7c1e22".into(),
        iat: 1000,
        exp: 2000,
        max_uses: Some(1),
        extra: Default::default(),
    }
}
fn event_claims() -> EventClaims {
    EventClaims {
        iss: "https://resource.example".into(),
        dwk: "aauth-resource.json".into(),
        aud: "aauth:k7q3p9n2@ap.example".into(),
        eid: "evt_8f3k2n9p".into(),
        jti: "ev-4d2a91".into(),
        iat: 1000,
        exp: 1300,
        body_s256: Some(body_s256(br#"{"event_type":"slot.available"}"#)),
        extra: Default::default(),
    }
}
fn signed(typ: &str, payload: &Value, seed: u8, kid: &str) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","typ":typ,"kid":kid}),
        payload.to_string().as_bytes(),
        &SigningKey::from_seed([seed; 32]),
    )
    .unwrap()
}

#[test]
fn a_subscribe_token_carries_the_draft_claims_and_verifies_with_the_ap_key() {
    let compact =
        mint_subscribe_token(&SigningKey::from_seed([1; 32]), "ap-1", &subscribe_claims()).unwrap();
    let parsed = Jws::parse(&compact).unwrap();
    assert_eq!(parsed.header()["typ"], "aa-subscribe+jwt");
    assert_eq!(parsed.header()["kid"], "ap-1");
    let payload: Value = serde_json::from_slice(parsed.payload()).unwrap();
    for name in [
        "iss", "dwk", "sub", "aud", "cnf", "eid", "jti", "iat", "exp", "max_uses",
    ] {
        assert!(payload.get(name).is_some(), "{name} missing");
    }
    let token = SubscribeToken::parse(&compact)
        .unwrap()
        .verify(&ap_keys(), 1500)
        .unwrap();
    assert_eq!(token.claims().eid, "evt_8f3k2n9p");
    assert_eq!(token.compact(), compact);
}

#[test]
fn subscribe_token_syntax_follows_the_draft() {
    let key = SigningKey::from_seed([1; 32]);
    let mut empty_eid = subscribe_claims();
    empty_eid.eid = String::new();
    assert_eq!(
        mint_subscribe_token(&key, "ap-1", &empty_eid).unwrap_err(),
        TokenError::InvalidJwt
    );
    let mut zero_uses = subscribe_claims();
    zero_uses.max_uses = Some(0);
    assert_eq!(
        mint_subscribe_token(&key, "ap-1", &zero_uses).unwrap_err(),
        TokenError::InvalidJwt
    );
    let mut unlimited = subscribe_claims();
    unlimited.max_uses = None;
    let compact = mint_subscribe_token(&key, "ap-1", &unlimited).unwrap();
    let payload: Value = serde_json::from_slice(Jws::parse(&compact).unwrap().payload()).unwrap();
    assert!(payload.get("max_uses").is_none());
    let mut foreign = subscribe_claims();
    foreign.sub = "aauth:k7q3p9n2@other.example".into();
    assert_eq!(
        mint_subscribe_token(&key, "ap-1", &foreign).unwrap_err(),
        TokenError::AgentIssuerMismatch
    );
    let mut wrong_dwk = serde_json::to_value(subscribe_claims()).unwrap();
    wrong_dwk["dwk"] = json!("aauth-resource.json");
    assert_eq!(
        SubscribeToken::parse(&signed("aa-subscribe+jwt", &wrong_dwk, 1, "ap-1")).unwrap_err(),
        TokenError::InvalidDiscoveryDocument
    );
    for bad in [json!(-1), json!(1.5), json!(null), json!("1")] {
        let mut value = serde_json::to_value(subscribe_claims()).unwrap();
        value["max_uses"] = bad;
        assert!(SubscribeToken::parse(&signed("aa-subscribe+jwt", &value, 1, "ap-1")).is_err());
    }
    let agent_typed = signed(
        "aa-agent+jwt",
        &serde_json::to_value(subscribe_claims()).unwrap(),
        1,
        "ap-1",
    );
    assert_eq!(
        SubscribeToken::parse(&agent_typed).unwrap_err(),
        TokenError::UnexpectedTokenType
    );
}

#[test]
fn a_subscribe_token_is_refused_at_or_after_exp_and_with_a_foreign_signature() {
    let compact =
        mint_subscribe_token(&SigningKey::from_seed([1; 32]), "ap-1", &subscribe_claims()).unwrap();
    let token = SubscribeToken::parse(&compact).unwrap();
    assert_eq!(
        token.verify(&ap_keys(), 2000).unwrap_err(),
        TokenError::ExpiredJwt
    );
    let forged = signed(
        "aa-subscribe+jwt",
        &serde_json::to_value(subscribe_claims()).unwrap(),
        9,
        "ap-1",
    );
    assert!(
        SubscribeToken::parse(&forged)
            .unwrap()
            .verify(&ap_keys(), 1500)
            .is_err()
    );
}

#[test]
fn an_event_token_never_carries_cnf() {
    let key = SigningKey::from_seed([5; 32]);
    let mut with_cnf = event_claims();
    with_cnf.extra.insert(
        "cnf".into(),
        json!({"jwk": SigningKey::from_seed([2; 32]).public_jwk()}),
    );
    assert_eq!(
        mint_event_token(&key, "resource-1", &with_cnf).unwrap_err(),
        TokenError::InvalidJwt
    );
    for cnf in [json!({"jwk": key.public_jwk()}), Value::Null, json!({})] {
        let mut payload = serde_json::to_value(event_claims()).unwrap();
        payload["cnf"] = cnf;
        assert_eq!(
            EventToken::parse(&signed("aa-event+jwt", &payload, 5, "resource-1")).unwrap_err(),
            TokenError::InvalidJwt
        );
    }
    let compact = mint_event_token(&key, "resource-1", &event_claims()).unwrap();
    let payload: Value = serde_json::from_slice(Jws::parse(&compact).unwrap().payload()).unwrap();
    assert!(payload.get("cnf").is_none());
    assert_eq!(
        Jws::parse(&compact).unwrap().header()["typ"],
        "aa-event+jwt"
    );
}

#[test]
fn an_event_token_verifies_with_the_resource_key_and_names_it() {
    let key = SigningKey::from_seed([5; 32]);
    let compact = mint_event_token(&key, "resource-1", &event_claims()).unwrap();
    let token = EventToken::parse(&compact)
        .unwrap()
        .verify(&resource_keys(), 1100)
        .unwrap();
    assert_eq!(
        token.issuer_key().thumbprint().unwrap(),
        key.public_jwk().thumbprint().unwrap()
    );
    assert_eq!(
        EventToken::parse(&compact)
            .unwrap()
            .verify(&resource_keys(), 1300)
            .unwrap_err(),
        TokenError::ExpiredJwt
    );
    let mut wrong_dwk = serde_json::to_value(event_claims()).unwrap();
    wrong_dwk["dwk"] = json!("aauth-agent.json");
    assert_eq!(
        EventToken::parse(&signed("aa-event+jwt", &wrong_dwk, 5, "resource-1")).unwrap_err(),
        TokenError::InvalidDiscoveryDocument
    );
}

#[test]
fn body_s256_is_present_exactly_when_there_is_a_body() {
    let body = br#"{"event_type":"slot.available"}"#;
    let claims = event_claims();
    assert!(claims.verify_body(body).is_ok());
    assert_eq!(
        claims.verify_body(b"{\"event_type\":\"slot.taken\"}"),
        Err(TokenError::InvalidJwt)
    );
    assert_eq!(claims.verify_body(b""), Err(TokenError::InvalidJwt));
    let mut bodiless = event_claims();
    bodiless.body_s256 = None;
    assert!(bodiless.verify_body(b"").is_ok());
    assert_eq!(bodiless.verify_body(body), Err(TokenError::InvalidJwt));
    let mut padded = serde_json::to_value(event_claims()).unwrap();
    padded["body_s256"] = json!(format!("{}=", body_s256(body)));
    assert!(EventToken::parse(&signed("aa-event+jwt", &padded, 5, "resource-1")).is_err());
    assert_eq!(
        body_s256(br#"{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}"#).len(),
        43
    );
}

#[test]
fn event_endpoint_is_read_only_from_matching_ap_metadata() {
    let good = br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","event_endpoint":"https://ap.example/events"}"#;
    assert_eq!(
        event_endpoint("https://ap.example", good).unwrap(),
        "https://ap.example/events"
    );
    assert_eq!(
        event_endpoint("https://other.example", good).unwrap_err(),
        TokenError::IssuerMismatch
    );
    assert_eq!(
        event_endpoint(
            "https://ap.example",
            br#"{"event_endpoint":"https://ap.example/e"}"#
        )
        .unwrap_err(),
        TokenError::IssuerMissing
    );
    for endpoint in [
        "http://ap.example/events",
        "https://ap.example/events?x=1",
        "https://ap.example/events#f",
        "https://user@ap.example/events",
        "/events",
    ] {
        let metadata = json!({"issuer":"https://ap.example","event_endpoint":endpoint});
        assert_eq!(
            event_endpoint("https://ap.example", metadata.to_string().as_bytes()).unwrap_err(),
            TokenError::InvalidDiscoveryMetadata,
            "{endpoint}"
        );
    }
    assert_eq!(
        event_endpoint("https://ap.example", br#"{"issuer":"https://ap.example"}"#).unwrap_err(),
        TokenError::InvalidDiscoveryMetadata
    );
}
