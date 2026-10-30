use aauth_rust_agent::{Agent, EventError, EventSubscriptions, verify_event};
use aauth_rust_core::events::{
    EventClaims, SubscribeClaims, body_s256, mint_event_token, mint_subscribe_token,
};
use aauth_rust_core::{Confirmation, TokenError, TrustedIssuerKeys};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest};
use http::Request;
use serde_json::{Value, json};

const AGENT: &str = "aauth:k7q3p9n2@ap.example";
const RESOURCE: &str = "https://resource.example";
const BODY: &[u8] = br#"{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}"#;

fn resource_keys() -> TrustedIssuerKeys {
    let jwks = json!({"keys":[{"kid":"resource-1",
        "kty":"OKP","crv":"Ed25519","alg":"Ed25519",
        "x":SigningKey::from_seed([5; 32]).public_jwk().x}]});
    TrustedIssuerKeys::from_documents(
        RESOURCE,
        "aauth-resource.json",
        br#"{"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks.json"}"#,
        jwks.to_string().as_bytes(),
    )
    .unwrap()
}
fn claims(body: &[u8]) -> EventClaims {
    EventClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: AGENT.into(),
        eid: "evt_8f3k2n9p".into(),
        jti: "ev-4d2a91".into(),
        iat: 1000,
        exp: 1300,
        body_s256: (!body.is_empty()).then(|| body_s256(body)),
        extra: Default::default(),
    }
}
fn event(claims: &EventClaims) -> String {
    mint_event_token(&SigningKey::from_seed([5; 32]), "resource-1", claims).unwrap()
}
fn subscribe_token(sub: &str, aud: &str, eid: &str, seed: u8) -> String {
    mint_subscribe_token(
        &SigningKey::from_seed([1; 32]),
        "ap-1",
        &SubscribeClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: sub.into(),
            aud: aud.into(),
            cnf: Confirmation {
                jwk: SigningKey::from_seed([seed; 32]).public_jwk(),
            },
            eid: eid.into(),
            jti: format!("st-{eid}"),
            iat: 1000,
            exp: 2000,
            max_uses: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}

#[test]
fn the_agent_acts_only_on_a_token_addressed_exactly_to_it() {
    let token = event(&claims(BODY));
    assert!(verify_event(&token, BODY, AGENT, &resource_keys(), 1000).is_ok());
    for other in [
        "aauth:K7q3p9n2@ap.example",
        "aauth:k7q3p9n2@AP.example",
        "aauth:k7q3p9n2x@ap.example",
    ] {
        assert_eq!(
            verify_event(&token, BODY, other, &resource_keys(), 1000).unwrap_err(),
            EventError::Audience,
            "{other}"
        );
    }
}

#[test]
fn the_agent_does_not_act_on_an_expired_event_token() {
    let token = event(&claims(BODY));
    assert!(verify_event(&token, BODY, AGENT, &resource_keys(), 1299).is_ok());
    for now in [1300, 1301, 5000] {
        assert_eq!(
            verify_event(&token, BODY, AGENT, &resource_keys(), now).unwrap_err(),
            EventError::Token(TokenError::ExpiredJwt)
        );
    }
}

#[test]
fn the_agent_verifies_typ_dwk_and_the_resource_signature() {
    let payload = serde_json::to_value(claims(BODY)).unwrap();
    let sign = |typ: &str, payload: &Value, seed: u8| {
        Jws::sign(
            &json!({"alg":"Ed25519","typ":typ,"kid":"resource-1"}),
            payload.to_string().as_bytes(),
            &SigningKey::from_seed([seed; 32]),
        )
        .unwrap()
    };
    assert_eq!(
        verify_event(
            &sign("aa-resource+jwt", &payload, 5),
            BODY,
            AGENT,
            &resource_keys(),
            1000
        )
        .unwrap_err(),
        EventError::Token(TokenError::UnexpectedTokenType)
    );
    let mut wrong_dwk = payload.clone();
    wrong_dwk["dwk"] = json!("aauth-agent.json");
    assert_eq!(
        verify_event(
            &sign("aa-event+jwt", &wrong_dwk, 5),
            BODY,
            AGENT,
            &resource_keys(),
            1000
        )
        .unwrap_err(),
        EventError::Token(TokenError::InvalidDiscoveryDocument)
    );
    assert!(matches!(
        verify_event(
            &sign("aa-event+jwt", &payload, 9),
            BODY,
            AGENT,
            &resource_keys(),
            1000
        ),
        Err(EventError::Token(_))
    ));
    let mut foreign = payload.clone();
    foreign["iss"] = json!("https://other.example");
    assert_eq!(
        verify_event(
            &sign("aa-event+jwt", &foreign, 5),
            BODY,
            AGENT,
            &resource_keys(),
            1000
        )
        .unwrap_err(),
        EventError::Token(TokenError::UntrustedIssuer)
    );
    assert!(
        verify_event(
            &sign("aa-event+jwt", &payload, 5),
            BODY,
            AGENT,
            &resource_keys(),
            1000
        )
        .is_ok()
    );
}

#[test]
fn the_agent_does_not_act_on_a_body_that_does_not_verify() {
    let with_body = event(&claims(BODY));
    let altered = br#"{"event_type":"slot.available","slot_time":"2026-07-15T11:00:00Z"}"#;
    assert_eq!(
        verify_event(&with_body, altered, AGENT, &resource_keys(), 1000).unwrap_err(),
        EventError::Body
    );
    assert_eq!(
        verify_event(&with_body, b"", AGENT, &resource_keys(), 1000).unwrap_err(),
        EventError::Body
    );
    let bodiless = event(&claims(b""));
    assert!(verify_event(&bodiless, b"", AGENT, &resource_keys(), 1000).is_ok());
    assert_eq!(
        verify_event(&bodiless, BODY, AGENT, &resource_keys(), 1000).unwrap_err(),
        EventError::Body
    );
}

#[test]
fn the_agent_maps_eid_to_its_context_and_ignores_a_repeated_event() {
    let mut subscriptions = EventSubscriptions::new(AGENT).unwrap();
    let eid = subscriptions
        .remember(
            &subscribe_token(AGENT, RESOURCE, "evt_8f3k2n9p", 2),
            "waitlist for Dr. Smith",
        )
        .unwrap();
    assert_eq!(eid, "evt_8f3k2n9p");
    let token = event(&claims(BODY));
    let received = subscriptions
        .receive(&token, BODY, &resource_keys(), 1000)
        .unwrap();
    assert_eq!(*received.context, "waitlist for Dr. Smith");
    assert_eq!(received.token.claims().eid, "evt_8f3k2n9p");
    assert_eq!(
        subscriptions
            .receive(&token, BODY, &resource_keys(), 1001)
            .unwrap_err(),
        EventError::Duplicate
    );
    let mut next = claims(BODY);
    next.jti = "ev-4d2a92".into();
    assert!(
        subscriptions
            .receive(&event(&next), BODY, &resource_keys(), 1001)
            .is_ok()
    );
    let mut unknown = claims(BODY);
    unknown.eid = "evt_unknown".into();
    unknown.jti = "ev-unknown".into();
    assert_eq!(
        subscriptions
            .receive(&event(&unknown), BODY, &resource_keys(), 1000)
            .unwrap_err(),
        EventError::UnknownSubscription
    );
    // An event must come from the Resource the subscription names.
    subscriptions
        .remember(
            &subscribe_token(AGENT, "https://other.example", "evt_other", 2),
            "other",
        )
        .unwrap();
    let mut misrouted = claims(BODY);
    misrouted.eid = "evt_other".into();
    misrouted.jti = "ev-misrouted".into();
    assert_eq!(
        subscriptions
            .receive(&event(&misrouted), BODY, &resource_keys(), 1000)
            .unwrap_err(),
        EventError::ResourceMismatch
    );
    assert!(
        subscriptions
            .remember(
                &subscribe_token("aauth:someone@ap.example", RESOURCE, "evt_x", 2),
                "x"
            )
            .is_err()
    );
    assert_eq!(
        subscriptions.forget("evt_8f3k2n9p"),
        Some("waitlist for Dr. Smith")
    );
}

#[test]
fn a_subscription_request_presents_the_subscribe_token_with_the_agent_key() {
    let key = SigningKey::from_seed([2; 32]);
    let agent_token = Jws::sign(
        &json!({"typ": "aa-agent+jwt", "alg": "Ed25519", "kid": "ap-1"}),
        json!({
            "iss": "https://ap.example",
            "dwk": "aauth-agent.json",
            "sub": AGENT,
            "jti": "agent-1",
            "iat": 1000,
            "exp": 2000,
            "cnf": {"jwk": key.public_jwk()}
        })
        .to_string()
        .as_bytes(),
        &SigningKey::from_seed([1; 32]),
    )
    .unwrap();
    let agent = Agent::new(key, agent_token).unwrap();
    let subscribe = subscribe_token(AGENT, RESOURCE, "evt_8f3k2n9p", 2);
    let mut request = Request::builder()
        .method("POST")
        .uri("https://resource.example/appointments/waitlist")
        .header("content-type", "application/json")
        .body(br#"{"event_types":["slot.available"]}"#.to_vec())
        .unwrap();
    agent
        .sign_subscription(&mut request, &subscribe, 1000)
        .unwrap();
    let proof = PreparedRequest::prepare_with_schemes(&request, "sig", 1000, 60, &["jwt"]).unwrap();
    let KeyMaterial::Jwt(presented) = proof.key() else {
        panic!("subscribe token is not the Signature-Key JWT")
    };
    assert_eq!(*presented, subscribe);
    proof
        .verify(&SigningKey::from_seed([2; 32]).public_jwk())
        .unwrap();
    // A subscribe token bound to another key is never presented.
    let mut other = Request::builder()
        .method("POST")
        .uri("https://resource.example/appointments/waitlist")
        .body(Vec::new())
        .unwrap();
    assert!(
        agent
            .sign_subscription(
                &mut other,
                &subscribe_token(AGENT, RESOURCE, "evt_y", 3),
                1000
            )
            .is_err()
    );
}
