use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{
    EventInbox, EventStore, EventStoreError, InboxConfigurationError, InboxDecision,
    MemoryEventStore, Recorded, RecordedEvent, SubscribeError, SubscribeRequest, Subscription,
};
use aauth_rust_core::events::{
    EventClaims, SubscribeToken, body_s256, generate_identifier, mint_event_token,
};
use aauth_rust_core::{
    AgentClaims, AgentProviderKeys, Confirmation, TokenError, TrustedIssuerKeys,
};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};

const AGENT: &str = "aauth:k7q3p9n2@ap.example";
const RESOURCE: &str = "https://resource.example";
const PAYLOAD: &[u8] = br#"{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}"#;

fn provider() -> AgentProvider {
    AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .with_event_endpoint("https://ap.example/events")
        .unwrap()
}
fn agent_token(ap: &AgentProvider) -> String {
    ap.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: AGENT.into(),
        jti: "agent-1".into(),
        iat: 1000,
        exp: 5000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })
    .unwrap()
}
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
fn inbox() -> (
    AgentProvider,
    EventInbox<TrustedIssuerKeys, MemoryEventStore>,
) {
    let ap = provider();
    let inbox = EventInbox::new(&ap, resource_keys(), MemoryEventStore::new()).unwrap();
    (ap, inbox)
}
fn subscribe(
    ap: &AgentProvider,
    inbox: &EventInbox<TrustedIssuerKeys, MemoryEventStore>,
    max_uses: Option<u64>,
) -> Subscription {
    ap.issue_subscribe_token(
        inbox.store(),
        &SubscribeRequest {
            agent_token: &agent_token(ap),
            resource: RESOURCE,
            expires_at: 2000,
            max_uses,
            subscription_expires_at: None,
        },
        1000,
    )
    .unwrap()
    .subscription
}
fn claims(eid: &str, body: &[u8]) -> EventClaims {
    EventClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: AGENT.into(),
        eid: eid.into(),
        jti: generate_identifier(),
        iat: 1000,
        exp: 1300,
        body_s256: (!body.is_empty()).then(|| body_s256(body)),
        extra: Default::default(),
    }
}
/// A Resource's delivery: the event token as a `self-jwt`, signed by the
/// same key, with the body and its media type.
fn delivery(token: &str, body: &[u8], seed: u8) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("https://ap.example/events");
    if !body.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder.body(body.to_vec()).unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::SelfJwt { jwt: token.into() },
        1000,
    )
    .unwrap();
    request
}
fn event(claims: &EventClaims) -> String {
    mint_event_token(&SigningKey::from_seed([5; 32]), "resource-1", claims).unwrap()
}
fn signature_error(response: &Response<Vec<u8>>) -> &str {
    response
        .headers()
        .get("signature-error")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

#[test]
fn ap_metadata_publishes_its_https_event_endpoint_when_it_supports_events() {
    let ap = provider();
    let metadata: Value = serde_json::from_slice(&ap.metadata().unwrap()).unwrap();
    assert_eq!(metadata["event_endpoint"], "https://ap.example/events");
    assert_eq!(metadata["issuer"], "https://ap.example");
    let plain =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let metadata: Value = serde_json::from_slice(&plain.metadata().unwrap()).unwrap();
    assert!(metadata.get("event_endpoint").is_none());
    // Without a published endpoint there is no inbox: an AP that receives
    // events through this library always publishes event_endpoint.
    assert_eq!(
        EventInbox::new(&plain, resource_keys(), MemoryEventStore::new()).err(),
        Some(InboxConfigurationError::NoEventEndpoint)
    );
    for endpoint in [
        "http://ap.example/events",
        "https://ap.example/events?x",
        "https://ap.example/events#x",
        "ap.example/events",
    ] {
        let plain =
            AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
                .unwrap();
        assert_eq!(
            plain.with_event_endpoint(endpoint).err(),
            Some(TokenError::InvalidDiscoveryMetadata),
            "{endpoint}"
        );
    }
}

#[test]
fn a_subscribe_token_binds_the_agent_token_and_is_retained_before_release() {
    let (ap, inbox) = inbox();
    let issued = ap
        .issue_subscribe_token(
            inbox.store(),
            &SubscribeRequest {
                agent_token: &agent_token(&ap),
                resource: RESOURCE,
                expires_at: 2000,
                max_uses: Some(1),
                subscription_expires_at: None,
            },
            1000,
        )
        .unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let token = SubscribeToken::parse(&issued.token)
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    let claims = token.claims();
    assert_eq!(claims.sub, AGENT);
    assert_eq!(claims.aud, RESOURCE);
    assert_eq!(claims.dwk, "aauth-agent.json");
    assert_eq!(claims.max_uses, Some(1));
    assert_eq!(
        claims.cnf.jwk.thumbprint().unwrap(),
        SigningKey::from_seed([2; 32])
            .public_jwk()
            .thumbprint()
            .unwrap()
    );
    assert_eq!(issued.subscription.eid, claims.eid);
    assert_eq!(
        inbox.store().subscription(&claims.eid).unwrap(),
        Some((issued.subscription.clone(), 0))
    );
    // A token outliving the Agent token, or a zero use limit, is refused.
    for (expires_at, max_uses) in [(5001, None), (1000, None), (2000, Some(0))] {
        assert!(
            ap.issue_subscribe_token(
                inbox.store(),
                &SubscribeRequest {
                    agent_token: &agent_token(&ap),
                    resource: RESOURCE,
                    expires_at,
                    max_uses,
                    subscription_expires_at: None,
                },
                1000,
            )
            .is_err()
        );
    }
}

struct FailingStore(MemoryEventStore);
impl EventStore for FailingStore {
    fn create(&self, _: &Subscription) -> Result<(), EventStoreError> {
        Err(EventStoreError::Unavailable)
    }
    fn subscription(&self, eid: &str) -> Result<Option<(Subscription, u64)>, EventStoreError> {
        self.0.subscription(eid)
    }
    fn record(&self, _: &RecordedEvent) -> Result<Recorded, EventStoreError> {
        Err(EventStoreError::Unavailable)
    }
    fn pending(&self, agent: &str) -> Result<Vec<RecordedEvent>, EventStoreError> {
        self.0.pending(agent)
    }
    fn acknowledge(&self, agent: &str, resource: &str, jti: &str) -> Result<(), EventStoreError> {
        self.0.acknowledge(agent, resource, jti)
    }
}

#[test]
fn no_subscribe_token_is_released_when_the_record_is_not_retained() {
    let ap = provider();
    let store = FailingStore(MemoryEventStore::new());
    assert_eq!(
        ap.issue_subscribe_token(
            &store,
            &SubscribeRequest {
                agent_token: &agent_token(&ap),
                resource: RESOURCE,
                expires_at: 2000,
                max_uses: None,
                subscription_expires_at: None,
            },
            1000,
        )
        .unwrap_err(),
        SubscribeError::Store(EventStoreError::Unavailable)
    );
}

#[test]
fn the_ap_returns_202_only_after_the_event_is_recorded() {
    let ap = provider();
    let memory = MemoryEventStore::new();
    let subscription = ap
        .issue_subscribe_token(
            &memory,
            &SubscribeRequest {
                agent_token: &agent_token(&ap),
                resource: RESOURCE,
                expires_at: 2000,
                max_uses: Some(3),
                subscription_expires_at: None,
            },
            1000,
        )
        .unwrap()
        .subscription;
    let failing = EventInbox::new(&ap, resource_keys(), FailingStore(memory)).unwrap();
    let request = delivery(&event(&claims(&subscription.eid, PAYLOAD)), PAYLOAD, 5);
    let decision = failing.receive(&request, 1000);
    assert!(matches!(decision, InboxDecision::Unavailable));
    let response = decision.into_response();
    assert_eq!(response.status(), 503);
    assert!(failing.store().pending(AGENT).unwrap().is_empty());

    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    let token = event(&claims(&subscription.eid, PAYLOAD));
    let response = inbox
        .receive(&delivery(&token, PAYLOAD, 5), 1000)
        .into_response();
    assert_eq!(response.status(), 202);
    let pending = inbox.store().pending(AGENT).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_token, token);
    assert_eq!(pending[0].body, PAYLOAD);
}

#[test]
fn a_limited_subscription_reports_remaining_uses_and_accepts_no_more_than_max_uses() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, Some(2));
    let mut remaining = Vec::new();
    for _ in 0..2 {
        let token = event(&claims(&subscription.eid, PAYLOAD));
        let response = inbox
            .receive(&delivery(&token, PAYLOAD, 5), 1000)
            .into_response();
        assert_eq!(response.status(), 202);
        assert_eq!(response.headers()["content-type"], "application/json");
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        remaining.push(body["remaining_uses"].as_u64().unwrap());
    }
    assert_eq!(remaining, [1, 0]);
    let third = event(&claims(&subscription.eid, PAYLOAD));
    let response = inbox
        .receive(&delivery(&third, PAYLOAD, 5), 1000)
        .into_response();
    assert_eq!(response.status(), 404);
    assert!(response.headers().get("signature-error").is_none());
    assert_eq!(
        inbox
            .store()
            .subscription(&subscription.eid)
            .unwrap()
            .unwrap()
            .1,
        2
    );
    assert_eq!(inbox.store().pending(AGENT).unwrap().len(), 2);
}

#[test]
fn an_unlimited_subscription_gets_202_without_remaining_uses() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    for _ in 0..3 {
        let token = event(&claims(&subscription.eid, b""));
        let response = inbox
            .receive(&delivery(&token, b"", 5), 1000)
            .into_response();
        assert_eq!(response.status(), 202);
        assert!(response.body().is_empty());
    }
}

#[test]
fn a_repeated_event_is_dropped_without_spending_a_use() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, Some(1));
    let token = event(&claims(&subscription.eid, PAYLOAD));
    for _ in 0..2 {
        let response = inbox
            .receive(&delivery(&token, PAYLOAD, 5), 1000)
            .into_response();
        assert_eq!(response.status(), 202);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["remaining_uses"], 0);
    }
    assert_eq!(inbox.store().pending(AGENT).unwrap().len(), 1);
}

#[test]
fn the_ap_validates_the_event_token_and_the_http_signature_with_one_key() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    let eid = subscription.eid.as_str();

    // Step 1: typ, dwk, cnf absence and exp.
    let mut payload = serde_json::to_value(claims(eid, PAYLOAD)).unwrap();
    let typed = |typ: &str, payload: &Value| {
        Jws::sign(
            &json!({"alg":"Ed25519","typ":typ,"kid":"resource-1"}),
            payload.to_string().as_bytes(),
            &SigningKey::from_seed([5; 32]),
        )
        .unwrap()
    };
    let response = inbox
        .receive(
            &delivery(&typed("aa-agent+jwt", &payload), PAYLOAD, 5),
            1000,
        )
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_jwt");
    payload["dwk"] = json!("aauth-agent.json");
    let response = inbox
        .receive(
            &delivery(&typed("aa-event+jwt", &payload), PAYLOAD, 5),
            1000,
        )
        .into_response();
    assert_eq!(signature_error(&response), "error=invalid_jwt");
    let mut with_cnf = serde_json::to_value(claims(eid, PAYLOAD)).unwrap();
    with_cnf["cnf"] = json!({"jwk": SigningKey::from_seed([5; 32]).public_jwk()});
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ap.example/events")
        .header("content-type", "application/json")
        .body(PAYLOAD.to_vec())
        .unwrap();
    // The library signer refuses a self-jwt with cnf; place one by hand.
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::SelfJwt {
            jwt: event(&claims(eid, PAYLOAD)),
        },
        1000,
    )
    .unwrap();
    let forged = typed("aa-event+jwt", &with_cnf);
    let header = request.headers()["signature-key"].to_str().unwrap();
    let start = header.find("jwt=\"").unwrap() + 5;
    let end = header[start..].find('"').unwrap() + start;
    let replaced = format!("{}{}{}", &header[..start], forged, &header[end..]);
    request
        .headers_mut()
        .insert("signature-key", replaced.parse().unwrap());
    let response = inbox.receive(&request, 1000).into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_jwt");
    let mut expired = claims(eid, PAYLOAD);
    expired.exp = 1001;
    let response = inbox
        .receive(&delivery(&event(&expired), PAYLOAD, 5), 1001)
        .into_response();
    assert_eq!(response.status(), 401);

    // An event token signed by another key under the Resource's kid fails
    // JWT verification, even though that key signed the request.
    let forged = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":"resource-1"}),
        serde_json::to_vec(&claims(eid, PAYLOAD))
            .unwrap()
            .as_slice(),
        &SigningKey::from_seed([9; 32]),
    )
    .unwrap();
    let response = inbox
        .receive(&delivery(&forged, PAYLOAD, 9), 1000)
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_jwt");

    // A jwt-scheme delivery is not self-jwt.
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ap.example/events")
        .header("content-type", "application/json")
        .body(PAYLOAD.to_vec())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::Jwt {
            jwt: event(&claims(eid, PAYLOAD)),
            cache: false,
        },
        1000,
    )
    .unwrap();
    let response = inbox.receive(&request, 1000).into_response();
    assert_eq!(signature_error(&response), "error=unsupported_scheme");
    assert_eq!(response.headers()["accept-signature-scheme"], "self-jwt");

    // Step 3: the HTTP signature must verify with the token's own key.
    let mut request = delivery(&event(&claims(eid, PAYLOAD)), PAYLOAD, 5);
    let signature = request.headers()["signature"].to_str().unwrap().to_owned();
    let mut altered = delivery(&event(&claims(eid, PAYLOAD)), PAYLOAD, 5);
    altered
        .headers_mut()
        .insert("signature", signature.parse().unwrap());
    let response = inbox.receive(&altered, 1000).into_response();
    assert_eq!(signature_error(&response), "error=invalid_signature");
    *request.uri_mut() = "https://ap.example/other".parse().unwrap();
    let response = inbox.receive(&request, 1000).into_response();
    assert_eq!(response.status(), 401);
    assert!(inbox.store().pending(AGENT).unwrap().is_empty());
}

#[test]
fn the_ap_checks_body_s256_against_the_body() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    let eid = subscription.eid.as_str();
    let other = br#"{"event_type":"slot.taken"}"#;
    let cases: [(EventClaims, &[u8]); 3] = [
        // Digest of a different body.
        (claims(eid, PAYLOAD), other),
        // A body without body_s256.
        (claims(eid, b""), PAYLOAD),
        // body_s256 without a body.
        (claims(eid, PAYLOAD), b""),
    ];
    for (claims, body) in cases {
        let response = inbox
            .receive(&delivery(&event(&claims), body, 5), 1000)
            .into_response();
        assert_eq!(response.status(), 401);
        assert_eq!(signature_error(&response), "error=invalid_jwt");
    }
    assert!(inbox.store().pending(AGENT).unwrap().is_empty());
}

#[test]
fn a_body_must_be_signed_with_content_digest_and_content_type() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    let token = event(&claims(&subscription.eid, PAYLOAD));
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ap.example/events")
        .body(PAYLOAD.to_vec())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::SelfJwt { jwt: token },
        1000,
    )
    .unwrap();
    let response = inbox.receive(&request, 1000).into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(
        signature_error(&response),
        "error=invalid_input, required_input=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-digest\" \"content-type\")"
    );
    assert!(inbox.store().pending(AGENT).unwrap().is_empty());
}

#[test]
fn the_ap_routes_by_eid_and_refuses_another_resource_or_agent() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, Some(1));
    let response = inbox
        .receive(
            &delivery(&event(&claims("evt_unknown", PAYLOAD)), PAYLOAD, 5),
            1000,
        )
        .into_response();
    assert_eq!(response.status(), 404);

    // A different, verified Resource delivering on this eid: 403.
    let other_jwks = json!({"keys":[{"kid":"other-1",
        "kty":"OKP","crv":"Ed25519","alg":"Ed25519",
        "x":SigningKey::from_seed([6; 32]).public_jwk().x}]});
    let other_keys = TrustedIssuerKeys::from_documents(
        "https://other.example",
        "aauth-resource.json",
        br#"{"issuer":"https://other.example","jwks_uri":"https://other.example/jwks.json"}"#,
        other_jwks.to_string().as_bytes(),
    )
    .unwrap();
    let other_inbox = EventInbox::new(
        &ap,
        other_keys,
        std::sync::Arc::new(MemoryEventStore::new()),
    )
    .unwrap();
    other_inbox.store().create(&subscription).unwrap();
    let mut foreign = claims(&subscription.eid, PAYLOAD);
    foreign.iss = "https://other.example".into();
    let token = mint_event_token(&SigningKey::from_seed([6; 32]), "other-1", &foreign).unwrap();
    let response = other_inbox
        .receive(&delivery(&token, PAYLOAD, 6), 1000)
        .into_response();
    assert_eq!(response.status(), 403);
    assert!(response.headers().get("signature-error").is_none());

    // Step 8: an aud other than the subscribed Agent is invalid_jwt, and
    // spends no use.
    let mut misaddressed = claims(&subscription.eid, PAYLOAD);
    misaddressed.aud = "aauth:K7q3p9n2@ap.example".into();
    let response = inbox
        .receive(&delivery(&event(&misaddressed), PAYLOAD, 5), 1000)
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_jwt");
    let response = inbox
        .receive(
            &delivery(&event(&claims(&subscription.eid, PAYLOAD)), PAYLOAD, 5),
            1000,
        )
        .into_response();
    assert_eq!(response.status(), 202);
}

#[test]
fn an_ended_subscription_is_404() {
    let ap = provider();
    let inbox = EventInbox::new(&ap, resource_keys(), MemoryEventStore::new()).unwrap();
    let subscription = ap
        .issue_subscribe_token(
            inbox.store(),
            &SubscribeRequest {
                agent_token: &agent_token(&ap),
                resource: RESOURCE,
                expires_at: 2000,
                max_uses: None,
                subscription_expires_at: Some(1100),
            },
            1000,
        )
        .unwrap()
        .subscription;
    let mut late = claims(&subscription.eid, PAYLOAD);
    late.iat = 1100;
    late.exp = 1400;
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ap.example/events")
        .header("content-type", "application/json")
        .body(PAYLOAD.to_vec())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::SelfJwt { jwt: event(&late) },
        1100,
    )
    .unwrap();
    assert_eq!(inbox.receive(&request, 1100).into_response().status(), 404);
}

#[test]
fn the_ap_hands_the_agent_the_exact_token_and_body_bytes() {
    let (ap, inbox) = inbox();
    let subscription = subscribe(&ap, &inbox, None);
    // Bytes a JSON parser or a trimming transport would normalize:
    // surrounding and inner whitespace, and member order.
    let body =
        b"\n{ \"slot_time\" : \"2026-07-15T10:00:00Z\",\n  \"event_type\":\"slot.available\" }\n";
    let token = event(&claims(&subscription.eid, body));
    let response = inbox
        .receive(&delivery(&token, body, 5), 1000)
        .into_response();
    assert_eq!(response.status(), 202);
    let pending = inbox.store().pending(AGENT).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].body, body);
    assert_eq!(pending[0].event_token, token);
    assert_eq!(pending[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(pending[0].eid, subscription.eid);
    assert_eq!(pending[0].agent, AGENT);
    inbox
        .store()
        .acknowledge(AGENT, RESOURCE, &pending[0].jti)
        .unwrap();
    assert!(inbox.store().pending(AGENT).unwrap().is_empty());
}
