//! AAuth Events across the four roles: the Agent Provider issues a subscribe
//! token, the Agent registers it at the Resource, the Resource delivers a
//! signed event to the Agent Provider, and the Agent verifies it.
use aauth_rust_agent::{Agent, EventSubscriptions};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{
    EventInbox, EventStore, MemoryEventStore, SubscribeRequest,
};
use aauth_rust_core::events::{SubscribeClaims, body_s256, mint_subscribe_token};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentProviderKeys, Confirmation, PersonClaims, PersonToken,
    TokenError, TrustedIssuerKeys, VerifiedPersonToken, mint_person_token,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_resource::Deny;
use aauth_rust_resource::events::{
    AsyncApiDeclarationError, DeliveryOutcome, EventDeliveryError, EventPayload, EventsConfig,
    EventsConfigurationError, EventsResource, MemorySubscriptionStore, RegistrationDecision,
    ResourceSubscription, SubscriptionStore, TicketError, check_subscribe_security_scheme,
    subscribe_security_scheme,
};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};

const AGENT: &str = "aauth:k7q3p9n2@ap.example";
const RESOURCE: &str = "https://resource.example";
const PAYLOAD: &[u8] = br#"{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}"#;

type Resource = EventsResource<AgentProviderKeys, MemorySubscriptionStore>;

fn provider() -> AgentProvider {
    AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .with_event_endpoint("https://ap.example/events")
        .unwrap()
}
fn ap_keys(ap: &AgentProvider) -> AgentProviderKeys {
    AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap()
}
fn agent_token(ap: &AgentProvider, seed: u8) -> String {
    ap.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: AGENT.into(),
        jti: format!("agent-{seed}"),
        iat: 1000,
        exp: 5000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([seed; 32]).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })
    .unwrap()
}
fn agent(ap: &AgentProvider) -> Agent {
    Agent::new(SigningKey::from_seed([2; 32]), agent_token(ap, 2)).unwrap()
}
fn config(issuer: &str, seed: u8) -> EventsConfig {
    EventsConfig {
        issuer: issuer.into(),
        signed_origin: issuer.into(),
        kid: "resource-1".into(),
        signing_key: SigningKey::from_seed([seed; 32]),
        ticket_path: "/appointments/waitlist/".into(),
        max_ticket_lifetime: 300,
    }
}
fn resource(ap: &AgentProvider) -> Resource {
    EventsResource::new(
        config(RESOURCE, 5),
        ap_keys(ap),
        MemorySubscriptionStore::new(),
    )
    .unwrap()
}
/// What the Agent Provider resolves for a Resource: its metadata and JWKS.
fn resource_keys(issuer: &str, jwks: &[u8]) -> TrustedIssuerKeys {
    let metadata = json!({"issuer":issuer,"jwks_uri":format!("{issuer}/.well-known/jwks.json")});
    TrustedIssuerKeys::from_documents(
        issuer,
        "aauth-resource.json",
        metadata.to_string().as_bytes(),
        jwks,
    )
    .unwrap()
}
fn subscribe_token(ap: &AgentProvider, store: &dyn EventStore, max_uses: Option<u64>) -> String {
    ap.issue_subscribe_token(
        store,
        &SubscribeRequest {
            agent_token: &agent_token(ap, 2),
            resource: RESOURCE,
            expires_at: 2000,
            max_uses,
            subscription_expires_at: None,
        },
        1000,
    )
    .unwrap()
    .token
}
fn subscribe_claims(aud: &str, eid: &str, seed: u8) -> SubscribeClaims {
    SubscribeClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: AGENT.into(),
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
    }
}
fn minted(claims: &SubscribeClaims) -> String {
    mint_subscribe_token(&SigningKey::from_seed([1; 32]), "ap-1", claims).unwrap()
}
fn registration(path: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}{path}"))
        .header("content-type", "application/json")
        .body(br#"{"event_types":["slot.available"]}"#.to_vec())
        .unwrap()
}
/// A registration signed by `seed`'s key, presenting `token` under `jwt`.
fn signed_registration(path: &str, token: &str, seed: u8, now: i64) -> Request<Vec<u8>> {
    let mut request = registration(path);
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::Jwt {
            jwt: token.into(),
            cache: false,
        },
        now,
    )
    .unwrap();
    request
}
fn allow(_: &aauth_rust_resource::events::SubscriptionRequest<'_>) -> Result<Vec<u8>, Deny> {
    Ok(b"waitlist".to_vec())
}
fn signature_error(response: &Response<Vec<u8>>) -> String {
    response
        .headers()
        .get("signature-error")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned()
}
fn payload_of(compact: &str) -> Value {
    serde_json::from_slice(Jws::parse(compact).unwrap().payload()).unwrap()
}

#[test]
fn the_resource_verifies_the_subscribe_token_before_registering() {
    let ap = provider();
    let store = MemoryEventStore::new();
    let resource = resource(&ap);
    let agent = agent(&ap);
    let path = "/appointments/waitlist";

    let token = subscribe_token(&ap, &store, Some(1));
    let mut request = registration(path);
    agent.sign_subscription(&mut request, &token, 1000).unwrap();
    let RegistrationDecision::Registered(subscription) = resource.register(&request, 1000, allow)
    else {
        panic!("a valid subscribe token was refused")
    };
    let claims = payload_of(&token);
    assert_eq!(subscription.eid, claims["eid"]);
    assert_eq!(subscription.agent_provider, "https://ap.example");
    assert_eq!(subscription.agent, AGENT);
    assert_eq!(subscription.max_uses, Some(1));
    assert_eq!(subscription.context, b"waitlist");
    assert_eq!(
        resource
            .store()
            .subscription("https://ap.example", subscription.eid.as_str())
            .unwrap(),
        Some(subscription.clone())
    );

    let refusals: Vec<(&str, Request<Vec<u8>>, i64, &str)> = vec![
        // aud names another Resource.
        (
            "aud",
            signed_registration(
                path,
                &minted(&subscribe_claims("https://other.example", "evt_aud", 2)),
                2,
                1000,
            ),
            1000,
            "error=invalid_jwt",
        ),
        // exp has passed by the Resource's own clock.
        (
            "exp",
            signed_registration(
                path,
                &minted(&subscribe_claims(RESOURCE, "evt_exp", 2)),
                2,
                2000,
            ),
            2000,
            "error=expired_jwt",
        ),
        // cnf.jwk is not the key that signed the request.
        (
            "cnf",
            signed_registration(
                path,
                &minted(&subscribe_claims(RESOURCE, "evt_cnf", 3)),
                2,
                1000,
            ),
            1000,
            "error=invalid_signature",
        ),
        // An Agent token in place of a subscribe token.
        (
            "typ",
            signed_registration(path, &agent_token(&ap, 2), 2, 1000),
            1000,
            "error=invalid_jwt",
        ),
    ];
    for (name, request, now, code) in refusals {
        let response = resource.register(&request, now, allow).into_response();
        assert_eq!(response.status(), 401, "{name}");
        assert_eq!(signature_error(&response), code, "{name}");
    }

    // dwk and eid are checked on the token itself.
    for (name, change) in [
        ("dwk", json!({"dwk": "aauth-resource.json"})),
        ("eid", json!({"eid": ""})),
    ] {
        let mut payload = serde_json::to_value(subscribe_claims(RESOURCE, "evt_x", 2)).unwrap();
        for (key, value) in change.as_object().unwrap() {
            payload[key] = value.clone();
        }
        let token = Jws::sign(
            &json!({"alg":"Ed25519","typ":"aa-subscribe+jwt","kid":"ap-1"}),
            payload.to_string().as_bytes(),
            &SigningKey::from_seed([1; 32]),
        )
        .unwrap();
        let response = resource
            .register(&signed_registration(path, &token, 2, 1000), 1000, allow)
            .into_response();
        assert_eq!(response.status(), 401, "{name}");
        assert_eq!(signature_error(&response), "error=invalid_jwt", "{name}");
    }

    // A subscribe token signed by another key under the AP's kid.
    let forged = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-subscribe+jwt","kid":"ap-1"}),
        serde_json::to_vec(&subscribe_claims(RESOURCE, "evt_forged", 2))
            .unwrap()
            .as_slice(),
        &SigningKey::from_seed([9; 32]),
    )
    .unwrap();
    let response = resource
        .register(&signed_registration(path, &forged, 2, 1000), 1000, allow)
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_jwt");

    // A subscribe token from an Agent Provider this Resource does not trust.
    let mut foreign = subscribe_claims(RESOURCE, "evt_foreign", 2);
    foreign.iss = "https://rogue.example".into();
    foreign.sub = "aauth:k7q3p9n2@rogue.example".into();
    let response = resource
        .register(
            &signed_registration(path, &minted(&foreign), 2, 1000),
            1000,
            allow,
        )
        .into_response();
    assert_eq!(response.status(), 401);
    assert_eq!(signature_error(&response), "error=invalid_key");

    // Policy runs only after verification and can still refuse.
    let token = subscribe_token(&ap, &store, None);
    let mut request = registration(path);
    agent.sign_subscription(&mut request, &token, 1000).unwrap();
    let response = resource
        .register(&request, 1000, |_| Err(Deny))
        .into_response();
    assert_eq!(response.status(), 403);
    assert!(response.headers().get("signature-error").is_none());
}

#[test]
fn a_repeated_registration_of_one_eid_is_refused() {
    let ap = provider();
    let store = MemoryEventStore::new();
    let resource = resource(&ap);
    let agent = agent(&ap);
    let token = subscribe_token(&ap, &store, None);
    let mut first = registration("/appointments/waitlist");
    agent.sign_subscription(&mut first, &token, 1000).unwrap();
    assert_eq!(
        resource
            .register(&first, 1000, allow)
            .into_response()
            .status(),
        200
    );
    let mut second = registration("/appointments/waitlist");
    agent.sign_subscription(&mut second, &token, 1001).unwrap();
    assert_eq!(
        resource
            .register(&second, 1001, allow)
            .into_response()
            .status(),
        409
    );
}

fn registered(
    ap: &AgentProvider,
    resource: &Resource,
    store: &dyn EventStore,
    max_uses: Option<u64>,
) -> ResourceSubscription {
    let token = subscribe_token(ap, store, max_uses);
    let mut request = registration("/appointments/waitlist");
    agent(ap)
        .sign_subscription(&mut request, &token, 1000)
        .unwrap();
    match resource.register(&request, 1000, allow) {
        RegistrationDecision::Registered(subscription) => subscription,
        other => panic!("registration refused: {other:?}"),
    }
}

#[test]
fn event_tokens_carry_the_subscription_eid_body_s256_and_no_cnf() {
    let ap = provider();
    let store = MemoryEventStore::new();
    let resource = resource(&ap);
    let subscription = registered(&ap, &resource, &store, None);
    let payload = EventPayload {
        content_type: "application/json",
        body: PAYLOAD,
    };
    let with_body = resource
        .prepare_event(
            "https://ap.example",
            &subscription.eid,
            Some(payload),
            1300,
            1000,
        )
        .unwrap();
    let bodiless = resource
        .prepare_event("https://ap.example", &subscription.eid, None, 1300, 1000)
        .unwrap();
    let header = Jws::parse(with_body.token()).unwrap().header().clone();
    assert_eq!(header["typ"], "aa-event+jwt");
    assert_eq!(header["kid"], "resource-1");
    assert_eq!(header["alg"], "Ed25519");
    let claims = payload_of(with_body.token());
    assert_eq!(claims["iss"], RESOURCE);
    assert_eq!(claims["dwk"], "aauth-resource.json");
    assert_eq!(claims["aud"], AGENT);
    assert_eq!(claims["eid"], subscription.eid.as_str());
    assert_eq!(claims["iat"], 1000);
    assert_eq!(claims["exp"], 1300);
    assert_eq!(claims["body_s256"], body_s256(PAYLOAD));
    assert!(claims.get("cnf").is_none());
    let bare = payload_of(bodiless.token());
    assert_eq!(bare["eid"], subscription.eid.as_str());
    assert!(bare.get("body_s256").is_none());
    assert!(bare.get("cnf").is_none());
    assert_ne!(claims["jti"], bare["jti"]);
    assert!(bodiless.body().is_empty());
    for (content_type, body) in [
        ("application/json", &b""[..]),
        ("", PAYLOAD),
        ("a\nb", PAYLOAD),
    ] {
        assert_eq!(
            resource
                .prepare_event(
                    "https://ap.example",
                    &subscription.eid,
                    Some(EventPayload { content_type, body }),
                    1300,
                    1000,
                )
                .unwrap_err(),
            EventDeliveryError::InvalidPayload
        );
    }
    assert_eq!(
        resource
            .prepare_event("https://ap.example", "evt_unknown", None, 1300, 1000)
            .unwrap_err(),
        EventDeliveryError::UnknownSubscription
    );
    assert_eq!(
        resource
            .prepare_event("https://ap.example", &subscription.eid, None, 1000, 1000)
            .unwrap_err(),
        EventDeliveryError::Token(TokenError::InvalidTokenLifetime)
    );
}

#[test]
fn a_delivery_with_a_body_covers_content_digest_and_content_type() {
    let ap = provider();
    let store = MemoryEventStore::new();
    let resource = resource(&ap);
    let subscription = registered(&ap, &resource, &store, None);
    let event = resource
        .prepare_event(
            "https://ap.example",
            &subscription.eid,
            Some(EventPayload {
                content_type: "application/json",
                body: PAYLOAD,
            }),
            1300,
            1000,
        )
        .unwrap();
    let request = resource
        .delivery_request(&event, &ap.metadata().unwrap(), 1000)
        .unwrap();
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri(), "https://ap.example/events");
    assert_eq!(request.body(), PAYLOAD);
    assert_eq!(request.headers()["content-type"], "application/json");
    let input = request.headers()["signature-input"].to_str().unwrap();
    for component in [
        "\"content-digest\"",
        "\"content-type\"",
        "\"signature-key\"",
        "\"@path\"",
    ] {
        assert!(
            input.contains(component),
            "{component} not covered: {input}"
        );
    }
    assert_eq!(
        request.headers()["signature-key"].to_str().unwrap(),
        format!("sig=self-jwt;jwt=\"{}\"", event.token())
    );
    let proof =
        PreparedRequest::prepare_with_schemes(&request, "sig", 1000, 60, &["self-jwt"]).unwrap();
    proof
        .verify(&SigningKey::from_seed([5; 32]).public_jwk())
        .unwrap();

    let bodiless = resource
        .prepare_event("https://ap.example", &subscription.eid, None, 1300, 1000)
        .unwrap();
    let request = resource
        .delivery_request(&bodiless, &ap.metadata().unwrap(), 1000)
        .unwrap();
    let input = request.headers()["signature-input"].to_str().unwrap();
    assert!(!input.contains("content-digest"));
    assert!(request.headers().get("content-type").is_none());
    assert!(request.body().is_empty());

    // The endpoint is resolved from the Agent Provider's current metadata.
    let moved = AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .with_event_endpoint("https://inbox.ap.example/v2/events")
        .unwrap();
    let request = resource
        .delivery_request(&bodiless, &moved.metadata().unwrap(), 1000)
        .unwrap();
    assert_eq!(request.uri(), "https://inbox.ap.example/v2/events");
    let impostor =
        br#"{"issuer":"https://rogue.example","event_endpoint":"https://rogue.example/e"}"#;
    assert_eq!(
        resource
            .delivery_request(&bodiless, impostor, 1000)
            .unwrap_err(),
        EventDeliveryError::Token(TokenError::IssuerMismatch)
    );
}

fn person_token(seed: u8) -> VerifiedPersonToken {
    let ps = SigningKey::from_seed([7; 32]);
    let compact = mint_person_token(
        &ps,
        "ps-1",
        &PersonClaims {
            iss: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "person-1".into(),
            jti: format!("person-{seed}"),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([seed; 32]).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )
    .unwrap();
    let mut jwk = serde_json::to_value(ps.public_jwk()).unwrap();
    jwk["kid"] = json!("ps-1");
    let keys = TrustedIssuerKeys::from_documents(
        "https://ps.example",
        "aauth-person.json",
        br#"{"issuer":"https://ps.example","jwks_uri":"https://ps.example/jwks.json"}"#,
        json!({"keys":[jwk]}).to_string().as_bytes(),
    )
    .unwrap();
    PersonToken::parse(&compact)
        .unwrap()
        .verify(&keys, 1000)
        .unwrap()
}
fn thumbprint(seed: u8) -> String {
    SigningKey::from_seed([seed; 32])
        .public_jwk()
        .thumbprint()
        .unwrap()
}
fn ticket_path(url: &str) -> &str {
    url.strip_prefix(RESOURCE).unwrap()
}

#[test]
fn a_ticket_is_bound_to_the_thumbprint_of_the_key_that_established_it() {
    let ap = provider();
    let resource = resource(&ap);
    let issued = resource
        .issue_ticket(&person_token(2), b"appointment:42", 300, 1000)
        .unwrap();
    assert!(
        issued
            .url
            .starts_with("https://resource.example/appointments/waitlist/")
    );
    assert_eq!(issued.ticket.key_thumbprint, thumbprint(2));
    assert_eq!(issued.ticket.expires_at, 1300);
    let path = ticket_path(&issued.url);

    // A subscribe token for another key is refused, and the ticket survives.
    let other_key = minted(&subscribe_claims(RESOURCE, "evt_other_key", 3));
    let response = resource
        .register_with_ticket(&signed_registration(path, &other_key, 3, 1000), 1000, allow)
        .into_response();
    assert_eq!(response.status(), 403);
    assert!(response.headers().get("signature-error").is_none());

    // The binding is the key, not the Agent identifier the token names.
    let mut renamed = subscribe_claims(RESOURCE, "evt_bound", 2);
    renamed.sub = "aauth:another@ap.example".into();
    let mut seen_context = Vec::new();
    let decision = resource.register_with_ticket(
        &signed_registration(path, &minted(&renamed), 2, 1000),
        1000,
        |request| {
            seen_context = request.ticket.unwrap().context.clone();
            Ok(b"appointment:42".to_vec())
        },
    );
    let subscription = match decision {
        RegistrationDecision::Registered(subscription) => subscription,
        other => panic!("the ticket's own key was refused: {other:?}"),
    };
    assert_eq!(seen_context, b"appointment:42");
    assert_eq!(subscription.eid, "evt_bound");
}

#[test]
fn a_ticket_is_single_use_and_short_lived() {
    let ap = provider();
    let resource = resource(&ap);
    let holder = person_token(2);
    let issued = resource.issue_ticket(&holder, b"ctx", 300, 1000).unwrap();
    let path = ticket_path(&issued.url).to_owned();
    let first = minted(&subscribe_claims(RESOURCE, "evt_first", 2));
    assert_eq!(
        resource
            .register_with_ticket(&signed_registration(&path, &first, 2, 1000), 1000, allow)
            .into_response()
            .status(),
        200
    );
    let second = minted(&subscribe_claims(RESOURCE, "evt_second", 2));
    assert_eq!(
        resource
            .register_with_ticket(&signed_registration(&path, &second, 2, 1001), 1001, allow)
            .into_response()
            .status(),
        403
    );
    assert!(
        resource
            .store()
            .ticket(&issued.ticket.id)
            .unwrap()
            .is_none()
    );

    let short = resource.issue_ticket(&holder, b"ctx", 10, 1000).unwrap();
    let late = minted(&subscribe_claims(RESOURCE, "evt_late", 2));
    assert_eq!(
        resource
            .register_with_ticket(
                &signed_registration(ticket_path(&short.url), &late, 2, 1010),
                1010,
                allow
            )
            .into_response()
            .status(),
        403
    );
    for lifetime in [0, 301, -5] {
        assert_eq!(
            resource
                .issue_ticket(&holder, b"ctx", lifetime, 1000)
                .unwrap_err(),
            TicketError::InvalidLifetime
        );
    }
    let unknown = minted(&subscribe_claims(RESOURCE, "evt_unknown", 2));
    assert_eq!(
        resource
            .register_with_ticket(
                &signed_registration("/appointments/waitlist/not-a-ticket", &unknown, 2, 1000),
                1000,
                allow
            )
            .into_response()
            .status(),
        403
    );
    let mut long = config(RESOURCE, 5);
    long.max_ticket_lifetime = 3601;
    assert_eq!(
        EventsResource::new(long, ap_keys(&ap), MemorySubscriptionStore::new()).err(),
        Some(EventsConfigurationError::InvalidTicketLifetime)
    );
}

#[test]
fn the_resource_declares_the_subscribe_security_scheme() {
    let scheme = subscribe_security_scheme();
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "aauth-subscribe");
    // The draft's example document, in JSON form.
    let document = json!({
        "asyncapi": "3.0.0",
        "info": {"title": "Appointments Events", "version": "1.0.0"},
        "channels": {"waitlistPublic": {"address": "/appointments/waitlist/public"}},
        "operations": {"subscribePublicWaitlist": {
            "action": "receive",
            "channel": {"$ref": "#/channels/waitlistPublic"},
            "security": [{"$ref": "#/components/securitySchemes/aauth_subscribe"}]
        }},
        "components": {"securitySchemes": {"aauth_subscribe": scheme}}
    })
    .to_string()
    .into_bytes();
    assert!(check_subscribe_security_scheme(&document).is_ok());
    let ap = provider();
    let published = resource(&ap).with_asyncapi(document.clone()).unwrap();
    assert_eq!(published.asyncapi(), Some(document.as_slice()));

    let missing = json!({"asyncapi":"3.0.0","components":{"securitySchemes":{}}}).to_string();
    let bearer = json!({"asyncapi":"3.0.0","components":{"securitySchemes":{
        "aauth_subscribe":{"type":"http","scheme":"bearer"}}}})
    .to_string();
    let apikey = json!({"asyncapi":"3.0.0","components":{"securitySchemes":{
        "aauth_subscribe":{"type":"httpApiKey","scheme":"aauth-subscribe"}}}})
    .to_string();
    for (document, error) in [
        (missing.as_bytes(), AsyncApiDeclarationError::Missing),
        (bearer.as_bytes(), AsyncApiDeclarationError::Mismatch),
        (apikey.as_bytes(), AsyncApiDeclarationError::Mismatch),
        (&b"asyncapi: 3.0.0"[..], AsyncApiDeclarationError::Malformed),
    ] {
        assert_eq!(
            check_subscribe_security_scheme(document).unwrap_err(),
            error
        );
        assert_eq!(
            resource(&ap).with_asyncapi(document.to_vec()).err(),
            Some(EventsConfigurationError::AsyncApi(error))
        );
    }
}

/// Resolves keys for several Resources, as an Agent Provider that accepts
/// events from more than one would.
struct Resources(Vec<TrustedIssuerKeys>);
impl AgentKeyResolver for Resources {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        for keys in &self.0 {
            match keys.key(issuer, dwk, kid) {
                Err(TokenError::UntrustedIssuer) => continue,
                result => return result,
            }
        }
        Err(TokenError::UntrustedIssuer)
    }
}

#[test]
fn events_flow_from_the_resource_through_the_ap_to_the_agent() {
    let ap = provider();
    let resource = resource(&ap);
    let other = EventsResource::new(
        config("https://other.example", 6),
        ap_keys(&ap),
        MemorySubscriptionStore::new(),
    )
    .unwrap();
    let inbox = EventInbox::new(
        &ap,
        Resources(vec![
            resource_keys(RESOURCE, &resource.jwks().unwrap()),
            resource_keys("https://other.example", &other.jwks().unwrap()),
        ]),
        MemoryEventStore::new(),
    )
    .unwrap();
    let agent = agent(&ap);

    // The AP issues and retains; the Agent records its context and registers.
    let token = subscribe_token(&ap, inbox.store(), Some(2));
    let mut contexts = EventSubscriptions::new(AGENT).unwrap();
    let eid = contexts.remember(&token, "waitlist for Dr. Smith").unwrap();
    let mut request = registration("/appointments/waitlist");
    agent.sign_subscription(&mut request, &token, 1000).unwrap();
    assert_eq!(
        resource
            .register(&request, 1000, allow)
            .into_response()
            .status(),
        200
    );

    // An event with a body: 202 with remaining_uses, then the Agent verifies
    // the exact bytes the Agent Provider recorded.
    let first = resource
        .prepare_event(
            "https://ap.example",
            &eid,
            Some(EventPayload {
                content_type: "application/json",
                body: PAYLOAD,
            }),
            1300,
            1000,
        )
        .unwrap();
    let third = resource
        .prepare_event("https://ap.example", &eid, None, 1300, 1000)
        .unwrap();
    let delivered = resource
        .delivery_request(&first, &ap.metadata().unwrap(), 1000)
        .unwrap();
    let response = inbox.receive(&delivered, 1000).into_response();
    assert_eq!(response.status(), 202);
    assert_eq!(
        resource.delivery_outcome(&first, &response).unwrap(),
        DeliveryOutcome::Accepted {
            remaining_uses: Some(1)
        }
    );
    let pending = inbox.store().pending(AGENT).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_token, first.token());
    assert_eq!(pending[0].body, PAYLOAD);
    let agent_keys = resource_keys(RESOURCE, &resource.jwks().unwrap());
    let received = contexts
        .receive(&pending[0].event_token, &pending[0].body, &agent_keys, 1001)
        .unwrap();
    assert_eq!(*received.context, "waitlist for Dr. Smith");

    // A retry of the same event is dropped by the AP and spends no use.
    let retried = resource
        .delivery_request(&first, &ap.metadata().unwrap(), 1005)
        .unwrap();
    let response = inbox.receive(&retried, 1005).into_response();
    assert_eq!(
        resource.delivery_outcome(&first, &response).unwrap(),
        DeliveryOutcome::Accepted {
            remaining_uses: Some(1)
        }
    );

    // Another Resource cannot deliver on this eid.
    other
        .store()
        .register(&ResourceSubscription {
            agent_provider: "https://ap.example".into(),
            eid: eid.clone(),
            agent: AGENT.into(),
            max_uses: None,
            token_jti: "copied".into(),
            registered_at: 1000,
            context: Vec::new(),
        })
        .unwrap();
    let hijack = other
        .prepare_event("https://ap.example", &eid, None, 1300, 1000)
        .unwrap();
    let response = inbox
        .receive(
            &other
                .delivery_request(&hijack, &ap.metadata().unwrap(), 1000)
                .unwrap(),
            1000,
        )
        .into_response();
    assert_eq!(response.status(), 403);

    // The second event spends the subscription; the Resource cleans up.
    let second = resource
        .prepare_event("https://ap.example", &eid, None, 1300, 1000)
        .unwrap();
    let response = inbox
        .receive(
            &resource
                .delivery_request(&second, &ap.metadata().unwrap(), 1010)
                .unwrap(),
            1010,
        )
        .into_response();
    assert_eq!(
        resource.delivery_outcome(&second, &response).unwrap(),
        DeliveryOutcome::Accepted {
            remaining_uses: Some(0)
        }
    );
    assert!(
        resource
            .store()
            .subscription("https://ap.example", &eid)
            .unwrap()
            .is_none()
    );
    let response = inbox
        .receive(
            &resource
                .delivery_request(&third, &ap.metadata().unwrap(), 1020)
                .unwrap(),
            1020,
        )
        .into_response();
    assert_eq!(response.status(), 404);
    assert_eq!(
        resource.delivery_outcome(&third, &response).unwrap(),
        DeliveryOutcome::Ended
    );
    assert_eq!(inbox.store().pending(AGENT).unwrap().len(), 2);

    // A 202 for a limited subscription without remaining_uses is not trusted.
    let bare = Response::builder().status(202).body(Vec::new()).unwrap();
    assert_eq!(
        resource.delivery_outcome(&first, &bare).unwrap_err(),
        EventDeliveryError::InvalidAcceptance
    );
}

fn restarted_resource(ap: &AgentProvider, subscription: &ResourceSubscription) -> Resource {
    let store = MemorySubscriptionStore::new();
    store.register(subscription).unwrap();
    EventsResource::new(config(RESOURCE, 5), ap_keys(ap), store).unwrap()
}

#[test]
fn a_restored_event_retries_the_exact_bytes_without_spending_another_use() {
    let ap = provider();
    let original = resource(&ap);
    let inbox = EventInbox::new(
        &ap,
        resource_keys(RESOURCE, &original.jwks().unwrap()),
        MemoryEventStore::new(),
    )
    .unwrap();
    let subscription = registered(&ap, &original, inbox.store(), Some(2));
    let event = original
        .prepare_event(
            "https://ap.example",
            &subscription.eid,
            Some(EventPayload {
                content_type: "application/json",
                body: PAYLOAD,
            }),
            1300,
            1000,
        )
        .unwrap();
    let saved = serde_json::to_vec(&event.to_record()).unwrap();
    let request = original
        .delivery_request(&event, &ap.metadata().unwrap(), 1000)
        .unwrap();
    // The AP accepted this delivery, but the Resource never received the reply.
    assert_eq!(inbox.receive(&request, 1000).into_response().status(), 202);
    let exact_token = event.token().to_owned();
    drop(event);
    drop(original);

    let recovered = restarted_resource(&ap, &subscription);
    let record = serde_json::from_slice(&saved).unwrap();
    let event = recovered.restore_event(record, 1005).unwrap();
    assert_eq!(event.token(), exact_token);
    assert_eq!(event.body(), PAYLOAD);
    assert_eq!(serde_json::to_vec(&event.to_record()).unwrap(), saved);
    let retry = recovered
        .delivery_request(&event, &ap.metadata().unwrap(), 1005)
        .unwrap();
    assert_eq!(retry.headers()["content-type"], "application/json");
    let reply = inbox.receive(&retry, 1005).into_response();
    assert_eq!(
        recovered.delivery_outcome(&event, &reply).unwrap(),
        DeliveryOutcome::Accepted {
            remaining_uses: Some(1)
        }
    );
    assert_eq!(inbox.store().pending(AGENT).unwrap().len(), 1);
    assert_eq!(
        inbox.store().pending(AGENT).unwrap()[0].event_token,
        exact_token
    );
}

#[test]
fn restored_events_verify_saved_tokens_bodies_and_subscription_binding() {
    let ap = provider();
    let original = resource(&ap);
    let subscription = registered(&ap, &original, &MemoryEventStore::new(), Some(u64::MAX));
    let event = original
        .prepare_event(
            "https://ap.example",
            &subscription.eid,
            Some(EventPayload {
                content_type: "application/json",
                body: PAYLOAD,
            }),
            1300,
            1000,
        )
        .unwrap();
    let record = event.to_record();
    assert_eq!(record.max_uses, Some(u64::MAX));
    let recovered = restarted_resource(&ap, &subscription);
    assert!(recovered.restore_event(record.clone(), 1005).is_ok());
    let mut changed = Vec::new();
    let mut r = record.clone();
    r.version += 1;
    changed.push(r);
    let mut r = record.clone();
    r.body[0] ^= 1;
    changed.push(r);
    let mut r = record.clone();
    r.content_type = None;
    changed.push(r);
    let mut r = record.clone();
    r.content_type = Some("a\nb".into());
    changed.push(r);
    let mut r = record.clone();
    r.body.clear();
    changed.push(r);
    let mut r = record.clone();
    r.agent_provider = "https://other.example".into();
    changed.push(r);
    let mut r = record.clone();
    r.eid.push('x');
    changed.push(r);
    let mut r = record.clone();
    r.agent = "aauth:other@ap.example".into();
    changed.push(r);
    let mut r = record.clone();
    r.max_uses = None;
    changed.push(r);
    let mut r = record.clone();
    r.subscription_jti.push('x');
    changed.push(r);
    let mut r = record.clone();
    let index = r.token.rfind('.').unwrap() + 4;
    r.token.replace_range(
        index..index + 1,
        if &r.token[index..index + 1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    changed.push(r);
    for (index, record) in changed.into_iter().enumerate() {
        assert!(
            recovered.restore_event(record, 1005).is_err(),
            "corruption {index}"
        );
    }
    assert_eq!(
        recovered
            .store()
            .subscription("https://ap.example", &subscription.eid)
            .unwrap(),
        Some(subscription.clone())
    );
    for c in [config(RESOURCE, 6), config("https://other.example", 5), {
        let mut c = config(RESOURCE, 5);
        c.kid = "different-key-id".into();
        c
    }] {
        let store = MemorySubscriptionStore::new();
        store.register(&subscription).unwrap();
        let other = EventsResource::new(c, ap_keys(&ap), store).unwrap();
        assert!(other.restore_event(record.clone(), 1005).is_err());
    }
}

#[test]
fn restoring_never_renews_an_expired_event_or_revives_a_subscription() {
    let ap = provider();
    let original = resource(&ap);
    let subscription = registered(&ap, &original, &MemoryEventStore::new(), None);
    let event = original
        .prepare_event("https://ap.example", &subscription.eid, None, 1300, 1000)
        .unwrap();
    let record = event.to_record();
    let recovered = restarted_resource(&ap, &subscription);
    let bare = recovered.restore_event(record.clone(), 1299).unwrap();
    assert!(bare.body().is_empty());
    assert!(
        !recovered
            .delivery_request(&bare, &ap.metadata().unwrap(), 1299)
            .unwrap()
            .headers()
            .contains_key("content-type")
    );
    assert_eq!(
        recovered.restore_event(record.clone(), 1300).unwrap_err(),
        EventDeliveryError::Token(TokenError::ExpiredJwt)
    );
    recovered
        .store()
        .remove("https://ap.example", &subscription.eid)
        .unwrap();
    assert_eq!(
        recovered.restore_event(record.clone(), 1005).unwrap_err(),
        EventDeliveryError::UnknownSubscription
    );
    let mut replacement = subscription.clone();
    replacement.token_jti.push('x');
    recovered.store().register(&replacement).unwrap();
    assert!(recovered.restore_event(record, 1005).is_err());
    assert_eq!(
        recovered
            .store()
            .subscription("https://ap.example", &subscription.eid)
            .unwrap(),
        Some(replacement)
    );
}
