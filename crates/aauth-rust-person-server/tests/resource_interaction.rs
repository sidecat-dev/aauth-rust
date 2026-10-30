//! A resource token that needs the resource's own flow before Person Server
//! consent (`draft-hardt-oauth-aauth-protocol`, Resource-Initiated Interaction
//! and Interaction Callback Errors).
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_core::interaction::{
    CallbackError, InteractionOutcome, ResourceInteraction, completion_redirect,
    parse_interaction_query,
};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentProviderKeys, AuthToken, Confirmation, PersonToken,
    ResourceClaims, TokenError, TrustedIssuerKeys, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy,
    PolicyError, ResourceInteractionCallback, ResourceInteractionConfig, ResourceInteractionError,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
const CONNECT: &str = "https://resource.example/connect";

struct Keys {
    ap: AgentProviderKeys,
}
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if (issuer, dwk, kid) == (RESOURCE, "aauth-resource.json", "resource-1") {
            return Ok(SigningKey::from_seed([4; 32]).public_jwk());
        }
        self.ap.key(issuer, dwk, kid)
    }
}

struct Host;
impl Policy for Host {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "internal-person".into(),
            subject: format!("directed-{}", request.resource),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
}

type Server = PersonServer<
    Keys,
    MemoryStore,
    Host,
    Box<dyn Fn() -> i64 + Send + Sync>,
    Box<dyn Fn() -> String + Send + Sync>,
>;

fn agent() -> (Agent, AgentProviderKeys) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let token = ap
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Agent@ap.example".into(),
            jti: "agent-1".into(),
            iat: 1000,
            exp: 5000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    (Agent::new(key, token).unwrap(), keys)
}

fn server(keys: AgentProviderKeys) -> Server {
    let ids = AtomicUsize::new(0);
    PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        Keys { ap: keys },
        MemoryStore::default(),
        Host,
        Box::new(|| 1000_i64) as Box<dyn Fn() -> i64 + Send + Sync>,
        Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)))
            as Box<dyn Fn() -> String + Send + Sync>,
    )
    .unwrap()
    .with_resource_interaction(ResourceInteractionConfig::new(
        MemoryContinuations::new(64),
        "https://ps.example/consent",
        "https://ps.example/resource-callback",
        |url: &str| !url.starts_with("https://blocked.example/"),
    ))
    .unwrap()
}

fn post(agent: &Agent, path: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

fn poll(agent: &Agent, server: &Server, location: &str) -> Response<Vec<u8>> {
    let mut request = Request::builder().uri(location).body(Vec::new()).unwrap();
    agent.sign(&mut request, 1000).unwrap();
    server.handle(&request)
}

fn body(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

fn location(response: &Response<Vec<u8>>) -> String {
    response.headers()["location"].to_str().unwrap().to_owned()
}

/// A Person token, then a resource token whose `interaction` claim names
/// the resource's own flow at `connect`.
fn challenge(agent: &Agent, server: &Server, jti: &str, connect: &str) -> (String, String, String) {
    let person = server.handle(&post(agent, "/person", json!({ "resource": RESOURCE })));
    assert_eq!(person.status(), 200, "{}", body(&person));
    let person = body(&person)["person_token"].as_str().unwrap().to_owned();
    let p = PersonToken::parse(&person).unwrap();
    let p = p.unverified_claims();
    let mut claims = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: PS.into(),
        sub: p.sub.clone(),
        jti: jti.into(),
        iat: 1000,
        exp: 1300,
        ps: p.iss.clone(),
        presented_jti: p.jti.clone(),
        agent_jkt: agent.public_jwk().thumbprint().unwrap(),
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: Some("calendar.read".into()),
        account: None,
        login_hint: None,
        extra: Default::default(),
    };
    let interaction = ResourceInteraction::open(connect).unwrap();
    interaction.insert_into(&mut claims);
    let resource =
        mint_resource_token(&SigningKey::from_seed([4; 32]), "resource-1", &claims).unwrap();
    (person, resource, interaction.code().to_owned())
}

/// `/token` with the interaction capability: the pending URL, the
/// interaction id and this server's code.
fn start(agent: &Agent, server: &Server, person: &str, resource: &str) -> (String, String, String) {
    let pending = server.handle(&post(
        agent,
        "/token",
        json!({
            "resource_token": resource,
            "presented_token": person,
            "capabilities": ["interaction"],
            "justification": "Find a free afternoon",
        }),
    ));
    assert_eq!(pending.status(), 202, "{}", body(&pending));
    let parsed = PendingResponse::parse(PS, &pending).unwrap();
    let Requirement::Interaction { url, code } = parsed.requirement else {
        panic!("expected requirement=interaction")
    };
    let id = url
        .strip_prefix("https://ps.example/consent/")
        .expect("this server's own interaction page")
        .to_owned();
    (parsed.location, id, code)
}

/// The resource's interaction endpoint: it reads `code` and `callback`,
/// checks its code, ends its flow with `outcome`, and returns the browser.
fn resource_flow(redirect: &Response<Vec<u8>>, code: &str, outcome: InteractionOutcome) -> String {
    assert_eq!(redirect.status(), 302);
    let target = location(redirect);
    let query = target
        .strip_prefix(&format!("{CONNECT}?"))
        .expect("the resource's own interaction endpoint");
    let arrived = parse_interaction_query(query).unwrap();
    assert_eq!(arrived.code, code);
    let callback = arrived.callback.expect("the Person Server's callback");
    location(&completion_redirect(&callback, outcome).unwrap())
}

/// The callback path segment and query the Person Server host routes.
fn flow_and_query(callback: &str) -> (String, Option<String>) {
    let rest = callback
        .strip_prefix("https://ps.example/resource-callback/")
        .expect("this server's per-flow callback");
    match rest.split_once('?') {
        Some((flow, query)) => (flow.to_owned(), Some(query.to_owned())),
        None => (rest.to_owned(), None),
    }
}

#[test]
fn the_resource_flow_runs_before_consent_and_the_agent_receives_the_grant() {
    let (agent, keys) = agent();
    let server = server(keys);
    let (person, resource, resource_code) = challenge(&agent, &server, "rt-1", CONNECT);

    let unreachable = server.handle(&post(
        &agent,
        "/token",
        json!({ "resource_token": resource, "presented_token": person }),
    ));
    assert_eq!(unreachable.status(), 403);
    assert_eq!(body(&unreachable)["error"], "user_unreachable");

    let (pending, id, code) = start(&agent, &server, &person, &resource);
    assert!(pending.starts_with("https://ps.example/token/interaction/"));
    let waiting = poll(&agent, &server, &pending);
    assert_eq!(waiting.status(), 202);
    assert!(
        waiting.headers()["aauth-requirement"]
            .to_str()
            .unwrap()
            .contains("requirement=interaction")
    );

    let shown = server.resource_interaction(&id).unwrap();
    assert_eq!(shown.resource, RESOURCE);
    assert_eq!(shown.scopes, ["calendar.read"]);
    assert_eq!(
        shown.justification.as_deref(),
        Some("Find a free afternoon")
    );
    assert_eq!(
        server
            .redirect_to_resource(&id, "code=0000-0000")
            .unwrap_err(),
        ResourceInteractionError::InvalidCode
    );
    let redirect = server
        .redirect_to_resource(
            &id,
            &format!(
                "code={}&callback=https%3A%2F%2Fagent.example%2Fdone",
                code.to_ascii_lowercase()
            ),
        )
        .unwrap();
    assert_eq!(redirect.headers()["cache-control"], "no-store");
    // The code is single use.
    assert_eq!(
        server
            .redirect_to_resource(&id, &format!("code={code}"))
            .unwrap_err(),
        ResourceInteractionError::InvalidCode
    );
    let interacting = poll(&agent, &server, &pending);
    assert_eq!(interacting.status(), 202);
    assert_eq!(body(&interacting)["status"], "interacting");

    let callback = resource_flow(&redirect, &resource_code, InteractionOutcome::Completed);
    let (flow, query) = flow_and_query(&callback);
    assert_eq!(query, None);
    let ResourceInteractionCallback::Consent { id: consent } = server
        .resource_interaction_callback(&flow, query.as_deref())
        .unwrap()
    else {
        panic!("a callback without error moves on to consent")
    };
    assert_eq!(consent, id);
    assert_eq!(
        server
            .resource_interaction_callback(&flow, None)
            .unwrap_err(),
        ResourceInteractionError::NotReady
    );
    let back = server
        .decide_resource_interaction(&id, true)
        .unwrap()
        .unwrap();
    assert_eq!(location(&back), "https://agent.example/done");

    let granted = poll(&agent, &server, &pending);
    assert_eq!(granted.status(), 200, "{}", body(&granted));
    let pskeys = TrustedIssuerKeys::from_documents(
        PS,
        "aauth-person.json",
        &server.metadata(),
        &server.jwks(),
    )
    .unwrap();
    let auth = AuthToken::parse(body(&granted)["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&pskeys, 1000)
        .unwrap();
    assert_eq!(auth.claims().aud, RESOURCE);
    assert_eq!(auth.claims().scope.as_deref(), Some("calendar.read"));
    assert_eq!(poll(&agent, &server, &pending).status(), 410);
}

#[test]
fn a_callback_error_is_never_completable_and_reaches_the_agent_as_its_polling_error() {
    let (agent, keys) = agent();
    let server = server(keys);
    for (index, (error, polling)) in [
        (CallbackError::AccessDenied, "denied"),
        (CallbackError::UserAbandoned, "abandoned"),
        (CallbackError::InteractionExpired, "expired"),
        (CallbackError::ServerError, "server_error"),
        (CallbackError::TemporarilyUnavailable, "server_error"),
    ]
    .into_iter()
    .enumerate()
    {
        let (person, resource, resource_code) =
            challenge(&agent, &server, &format!("rt-error-{index}"), CONNECT);
        let (pending, id, code) = start(&agent, &server, &person, &resource);
        let redirect = server
            .redirect_to_resource(
                &id,
                &format!("code={code}&callback=https%3A%2F%2Fagent.example%2Fdone"),
            )
            .unwrap();
        let callback = resource_flow(&redirect, &resource_code, InteractionOutcome::Failed(error));
        let (flow, query) = flow_and_query(&callback);
        assert!(query.as_deref().unwrap().starts_with("error="));
        let ResourceInteractionCallback::Failed {
            polling_error,
            redirect,
        } = server
            .resource_interaction_callback(&flow, query.as_deref())
            .unwrap()
        else {
            panic!("a callback with error is not completable")
        };
        assert_eq!(polling_error, polling);
        assert!(location(&redirect.unwrap()).starts_with("https://agent.example/done?error="));
        assert_eq!(
            server.decide_resource_interaction(&id, true).unwrap_err(),
            ResourceInteractionError::InvalidCode
        );
        let ended = poll(&agent, &server, &pending);
        assert_eq!(body(&ended)["error"], polling, "{error:?}");
        assert!(ended.status().is_client_error() || ended.status().is_server_error());
        assert!(body(&ended).get("auth_token").is_none());
    }
}

#[test]
fn refused_egress_failed_codes_and_denial_end_the_request() {
    let (agent, keys) = agent();
    let server = server(keys);

    let (person, resource, _) = challenge(
        &agent,
        &server,
        "rt-blocked",
        "https://blocked.example/connect",
    );
    let (pending, id, code) = start(&agent, &server, &person, &resource);
    assert_eq!(
        server
            .redirect_to_resource(&id, &format!("code={code}"))
            .unwrap_err(),
        ResourceInteractionError::Refused
    );
    let refused = poll(&agent, &server, &pending);
    assert_eq!(refused.status(), 500);
    assert_eq!(body(&refused)["error"], "server_error");

    let (person, resource, _) = challenge(&agent, &server, "rt-guessed", CONNECT);
    let (pending, id, code) = start(&agent, &server, &person, &resource);
    for _ in 0..3 {
        assert_eq!(
            server
                .redirect_to_resource(&id, "code=ZZZZ-ZZZZ")
                .unwrap_err(),
            ResourceInteractionError::InvalidCode
        );
    }
    assert_eq!(
        server
            .redirect_to_resource(&id, &format!("code={code}"))
            .unwrap_err(),
        ResourceInteractionError::InvalidCode
    );
    let dead = poll(&agent, &server, &pending);
    assert_eq!(dead.status(), 410);
    assert_eq!(body(&dead)["error"], "invalid_code");

    let (person, resource, resource_code) = challenge(&agent, &server, "rt-denied", CONNECT);
    let (pending, id, code) = start(&agent, &server, &person, &resource);
    let redirect = server
        .redirect_to_resource(&id, &format!("code={code}"))
        .unwrap();
    let callback = resource_flow(&redirect, &resource_code, InteractionOutcome::Completed);
    let (flow, _) = flow_and_query(&callback);
    assert!(matches!(
        server.resource_interaction_callback(&flow, None).unwrap(),
        ResourceInteractionCallback::Consent { .. }
    ));
    assert!(
        server
            .decide_resource_interaction(&id, false)
            .unwrap()
            .is_none()
    );
    let denied = poll(&agent, &server, &pending);
    assert_eq!(denied.status(), 403);
    assert_eq!(body(&denied)["error"], "denied");
}
