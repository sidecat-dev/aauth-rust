//! Buffered native-role fixture: no sockets, TLS, identity or payment provider.
//! Run with `cargo run --locked -p aauth-rust-resource --example subagent`.
use aauth_rust_access_server::{AccessServer, Config as AccessConfig, Decision as AccessDecision};
use aauth_rust_agent::{Agent, FederatedContext, PollSession, Requirement, Subagent};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAgentToken,
    VerifiedAuthToken,
    continuation::{
        ContinuationStore, MemoryContinuations, PendingResponse, Requirement as PendingRequirement,
    },
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey, strict_json};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Federation, FederationError, FederationInput, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError,
};
use aauth_rust_resource::{AgentIdentityResource, PsAuthorizationConfig, PsAuthorizationResource};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const RESOURCE: &str = "https://resource.example";
const PARENT: &str = "aauth:parent@ap.example";
const CHILD: &str = "aauth:parent+worker@ap.example";
// Fixed Unix seconds and zero polling intervals are only for this bounded fixture.
const NOW: i64 = 1000;
const SCOPE: &str = "records.read";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Direct,
    Federated,
    Deferred,
}
struct Transcript {
    auth_issuer: String,
    resource_status: u16,
    protected_calls: usize,
    child_person_request_status: u16,
    parent_jkt: String,
    child_jkt: String,
    person_jkt: String,
    auth_jkt: String,
    access_statuses: Vec<u16>,
    agent_statuses: Vec<u16>,
    child_pending_status: Option<u16>,
    as_calls_after_parent_wait: usize,
    forwarded_exactly: bool,
    custody_consumed: bool,
}

// The host admits these four issuer/role pairs before any token is inspected.
// Documents come directly from the native role APIs below, without network I/O.
#[derive(Clone, Default)]
struct Trust(Arc<RwLock<BTreeMap<(String, String), TrustedIssuerKeys>>>);
impl Trust {
    fn admit(&self, issuer: &str, dwk: &str, metadata: &[u8], jwks: &[u8]) -> Result<()> {
        if !matches!(
            (issuer, dwk),
            (AP, "aauth-agent.json")
                | (PS, "aauth-person.json")
                | (AS, "aauth-access.json")
                | (RESOURCE, "aauth-resource.json")
        ) || metadata_jwks_uri(issuer, metadata)? != format!("{issuer}/.well-known/jwks.json")
        {
            return Err("fixture issuer or JWKS route was not admitted".into());
        }
        let snapshot = TrustedIssuerKeys::from_documents(issuer, dwk, metadata, jwks)?;
        self.0
            .write()
            .map_err(|_| "trust lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
}
impl AgentKeyResolver for Trust {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> std::result::Result<Jwk, TokenError> {
        self.0
            .read()
            .map_err(|_| TokenError::InvalidKey)?
            .get(&(issuer.into(), dwk.into()))
            .ok_or(TokenError::UntrustedIssuer)?
            .key(issuer, dwk, kid)
    }
}
fn fixture_now() -> i64 {
    NOW
}
fn get(endpoint: &str) -> Result<Request<Vec<u8>>> {
    Ok(Request::get(endpoint).body(Vec::new())?)
}
fn signed(agent: &Agent, endpoint: &str, body: Option<Value>) -> Result<Request<Vec<u8>>> {
    let mut request = match body {
        Some(body) => Request::post(endpoint)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body)?)?,
        None => get(endpoint)?,
    };
    agent.sign(&mut request, NOW)?;
    Ok(request)
}
// BEGIN guide-response-token
fn response_token(response: &Response<Vec<u8>>, member: &str) -> Result<String> {
    if response.status() != 200 {
        return Err(format!(
            "expected native 200, received {}: {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
        .into());
    }
    let body: Value = serde_json::from_slice(response.body())?;
    Ok(body[member].as_str().ok_or("missing credential")?.into())
}
// END guide-response-token
fn admitted_endpoint(metadata: &Value, member: &str, expected: &str) -> Result<String> {
    if metadata[member].as_str() != Some(expected) {
        return Err("native metadata endpoint differs from the configured route".into());
    }
    Ok(expected.into())
}
// BEGIN guide-ap-route
fn json_response(status: u16, body: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
        .unwrap()
}
fn child_route(
    provider: &AgentProvider,
    keys: &dyn AgentKeyResolver,
    ids: &AtomicUsize,
    request: &Request<Vec<u8>>,
    now: i64,
) -> Response<Vec<u8>> {
    if request.method() != "POST"
        || request.uri().path() != "/subagents"
        || request.uri().query().is_some()
    {
        return json_response(404, json!({"error":"not_found"}));
    }
    // A network adapter must also bound collection before allocating this body.
    if request.body().len() > 2048 {
        return json_response(413, json!({"error":"enrollment_body_too_large"}));
    }
    let gate = AgentIdentityResource::for_origin(
        AP,
        keys,
        |parent: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            parent.claims().iss == AP
                && parent.claims().sub == PARENT
                && parent.claims().parent_agent.is_none()
        },
    )
    .expect("configured AP origin");
    let (parent, ()) = match gate.authorize(request, now).into_result() {
        Ok(verified) => verified,
        Err(refusal) => return *refusal,
    };
    let Ok(body) = strict_json(request.body()) else {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    };
    let Some(body) = body.as_object() else {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    };
    if request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        != Some("application/json")
        || body.len() != 2
        || !body.contains_key("discriminator")
        || !body.contains_key("jwk")
    {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    }
    let Some(name) = body["discriminator"].as_str().filter(|s| {
        !s.is_empty()
            && s.len() <= 32
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
    }) else {
        return json_response(400, json!({"error":"invalid_discriminator"}));
    };
    // This fixture approves one child slot for this authenticated parent.
    if name != "worker" {
        return json_response(403, json!({"error":"enrollment_denied"}));
    }
    let Ok(key) = serde_json::from_value::<Jwk>(body["jwk"].clone()) else {
        return json_response(400, json!({"error":"invalid_child_key"}));
    };
    if key.validate().is_err() || key.thumbprint().ok() == parent.claims().cnf.jwk.thumbprint().ok()
    {
        return json_response(400, json!({"error":"invalid_child_key"}));
    }
    let (local, domain) = parent
        .claims()
        .sub
        .rsplit_once('@')
        .expect("verified Agent identifier");
    let claims = AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: format!("{local}+{name}@{domain}"),
        jti: format!("child-{}", ids.fetch_add(1, Ordering::SeqCst)),
        iat: now,
        exp: now.saturating_add(900),
        cnf: Confirmation { jwk: key },
        ps: parent.claims().ps.clone(),
        parent_agent: Some(parent.claims().sub.clone()),
        nbf: None,
        extra: Default::default(),
    };
    // The AP independently authenticates this exact parent using its own key.
    match provider.issue_subagent(&claims, parent.compact(), now) {
        Ok(compact) => json_response(200, json!({"agent_token":compact})),
        Err(_) => json_response(400, json!({"error":"invalid_child_enrollment"})),
    }
}
// END guide-ap-route
struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, r: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        // An established, host-authenticated fixture account supplies this mapping.
        // Neither the child nor login_hint authenticates this person.
        if r.agent.claims().sub != PARENT
            || r.resource != RESOURCE
            || r.subagent.as_ref().is_none_or(|c| c.claims().sub != CHILD)
        {
            return Err(PolicyError::Denied);
        }
        Ok(Person {
            id: "fixture-account".into(),
            subject: "resource-pairwise-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, r: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        self.consent(r)?;
        Ok(Grant {
            scopes: r.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, r: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        if r.agent.claims().sub != PARENT
            || r.resource.claims().iss != RESOURCE
            || r.subagent.as_ref().is_none_or(|c| c.claims().sub != CHILD)
            || r.scopes != [SCOPE]
        {
            return Err(PolicyError::Denied);
        }
        Ok(())
    }
}
#[derive(Default)]
struct FixtureDecisions {
    settlement: AtomicBool,
    approval: AtomicBool,
}
type Handler = Arc<dyn Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;
#[derive(Clone)]
struct NativeAccess {
    endpoint: String,
    handler: Handler,
    statuses: Arc<Mutex<Vec<u16>>>,
    original_posts: Arc<Mutex<Vec<Value>>>,
}
impl Federation for NativeAccess {
    fn endpoint(&self, issuer: &str) -> std::result::Result<String, FederationError> {
        if issuer != AS {
            return Err(FederationError);
        }
        Ok(self.endpoint.clone())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        // Explicit fixture routing invokes the actual AS handler once. It does
        // not fetch a URL or provide TLS. Production adapters supply verified TLS,
        // egress/redirect admission, bounded collection and timeouts here.
        if request.uri().scheme_str() != Some("https")
            || request.uri().authority().map(|a| a.as_str()) != Some("as.example")
            || request.uri().query().is_some()
            || !(request.uri().path() == "/token"
                || request.uri().path().starts_with("/token/pending/"))
        {
            return Err(FederationError);
        }
        if request.method() == "POST" && request.uri().path() == "/token" {
            self.original_posts
                .lock()
                .map_err(|_| FederationError)?
                .push(serde_json::from_slice(request.body()).map_err(|_| FederationError)?);
        }
        let response = (self.handler)(request);
        self.statuses
            .lock()
            .map_err(|_| FederationError)?
            .push(response.status().as_u16());
        Ok(response)
    }
}

fn run_scene(mode: Mode) -> Result<Transcript> {
    // BEGIN guide-ap-trust
    let trust = Trust::default();
    let ap = AgentProvider::new(AP, "ap", SigningKey::generate())?;
    trust.admit(AP, "aauth-agent.json", &ap.metadata()?, &ap.jwks()?)?;
    // END guide-ap-trust
    let parent_key = SigningKey::generate();
    let child_key = SigningKey::generate();
    let parent_claims = AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: PARENT.into(),
        jti: "parent-agent".into(),
        iat: NOW,
        exp: NOW + 1200,
        cnf: Confirmation {
            jwk: parent_key.public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let parent_compact = ap.issue(&parent_claims)?;
    let parent = Agent::new(parent_key, parent_compact)?;
    let enrollment_ids = AtomicUsize::new(0);
    // BEGIN guide-ap-request
    let mut enrollment_request = Request::post(format!("{AP}/subagents"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({
            "discriminator":"worker", "jwk":child_key.public_jwk(),
        }))?)?;
    parent.sign(&mut enrollment_request, NOW)?;
    let enrollment_response = child_route(&ap, &trust, &enrollment_ids, &enrollment_request, NOW);
    let child_compact = response_token(&enrollment_response, "agent_token")?;
    // END guide-ap-request
    // This separate value represents the child process's own retained proof key.
    let child = Agent::new(child_key, child_compact.clone())?;

    let decisions = Arc::new(FixtureDecisions::default());
    let mut access = AccessServer::new(
        AccessConfig::new(AS, "as", SigningKey::generate()),
        trust.clone(),
        |r: &aauth_rust_access_server::AuthorizationRequest| {
            if r.person_server != PS
                || r.agent.claims().sub != PARENT
                || r.subagent.as_ref().is_none_or(|c| c.claims().sub != CHILD)
                || r.resource.claims().iss != RESOURCE
                || r.scopes != [SCOPE]
            {
                return Err(aauth_rust_access_server::PolicyError::Denied);
            }
            Ok(AccessDecision {
                scopes: r.scopes.clone(),
                lifetime: 600,
            })
        },
        fixture_now,
        {
            let ids = AtomicUsize::new(0);
            move || format!("as-{}", ids.fetch_add(1, Ordering::SeqCst))
        },
    )?;
    let as_custody = Arc::new(MemoryContinuations::new(8));
    if mode == Mode::Deferred {
        let controls = decisions.clone();
        let mut config = aauth_rust_access_server::DeferredConfig::new(as_custody.clone());
        config.lifetime = 60;
        config.retry_after = 0;
        access = access.with_deferred(
            config,
            move |_: &aauth_rust_access_server::DeferredContext| {
                Ok(if !controls.settlement.load(Ordering::SeqCst) {
                    Some(PendingRequirement::Payment {
                        authenticate: "Payment id=\"fixture-bill\", method=\"example\"".into(),
                    })
                } else if !controls.approval.load(Ordering::SeqCst) {
                    Some(PendingRequirement::Approval)
                } else {
                    None
                })
            },
        )?;
    }
    let as_metadata = access.handle(&get(&format!("{AS}/.well-known/aauth-access.json"))?);
    let as_jwks = access.handle(&get(&format!("{AS}/.well-known/jwks.json"))?);
    trust.admit(AS, "aauth-access.json", as_metadata.body(), as_jwks.body())?;
    let endpoint = admitted_endpoint(
        &serde_json::from_slice(as_metadata.body())?,
        "auth_token_endpoint",
        &format!("{AS}/token"),
    )?;
    let transport = NativeAccess {
        endpoint,
        handler: Arc::new(move |request| access.handle(request)),
        statuses: Arc::default(),
        original_posts: Arc::default(),
    };
    let as_statuses = transport.statuses.clone();
    let forwarded = transport.original_posts.clone();
    let ps_custody = Arc::new(MemoryContinuations::new(8));
    let mut person_server = PersonServer::new(
        Config::new(PS, "ps", SigningKey::generate()),
        trust.clone(),
        MemoryStore::default(),
        HostPolicy,
        fixture_now,
        {
            let ids = AtomicUsize::new(0);
            move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))
        },
    )?;
    if mode != Mode::Direct {
        person_server = person_server.with_federation(transport);
    }
    if mode == Mode::Deferred {
        let mut config = aauth_rust_person_server::DeferredConfig::new(ps_custody.clone());
        config.lifetime = 60;
        config.retry_after = 0;
        person_server = person_server.with_deferred(config)?;
    }
    let ps_metadata = person_server.handle(&get(&format!("{PS}/.well-known/aauth-person.json"))?);
    let ps_jwks = person_server.handle(&get(&format!("{PS}/.well-known/jwks.json"))?);
    trust.admit(PS, "aauth-person.json", ps_metadata.body(), ps_jwks.body())?;
    let metadata: Value = serde_json::from_slice(ps_metadata.body())?;
    let person_endpoint =
        admitted_endpoint(&metadata, "person_token_endpoint", &format!("{PS}/person"))?;
    let token_endpoint =
        admitted_endpoint(&metadata, "auth_token_endpoint", &format!("{PS}/token"))?;

    let config = PsAuthorizationConfig {
        issuer: RESOURCE.into(),
        signed_origin: RESOURCE.into(),
        kid: "resource".into(),
        signing_key: SigningKey::generate(),
        scopes: vec![SCOPE.into()],
    };
    let policy = |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true;
    let resource = if mode == Mode::Direct {
        PsAuthorizationResource::new(config, trust.clone(), policy)?
    } else {
        PsAuthorizationResource::new_federated(config, AS, trust.clone(), policy)?
    };
    trust.admit(
        RESOURCE,
        "aauth-resource.json",
        &resource.metadata()?,
        &resource.jwks()?,
    )?;
    let protected_calls = AtomicUsize::new(0);
    let resource_handler = |request: &Request<Vec<u8>>, id: &str| match resource
        .authorize(request, NOW, id)
        .into_result()
    {
        Ok((_token, ())) if request.method() == "GET" && request.uri().path() == "/records" => {
            protected_calls.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .header("content-type", "application/json")
                .body(br#"{"record":"fixture"}"#.to_vec())
                .unwrap()
        }
        Ok(_) => Response::builder().status(404).body(Vec::new()).unwrap(),
        Err(response) => *response,
    };
    assert_eq!(
        resource_handler(&get(&format!("{RESOURCE}/records"))?, "unsigned").status(),
        401
    );

    // BEGIN service-guide snippet: the parent needs only child token/public data.
    let admitted_child = Subagent::verify(parent.token(), &child_compact, &trust, NOW)?;
    let request =
        admitted_child.person_request(&parent, &person_endpoint, RESOURCE, &trust, NOW)?;
    let delivered_person = person_server.handle(&request);
    let person_compact = response_token(&delivered_person, "person_token")?;
    let verified_person =
        admitted_child.verify_person_delivery(&person_compact, RESOURCE, PS, &trust, NOW)?;
    // END service-guide snippet.
    assert!(parent.with_token(person_compact.clone()).is_err());
    let child_person_request_status = person_server
        .handle(&signed(
            &child,
            &person_endpoint,
            Some(json!({"resource":RESOURCE})),
        )?)
        .status()
        .as_u16();
    assert_eq!(child_person_request_status, 401);
    // BEGIN guide-child-exchange
    let person_holder = child.with_token(person_compact.clone())?;
    let challenge = resource_handler(
        &signed(&person_holder, &format!("{RESOURCE}/records"), None)?,
        "challenge",
    );
    let Some(Requirement::AuthToken { resource_token }) =
        Requirement::from_headers(challenge.headers())?
    else {
        return Err("native Resource did not issue an Auth challenge".into());
    };
    assert_eq!(protected_calls.load(Ordering::SeqCst), 0);
    let context = FederatedContext {
        resource: RESOURCE,
        person_server: PS,
        access_server: AS,
        presented_token: &person_compact,
    };
    let verified_challenge = if mode == Mode::Direct {
        admitted_child.verify_resource_challenge(
            &resource_token,
            RESOURCE,
            PS,
            &person_compact,
            &trust,
            NOW,
        )?
    } else {
        admitted_child.verify_federated_resource_challenge(
            &resource_token,
            &context,
            &trust,
            NOW,
        )?
    };
    let first = person_server.handle(&admitted_child.auth_request(
        &parent,
        &token_endpoint,
        &verified_challenge,
        &person_compact,
        &trust,
        NOW,
    )?);
    // END guide-child-exchange
    let mut agent_statuses = vec![first.status().as_u16()];
    let mut child_pending_status = None;
    let mut as_calls_after_parent_wait = 0;
    let mut custody_consumed = true;
    let terminal = if mode == Mode::Deferred {
        assert_eq!(first.status(), 202);
        let own = PendingResponse::parse(&token_endpoint, &first)?;
        let original_as = person_server.federation_pending(&own.location)?;
        let bill = original_as
            .payment_challenge()?
            .ok_or("missing native Payment requirement")?;
        assert_eq!(bill.id, "fixture-bill");
        let mut polls = PollSession::new(&token_endpoint, &first, NOW, NOW + 60)?;
        child_pending_status = Some(
            person_server
                .handle(&signed(&child, &own.location, None)?)
                .status()
                .as_u16(),
        );
        let waiting = person_server.handle(&polls.request(&parent, NOW)?);
        agent_statuses.push(waiting.status().as_u16());
        assert!(polls.accept(waiting, NOW)?.is_none());
        as_calls_after_parent_wait = as_statuses.lock().unwrap().len();
        assert_eq!(
            as_calls_after_parent_wait, 1,
            "parent polling must not advance AS state"
        );
        // The host explicitly confirms this fixture bill. No payment provider runs.
        decisions.settlement.store(true, Ordering::SeqCst);
        assert_eq!(
            person_server
                .advance_federation(&own.location, FederationInput::Poll)?
                .status(),
            202
        );
        let approval = person_server.handle(&polls.request(&parent, NOW)?);
        agent_statuses.push(approval.status().as_u16());
        assert!(polls.accept(approval, NOW)?.is_none());
        assert_eq!(polls.pending().location, own.location);
        // The host separately confirms fixture approval before one more AS poll.
        decisions.approval.store(true, Ordering::SeqCst);
        assert_eq!(
            person_server
                .advance_federation(&own.location, FederationInput::Poll)?
                .status(),
            200
        );
        let delivered = person_server.handle(&polls.request(&parent, NOW)?);
        agent_statuses.push(delivered.status().as_u16());
        let terminal = polls
            .accept(delivered, NOW)?
            .ok_or("missing terminal delivery")?;
        agent_statuses.push(
            person_server
                .handle(&signed(&parent, &own.location, None)?)
                .status()
                .as_u16(),
        );
        let as_id = original_as
            .location
            .rsplit('/')
            .next()
            .ok_or("missing AS pending id")?;
        let ps_id = own
            .location
            .rsplit('/')
            .next()
            .ok_or("missing PS pending id")?;
        custody_consumed = as_custody.load(as_id)?.is_none() && ps_custody.load(ps_id)?.is_none();
        terminal
    } else {
        first
    };
    // BEGIN guide-child-delivery
    let grant = response_token(&terminal, "auth_token")?;
    let verified_auth = if mode == Mode::Direct {
        admitted_child.verify_auth_delivery(
            &grant,
            RESOURCE,
            &verified_challenge,
            &person_compact,
            &trust,
            NOW,
        )?
    } else {
        admitted_child.verify_federated_auth_delivery(
            &grant,
            &verified_challenge,
            &context,
            &trust,
            NOW,
        )?
    };
    let authorized = resource_handler(
        &signed(
            &child.with_token(grant)?,
            &format!("{RESOURCE}/records"),
            None,
        )?,
        "authorized",
    );
    // END guide-child-delivery
    assert!(
        verified_auth.claims().exp <= admitted_child.token().claims().exp
            && verified_auth.claims().exp <= parent_claims.exp
    );
    assert!(!verified_auth.claims().extra.contains_key("parent_agent"));
    let posts = forwarded.lock().unwrap();
    let forwarded_exactly = mode == Mode::Direct
        || posts.as_slice()
            == [json!({
                "agent_token":parent.token(), "subagent_token":child_compact,
                "resource_token":resource_token, "presented_token":person_compact,
            })];
    Ok(Transcript {
        auth_issuer: verified_auth.claims().iss.clone(),
        resource_status: authorized.status().as_u16(),
        protected_calls: protected_calls.load(Ordering::SeqCst),
        child_person_request_status,
        parent_jkt: parent.public_jwk().thumbprint()?,
        child_jkt: child.public_jwk().thumbprint()?,
        person_jkt: verified_person.claims().cnf.jwk.thumbprint()?,
        auth_jkt: verified_auth.claims().cnf.jwk.thumbprint()?,
        access_statuses: as_statuses.lock().unwrap().clone(),
        agent_statuses,
        child_pending_status,
        as_calls_after_parent_wait,
        forwarded_exactly,
        custody_consumed,
    })
}

fn main() -> Result<()> {
    for mode in [Mode::Direct, Mode::Federated, Mode::Deferred] {
        let t = run_scene(mode)?;
        assert_eq!(t.auth_issuer, if mode == Mode::Direct { PS } else { AS });
        assert_eq!(
            (
                t.resource_status,
                t.protected_calls,
                t.child_person_request_status
            ),
            (200, 1, 401)
        );
        assert_ne!(t.parent_jkt, t.child_jkt);
        assert_eq!(t.person_jkt, t.child_jkt);
        assert_eq!(t.auth_jkt, t.child_jkt);
        assert!(t.forwarded_exactly && t.custody_consumed);
        if mode == Mode::Deferred {
            assert_eq!(t.access_statuses, [402, 202, 200]);
            assert_eq!(t.agent_statuses, [202, 202, 202, 200, 410]);
            assert_eq!(t.child_pending_status, Some(403));
            assert_eq!(t.as_calls_after_parent_wait, 1);
        } else {
            assert_eq!(t.agent_statuses, [200]);
            assert_eq!(
                t.access_statuses,
                if mode == Mode::Direct {
                    vec![]
                } else {
                    vec![200]
                }
            );
        }
        println!(
            "{mode:?}: authenticated AP route enrolls child; parent verifies child-bound Person/Auth without child secret; child proof admits one Resource request"
        );
        if mode == Mode::Deferred {
            println!(
                "host confirmed fixture settlement, then fixture approval; AS {:?}; parent PS {:?}; child polls refused; custody consumed",
                t.access_statuses, t.agent_statuses
            );
        }
    }
    println!("buffered native handlers only; no sockets, TLS or identity/payment provider");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_fixture() -> (AgentProvider, Trust, Agent) {
        let provider = AgentProvider::new(AP, "ap", SigningKey::generate()).unwrap();
        let trust = Trust::default();
        trust
            .admit(
                AP,
                "aauth-agent.json",
                &provider.metadata().unwrap(),
                &provider.jwks().unwrap(),
            )
            .unwrap();
        let key = SigningKey::generate();
        let claims = AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: PARENT.into(),
            jti: "parent".into(),
            iat: NOW,
            exp: NOW + 1200,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        };
        let compact = provider.issue(&claims).unwrap();
        (provider, trust, Agent::new(key, compact).unwrap())
    }

    #[test]
    fn ap_route_authenticates_parent_and_returns_an_independently_verifiable_child() {
        let (ap, trust, parent) = parent_fixture();
        let child_key = SigningKey::generate();
        let request = signed(
            &parent,
            &format!("{AP}/subagents"),
            Some(json!({
                "discriminator":"worker", "jwk":child_key.public_jwk(),
            })),
        )
        .unwrap();
        let response = child_route(&ap, &trust, &AtomicUsize::new(0), &request, NOW);
        let compact = response_token(&response, "agent_token").unwrap();
        assert_eq!(
            Subagent::verify(parent.token(), &compact, &Trust::default(), NOW).unwrap_err(),
            TokenError::UntrustedIssuer
        );
        let verified = Subagent::verify(parent.token(), &compact, &trust, NOW).unwrap();
        assert_eq!(verified.parent().compact(), parent.token());
        assert_eq!(verified.token().claims().sub, CHILD);
        assert_eq!(
            verified.token().claims().parent_agent.as_deref(),
            Some(PARENT)
        );
        assert_eq!(
            verified.token().claims().cnf.jwk.thumbprint().unwrap(),
            child_key.public_jwk().thumbprint().unwrap()
        );
        assert_eq!(verified.token().claims().exp, NOW + 900);
    }

    #[test]
    fn ap_route_refuses_unsigned_and_body_tampering_before_issuance() {
        let (ap, trust, parent) = parent_fixture();
        let ids = AtomicUsize::new(0);
        let body = json!({"discriminator":"worker", "jwk":SigningKey::generate().public_jwk()});
        let unsigned = Request::post(format!("{AP}/subagents"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        assert_eq!(child_route(&ap, &trust, &ids, &unsigned, NOW).status(), 401);
        let mut tampered = signed(&parent, &format!("{AP}/subagents"), Some(body)).unwrap();
        tampered.body_mut().push(b' ');
        assert_eq!(child_route(&ap, &trust, &ids, &tampered, NOW).status(), 401);
        assert_eq!(ids.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ap_route_refuses_a_child_caller_before_enrollment() {
        let (ap, trust, parent) = parent_fixture();
        let ids = AtomicUsize::new(0);
        let key = SigningKey::generate();
        let request = signed(
            &parent,
            &format!("{AP}/subagents"),
            Some(json!({
                "discriminator":"worker", "jwk":key.public_jwk(),
            })),
        )
        .unwrap();
        let compact = response_token(
            &child_route(&ap, &trust, &ids, &request, NOW),
            "agent_token",
        )
        .unwrap();
        let child = Agent::new(key, compact).unwrap();
        let request = signed(
            &child,
            &format!("{AP}/subagents"),
            Some(json!({
                "discriminator":"worker", "jwk":SigningKey::generate().public_jwk(),
            })),
        )
        .unwrap();
        assert_eq!(child_route(&ap, &trust, &ids, &request, NOW).status(), 403);
        assert_eq!(ids.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ap_route_bounds_body_discriminator_and_public_key() {
        let (ap, trust, parent) = parent_fixture();
        let ids = AtomicUsize::new(0);
        let key = SigningKey::generate().public_jwk();
        let mut private = serde_json::to_value(&key).unwrap();
        private["d"] = json!("not-public");
        for (body, status) in [
            (json!({}), 400),
            (
                json!({"discriminator":"worker","jwk":key,"parent_agent":PARENT}),
                400,
            ),
            (json!({"discriminator":"worker","jwk":private}), 400),
            (
                json!({"discriminator":"worker","jwk":parent.public_jwk()}),
                400,
            ),
            (json!({"discriminator":"worker+deeper","jwk":key}), 400),
            (json!({"discriminator":"","jwk":key}), 400),
            (json!({"discriminator":"x".repeat(33),"jwk":key}), 400),
            (json!({"discriminator":"other","jwk":key}), 403),
        ] {
            let request = signed(&parent, &format!("{AP}/subagents"), Some(body)).unwrap();
            assert_eq!(
                child_route(&ap, &trust, &ids, &request, NOW).status(),
                status
            );
        }
        for body in [b"{".to_vec(), b" ".repeat(2049)] {
            let mut request = Request::post(format!("{AP}/subagents"))
                .header("content-type", "application/json")
                .body(body)
                .unwrap();
            parent.sign(&mut request, NOW).unwrap();
            let expected = if request.body().len() > 2048 {
                413
            } else {
                400
            };
            assert_eq!(
                child_route(&ap, &trust, &ids, &request, NOW).status(),
                expected
            );
        }
        assert_eq!(ids.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ap_route_does_not_substitute_gateway_trust_for_the_provider_parent_check() {
        let (wrong_provider, wrong_trust, parent) = parent_fixture();
        let own_provider = AgentProvider::new(AP, "ap", SigningKey::generate()).unwrap();
        assert_ne!(own_provider.jwks().unwrap(), wrong_provider.jwks().unwrap());
        let ids = AtomicUsize::new(0);
        let request = signed(
            &parent,
            &format!("{AP}/subagents"),
            Some(json!({
                "discriminator":"worker", "jwk":SigningKey::generate().public_jwk(),
            })),
        )
        .unwrap();
        let response = child_route(&own_provider, &wrong_trust, &ids, &request, NOW);
        assert_eq!(response.status(), 400);
        assert!(
            serde_json::from_slice::<Value>(response.body())
                .unwrap()
                .get("agent_token")
                .is_none()
        );
    }

    #[test]
    fn immediate_ps_scene_uses_parent_consent_and_child_resource_proof() {
        let observed = run_scene(Mode::Direct).unwrap();
        assert_eq!(observed.auth_issuer, PS);
        assert_eq!(observed.resource_status, 200);
        assert_eq!(observed.protected_calls, 1);
        assert_eq!(observed.child_person_request_status, 401);
        assert_ne!(observed.parent_jkt, observed.child_jkt);
        assert_eq!(observed.person_jkt, observed.child_jkt);
        assert_eq!(observed.auth_jkt, observed.child_jkt);
        assert!(observed.access_statuses.is_empty());
        assert_eq!(observed.agent_statuses, [200]);
    }

    #[test]
    fn immediate_as_scene_preserves_all_four_compact_tokens() {
        let observed = run_scene(Mode::Federated).unwrap();
        assert_eq!(observed.auth_issuer, AS);
        assert_eq!(observed.resource_status, 200);
        assert_eq!(observed.protected_calls, 1);
        assert_eq!(observed.auth_jkt, observed.child_jkt);
        assert_eq!(observed.access_statuses, [200]);
        assert!(observed.forwarded_exactly);
        assert_eq!(observed.agent_statuses, [200]);
    }

    #[test]
    fn deferred_as_scene_requires_explicit_host_steps_and_one_parent_delivery() {
        let observed = run_scene(Mode::Deferred).unwrap();
        assert_eq!(observed.auth_issuer, AS);
        assert_eq!(observed.resource_status, 200);
        assert_eq!(observed.protected_calls, 1);
        assert_eq!(observed.auth_jkt, observed.child_jkt);
        assert_eq!(observed.access_statuses, [402, 202, 200]);
        assert_eq!(observed.agent_statuses, [202, 202, 202, 200, 410]);
        assert_eq!(observed.child_pending_status, Some(403));
        assert_eq!(observed.as_calls_after_parent_wait, 1);
        assert!(observed.forwarded_exactly && observed.custody_consumed);
    }
}
