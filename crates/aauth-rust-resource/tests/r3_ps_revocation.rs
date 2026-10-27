//! Direct class R3 issuance against concurrent revocation.
//!
//! A Resource, Agent or presented token revoked while R3 host callbacks run
//! must not yield an Auth token, and a completed revocation must still reach
//! an R3 Auth token registered before it. The Resource is in process; the PS
//! fetch transport calls its signed document endpoint directly. Stores here
//! are volatile test doubles.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, CallOutcome, Confirmation, PersonToken,
    RevocationDirectory, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Grant, MemoryStore, Person,
    PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest, R3Decision,
    R3IssuerConfig,
};
use aauth_rust_r3::{
    DefinitionRegistry, FetchBody, FetchLimits, FetchResponse, FetchTransport, GrantedOperations,
    IssuanceError, IssuanceRecord, IssuanceStore, McpCodec, Operation, ToolsListPage,
    ToolsListSnapshot, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthPolicy, PsAuthorizationConfig, PsAuthorizationResource, R3Config,
    R3DocumentRecord, R3DocumentStore, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Instant;

const NOW: i64 = 1_700_000_000;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}}]}"#;

#[derive(Clone)]
struct Keys(Vec<TrustedIssuerKeys>);
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        for snapshot in &self.0 {
            match snapshot.key(issuer, dwk, kid) {
                Err(TokenError::UntrustedIssuer | TokenError::InvalidDiscoveryDocument) => continue,
                other => return other,
            }
        }
        Err(TokenError::UntrustedIssuer)
    }
}
fn issuer_key(issuer: &str, dwk: &str, seed: u8, kid: &str) -> TrustedIssuerKeys {
    let mut jwk = serde_json::to_value(SigningKey::from_seed([seed; 32]).public_jwk()).unwrap();
    jwk["kid"] = json!(kid);
    TrustedIssuerKeys::from_documents(
        issuer,
        dwk,
        &serde_json::to_vec(&json!({"issuer":issuer,"jwks_uri":format!("{issuer}/keys")})).unwrap(),
        &serde_json::to_vec(&json!({"keys":[jwk]})).unwrap(),
    )
    .unwrap()
}
fn keys() -> Keys {
    Keys(vec![
        issuer_key(AP, "aauth-agent.json", 1, "ap-1"),
        issuer_key(PS, "aauth-person.json", 3, "ps-1"),
        issuer_key(RESOURCE, "aauth-resource.json", 4, "resource-1"),
    ])
}
fn mcp(tool: &str) -> Operation {
    Operation::new(
        &McpCodec::vocabulary().unwrap(),
        format!(r#"{{"tool":"{tool}"}}"#).as_bytes(),
    )
    .unwrap()
}

#[derive(Default)]
struct Documents(Mutex<BTreeMap<String, R3DocumentRecord>>);
impl R3DocumentStore for Documents {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        let mut records = self.0.lock().unwrap();
        match records.get(record.reference.uri()) {
            Some(existing) if existing != record => Err(R3StoreError::Conflict),
            _ => {
                records.insert(record.reference.uri().to_owned(), record.clone());
                Ok(())
            }
        }
    }
    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError> {
        Ok(self.0.lock().unwrap().get(uri).cloned())
    }
}
type Resource = PsAuthorizationResource<Keys, BoxedAuthPolicy>;
fn resource() -> Arc<Resource> {
    let mapper: aauth_rust_resource::BoxedR3OperationMapper =
        Box::new(|request: &Request<Vec<u8>>| {
            Ok((request.uri().path() == "/records/read").then(|| mcp("records.read")))
        });
    Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: RESOURCE.into(),
                signed_origin: RESOURCE.into(),
                kid: "resource-1".into(),
                signing_key: SigningKey::from_seed([4; 32]),
                scopes: vec!["records.read".into()],
            },
            keys(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(R3Config {
            registry: standard_registry().unwrap(),
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration().unwrap()])
                .unwrap(),
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{RESOURCE}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )
                .unwrap(),
                display: None,
            }],
            documents: Arc::new(Documents::default()),
            operation_for_request: mapper,
            require_core_scope: false,
        })
        .unwrap(),
    )
}

/// The PS document transport: the Resource's signed endpoint, in process.
struct InProcess(Arc<Resource>);
struct Buffered(Vec<u8>, usize);
impl FetchBody for Buffered {
    fn read(&mut self, output: &mut [u8], _: Instant) -> std::io::Result<usize> {
        let count = (self.0.len() - self.1).min(output.len());
        output[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
        self.1 += count;
        Ok(count)
    }
}
impl FetchTransport for InProcess {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> std::io::Result<FetchResponse> {
        let (parts, body) = self.0.r3_document(&request, NOW).into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

/// One host callback paused until the test releases it.
struct Hold {
    entered: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl Hold {
    fn wait(&self) {
        let _ = self.entered.lock().unwrap().send(());
        let _ = self.release.lock().unwrap().recv();
    }
}
struct Control {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}
fn hold() -> (Arc<Hold>, Control) {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    (
        Arc::new(Hold {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
        }),
        Control { entered, release },
    )
}

#[derive(Default)]
struct Audit {
    records: Mutex<Vec<IssuanceRecord>>,
    hold: Mutex<Option<Arc<Hold>>>,
}
impl IssuanceStore for Audit {
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError> {
        let paused = self.hold.lock().unwrap().clone();
        if let Some(hold) = paused {
            hold.wait();
        }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, String)>>);
impl RevocationDirectory for Recorder {
    fn revoke(&self, recipient: &str, jti: &str, _: i64) -> CallOutcome {
        self.0
            .lock()
            .unwrap()
            .push((recipient.to_owned(), jti.to_owned()));
        CallOutcome::Recorded
    }
}

struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}
type Ps = PersonServer<Keys, MemoryStore, HostPolicy, BoxedClock, BoxedTokenIds>;

struct Fixture {
    ps: Arc<Ps>,
    resource: Arc<Resource>,
    agent: Agent,
    audit: Arc<Audit>,
    cascade: Arc<Recorder>,
}
fn fixture(policy_hold: Option<Arc<Hold>>) -> Fixture {
    fixture_with(policy_hold, &[])
}
/// `granted_scopes` is the host decision's Core scope grant.
fn fixture_with(policy_hold: Option<Arc<Hold>>, granted_scopes: &'static [&'static str]) -> Fixture {
    let resource = resource();
    let audit = Arc::new(Audit::default());
    let cascade = Arc::new(Recorder::default());
    let ids = AtomicUsize::new(0);
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        keys(),
        MemoryStore::default(),
        HostPolicy,
        Box::new(|| NOW) as BoxedClock,
        Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
    )
    .unwrap()
    .with_revocation_directory(cascade.clone())
    .with_r3(R3IssuerConfig {
        registry: standard_registry().unwrap(),
        egress: Box::new(|uri: &str, _: Instant| {
            if uri.starts_with(&format!("{RESOURCE}/r3/c.")) {
                Ok(())
            } else {
                Err(std::io::Error::other("egress refused"))
            }
        }),
        transport: Box::new(InProcess(resource.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(
            move |_: &R3AuthorizationRequest<'_>| -> Result<R3Decision, PolicyError> {
                if let Some(hold) = &policy_hold {
                    hold.wait();
                }
                let vocabulary = McpCodec::vocabulary().unwrap();
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocabulary, &[mcp("records.read")]).unwrap(),
                    scopes: granted_scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    lifetime: 600,
                })
            },
        ),
        audit: audit.clone(),
    })
    .unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let token = AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:reader@ap.example".into(),
            jti: "agent-1".into(),
            iat: NOW,
            exp: NOW + 1800,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Fixture {
        ps: Arc::new(ps),
        resource,
        agent: Agent::new(key, token).unwrap(),
        audit,
        cascade,
    }
}
fn post(agent: &Agent, uri: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, NOW).unwrap();
    request
}
fn member(response: &Response<Vec<u8>>, name: &str) -> Option<String> {
    serde_json::from_slice::<Value>(response.body())
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}
/// Person token, then an R3 Resource token from `/authorize`.
fn tokens(f: &Fixture) -> (String, String) {
    tokens_with(f, None)
}
fn tokens_with(f: &Fixture, scope: Option<&str>) -> (String, String) {
    let person = f
        .ps
        .handle(&post(
            &f.agent,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        ));
    let person = member(&person, "person_token").expect("person token");
    let mut body = json!({ "r3_operations": {
        "vocabulary": "urn:aauth:vocabulary:mcp",
        "operations": [{ "tool": "records.read" }],
    } });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    let authorize = post(
        &f.agent.with_token(person.clone()).unwrap(),
        &format!("{RESOURCE}/authorize"),
        body,
    );
    let response = f
        .resource
        .authorize_endpoint(&authorize, NOW, "rt-1")
        .into_response();
    let resource_token = member(&response, "resource_token").expect("resource token");
    (person, resource_token)
}
fn token_request(f: &Fixture, person: &str, resource_token: &str) -> Request<Vec<u8>> {
    post(
        &f.agent,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    )
}
fn revocation(id: &str, dwk: &str, kid: &str, seed: u8, jti: &str, exp: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "jti": jti, "exp": exp })).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::JwksUri {
            id: id.into(),
            dwk: dwk.into(),
            kid: kid.into(),
        },
        NOW,
    )
    .unwrap();
    request
}
/// Run `/token` on another thread, revoke while the hold is entered, then release.
fn race(
    f: &Fixture,
    control: Control,
    request: Request<Vec<u8>>,
    revoke: impl FnOnce() -> u16,
) -> Response<Vec<u8>> {
    let ps = f.ps.clone();
    let exchange = std::thread::spawn(move || ps.handle(&request));
    control.entered.recv().expect("host callback entered");
    assert_eq!(revoke(), 200, "revocation completed before release");
    control.release.send(()).unwrap();
    exchange.join().unwrap()
}

#[test]
fn resource_token_revoked_during_r3_policy_releases_no_auth_token() {
    let (paused, control) = hold();
    let f = fixture(Some(paused));
    let (person, resource_token) = tokens(&f);
    let response = race(&f, control, token_request(&f, &person, &resource_token), || {
        f.ps.handle(&revocation(
            RESOURCE,
            "aauth-resource.json",
            "resource-1",
            4,
            "rt-1",
            NOW + 300,
        ))
        .status()
        .as_u16()
    });
    assert_eq!(response.status(), 400);
    assert_eq!(
        member(&response, "error").as_deref(),
        Some("revoked_resource_token")
    );
    assert!(member(&response, "auth_token").is_none());
    assert!(f.audit.records.lock().unwrap().is_empty());
}

#[test]
fn agent_token_revoked_during_r3_policy_releases_no_auth_token() {
    let (paused, control) = hold();
    let f = fixture(Some(paused));
    let (person, resource_token) = tokens(&f);
    let response = race(&f, control, token_request(&f, &person, &resource_token), || {
        f.ps.handle(&revocation(
            AP,
            "aauth-agent.json",
            "ap-1",
            1,
            "agent-1",
            NOW + 1800,
        ))
        .status()
        .as_u16()
    });
    assert_eq!(response.status(), 401);
    assert_eq!(member(&response, "error").as_deref(), Some("revoked_jwt"));
    assert_eq!(response.headers()["signature-error"], "error=revoked_jwt");
    assert!(member(&response, "auth_token").is_none());
    assert!(f.audit.records.lock().unwrap().is_empty());
}

#[test]
fn presented_token_revoked_during_r3_policy_releases_no_auth_token() {
    let (paused, control) = hold();
    let f = fixture(Some(paused));
    let (person, resource_token) = tokens(&f);
    let person_jti = PersonToken::parse(&person)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    let response = race(&f, control, token_request(&f, &person, &resource_token), || {
        f.ps.revoke_person_token(&person_jti).status().as_u16()
    });
    assert_eq!(response.status(), 400);
    assert_eq!(
        member(&response, "error").as_deref(),
        Some("revoked_presented_token")
    );
    assert!(member(&response, "auth_token").is_none());
}

#[test]
fn resource_token_revoked_during_r3_audit_commit_releases_no_auth_token() {
    let (paused, control) = hold();
    let f = fixture(None);
    *f.audit.hold.lock().unwrap() = Some(paused);
    let (person, resource_token) = tokens(&f);
    let response = race(&f, control, token_request(&f, &person, &resource_token), || {
        f.ps.handle(&revocation(
            RESOURCE,
            "aauth-resource.json",
            "resource-1",
            4,
            "rt-1",
            NOW + 300,
        ))
        .status()
        .as_u16()
    });
    assert_eq!(response.status(), 400);
    assert_eq!(
        member(&response, "error").as_deref(),
        Some("revoked_resource_token")
    );
    assert!(member(&response, "auth_token").is_none());
}

#[test]
fn completed_agent_revocation_cascades_to_a_registered_r3_auth_token() {
    let f = fixture(None);
    let (person, resource_token) = tokens(&f);
    let issued = f.ps.handle(&token_request(&f, &person, &resource_token));
    assert_eq!(issued.status(), 200);
    let auth = member(&issued, "auth_token").expect("auth token");
    let auth_jti = AuthToken::parse(&auth)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    assert_eq!(f.audit.records.lock().unwrap().len(), 1);
    let revoked = f.ps.handle(&revocation(
        AP,
        "aauth-agent.json",
        "ap-1",
        1,
        "agent-1",
        NOW + 1800,
    ));
    assert_eq!(revoked.status(), 200);
    assert!(
        f.cascade
            .0
            .lock()
            .unwrap()
            .contains(&(RESOURCE.to_owned(), auth_jti)),
        "the cascade reached the R3 Auth token at its Resource"
    );
    // A later exchange by the revoked Agent is refused before any callback.
    let again = f.ps.handle(&token_request(&f, &person, &resource_token));
    assert_eq!(again.status(), 401);
    assert!(member(&again, "auth_token").is_none());
}

/// Issue through the PS and verify both tokens as the Agent does.
fn deliver(
    f: &Fixture,
    requested: Option<&str>,
) -> (
    aauth_rust_r3::VerifiedR3ResourceToken,
    String,
    String,
    Response<Vec<u8>>,
) {
    let (person, resource_token) = tokens_with(f, requested);
    let verified = f
        .agent
        .verify_r3_resource_token(&resource_token, RESOURCE, PS, &person, requested, &keys(), NOW)
        .unwrap();
    let issued = f.ps.handle(&token_request(f, &person, &resource_token));
    (verified, person, resource_token, issued)
}

#[test]
fn r3_grant_without_core_scope_is_accepted_when_scope_was_requested() {
    let f = fixture_with(None, &[]);
    let (verified, person, _, issued) = deliver(&f, Some("records.read"));
    assert_eq!(verified.claims().scope.as_deref(), Some("records.read"));
    assert_eq!(issued.status(), 200);
    let auth = member(&issued, "auth_token").unwrap();
    let delivered = f
        .agent
        .verify_r3_auth_delivery(
            &auth,
            RESOURCE,
            &verified,
            &person,
            &standard_registry().unwrap(),
            &keys(),
            NOW,
        )
        .expect("an R3 grant of no Core scope is no broader than requested");
    assert!(delivered.claims().scope.is_none());
    assert_eq!(delivered.reference(), verified.reference());
}

#[test]
fn r3_grant_scope_must_stay_within_the_requested_scope() {
    // Granting the requested scope is accepted.
    let f = fixture_with(None, &["records.read"]);
    let (verified, person, _, issued) = deliver(&f, Some("records.read"));
    let auth = member(&issued, "auth_token").unwrap();
    let registry = standard_registry().unwrap();
    let delivered = f
        .agent
        .verify_r3_auth_delivery(&auth, RESOURCE, &verified, &person, &registry, &keys(), NOW)
        .unwrap();
    assert_eq!(delivered.claims().scope.as_deref(), Some("records.read"));

    // Without a requested scope, a granted scope is refused by the PS.
    let unrequested = fixture_with(None, &["records.read"]);
    let (_, _, _, refused) = deliver(&unrequested, None);
    assert_eq!(refused.status(), 500);
    assert!(member(&refused, "auth_token").is_none());

    // A PS-signed grant wider than the request is refused by the Agent.
    let wider = forged_scope(&f, &verified, "records.read records.write");
    assert!(matches!(
        f.agent
            .verify_r3_auth_delivery(&wider, RESOURCE, &verified, &person, &registry, &keys(), NOW),
        Err(aauth_rust_agent::R3AgentError::Context)
    ));
}

/// Fetch the exact document as the PS and sign a grant with `scope`.
fn forged_scope(
    f: &Fixture,
    verified: &aauth_rust_r3::VerifiedR3ResourceToken,
    scope: &str,
) -> String {
    let mut fetch = Request::builder()
        .method("GET")
        .uri(verified.reference().uri())
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut fetch,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        NOW,
    )
    .unwrap();
    let exact = f.resource.r3_document(&fetch, NOW).into_body();
    let registry = standard_registry().unwrap();
    let document = registry
        .parse_referenced_document(verified.reference(), &exact)
        .unwrap();
    let grant = aauth_rust_r3::Grant::new(
        &GrantedOperations::new(&McpCodec::vocabulary().unwrap(), &[mcp("records.read")])
            .unwrap(),
        &document,
    )
    .unwrap();
    let r = verified.claims();
    aauth_rust_r3::mint_direct_auth_token(
        &registry,
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &aauth_rust_core::AuthClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: r.sub.clone(),
            jti: "forged-1".into(),
            iat: NOW,
            exp: NOW + 600,
            ps: PS.into(),
            cnf: Confirmation {
                jwk: f.agent.public_jwk(),
            },
            scope: Some(scope.into()),
            account: None,
            nbf: None,
            tenant: r.tenant.clone(),
            mission_s256: None,
            extra: Default::default(),
        },
        verified.reference(),
        &exact,
        &grant,
    )
    .unwrap()
}

#[test]
fn observed_admission_carries_the_class_grant_for_the_mapped_request() {
    let f = fixture(None);
    let (person, resource_token) = tokens(&f);
    let issued = f.ps.handle(&token_request(&f, &person, &resource_token));
    let auth = member(&issued, "auth_token").unwrap();
    let reference = aauth_rust_r3::verify_auth_token_claims(
        &standard_registry().unwrap(),
        &auth,
        &keys(),
        NOW,
    )
    .unwrap()
    .reference()
    .clone();
    let holder = f.agent.with_token(auth).unwrap();
    let body = br#"{"record":"r-1"}"#.to_vec();
    let mut call = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/records/read"))
        .header("content-type", "application/json")
        .body(body.clone())
        .unwrap();
    holder.sign(&mut call, NOW).unwrap();
    let signed_bytes = call.body().clone();

    match f.resource.authorize_observed(&call, NOW, "observed-1") {
        AuthDecision::Observed(admitted) => {
            let grant = admitted.r3_grant().expect("Observed carries the R3 grant");
            assert_eq!(grant.reference(), &reference);
            assert_eq!(
                grant.operation().json().unwrap(),
                br#"{"tool":"records.read"}"#
            );
            assert!(admitted.admitted_maximum().is_none());
        }
        other => panic!("expected Observed, got {other:?}"),
    }
    // Buffered admission of the same signed bytes carries the same grant.
    match f.resource.authorize(&call, NOW, "buffered-1") {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.r3_grant().unwrap().reference(), &reference);
        }
        other => panic!("expected Granted, got {other:?}"),
    }
    assert_eq!(call.body(), &signed_bytes);
    assert_eq!(call.body(), &body);

    // The same R3 token on an unmapped route is refused, not Observed.
    let mut core = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/records/other"))
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    holder.sign(&mut core, NOW).unwrap();
    assert!(matches!(
        f.resource.authorize_observed(&core, NOW, "observed-2"),
        AuthDecision::Forbidden { .. }
    ));
}
