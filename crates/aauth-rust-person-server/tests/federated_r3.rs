//! Product qualification of federated R3. The Person Server fetches the
//! artifact, takes the matching consent, and relays the original tokens.
//! The access server signs the Auth token. A changed reference, subject, or
//! issuer is not released.

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, Confirmation, ResourceClaims, TokenError,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedPolicy, BoxedTokenIds, Config, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest, R3Decision,
    R3IssuerConfig, R3Policy, R3ProposalDecision, R3ProposalRequest,
};
use aauth_rust_r3::{
    FetchBody, FetchLimits, FetchResponse, FetchTransport, IssuanceError, IssuanceRecord,
    IssuanceStore, Parameters, Proposal, ProposalOptions, mint_direct_auth_token,
    mint_per_call_auth_token, mint_proposal_resource_token, mint_resource_token, standard_registry,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

const NOW: i64 = 1_000;
const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
const ACCESS: &str = "https://as.example";
const CLASS: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.delete"}]}"#;
const READ: &[u8] =
    br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}"#;
const CLASS_URI: &str = "https://resource.example/r3/class";

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed: [u8; 32] = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap-key") => [1; 32],
            (RESOURCE, "aauth-resource.json", "resource-key") => [4; 32],
            (ACCESS, "aauth-access.json", "as-key") => [7; 32],
            ("https://other.example", "aauth-access.json", "other-key") => [8; 32],
            (PS, "aauth-person.json", "ps-key") => [3; 32],
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed(seed).public_jwk())
    }
}

struct Body {
    bytes: Vec<u8>,
    offset: usize,
}
impl FetchBody for Body {
    fn read(&mut self, out: &mut [u8], _: Instant) -> io::Result<usize> {
        let size = out.len().min(self.bytes.len() - self.offset);
        out[..size].copy_from_slice(&self.bytes[self.offset..self.offset + size]);
        self.offset += size;
        Ok(size)
    }
}

struct Documents {
    artifacts: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    order: Arc<Mutex<Vec<&'static str>>>,
}
impl FetchTransport for Documents {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> io::Result<FetchResponse> {
        self.order.lock().unwrap().push("fetch");
        let uri = request.uri().to_string();
        let bytes = self
            .artifacts
            .lock()
            .unwrap()
            .get(&uri)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("unexpected fetch {uri}")))?;
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json; charset=utf-8")
            .body(Box::new(Body { bytes, offset: 0 }) as Box<dyn FetchBody>)
            .unwrap())
    }
}

struct Relay {
    order: Arc<Mutex<Vec<&'static str>>>,
    original: Arc<Mutex<Option<(String, String, String)>>>,
    mode: Arc<Mutex<Mode>>,
    good_class: Mutex<String>,
    good_proposal: Mutex<String>,
    bad_subject: Mutex<String>,
    bad_reference: Mutex<String>,
    bad_issuer: Mutex<String>,
    bad_proposal: Mutex<String>,
}
#[derive(Clone, Copy)]
enum Mode {
    Class,
    Proposal,
    BadSubject,
    BadReference,
    BadIssuer,
    BadProposal,
}
impl aauth_rust_person_server::Federation for Relay {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        if issuer != ACCESS {
            return Err(aauth_rust_person_server::FederationError);
        }
        Ok("https://as.example/token".into())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        self.order.lock().unwrap().push("access");
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        let (resource, presented, agent) = self
            .original
            .lock()
            .unwrap()
            .clone()
            .expect("original tokens");
        assert_eq!(body["resource_token"], resource, "original resource token");
        assert_eq!(
            body["presented_token"], presented,
            "original presented token"
        );
        assert_eq!(body["agent_token"], agent, "original agent token");
        let token = match *self.mode.lock().unwrap() {
            Mode::Class => self.good_class.lock().unwrap().clone(),
            Mode::Proposal => self.good_proposal.lock().unwrap().clone(),
            Mode::BadSubject => self.bad_subject.lock().unwrap().clone(),
            Mode::BadReference => self.bad_reference.lock().unwrap().clone(),
            Mode::BadIssuer => self.bad_issuer.lock().unwrap().clone(),
            Mode::BadProposal => self.bad_proposal.lock().unwrap().clone(),
        };
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"auth_token": token, "expires_in": 600})).unwrap())
            .unwrap())
    }
}

struct Consent {
    order: Arc<Mutex<Vec<&'static str>>>,
    core: AtomicUsize,
    documents: AtomicUsize,
    proposals: AtomicUsize,
    deny_proposal: Mutex<bool>,
}
impl Policy for Consent {
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.core.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "person-1".into(),
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
impl R3Policy for Consent {
    fn authorize_document(
        &self,
        _: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        self.order.lock().unwrap().push("document-consent");
        self.documents.fetch_add(1, Ordering::SeqCst);
        let registry = standard_registry().unwrap();
        let document = registry.parse_document(CLASS).unwrap();
        let grant = registry.parse_grant(READ, &document).unwrap();
        Ok(R3Decision {
            granted: grant.granted_operations(),
            per_call: None,
            scopes: vec!["records.read".into()],
            lifetime: 600,
        })
    }
    fn authorize_proposal(
        &self,
        _: &R3ProposalRequest<'_>,
    ) -> Result<R3ProposalDecision, PolicyError> {
        self.order.lock().unwrap().push("proposal-consent");
        self.proposals.fetch_add(1, Ordering::SeqCst);
        if *self.deny_proposal.lock().unwrap() {
            return Err(PolicyError::Denied);
        }
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime: 600,
        })
    }
}

struct NoAudit;
impl IssuanceStore for NoAudit {
    fn commit(&self, _: &IssuanceRecord) -> Result<(), IssuanceError> {
        Ok(())
    }
}

fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = AgentProvider::new(
        "https://ap.example",
        "ap-key",
        SigningKey::from_seed([1; 32]),
    )
    .unwrap()
    .issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Caller@ap.example".into(),
        jti: "agent-2".into(),
        iat: NOW,
        exp: NOW + 4_000,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })
    .unwrap();
    Agent::new(key, token).unwrap()
}

fn auth_base(holder: &Agent, jti: &str) -> AuthClaims {
    AuthClaims {
        iss: ACCESS.into(),
        dwk: "aauth-access.json".into(),
        aud: RESOURCE.into(),
        sub: "person-1".into(),
        jti: jti.into(),
        iat: NOW,
        exp: NOW + 900,
        ps: PS.into(),
        cnf: Confirmation {
            jwk: holder.public_jwk(),
        },
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: Some("records.read".into()),
        account: None,
        extra: Default::default(),
    }
}

#[test]
fn federated_class_and_proposal_keep_original_tokens_and_reject_changed_authority() {
    let registry = standard_registry().unwrap();
    let holder = agent();
    let order = Arc::new(Mutex::new(Vec::new()));
    let artifacts = Arc::new(Mutex::new(std::collections::BTreeMap::from([(
        CLASS_URI.to_owned(),
        CLASS.to_vec(),
    )])));
    let documents = Documents {
        artifacts: artifacts.clone(),
        order: order.clone(),
    };
    let document = registry.parse_document(CLASS).unwrap();
    let read = registry.parse_grant(READ, &document).unwrap();
    let class_reference =
        aauth_rust_r3::Reference::new(CLASS_URI, aauth_rust_r3::digest(CLASS)).unwrap();
    let mut resource_claims = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: ACCESS.into(),
        ps: PS.into(),
        sub: "person-1".into(),
        jti: "resource-class".into(),
        presented_jti: "filled-after-person".into(),
        agent_jkt: holder.public_jwk().thumbprint().unwrap(),
        iat: NOW,
        exp: NOW + 300,
        scope: Some("records.read".into()),
        account: None,
        login_hint: None,
        nbf: None,
        tenant: None,
        mission_s256: None,
        extra: Default::default(),
    };
    let good_class = mint_direct_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &auth_base(&holder, "class-auth"),
        &class_reference,
        CLASS,
        &read,
    )
    .unwrap();
    let mut bad_subject_claims = auth_base(&holder, "bad-subject");
    bad_subject_claims.sub = "other-person".into();
    let bad_subject = mint_direct_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &bad_subject_claims,
        &class_reference,
        CLASS,
        &read,
    )
    .unwrap();
    let other_uri = "https://resource.example/r3/other";
    let other_reference =
        aauth_rust_r3::Reference::new(other_uri, aauth_rust_r3::digest(CLASS)).unwrap();
    let bad_reference = mint_direct_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &auth_base(&holder, "bad-reference"),
        &other_reference,
        CLASS,
        &read,
    )
    .unwrap();
    let mut foreign = auth_base(&holder, "foreign");
    foreign.iss = "https://other.example".into();
    let bad_issuer = mint_direct_auth_token(
        &registry,
        &SigningKey::from_seed([8; 32]),
        "other-key",
        &foreign,
        &class_reference,
        CLASS,
        &read,
    )
    .unwrap();

    let operation = read
        .granted_operations()
        .operations()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let proposal = Proposal::new(
        &operation,
        &Parameters::new(std::iter::empty()).unwrap(),
        ProposalOptions::default(),
    )
    .unwrap();
    let exact_proposal = serde_json::to_vec(&proposal).unwrap();
    let proposal_uri = "https://resource.example/r3/proposal";
    let proposal_reference =
        aauth_rust_r3::Reference::new(proposal_uri, aauth_rust_r3::digest(&exact_proposal))
            .unwrap();
    let mut proposal_auth = auth_base(&holder, "proposal-auth");
    proposal_auth.scope = None;
    let good_proposal = mint_per_call_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &proposal_auth,
        &proposal_reference,
        &exact_proposal,
    )
    .unwrap();
    let delete_grant = registry
        .parse_grant(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}"#,
            &document,
        )
        .unwrap();
    let delete_operation = delete_grant
        .granted_operations()
        .operations()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let delete_proposal = Proposal::new(
        &delete_operation,
        &Parameters::new(std::iter::empty()).unwrap(),
        ProposalOptions::default(),
    )
    .unwrap();
    let delete_bytes = serde_json::to_vec(&delete_proposal).unwrap();
    let delete_reference = aauth_rust_r3::Reference::new(
        "https://resource.example/r3/proposal-delete",
        aauth_rust_r3::digest(&delete_bytes),
    )
    .unwrap();
    let bad_proposal = mint_per_call_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &auth_base(&holder, "bad-proposal"),
        &delete_reference,
        &delete_bytes,
    )
    .unwrap();

    let relay_original = Arc::new(Mutex::new(None));
    let relay_mode = Arc::new(Mutex::new(Mode::Class));
    let relay = Relay {
        order: order.clone(),
        original: relay_original.clone(),
        mode: relay_mode.clone(),
        good_class: Mutex::new(good_class.clone()),
        good_proposal: Mutex::new(good_proposal.clone()),
        bad_subject: Mutex::new(bad_subject),
        bad_reference: Mutex::new(bad_reference),
        bad_issuer: Mutex::new(bad_issuer),
        bad_proposal: Mutex::new(bad_proposal),
    };
    let consent = Consent {
        order: order.clone(),
        core: AtomicUsize::new(0),
        documents: AtomicUsize::new(0),
        proposals: AtomicUsize::new(0),
        deny_proposal: Mutex::new(false),
    };
    let consent = Arc::new(consent);
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Box::new(ConsentGate(consent.clone())) as BoxedPolicy,
        Box::new(|| NOW) as BoxedClock,
        Box::new(|| "ps-token".into()) as BoxedTokenIds,
    )
    .unwrap()
    .with_federation(relay)
    .with_r3(R3IssuerConfig {
        registry: registry.clone(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(documents),
        limits: FetchLimits::default(),
        policy: Box::new(R3Gate(consent.clone())) as _,
        audit: Arc::new(NoAudit),
    })
    .unwrap();

    let caller = agent();
    let mut person_request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"resource": RESOURCE})).unwrap())
        .unwrap();
    caller.sign(&mut person_request, NOW).unwrap();
    let person = server.handle(&person_request);
    assert_eq!(
        person.status(),
        200,
        "{}",
        String::from_utf8_lossy(person.body())
    );
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let person_jti = aauth_rust_core::PersonToken::parse(&person_token)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    resource_claims.presented_jti = person_jti;
    let (class_token, _) = mint_resource_token(
        &registry,
        &SigningKey::from_seed([4; 32]),
        "resource-key",
        &resource_claims,
        CLASS_URI,
        CLASS,
    )
    .unwrap();
    resource_claims.jti = "resource-proposal".into();
    let (proposal_token, minted_reference) = mint_proposal_resource_token(
        &registry,
        &SigningKey::from_seed([4; 32]),
        "resource-key",
        &resource_claims,
        proposal_uri,
        &exact_proposal,
    )
    .unwrap();
    assert_eq!(minted_reference, proposal_reference);
    artifacts
        .lock()
        .unwrap()
        .insert(minted_reference.uri().to_owned(), exact_proposal.clone());
    let agent_token = caller.token().to_owned();
    let exchange = |mode: Mode, resource_token: &str| {
        *relay_mode.lock().unwrap() = mode;
        *relay_original.lock().unwrap() = Some((
            resource_token.to_owned(),
            person_token.clone(),
            agent_token.clone(),
        ));
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}/token"))
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&json!({
                    "resource_token": resource_token,
                    "presented_token": person_token,
                }))
                .unwrap(),
            )
            .unwrap();
        caller.sign(&mut request, NOW).unwrap();
        server.handle(&request)
    };
    order.lock().unwrap().clear();
    let classed = exchange(Mode::Class, &class_token);
    assert_eq!(
        classed.status(),
        200,
        "{}",
        String::from_utf8_lossy(classed.body())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(classed.body()).unwrap()["auth_token"],
        good_class
    );
    assert_eq!(
        order.lock().unwrap().as_slice(),
        ["fetch", "document-consent", "access"]
    );
    assert_eq!(consent.core.load(Ordering::SeqCst), 0);
    assert_eq!(consent.documents.load(Ordering::SeqCst), 1);

    let before_access = order
        .lock()
        .unwrap()
        .iter()
        .filter(|step| **step == "access")
        .count();
    let changed_subject = exchange(Mode::BadSubject, &class_token);
    assert_eq!(changed_subject.status(), 502);
    assert_eq!(
        serde_json::from_slice::<Value>(changed_subject.body()).unwrap()["error"],
        "as_unreachable"
    );
    assert!(
        serde_json::from_slice::<Value>(changed_subject.body())
            .unwrap()
            .get("auth_token")
            .is_none()
    );
    let changed_reference = exchange(Mode::BadReference, &class_token);
    assert_eq!(changed_reference.status(), 502);
    assert_eq!(
        serde_json::from_slice::<Value>(changed_reference.body()).unwrap()["error"],
        "as_unreachable"
    );
    let changed_issuer = exchange(Mode::BadIssuer, &class_token);
    assert_eq!(changed_issuer.status(), 502);
    assert_eq!(
        serde_json::from_slice::<Value>(changed_issuer.body()).unwrap()["error"],
        "as_unreachable"
    );
    assert!(
        order
            .lock()
            .unwrap()
            .iter()
            .filter(|step| **step == "access")
            .count()
            > before_access
    );
    let documents_after_class = consent.documents.load(Ordering::SeqCst);
    assert_eq!(documents_after_class, 4);
    assert_eq!(consent.proposals.load(Ordering::SeqCst), 0);

    order.lock().unwrap().clear();
    let proposed = exchange(Mode::Proposal, &proposal_token);
    assert_eq!(
        proposed.status(),
        200,
        "{}",
        String::from_utf8_lossy(proposed.body())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(proposed.body()).unwrap()["auth_token"],
        good_proposal
    );
    assert_eq!(
        order.lock().unwrap().as_slice(),
        ["fetch", "proposal-consent", "access"]
    );
    assert_eq!(consent.core.load(Ordering::SeqCst), 0);
    assert_eq!(
        consent.documents.load(Ordering::SeqCst),
        documents_after_class
    );
    assert_eq!(consent.proposals.load(Ordering::SeqCst), 1);

    *consent.deny_proposal.lock().unwrap() = true;
    let accesses = order
        .lock()
        .unwrap()
        .iter()
        .filter(|step| **step == "access")
        .count();
    let declined = exchange(Mode::Proposal, &proposal_token);
    assert_eq!(declined.status(), 403);
    assert_eq!(
        order
            .lock()
            .unwrap()
            .iter()
            .filter(|step| **step == "access")
            .count(),
        accesses,
        "declined proposal consent does not call the access server"
    );
    *consent.deny_proposal.lock().unwrap() = false;
    let mismatched = exchange(Mode::BadProposal, &proposal_token);
    assert_eq!(
        mismatched.status(),
        502,
        "{}",
        String::from_utf8_lossy(mismatched.body())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(mismatched.body()).unwrap()["error"],
        "as_unreachable"
    );
    assert!(
        serde_json::from_slice::<Value>(mismatched.body())
            .unwrap()
            .get("auth_token")
            .is_none()
    );
}

struct ConsentGate(Arc<Consent>);
impl Policy for ConsentGate {
    fn consent(&self, request: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.0.consent(request)
    }
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.bind_person(request)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.0.authorize(request)
    }
}
struct R3Gate(Arc<Consent>);
impl R3Policy for R3Gate {
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        self.0.authorize_document(request)
    }
    fn authorize_proposal(
        &self,
        request: &R3ProposalRequest<'_>,
    ) -> Result<R3ProposalDecision, PolicyError> {
        self.0.authorize_proposal(request)
    }
}
