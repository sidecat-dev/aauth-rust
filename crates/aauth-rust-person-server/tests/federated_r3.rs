//! Product qualification of federated R3. The Person Server fetches the
//! artifact, takes the matching consent, and relays the original tokens.
//! The access server signs the Auth token. A changed reference, subject, or
//! issuer is not released. A class document or a per-call proposal that
//! offers a budget is relayed with this Person Server's ceiling, and only a
//! grant within it is released.

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::continuation::{ContinuationStore, MemoryContinuations, Snapshot, StoreError};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, Confirmation, ResourceClaims, TokenError,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedPolicy, BoxedTokenIds, Config, DeferredConfig, Grant,
    MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest,
    R3Decision, R3IssuerConfig, R3Policy, R3ProposalDecision, R3ProposalRequest,
};
use aauth_rust_r3::{
    Authorization, FetchBody, FetchLimits, FetchResponse, FetchTransport, IssuanceError,
    IssuanceRecord, IssuanceStore, Parameters, Proposal, ProposalOptions, Reference,
    mint_auth_token as mint_class_auth_token, mint_budget_auth_token,
    mint_budget_per_call_auth_token, mint_budget_proposal_resource_token,
    mint_budget_resource_token, mint_direct_auth_token, mint_per_call_auth_token,
    mint_proposal_resource_token, mint_resource_token, standard_registry, verify_budget_auth_token,
    verify_budget_per_call_auth_token,
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
    status: Arc<Mutex<u16>>,
    fail: Arc<Mutex<bool>>,
}
impl FetchTransport for Documents {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> io::Result<FetchResponse> {
        self.order.lock().unwrap().push("fetch");
        if *self.fail.lock().unwrap() {
            return Err(io::Error::other("resource transport unavailable"));
        }
        let status = *self.status.lock().unwrap();
        let uri = request.uri().to_string();
        let bytes = if status == 200 {
            self.artifacts
                .lock()
                .unwrap()
                .get(&uri)
                .cloned()
                .ok_or_else(|| io::Error::other(format!("unexpected fetch {uri}")))?
        } else {
            Vec::new()
        };
        Ok(Response::builder()
            .status(status)
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
    bad_tenant: Mutex<String>,
    bad_account: Mutex<String>,
    bad_key: Mutex<String>,
    bad_operation: Mutex<String>,
    continued_per_call: Mutex<String>,
    core_only: Mutex<String>,
    hold: Arc<Mutex<Option<u16>>>,
}
#[derive(Clone, Copy)]
enum Mode {
    Class,
    Proposal,
    BadSubject,
    BadReference,
    BadIssuer,
    BadProposal,
    BadTenant,
    BadAccount,
    BadKey,
    BadOperation,
    ContinuedPerCall,
    CoreOnly,
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
        if let Some(status) = *self.hold.lock().unwrap() {
            return Ok(Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(br#"{"invoice":"private-invoice"}"#.to_vec())
                .unwrap());
        }
        let token = match *self.mode.lock().unwrap() {
            Mode::Class => self.good_class.lock().unwrap().clone(),
            Mode::Proposal => self.good_proposal.lock().unwrap().clone(),
            Mode::BadSubject => self.bad_subject.lock().unwrap().clone(),
            Mode::BadReference => self.bad_reference.lock().unwrap().clone(),
            Mode::BadIssuer => self.bad_issuer.lock().unwrap().clone(),
            Mode::BadProposal => self.bad_proposal.lock().unwrap().clone(),
            Mode::BadTenant => self.bad_tenant.lock().unwrap().clone(),
            Mode::BadAccount => self.bad_account.lock().unwrap().clone(),
            Mode::BadKey => self.bad_key.lock().unwrap().clone(),
            Mode::BadOperation => self.bad_operation.lock().unwrap().clone(),
            Mode::ContinuedPerCall => self.continued_per_call.lock().unwrap().clone(),
            Mode::CoreOnly => self.core_only.lock().unwrap().clone(),
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

fn raw_proposal_auth(
    holder: &Agent,
    jti: &str,
    reference: &aauth_rust_r3::Reference,
    granted: &Value,
    per_call: Option<&Value>,
    edit: impl FnOnce(&mut AuthClaims),
) -> String {
    let mut claims = auth_base(holder, jti);
    claims.scope = None;
    claims.extra.insert("r3_uri".into(), json!(reference.uri()));
    claims
        .extra
        .insert("r3_s256".into(), json!(reference.digest()));
    claims.extra.insert("r3_granted".into(), granted.clone());
    if let Some(per_call) = per_call {
        claims.extra.insert("r3_per_call".into(), per_call.clone());
    }
    edit(&mut claims);
    aauth_rust_core::mint_auth_token(&SigningKey::from_seed([7; 32]), "as-key", &claims).unwrap()
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
    let fetch_status = Arc::new(Mutex::new(200_u16));
    let fetch_fail = Arc::new(Mutex::new(false));
    let documents = Documents {
        artifacts: artifacts.clone(),
        order: order.clone(),
        status: fetch_status.clone(),
        fail: fetch_fail.clone(),
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
    let read_ops = serde_json::to_value(read.granted_operations()).unwrap();
    let delete_ops = serde_json::to_value(delete_grant.granted_operations()).unwrap();
    let mut empty_ops = read_ops.clone();
    empty_ops["operations"] = json!([]);
    let bad_tenant = raw_proposal_auth(
        &holder,
        "changed-tenant",
        &proposal_reference,
        &read_ops,
        None,
        |claims| claims.tenant = Some("other-tenant".into()),
    );
    let bad_account = raw_proposal_auth(
        &holder,
        "changed-account",
        &proposal_reference,
        &read_ops,
        None,
        |claims| claims.account = Some("other-account".into()),
    );
    let other_key = SigningKey::from_seed([9; 32]);
    let bad_key = raw_proposal_auth(
        &holder,
        "changed-key",
        &proposal_reference,
        &read_ops,
        None,
        |claims| {
            claims.cnf = Confirmation {
                jwk: other_key.public_jwk(),
            };
        },
    );
    let bad_operation = raw_proposal_auth(
        &holder,
        "changed-operation",
        &proposal_reference,
        &delete_ops,
        None,
        |_| {},
    );
    let continued_per_call = raw_proposal_auth(
        &holder,
        "continued-per-call",
        &proposal_reference,
        &read_ops,
        Some(&empty_ops),
        |_| {},
    );
    let core_only = aauth_rust_core::mint_auth_token(
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &auth_base(&holder, "core-only"),
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
    let relay_hold = Arc::new(Mutex::new(None));
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
        bad_tenant: Mutex::new(bad_tenant),
        bad_account: Mutex::new(bad_account),
        bad_key: Mutex::new(bad_key),
        bad_operation: Mutex::new(bad_operation),
        continued_per_call: Mutex::new(continued_per_call),
        core_only: Mutex::new(core_only),
        hold: relay_hold.clone(),
    };
    let continuation_inserts = Arc::new(AtomicUsize::new(0));
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
    .with_deferred(DeferredConfig::new(CountStore {
        inner: MemoryContinuations::new(4),
        inserts: continuation_inserts.clone(),
    }))
    .unwrap()
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

    let as_refused = |mode: Mode, resource_token: &str| {
        let response = exchange(mode, resource_token);
        let body = String::from_utf8_lossy(response.body()).into_owned();
        assert_eq!(response.status(), 502, "{body}");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
            "as_unreachable"
        );
        assert!(
            serde_json::from_slice::<Value>(response.body())
                .unwrap()
                .get("auth_token")
                .is_none()
        );
    };
    as_refused(Mode::BadTenant, &proposal_token);
    as_refused(Mode::BadAccount, &proposal_token);
    as_refused(Mode::BadKey, &proposal_token);
    as_refused(Mode::BadOperation, &proposal_token);
    as_refused(Mode::ContinuedPerCall, &proposal_token);
    as_refused(Mode::CoreOnly, &class_token);

    let documents_before_fetch = consent.documents.load(Ordering::SeqCst);
    let proposals_before_fetch = consent.proposals.load(Ordering::SeqCst);
    order.lock().unwrap().clear();
    artifacts.lock().unwrap().insert(
        CLASS_URI.to_owned(),
        CLASS.iter().copied().chain(std::iter::once(b' ')).collect(),
    );
    let mismatched_hash = exchange(Mode::Class, &class_token);
    assert_eq!(
        mismatched_hash.status(),
        400,
        "{}",
        String::from_utf8_lossy(mismatched_hash.body())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(mismatched_hash.body()).unwrap()["error"],
        "invalid_resource_token"
    );
    assert_eq!(order.lock().unwrap().as_slice(), ["fetch"]);
    artifacts
        .lock()
        .unwrap()
        .insert(CLASS_URI.to_owned(), CLASS.to_vec());

    order.lock().unwrap().clear();
    *fetch_status.lock().unwrap() = 401;
    let unauthorized_fetch = exchange(Mode::Class, &class_token);
    assert_eq!(
        unauthorized_fetch.status(),
        500,
        "{}",
        String::from_utf8_lossy(unauthorized_fetch.body())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(unauthorized_fetch.body()).unwrap()["error"],
        "server_error"
    );
    assert_eq!(order.lock().unwrap().as_slice(), ["fetch"]);
    *fetch_status.lock().unwrap() = 200;

    order.lock().unwrap().clear();
    *fetch_fail.lock().unwrap() = true;
    let unavailable_fetch = exchange(Mode::Class, &class_token);
    assert_eq!(
        unavailable_fetch.status(),
        500,
        "{}",
        String::from_utf8_lossy(unavailable_fetch.body())
    );
    assert_eq!(order.lock().unwrap().as_slice(), ["fetch"]);
    *fetch_fail.lock().unwrap() = false;
    assert_eq!(
        consent.documents.load(Ordering::SeqCst),
        documents_before_fetch
    );
    assert_eq!(
        consent.proposals.load(Ordering::SeqCst),
        proposals_before_fetch
    );
    assert_eq!(consent.core.load(Ordering::SeqCst), 0);

    let refused = |status: u16, mode: Mode, resource_token: &str| {
        order.lock().unwrap().clear();
        *relay_hold.lock().unwrap() = Some(status);
        let response = exchange(mode, resource_token);
        let body = String::from_utf8_lossy(response.body()).into_owned();
        assert_eq!(response.status(), 500, "{body}");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["error"],
            "server_error"
        );
        assert!(
            serde_json::from_slice::<Value>(response.body())
                .unwrap()
                .get("auth_token")
                .is_none()
        );
        assert!(!body.contains("private-invoice"));
        assert_eq!(continuation_inserts.load(Ordering::SeqCst), 0);
        response
    };
    refused(202, Mode::Class, &class_token);
    assert_eq!(
        order.lock().unwrap().as_slice(),
        ["fetch", "document-consent", "access"]
    );
    refused(402, Mode::Proposal, &proposal_token);
    assert_eq!(
        order.lock().unwrap().as_slice(),
        ["fetch", "proposal-consent", "access"]
    );
    assert_eq!(consent.core.load(Ordering::SeqCst), 0);
}

struct CountStore {
    inner: MemoryContinuations,
    inserts: Arc<AtomicUsize>,
}
impl ContinuationStore for CountStore {
    fn insert(&self, id: &str, value: Value) -> Result<(), StoreError> {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.inner.insert(id, value)
    }
    fn load(&self, id: &str) -> Result<Option<Snapshot>, StoreError> {
        self.inner.load(id)
    }
    fn replace(&self, id: &str, revision: u64, value: Option<Value>) -> Result<bool, StoreError> {
        self.inner.replace(id, revision, value)
    }
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

/// An access server as aauth-go's: its class grant leaves `records.delete` per
/// call, and it signs each per-call token with `grant` as its budget, or with
/// none. It records the `budget` member of every request it receives.
struct MeteredAccess {
    template: AuthClaims,
    class_resource: Mutex<String>,
    class_auth: String,
    proposal: Mutex<Option<(Reference, Vec<u8>)>>,
    grant: Mutex<Option<i64>>,
    ceilings: Mutex<Vec<Option<Value>>>,
    issued: AtomicUsize,
}
struct MeteredRelay(Arc<MeteredAccess>);
impl aauth_rust_person_server::Federation for MeteredRelay {
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
        let access = &self.0;
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        access
            .ceilings
            .lock()
            .unwrap()
            .push(body.get("budget").cloned());
        let token = if body["resource_token"] == *access.class_resource.lock().unwrap() {
            access.class_auth.clone()
        } else {
            let (reference, exact) = access.proposal.lock().unwrap().clone().unwrap();
            let mut claims = access.template.clone();
            claims.jti = format!("per-call-{}", access.issued.fetch_add(1, Ordering::SeqCst));
            claims.scope = None;
            let registry = standard_registry().unwrap();
            let key = SigningKey::from_seed([7; 32]);
            match *access.grant.lock().unwrap() {
                Some(amount) => mint_budget_per_call_auth_token(
                    &registry,
                    &key,
                    "as-key",
                    &claims,
                    &reference,
                    &exact,
                    &Budget::new(amount, "USD", 2).unwrap(),
                ),
                None => {
                    mint_per_call_auth_token(&registry, &key, "as-key", &claims, &reference, &exact)
                }
            }
            .unwrap()
        };
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"auth_token": token, "expires_in": 600})).unwrap())
            .unwrap())
    }
}

#[test]
fn federated_budgeted_proposal_relays_the_ceiling_and_releases_only_a_grant_within_it() {
    let registry = standard_registry().unwrap();
    let holder = agent();
    let document = registry.parse_document(CLASS).unwrap();
    let read = registry.parse_grant(READ, &document).unwrap();
    let delete = registry
        .parse_grant(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}"#,
            &document,
        )
        .unwrap();
    let delete_operation = delete.granted_operations().operations().unwrap().remove(0);
    let exact = serde_json::to_vec(
        &Proposal::new(
            &delete_operation,
            &Parameters::new(std::iter::empty()).unwrap(),
            ProposalOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let proposal_uri = "https://resource.example/r3/proposal";
    let class_reference = Reference::new(CLASS_URI, aauth_rust_r3::digest(CLASS)).unwrap();
    let class_auth = mint_class_auth_token(
        &registry,
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &auth_base(&holder, "class-auth"),
        &class_reference,
        CLASS,
        &Authorization::new(
            &read.granted_operations(),
            &delete.granted_operations(),
            &document,
        )
        .unwrap(),
    )
    .unwrap();
    let access = Arc::new(MeteredAccess {
        template: auth_base(&holder, "unused"),
        class_resource: Mutex::new(String::new()),
        class_auth: class_auth.clone(),
        proposal: Mutex::new(None),
        grant: Mutex::new(None),
        ceilings: Mutex::new(Vec::new()),
        issued: AtomicUsize::new(0),
    });
    let order = Arc::new(Mutex::new(Vec::new()));
    let consent = Arc::new(Consent {
        order: order.clone(),
        core: AtomicUsize::new(0),
        documents: AtomicUsize::new(0),
        proposals: AtomicUsize::new(0),
        deny_proposal: Mutex::new(false),
    });
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Box::new(ConsentGate(consent.clone())) as BoxedPolicy,
        Box::new(|| NOW) as BoxedClock,
        Box::new(|| "ps-token".into()) as BoxedTokenIds,
    )
    .unwrap()
    .with_federation(MeteredRelay(access.clone()))
    .with_r3(R3IssuerConfig {
        registry: registry.clone(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(Documents {
            artifacts: Arc::new(Mutex::new(std::collections::BTreeMap::from([
                (CLASS_URI.to_owned(), CLASS.to_vec()),
                (proposal_uri.to_owned(), exact.clone()),
            ]))),
            order: order.clone(),
            status: Arc::new(Mutex::new(200)),
            fail: Arc::new(Mutex::new(false)),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(R3Gate(consent.clone())) as _,
        audit: Arc::new(NoAudit),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let post = |path: &str, body: Value| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}{path}"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        holder.sign(&mut request, NOW).unwrap();
        server.handle(&request)
    };
    let person = post("/person", json!({"resource": RESOURCE}));
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut claims = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: ACCESS.into(),
        ps: PS.into(),
        sub: "person-1".into(),
        jti: "resource-class".into(),
        presented_jti: aauth_rust_core::PersonToken::parse(&person_token)
            .unwrap()
            .unverified_claims()
            .jti
            .clone(),
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
    let resource_key = SigningKey::from_seed([4; 32]);
    let (class_resource, _) = mint_resource_token(
        &registry,
        &resource_key,
        "resource-key",
        &claims,
        CLASS_URI,
        CLASS,
    )
    .unwrap();
    *access.class_resource.lock().unwrap() = class_resource.clone();
    let classed = post(
        "/token",
        json!({"resource_token": class_resource, "presented_token": person_token}),
    );
    assert_eq!(
        classed.status(),
        200,
        "{}",
        String::from_utf8_lossy(classed.body())
    );

    // The call the class grant left per call, offering its release cost.
    claims.jti = "resource-proposal".into();
    claims.presented_jti = "class-auth".into();
    claims.scope = None;
    let (proposal_resource, reference) = mint_budget_proposal_resource_token(
        &registry,
        &resource_key,
        "resource-key",
        &claims,
        proposal_uri,
        &exact,
        &Budget::new(5_000_000, "USD", 2).unwrap(),
    )
    .unwrap();
    *access.proposal.lock().unwrap() = Some((reference.clone(), exact.clone()));
    let propose = || {
        post(
            "/token",
            json!({"resource_token": proposal_resource, "presented_token": class_auth}),
        )
    };
    // A grant the ceiling does not bound, or no grant, is not released.
    for grant in [None, Some(2_000_001)] {
        *access.grant.lock().unwrap() = grant;
        let refused = propose();
        assert_eq!(refused.status(), 502, "{grant:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(refused.body()).unwrap()["error"],
            "as_unreachable"
        );
    }
    *access.grant.lock().unwrap() = Some(2_000_000);
    let funded = propose();
    assert_eq!(
        funded.status(),
        200,
        "{}",
        String::from_utf8_lossy(funded.body())
    );
    let delivered = serde_json::from_slice::<Value>(funded.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, budget) =
        verify_budget_per_call_auth_token(&registry, &delivered, &Keys, NOW, &reference, &exact)
            .unwrap();
    assert_eq!(budget.amount(), 2_000_000);
    // The class exchange sent no ceiling; each proposal sent the offer
    // narrowed to this Person Server's cap.
    let ceiling = Budget::new(2_000_000, "USD", 2).unwrap().to_value();
    assert_eq!(
        access.ceilings.lock().unwrap().as_slice(),
        [
            None,
            Some(ceiling.clone()),
            Some(ceiling.clone()),
            Some(ceiling)
        ]
    );
    assert_eq!(server.budget_accounted(), Some(2_000_000));
    assert_eq!(consent.proposals.load(Ordering::SeqCst), 3);
}

/// An access server as aauth-go's for a class document: it signs the class
/// grant with `grant` as its budget, or with none, and records the `budget`
/// member of every request it receives.
struct ClassAccess {
    template: AuthClaims,
    grant: Mutex<Option<Budget>>,
    ceilings: Mutex<Vec<Option<Value>>>,
    issued: AtomicUsize,
}
struct ClassRelay(Arc<ClassAccess>);
impl aauth_rust_person_server::Federation for ClassRelay {
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
        let access = &self.0;
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        access
            .ceilings
            .lock()
            .unwrap()
            .push(body.get("budget").cloned());
        let registry = standard_registry().unwrap();
        let document = registry.parse_document(CLASS).unwrap();
        let read = registry.parse_grant(READ, &document).unwrap();
        let reference = Reference::new(CLASS_URI, aauth_rust_r3::digest(CLASS)).unwrap();
        let mut claims = access.template.clone();
        claims.jti = format!("class-{}", access.issued.fetch_add(1, Ordering::SeqCst));
        let key = SigningKey::from_seed([7; 32]);
        let token = match &*access.grant.lock().unwrap() {
            Some(budget) => mint_budget_auth_token(
                &registry, &key, "as-key", &claims, &reference, CLASS, &read, budget,
            ),
            None => {
                mint_direct_auth_token(&registry, &key, "as-key", &claims, &reference, CLASS, &read)
            }
        }
        .unwrap();
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"auth_token": token, "expires_in": 600})).unwrap())
            .unwrap())
    }
}

#[test]
fn federated_budgeted_class_grant_is_released_only_within_the_ceiling() {
    let registry = standard_registry().unwrap();
    let holder = agent();
    let access = Arc::new(ClassAccess {
        template: auth_base(&holder, "unused"),
        grant: Mutex::new(None),
        ceilings: Mutex::new(Vec::new()),
        issued: AtomicUsize::new(0),
    });
    let order = Arc::new(Mutex::new(Vec::new()));
    let consent = Arc::new(Consent {
        order: order.clone(),
        core: AtomicUsize::new(0),
        documents: AtomicUsize::new(0),
        proposals: AtomicUsize::new(0),
        deny_proposal: Mutex::new(false),
    });
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Box::new(ConsentGate(consent.clone())) as BoxedPolicy,
        Box::new(|| NOW) as BoxedClock,
        Box::new(|| "ps-token".into()) as BoxedTokenIds,
    )
    .unwrap()
    .with_federation(ClassRelay(access.clone()))
    .with_r3(R3IssuerConfig {
        registry: registry.clone(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(Documents {
            artifacts: Arc::new(Mutex::new(std::collections::BTreeMap::from([(
                CLASS_URI.to_owned(),
                CLASS.to_vec(),
            )]))),
            order,
            status: Arc::new(Mutex::new(200)),
            fail: Arc::new(Mutex::new(false)),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(R3Gate(consent.clone())) as _,
        audit: Arc::new(NoAudit),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let post = |path: &str, body: Value| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}{path}"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        holder.sign(&mut request, NOW).unwrap();
        server.handle(&request)
    };
    let person = post("/person", json!({"resource": RESOURCE}));
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut claims = ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: ACCESS.into(),
        ps: PS.into(),
        sub: "person-1".into(),
        jti: "resource-offered".into(),
        presented_jti: aauth_rust_core::PersonToken::parse(&person_token)
            .unwrap()
            .unverified_claims()
            .jti
            .clone(),
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
    let resource_key = SigningKey::from_seed([4; 32]);
    let (offered, _) = mint_budget_resource_token(
        &registry,
        &resource_key,
        "resource-key",
        &claims,
        CLASS_URI,
        CLASS,
        &Budget::new(5_000_000, "USD", 2).unwrap(),
        None,
    )
    .unwrap();
    let exchange = |resource_token: &str| {
        post(
            "/token",
            json!({"resource_token": resource_token, "presented_token": person_token}),
        )
    };
    // A missing, wider or re-denominated budget is not released.
    for grant in [
        None,
        Some(Budget::new(2_000_001, "USD", 2).unwrap()),
        Some(Budget::new(1_000_000, "EUR", 2).unwrap()),
        Some(Budget::new(1_000_000, "USD", 3).unwrap()),
    ] {
        *access.grant.lock().unwrap() = grant.clone();
        let refused = exchange(&offered);
        assert_eq!(refused.status(), 502, "{grant:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(refused.body()).unwrap()["error"],
            "as_unreachable"
        );
    }
    *access.grant.lock().unwrap() = Some(Budget::new(2_000_000, "USD", 2).unwrap());
    let funded = exchange(&offered);
    assert_eq!(
        funded.status(),
        200,
        "{}",
        String::from_utf8_lossy(funded.body())
    );
    let delivered = serde_json::from_slice::<Value>(funded.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, budget) = verify_budget_auth_token(&registry, &delivered, &Keys, NOW).unwrap();
    assert_eq!(budget.amount(), 2_000_000);
    assert_eq!(server.budget_accounted(), Some(2_000_000));
    // Each exchange sent the offer narrowed to this Person Server's cap.
    let ceiling = Budget::new(2_000_000, "USD", 2).unwrap().to_value();
    assert_eq!(
        access.ceilings.lock().unwrap().as_slice(),
        vec![Some(ceiling); 5].as_slice()
    );

    // Without an offer no ceiling is sent, and a budget the access server
    // adds anyway is not released.
    claims.jti = "resource-plain".into();
    let (plain, _) = mint_resource_token(
        &registry,
        &resource_key,
        "resource-key",
        &claims,
        CLASS_URI,
        CLASS,
    )
    .unwrap();
    let refused = exchange(&plain);
    assert_eq!(refused.status(), 502);
    assert_eq!(access.ceilings.lock().unwrap().last(), Some(&None));
    assert_eq!(server.budget_accounted(), Some(2_000_000));
}

/// The access server's own document transport: it keeps each fetch's
/// `Signature-Key` and serves `served` as the class document.
struct AccessDocuments {
    served: Arc<Mutex<Vec<u8>>>,
    signers: Arc<Mutex<Vec<String>>>,
}
impl FetchTransport for AccessDocuments {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> io::Result<FetchResponse> {
        assert_eq!(request.uri().to_string(), CLASS_URI);
        let signer = request.headers()["signature-key"].to_str().unwrap();
        self.signers.lock().unwrap().push(signer.to_owned());
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Box::new(Body {
                bytes: self.served.lock().unwrap().clone(),
                offset: 0,
            }) as Box<dyn FetchBody>)
            .unwrap())
    }
}

/// Hands the Person Server's signed request to a native access server in
/// process, unchanged.
type AccessHandler = Box<dyn Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;
struct NativeAccess(AccessHandler);
impl aauth_rust_person_server::Federation for NativeAccess {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        if issuer != ACCESS {
            return Err(aauth_rust_person_server::FederationError);
        }
        Ok(format!("{ACCESS}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        Ok((self.0)(request))
    }
}

#[derive(Default)]
struct Audit(Mutex<Vec<IssuanceRecord>>);
impl IssuanceStore for Audit {
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

#[test]
fn native_access_server_fetches_as_itself_and_signs_only_a_verified_class_grant() {
    use aauth_rust_access_server as access_server;
    let registry = standard_registry().unwrap();
    let holder = agent();
    let served = Arc::new(Mutex::new(CLASS.to_vec()));
    let signers = Arc::new(Mutex::new(Vec::new()));
    let audit = Arc::new(Audit::default());
    // Core grants are closed; the R3 policy grants `records.read` and the
    // requested scopes.
    let access = access_server::AccessServer::new(
        access_server::Config::new(ACCESS, "as-key", SigningKey::from_seed([7; 32])),
        Keys,
        |_: &access_server::AuthorizationRequest| Err(access_server::PolicyError::Denied),
        || NOW,
        || "as-token".to_owned(),
    )
    .unwrap()
    .with_r3(access_server::R3IssuerConfig {
        registry: registry.clone(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(AccessDocuments {
            served: served.clone(),
            signers: signers.clone(),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(
            |request: &access_server::R3AuthorizationRequest<'_>| -> Result<
                access_server::R3Decision,
                access_server::PolicyError,
            > {
                let grant = standard_registry()
                    .unwrap()
                    .parse_grant(READ, request.document)
                    .map_err(|_| access_server::PolicyError::Denied)?;
                Ok(access_server::R3Decision {
                    granted: grant.granted_operations(),
                    scopes: request.core.scopes.clone(),
                    lifetime: 600,
                })
            },
        ),
        audit: audit.clone(),
    })
    .unwrap();
    let consent = Arc::new(Consent {
        order: Arc::new(Mutex::new(Vec::new())),
        core: AtomicUsize::new(0),
        documents: AtomicUsize::new(0),
        proposals: AtomicUsize::new(0),
        deny_proposal: Mutex::new(false),
    });
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        MemoryStore::default(),
        Box::new(ConsentGate(consent.clone())) as BoxedPolicy,
        Box::new(|| NOW) as BoxedClock,
        Box::new(|| "ps-token".into()) as BoxedTokenIds,
    )
    .unwrap()
    .with_federation(NativeAccess(Box::new(move |request: &Request<Vec<u8>>| {
        access.handle(request)
    })))
    .with_r3(R3IssuerConfig {
        registry: registry.clone(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(Documents {
            artifacts: Arc::new(Mutex::new(std::collections::BTreeMap::from([(
                CLASS_URI.to_owned(),
                CLASS.to_vec(),
            )]))),
            order: Arc::new(Mutex::new(Vec::new())),
            status: Arc::new(Mutex::new(200)),
            fail: Arc::new(Mutex::new(false)),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(R3Gate(consent.clone())) as _,
        audit: Arc::new(NoAudit),
    })
    .unwrap();
    let post = |path: &str, body: Value| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}{path}"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap();
        holder.sign(&mut request, NOW).unwrap();
        server.handle(&request)
    };
    let person = post("/person", json!({"resource": RESOURCE}));
    let person_token = serde_json::from_slice::<Value>(person.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let person_jti = aauth_rust_core::PersonToken::parse(&person_token)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    let (resource_token, reference) = mint_resource_token(
        &registry,
        &SigningKey::from_seed([4; 32]),
        "resource-key",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: ACCESS.into(),
            ps: PS.into(),
            sub: "person-1".into(),
            jti: "resource-class".into(),
            presented_jti: person_jti.clone(),
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
        },
        CLASS_URI,
        CLASS,
    )
    .unwrap();
    let exchange = || {
        post(
            "/token",
            json!({"resource_token": resource_token, "presented_token": person_token}),
        )
    };

    // The access server signs the class grant from the bytes it fetched itself.
    let granted = exchange();
    assert_eq!(
        granted.status(),
        200,
        "{}",
        String::from_utf8_lossy(granted.body())
    );
    let delivered = serde_json::from_slice::<Value>(granted.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = aauth_rust_core::AuthToken::parse(&delivered)
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    let claims = token.claims();
    assert_eq!((claims.iss.as_str(), claims.ps.as_str()), (ACCESS, PS));
    assert_eq!(claims.scope.as_deref(), Some("records.read"));
    assert_eq!(claims.extra["r3_uri"], CLASS_URI);
    assert_eq!(claims.extra["r3_s256"], reference.digest());
    assert_eq!(
        claims.extra["r3_granted"],
        serde_json::from_slice::<Value>(READ).unwrap()
    );
    assert!(!claims.extra.contains_key("r3_per_call"));
    let signer = signers.lock().unwrap()[0].clone();
    assert!(
        signer.contains(r#"id="https://as.example""#)
            && signer.contains(r#"dwk="aauth-access.json""#),
        "{signer}"
    );
    {
        let records = audit.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.auth_token_issuer, ACCESS);
        assert_eq!(record.auth_token_jti, claims.jti);
        assert_eq!(record.r3_reference, reference);
        assert_eq!(record.person_server, PS);
        assert_eq!(record.presented_jti, person_jti);
        assert_eq!(record.agent, "aauth:Caller@ap.example");
        assert_eq!(record.parent_agent, None);
    }

    // Bytes served to the access server that do not hash to `r3_s256` refuse
    // the Resource token. Nothing is signed or recorded.
    *served.lock().unwrap() = CLASS.iter().copied().chain(*b" ").collect();
    let refused = exchange();
    assert_eq!(refused.status(), 400);
    let body = serde_json::from_slice::<Value>(refused.body()).unwrap();
    assert_eq!(body["error"], "invalid_resource_token");
    assert!(body.get("auth_token").is_none());
    assert_eq!(signers.lock().unwrap().len(), 2);
    assert_eq!(audit.0.lock().unwrap().len(), 1);
}
