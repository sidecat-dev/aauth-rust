//! Direct three-party R3 issuance: the Person Server is the issuer. It fetches
//! `r3_uri`, rejects bytes whose digest differs from `r3_s256`, and commits the
//! R3 audit entry in the same store write as the token issuance.

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonToken, ResourceClaims, TokenError,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Binding, BoxedClock, BoxedTokenIds, Config, Grant,
    MemoryStore, Person, PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest,
    R3Decision, R3IssuerConfig, R3Policy, Store, StoreError, TokenKind, TokenRecord,
    TokenReference,
};
use aauth_rust_r3::{
    FetchBody, FetchLimits, FetchResponse, FetchTransport, IssuanceError, IssuanceRecord,
    IssuanceStore, digest, mint_resource_token, standard_registry,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

const NOW: i64 = 1_000;
const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";
const CLASS: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.delete"}]}"#;
const READ: &[u8] =
    br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}"#;
const CLASS_URI: &str = "https://resource.example/r3/class";

type Steps = Arc<Mutex<Vec<&'static str>>>;

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed: [u8; 32] = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap-key") => [1; 32],
            (RESOURCE, "aauth-resource.json", "resource-key") => [4; 32],
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

/// Serves `served` at `CLASS_URI`, whatever the Resource token's digest says.
struct Documents {
    served: Arc<Mutex<Vec<u8>>>,
    steps: Steps,
}
impl FetchTransport for Documents {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> io::Result<FetchResponse> {
        assert_eq!(request.uri().to_string(), CLASS_URI);
        self.steps.lock().unwrap().push("fetch");
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json; charset=utf-8")
            .body(Box::new(Body {
                bytes: self.served.lock().unwrap().clone(),
                offset: 0,
            }) as Box<dyn FetchBody>)
            .unwrap())
    }
}

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "person-1".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

/// Grants `records.read` and records the reference and operations it judged.
struct Consent {
    steps: Steps,
    judged: Arc<Mutex<Vec<(String, usize)>>>,
}
impl R3Policy for Consent {
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        self.steps.lock().unwrap().push("consent");
        let operations = request.document.operation_set().operations().unwrap().len();
        self.judged
            .lock()
            .unwrap()
            .push((request.reference.digest().to_owned(), operations));
        let registry = standard_registry().unwrap();
        let grant = registry.parse_grant(READ, request.document).unwrap();
        Ok(R3Decision {
            granted: grant.granted_operations(),
            per_call: None,
            scopes: vec!["records.read".into()],
            lifetime: 600,
        })
    }
}

/// The host audit log. It may be told to fail.
#[derive(Default)]
struct AuditLog {
    records: Mutex<Vec<IssuanceRecord>>,
    fail: AtomicBool,
    steps: Steps,
}
impl IssuanceStore for AuditLog {
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError> {
        self.steps.lock().unwrap().push("audit-log");
        if self.fail.load(Ordering::SeqCst) {
            return Err(IssuanceError::Store("audit log unavailable".into()));
        }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// Memory store whose Auth issuance commit can be told to fail.
#[derive(Clone)]
struct Gated {
    inner: MemoryStore,
    fail_auth: Arc<AtomicBool>,
    steps: Steps,
}
impl Store for Gated {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.inner.binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.inner.token(reference)
    }
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError> {
        if record.kind == TokenKind::Auth {
            self.steps.lock().unwrap().push("commit");
            if self.fail_auth.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable);
            }
        }
        self.inner.commit(record, establish_binding)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        self.inner.revoke_binding(issuer, agent)
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        self.inner.retained()
    }
}

struct Fixture {
    server: PersonServer<Keys, Gated, Host, BoxedClock, BoxedTokenIds>,
    store: Gated,
    served: Arc<Mutex<Vec<u8>>>,
    audit: Arc<AuditLog>,
    steps: Steps,
    judged: Arc<Mutex<Vec<(String, usize)>>>,
    agent: Agent,
    person: String,
}

fn fixture() -> Fixture {
    let steps = Steps::default();
    let store = Gated {
        inner: MemoryStore::default(),
        fail_auth: Arc::new(AtomicBool::new(false)),
        steps: steps.clone(),
    };
    let served = Arc::new(Mutex::new(CLASS.to_vec()));
    let audit = Arc::new(AuditLog {
        steps: steps.clone(),
        ..AuditLog::default()
    });
    let judged = Arc::new(Mutex::new(Vec::new()));
    let ids = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        store.clone(),
        Host,
        Box::new(|| NOW) as BoxedClock,
        Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
    )
    .unwrap()
    .with_r3(R3IssuerConfig {
        registry: standard_registry().unwrap(),
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(Documents {
            served: served.clone(),
            steps: steps.clone(),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(Consent {
            steps: steps.clone(),
            judged: judged.clone(),
        }),
        audit: audit.clone(),
    })
    .unwrap();
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
        jti: "agent-1".into(),
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
    let agent = Agent::new(key, token).unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"resource": RESOURCE})).unwrap())
        .unwrap();
    agent.sign(&mut request, NOW).unwrap();
    let response = server.handle(&request);
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let person = serde_json::from_slice::<Value>(response.body()).unwrap()["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    Fixture {
        server,
        store,
        served,
        audit,
        steps,
        judged,
        agent,
        person,
    }
}

impl Fixture {
    /// A three-party R3 Resource token for the class document, then `/token`.
    fn exchange(&self, jti: &str) -> Response<Vec<u8>> {
        let claims = ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            ps: PS.into(),
            sub: "person-1".into(),
            jti: jti.into(),
            presented_jti: PersonToken::parse(&self.person)
                .unwrap()
                .unverified_claims()
                .jti
                .clone(),
            agent_jkt: self.agent.public_jwk().thumbprint().unwrap(),
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
        let (resource_token, _) = mint_resource_token(
            &standard_registry().unwrap(),
            &SigningKey::from_seed([4; 32]),
            "resource-key",
            &claims,
            CLASS_URI,
            CLASS,
        )
        .unwrap();
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{PS}/token"))
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&json!({
                    "resource_token": resource_token,
                    "presented_token": self.person,
                }))
                .unwrap(),
            )
            .unwrap();
        self.agent.sign(&mut request, NOW).unwrap();
        self.server.handle(&request)
    }

    fn auth_records(&self) -> Vec<TokenRecord> {
        self.store
            .retained()
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == TokenKind::Auth)
            .collect()
    }
}

fn error_of(response: &Response<Vec<u8>>) -> String {
    serde_json::from_slice::<Value>(response.body()).unwrap()["error"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

#[test]
fn direct_issuer_records_the_r3_audit_entry_with_the_token_issuance() {
    let f = fixture();
    let response = f.exchange("resource-1");
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let compact = serde_json::from_slice::<Value>(response.body()).unwrap()["auth_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = AuthToken::parse(&compact).unwrap();
    let claims = auth.unverified_claims();
    // Steps 2 and 3: the exact bytes at r3_uri, matched to r3_s256.
    // Step 5: policy judged that document's operations.
    assert_eq!(
        f.judged.lock().unwrap().as_slice(),
        [(digest(CLASS), 2_usize)]
    );
    // Step 6: the issued token carries the reference and the grant.
    assert_eq!(claims.extra["r3_uri"], CLASS_URI);
    assert_eq!(claims.extra["r3_s256"], json!(digest(CLASS)));
    assert_eq!(
        claims.extra["r3_granted"]["operations"],
        json!([{"tool": "records.read"}])
    );
    // Step 4 and Audit Log Integrity: the audit entry is in the issuance
    // record itself, committed before the host log copy and the release.
    assert_eq!(
        f.steps.lock().unwrap().as_slice(),
        ["fetch", "consent", "commit", "audit-log"]
    );
    let record = f
        .store
        .token(&TokenReference {
            issuer: PS.into(),
            jti: claims.jti.clone(),
        })
        .unwrap()
        .expect("issuance record");
    let entry = record.r3.as_ref().expect("R3 audit entry");
    assert_eq!(entry.r3_uri, CLASS_URI);
    assert_eq!(entry.r3_s256, digest(CLASS));
    assert_eq!(entry.vocabulary, "urn:aauth:vocabulary:mcp");
    assert_eq!(record.issued_at, claims.iat);
    assert_eq!(entry.person_server, PS);
    assert_eq!(entry.subject, "person-1");
    assert_eq!(entry.agent_jkt, f.agent.public_jwk().thumbprint().unwrap());
    assert_eq!(entry.agent, "aauth:Caller@ap.example");
    assert_eq!(entry.parent_agent, None);
    assert_eq!(
        entry.presented_jti,
        PersonToken::parse(&f.person)
            .unwrap()
            .unverified_claims()
            .jti
    );
    // The host log holds exactly the committed entry.
    let issuance = record.r3_issuance().unwrap().expect("R3 issuance");
    assert_eq!(issuance.auth_token_issuer, PS);
    assert_eq!(issuance.auth_token_jti, claims.jti);
    assert_eq!(issuance.resource, RESOURCE);
    assert_eq!(issuance.r3_reference.uri(), CLASS_URI);
    assert_eq!(issuance.issued_at, NOW);
    assert_eq!(f.audit.records.lock().unwrap().as_slice(), [issuance]);
}

#[test]
fn direct_issuer_rejects_a_document_whose_digest_differs() {
    let f = fixture();
    // The Resource token names CLASS; the fetch returns other valid bytes.
    *f.served.lock().unwrap() = READ.to_vec();
    let response = f.exchange("resource-mismatch");
    assert_eq!(response.status(), 400);
    assert_eq!(error_of(&response), "invalid_resource_token");
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert!(body.get("auth_token").is_none());
    // Fetched, then refused: no consent, no issuance, no audit entry.
    assert_eq!(f.steps.lock().unwrap().as_slice(), ["fetch"]);
    assert!(f.judged.lock().unwrap().is_empty());
    assert!(f.auth_records().is_empty());
    assert!(f.audit.records.lock().unwrap().is_empty());
    // The same bytes the digest names are then issued.
    *f.served.lock().unwrap() = CLASS.to_vec();
    assert_eq!(f.exchange("resource-match").status(), 200);
}

#[test]
fn failed_issuance_commit_writes_no_r3_audit_entry() {
    let f = fixture();
    f.store.fail_auth.store(true, Ordering::SeqCst);
    let withheld = f.exchange("resource-fail");
    assert_eq!(withheld.status(), 500);
    assert_eq!(error_of(&withheld), "server_error");
    // Neither the issuance nor its audit entry was written anywhere.
    assert_eq!(
        f.steps.lock().unwrap().as_slice(),
        ["fetch", "consent", "commit"]
    );
    assert!(f.auth_records().is_empty());
    assert!(f.audit.records.lock().unwrap().is_empty());
    f.store.fail_auth.store(false, Ordering::SeqCst);
    assert_eq!(f.exchange("resource-ok").status(), 200);
    let records = f.auth_records();
    assert_eq!(records.len(), 1);
    assert!(records[0].r3.is_some());
    assert_eq!(f.audit.records.lock().unwrap().len(), 1);
}

#[test]
fn failed_host_audit_log_withholds_the_token() {
    let f = fixture();
    f.audit.fail.store(true, Ordering::SeqCst);
    let withheld = f.exchange("resource-log-fail");
    assert_eq!(withheld.status(), 500);
    let body: Value = serde_json::from_slice(withheld.body()).unwrap();
    assert!(body.get("auth_token").is_none());
    // The unreleased issuance still carries its own audit entry.
    let records = f.auth_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].r3.as_ref().unwrap().r3_s256, digest(CLASS));
}
