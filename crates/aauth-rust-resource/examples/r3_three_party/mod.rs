//! Real TLS immediate class R3: Rust Agent, Rust Person Server, Rust Resource.
//!
//! The Resource publishes identity at `records.example` and serves every R3
//! endpoint at its signed origin `api.records.example`. The Agent asks for two
//! operations, the PS fetches the literal document with its own `jwks_uri`
//! signature and grants one, and the Resource writes one receipt for the exact
//! signed body. Each refusal below is checked to leave no application effect.
//!
//! Host responsibilities shown explicitly, not provided by the libraries:
//! - Resource document custody: `FileCustody`, an example file store in a
//!   per-run directory. A production host supplies its own durable store.
//! - PS issuance store and R3 audit log: process memory (`MemoryStore`,
//!   `AuditLog`). They are volatile and do not satisfy the durable contracts.
//! - PS egress admission and HTTPS transport: one admitted origin and prefix,
//!   over the example TLS client with 3-second socket timeouts.
//! - PS consent: `HostConsent` is a fixed demonstration decision standing in
//!   for an authenticated person's choice. There is no consent UI here.
#[path = "../support/tls.rs"]
mod tls;

use aauth_rust_agent::{Agent, R3AgentError};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy,
    PolicyError, R3AuthorizationRequest, R3Decision, R3IssuerConfig,
};
use aauth_rust_r3::{
    DefinitionRegistry, Display, FetchBody, FetchLimits, FetchResponse, FetchTransport,
    GrantedOperations, IssuanceError, IssuanceRecord, IssuanceStore, McpCodec, Operation,
    OperationSet, Reference, Registry, ToolsListPage, ToolsListSnapshot, digest, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, PsAuthorizationConfig, PsAuthorizationResource, R3Config, R3DocumentRecord,
    R3DocumentStore, R3HostError, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
/// Published Resource identity: JWT `iss`/`aud`, metadata and JWKS.
const RECORDS: &str = "https://records.example";
/// Signed origin: `/authorize`, `/r3/…` and the protected routes.
const API: &str = "https://api.records.example";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.export","inputSchema":{"type":"object"}}]}"#;
const READ_BODY: &[u8] = br#"{"record":"r-1"}"#;

/// Observable results, asserted by `tests/r3_three_party_tls.rs`.
#[derive(Debug)]
pub struct Transcript {
    pub authorization_endpoint: String,
    pub r3_uri_at_signed_origin: bool,
    pub documents_served: usize,
    pub granted: Vec<String>,
    pub authorized_status: u16,
    pub receipts: usize,
    pub receipt_matches_signed_body: bool,
    pub audit_records: usize,
    pub not_granted_status: u16,
    pub tampered_status: u16,
    pub wrong_holder_status: u16,
    pub agent_fetch_status: u16,
    pub unsigned_fetch_status: u16,
    pub substituted_reference_refused: bool,
    pub unknown_operation_status: u16,
    pub widened_grant_status: u16,
    pub fetch_refused_status: u16,
    pub resource_store_failure_status: u16,
    pub audit_failure_status: u16,
    pub untrusted_tls_refused: bool,
}

// Only this demonstration's explicitly admitted issuers are inserted.
#[derive(Clone, Default)]
struct Trust(Arc<RwLock<BTreeMap<(String, String), TrustedIssuerKeys>>>);
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
impl Trust {
    fn discover(&self, server: &TlsServer, issuer: &str, dwk: &str) -> Result<()> {
        let metadata = server.send(&get(&format!("{issuer}/.well-known/{dwk}"))?)?;
        if metadata.status() != 200 {
            return Err("metadata discovery failed".into());
        }
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = server.send(&get(&uri)?)?;
        if jwks.status() != 200 {
            return Err("JWKS discovery failed".into());
        }
        let snapshot =
            TrustedIssuerKeys::from_documents(issuer, dwk, metadata.body(), jwks.body())?;
        self.0
            .write()
            .map_err(|_| "trust snapshot lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs() as i64
}
fn get(uri: &str) -> Result<Request<Vec<u8>>> {
    Ok(Request::builder().uri(uri).body(Vec::new())?)
}
fn json_response(status: u16, value: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .unwrap()
}
fn json_document(bytes: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .header("content-type", "application/json")
        .body(bytes)
        .unwrap()
}
fn signed(agent: &Agent, uri: &str, body: &[u8]) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.to_vec())?;
    agent.sign(&mut request, now())?;
    Ok(request)
}
fn token_from(response: Response<Vec<u8>>, member: &str) -> Result<String> {
    if response.status() != 200 {
        return Err(format!("protocol operation refused with HTTP {}", response.status()).into());
    }
    let value: Value = serde_json::from_slice(response.body())?;
    Ok(value
        .get(member)
        .and_then(Value::as_str)
        .ok_or("successful response omitted token")?
        .to_owned())
}
fn mcp_operations(tools: &[&str]) -> Result<OperationSet> {
    let operations: Vec<Value> = tools.iter().map(|tool| json!({ "tool": tool })).collect();
    let envelope = json!({ "vocabulary": MCP, "operations": operations });
    Ok(standard_registry()?.parse_operation_set(&serde_json::to_vec(&envelope)?)?)
}
fn mcp(tool: &str) -> std::result::Result<Operation, R3HostError> {
    let vocabulary = McpCodec::vocabulary().map_err(|e| R3HostError::new(e.to_string()))?;
    Operation::new(&vocabulary, format!(r#"{{"tool":"{tool}"}}"#).as_bytes())
        .map_err(|e| R3HostError::new(e.to_string()))
}
fn enrolled(provider: &AgentProvider, subject: &str, jti: &str) -> Result<Agent> {
    let key = SigningKey::generate();
    let issued = now();
    let token = provider.issue(&AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: subject.into(),
        jti: jti.into(),
        iat: issued,
        exp: issued + 1800,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}

// ---- Resource host: document custody -------------------------------------

/// Example file custody: one exact record per URI, never overwritten. Each
/// commit writes a private temporary file, syncs it, renames it into place
/// and (on Unix) syncs the directory. Durability is the host filesystem's.
struct FileCustody {
    root: PathBuf,
    serial: Mutex<()>,
    fail_commit: Arc<AtomicBool>,
}
impl Drop for FileCustody {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn unavailable(error: impl ToString) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new(error.to_string()))
}
fn encode(r: &R3DocumentRecord) -> Vec<u8> {
    json!({
        "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
        "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
        "auth_token_issuer_document": r.auth_token_issuer_document,
        "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
        "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
        "tenant": r.tenant, "account": r.account, "scope": r.scope,
        "issued_at": r.issued_at, "expires_at": r.expires_at,
    })
    .to_string()
    .into_bytes()
}
fn decode(bytes: &[u8]) -> Result<R3DocumentRecord> {
    let v: Value = serde_json::from_slice(bytes)?;
    let text = |name: &str| -> Result<String> {
        Ok(v.get(name)
            .and_then(Value::as_str)
            .ok_or("missing stored string")?
            .to_owned())
    };
    let optional = |name: &str| v.get(name).and_then(Value::as_str).map(str::to_owned);
    let number = |name: &str| -> Result<i64> {
        Ok(v.get(name)
            .and_then(Value::as_i64)
            .ok_or("missing stored integer")?)
    };
    Ok(R3DocumentRecord {
        reference: Reference::new(text("uri")?, text("digest")?)?,
        exact_json: serde_json::from_value(v["exact_json"].clone())?,
        person_server: text("person_server")?,
        auth_token_issuer: text("auth_token_issuer")?,
        auth_token_issuer_document: text("auth_token_issuer_document")?,
        resource_token_jti: text("resource_token_jti")?,
        resource_token: text("resource_token")?,
        presented_jti: text("presented_jti")?,
        subject: text("subject")?,
        agent_jkt: text("agent_jkt")?,
        tenant: optional("tenant"),
        account: optional("account"),
        scope: optional("scope"),
        issued_at: number("issued_at")?,
        expires_at: number("expires_at")?,
    })
}
impl R3DocumentStore for FileCustody {
    fn commit(&self, record: &R3DocumentRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(unavailable("injected commit failure"));
        }
        let path = self.root.join(format!(
            "{}.json",
            digest(record.reference.uri().as_bytes())
        ));
        let bytes = encode(record);
        match fs::read(&path) {
            Ok(existing) if existing == bytes => return Ok(()),
            Ok(_) => return Err(R3StoreError::Conflict),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(unavailable(error)),
        }
        let pending = self.root.join("pending.tmp");
        {
            use std::io::Write;
            let mut file = fs::File::create(&pending).map_err(unavailable)?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(unavailable)?;
        }
        fs::rename(&pending, &path).map_err(unavailable)?;
        #[cfg(unix)]
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(unavailable)?;
        Ok(())
    }
    fn load(&self, uri: &str) -> std::result::Result<Option<R3DocumentRecord>, R3StoreError> {
        match fs::read(self.root.join(format!("{}.json", digest(uri.as_bytes())))) {
            Ok(bytes) => {
                let record = decode(&bytes).map_err(unavailable)?;
                if record.reference.uri() != uri {
                    return Err(unavailable("stored key does not name this URI"));
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }
}

// ---- Person Server host: consent, audit, egress and transport ------------

struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        if request.agent.claims().sub != "aauth:analyst@ap.example" || request.resource != RECORDS {
            return Err(PolicyError::Denied);
        }
        Ok(Person {
            id: "host-internal-person".into(),
            subject: "records-pairwise-person".into(),
            tenant: None,
        })
    }
    /// Core-scope exchanges are not offered by this demonstration.
    fn authorize(&self, _: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

/// Fixed demonstration consent: read only, never export, for this Resource.
struct HostConsent {
    widen: Arc<AtomicBool>,
}
impl HostConsent {
    fn decide(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> std::result::Result<R3Decision, PolicyError> {
        let unavailable = |_| PolicyError::Unavailable;
        if request.core.resource.claims().iss != RECORDS
            || request.core.agent.claims().sub != "aauth:analyst@ap.example"
        {
            return Err(PolicyError::Denied);
        }
        let read = mcp("records.read").map_err(unavailable)?;
        let wanted =
            OperationSet::new(std::slice::from_ref(&read)).map_err(|_| PolicyError::Unavailable)?;
        if !wanted
            .is_subset_of(&request.document.operation_set())
            .map_err(|_| PolicyError::Unavailable)?
        {
            return Err(PolicyError::Denied);
        }
        let mut granted = vec![read];
        if self.widen.load(Ordering::SeqCst) {
            // A host bug: more than the document. The PS must refuse to issue it.
            granted.push(mcp("records.purge").map_err(unavailable)?);
        }
        let vocabulary = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
        Ok(R3Decision {
            granted: GrantedOperations::new(&vocabulary, &granted)
                .map_err(|_| PolicyError::Unavailable)?,
            per_call: None,
            scopes: Vec::new(),
            lifetime: 600,
        })
    }
}

/// Volatile R3 audit log. A production host commits durably and confidentially.
#[derive(Default)]
struct AuditLog {
    records: Mutex<Vec<IssuanceRecord>>,
    fail: AtomicBool,
}
impl IssuanceStore for AuditLog {
    fn commit(&self, record: &IssuanceRecord) -> std::result::Result<(), IssuanceError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(IssuanceError::Store("injected audit failure".into()));
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| IssuanceError::Store("audit lock poisoned".into()))?;
        let same_key = records.iter().find(|existing| {
            existing.auth_token_issuer == record.auth_token_issuer
                && existing.auth_token_jti == record.auth_token_jti
        });
        match same_key {
            Some(existing) if existing == record => Ok(()),
            Some(_) => Err(IssuanceError::Conflict),
            None => {
                records.push(record.clone());
                Ok(())
            }
        }
    }
}

/// Example fetch transport: one buffered TLS exchange with the admitted origin.
struct TlsFetch(Arc<TlsServer>);
struct Buffered(Vec<u8>, usize);
impl FetchBody for Buffered {
    fn read(&mut self, output: &mut [u8], deadline: Instant) -> io::Result<usize> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let count = (self.0.len() - self.1).min(output.len());
        output[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
        self.1 += count;
        Ok(count)
    }
}
impl FetchTransport for TlsFetch {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let response = self
            .0
            .send(&request)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

/// One `/authorize` then `/token` attempt; returns the PS status.
fn exchange_status(
    agent: &Agent,
    api: &TlsServer,
    ps: &TlsServer,
    endpoint: &str,
    person: &str,
    trust: &Trust,
) -> Result<u16> {
    let operations = mcp_operations(&["records.read", "records.export"])?;
    let resource_token = agent.r3_authorize(
        |request| api.send(&request),
        endpoint,
        person,
        &operations,
        None,
        now(),
    )?;
    agent.verify_r3_resource_token(&resource_token, RECORDS, PS, person, None, trust, now())?;
    let body = json!({"resource_token": resource_token, "presented_token": person});
    let response = ps.send(&signed(
        agent,
        &format!("{PS}/token"),
        &serde_json::to_vec(&body)?,
    )?)?;
    Ok(response.status().as_u16())
}

pub fn run() -> Result<Transcript> {
    let trust = Trust::default();
    let registry: Registry = standard_registry()?;

    let provider = Arc::new(AgentProvider::new(AP, "ap-1", SigningKey::generate())?);
    let agent = enrolled(&provider, "aauth:analyst@ap.example", "agent-1")?;
    let serving = provider.clone();
    let ap_tls = TlsServer::start("ap.example", move |request| match request.uri().path() {
        "/.well-known/aauth-agent.json" => json_document(serving.metadata().unwrap()),
        "/.well-known/jwks.json" => json_document(serving.jwks().unwrap()),
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, AP, "aauth-agent.json")?;

    // Resource: identity at RECORDS, endpoints at the API signed origin.
    let custody_root = std::env::temp_dir().join(format!(
        "aauth-r3-example-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&custody_root)?;
    let fail_commit = Arc::new(AtomicBool::new(false));
    let resource = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: RECORDS.into(),
                signed_origin: API.into(),
                kid: "records-1".into(),
                signing_key: SigningKey::generate(),
                scopes: vec!["records.read".into()],
            },
            trust.clone(),
            |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| token.claims().ps == PS,
        )?
        .with_authorization_endpoint()
        .with_r3(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{API}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )?,
                display: Some(Box::new(|_: &OperationSet| {
                    Display::new(
                        "Read and export your records",
                        Some("Exports leave this service"),
                        Some("Record contents"),
                        Some("Exported copies cannot be recalled"),
                    )
                    .map_err(|e| R3HostError::new(e.to_string()))
                })),
            }],
            documents: Arc::new(FileCustody {
                root: custody_root,
                serial: Mutex::new(()),
                fail_commit: fail_commit.clone(),
            }),
            operation_for_request: Box::new(|request: &Request<Vec<u8>>| {
                match request.uri().path() {
                    "/records/read" => mcp("records.read").map(Some),
                    "/records/export" => mcp("records.export").map(Some),
                    _ => Ok(None),
                }
            }),
            require_core_scope: false,
        })?,
    );
    let identity = resource.clone();
    let records_tls = TlsServer::start("records.example", move |request| {
        match request.uri().path() {
            "/.well-known/aauth-resource.json" => json_document(identity.metadata().unwrap()),
            "/.well-known/jwks.json" => json_document(identity.jwks().unwrap()),
            _ => json_response(404, json!({"error":"not_found"})),
        }
    })?;
    let receipts: Arc<Mutex<Vec<Value>>> = Arc::default();
    let written = receipts.clone();
    let served = Arc::new(AtomicUsize::new(0));
    let serving_documents = served.clone();
    let ids = AtomicUsize::new(0);
    let api = resource.clone();
    let api_tls = Arc::new(TlsServer::start("api.records.example", move |request| {
        let jti = format!("records-{}", ids.fetch_add(1, Ordering::SeqCst));
        let path = request.uri().path().to_owned();
        match path.as_str() {
            "/mcp" => json_document(TOOLS.to_vec()),
            "/authorize" => api
                .authorize_endpoint(&request, now(), &jti)
                .into_response(),
            p if p.starts_with("/r3/") => {
                let response = api.r3_document(&request, now());
                if response.status() == 200 {
                    serving_documents.fetch_add(1, Ordering::SeqCst);
                }
                response
            }
            "/records/read" | "/records/export" => match api.authorize(&request, now(), &jti) {
                AuthDecision::Granted(admitted) => {
                    let Some(grant) = admitted.r3_grant() else {
                        return json_response(403, json!({"error":"access_denied"}));
                    };
                    let receipt = json!({
                        "path": path,
                        "body_s256": digest(request.body()),
                        "subject": admitted.token().claims().sub,
                        "operation": String::from_utf8_lossy(&grant.operation().json().unwrap_or_default()),
                        "r3_uri": grant.reference().uri(),
                    });
                    written.lock().unwrap().push(receipt.clone());
                    json_response(200, receipt)
                }
                other => other.into_response(),
            },
            _ => json_response(404, json!({"error":"not_found"})),
        }
    })?);
    trust.discover(&records_tls, RECORDS, "aauth-resource.json")?;

    // Person Server with opt-in class R3.
    let open_egress = Arc::new(AtomicBool::new(true));
    let admitting = open_egress.clone();
    let widen = Arc::new(AtomicBool::new(false));
    let consent = HostConsent {
        widen: widen.clone(),
    };
    let audit = Arc::new(AuditLog::default());
    let token_ids = AtomicUsize::new(0);
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::generate()),
        trust.clone(),
        MemoryStore::default(),
        HostPolicy,
        now,
        move || format!("ps-{}", token_ids.fetch_add(1, Ordering::SeqCst)),
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(move |uri: &str, _deadline: Instant| -> io::Result<()> {
            if admitting.load(Ordering::SeqCst) && uri.starts_with(&format!("{API}/r3/c.")) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "egress admission refused",
                ))
            }
        }),
        transport: Box::new(TlsFetch(api_tls.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(move |request: &R3AuthorizationRequest<'_>| consent.decide(request)),
        audit: audit.clone() as Arc<dyn IssuanceStore>,
    })?;
    let ps_tls = TlsServer::start("ps.example", move |request| ps.handle(&request))?;
    trust.discover(&ps_tls, PS, "aauth-person.json")?;
    let untrusted_tls_refused = api_tls.refuses_untrusted_certificate();

    // Agent: Person token, metadata, signed r3_operations request.
    let person = token_from(
        ps_tls.send(&signed(
            &agent,
            &format!("{PS}/person"),
            &serde_json::to_vec(&json!({ "resource": RECORDS }))?,
        )?)?,
        "person_token",
    )?;
    let metadata: Value = serde_json::from_slice(
        records_tls
            .send(&get(&format!("{RECORDS}/.well-known/aauth-resource.json"))?)?
            .body(),
    )?;
    let endpoint = metadata["authorization_endpoint"]
        .as_str()
        .ok_or("metadata omitted authorization_endpoint")?
        .to_owned();
    if metadata["r3_vocabularies"][MCP].as_str() != Some(format!("{API}/mcp").as_str()) {
        return Err("metadata does not advertise the MCP definition".into());
    }
    let operations = mcp_operations(&["records.read", "records.export"])?;
    let resource_token = agent.r3_authorize(
        |request| api_tls.send(&request),
        &endpoint,
        &person,
        &operations,
        None,
        now(),
    )?;
    let verified_resource = agent.verify_r3_resource_token(
        &resource_token,
        RECORDS,
        PS,
        &person,
        None,
        &trust,
        now(),
    )?;
    let r3_uri = verified_resource.reference().uri().to_owned();

    // Agents are not entitled to the document, signed or not.
    let mut agent_fetch = get(&r3_uri)?;
    agent
        .with_token(person.clone())?
        .sign(&mut agent_fetch, now())?;
    let agent_fetch_status = api_tls.send(&agent_fetch)?.status().as_u16();
    let unsigned_fetch_status = api_tls.send(&get(&r3_uri)?)?.status().as_u16();

    // PS: literal fetch, consent to a narrower grant, audit, commit, release.
    let auth = token_from(
        ps_tls.send(&signed(
            &agent,
            &format!("{PS}/token"),
            &serde_json::to_vec(&json!({
                "resource_token": resource_token,
                "presented_token": person,
            }))?,
        )?)?,
        "auth_token",
    )?;
    let verified_auth = agent.verify_r3_auth_delivery(
        &auth,
        RECORDS,
        &verified_resource,
        &person,
        &registry,
        &trust,
        now(),
    )?;
    let granted: Vec<String> = verified_auth
        .operations()
        .granted_operations()
        .operations()?
        .iter()
        .map(|operation| {
            operation
                .json()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        })
        .collect::<std::result::Result<_, _>>()?;

    // A second, valid Resource token for the same request has another reference.
    let other_token = agent.r3_authorize(
        |request| api_tls.send(&request),
        &endpoint,
        &person,
        &operations,
        None,
        now(),
    )?;
    let other =
        agent.verify_r3_resource_token(&other_token, RECORDS, PS, &person, None, &trust, now())?;
    let substituted_reference_refused = matches!(
        agent.verify_r3_auth_delivery(&auth, RECORDS, &other, &person, &registry, &trust, now()),
        Err(R3AgentError::Context)
    );

    // Protected calls with the delivered grant.
    let holder = agent.with_token(auth.clone())?;
    let read = signed(&holder, &format!("{API}/records/read"), READ_BODY)?;
    let mut tampered = read.clone();
    *tampered.body_mut() = br#"{"record":"r-2"}"#.to_vec();
    let tampered_status = api_tls.send(&tampered)?.status().as_u16();
    let mut stolen = Request::builder()
        .method("POST")
        .uri(format!("{API}/records/read"))
        .header("content-type", "application/json")
        .body(READ_BODY.to_vec())?;
    sign_request(
        &mut stolen,
        &SigningKey::generate(),
        KeyMaterial::Jwt(auth.clone()),
        now(),
    )?;
    let wrong_holder_status = api_tls.send(&stolen)?.status().as_u16();
    let not_granted_status = api_tls
        .send(&signed(
            &holder,
            &format!("{API}/records/export"),
            READ_BODY,
        )?)?
        .status()
        .as_u16();
    let authorized = api_tls.send(&read)?;
    let authorized_status = authorized.status().as_u16();
    let receipt: Value = serde_json::from_slice(authorized.body())?;
    let receipt_matches_signed_body = receipt["body_s256"] == json!(digest(READ_BODY))
        && receipt["r3_uri"] == json!(r3_uri)
        && receipt["operation"] == json!(r#"{"tool":"records.read"}"#);

    // Refusals that must release nothing and change nothing.
    let unknown_operation_status = match agent.r3_authorize(
        |request| api_tls.send(&request),
        &endpoint,
        &person,
        &mcp_operations(&["records.purge"])?,
        None,
        now(),
    ) {
        Err(R3AgentError::Refused { status, .. }) => status,
        Ok(_) => 200,
        Err(error) => return Err(error.into()),
    };
    widen.store(true, Ordering::SeqCst);
    let widened_grant_status =
        exchange_status(&agent, &api_tls, &ps_tls, &endpoint, &person, &trust)?;
    widen.store(false, Ordering::SeqCst);
    open_egress.store(false, Ordering::SeqCst);
    let fetch_refused_status =
        exchange_status(&agent, &api_tls, &ps_tls, &endpoint, &person, &trust)?;
    open_egress.store(true, Ordering::SeqCst);
    audit.fail.store(true, Ordering::SeqCst);
    let audit_failure_status =
        exchange_status(&agent, &api_tls, &ps_tls, &endpoint, &person, &trust)?;
    audit.fail.store(false, Ordering::SeqCst);
    fail_commit.store(true, Ordering::SeqCst);
    let resource_store_failure_status = match agent.r3_authorize(
        |request| api_tls.send(&request),
        &endpoint,
        &person,
        &operations,
        None,
        now(),
    ) {
        Err(R3AgentError::Refused { status, .. }) => status,
        Ok(_) => 200,
        Err(error) => return Err(error.into()),
    };
    fail_commit.store(false, Ordering::SeqCst);

    let receipts = receipts.lock().map_err(|_| "receipt lock poisoned")?.len();
    let audit_records = audit
        .records
        .lock()
        .map_err(|_| "audit lock poisoned")?
        .len();
    Ok(Transcript {
        authorization_endpoint: endpoint,
        r3_uri_at_signed_origin: r3_uri.starts_with(&format!("{API}/r3/c.")),
        documents_served: served.load(Ordering::SeqCst),
        granted,
        authorized_status,
        receipts,
        receipt_matches_signed_body,
        audit_records,
        not_granted_status,
        tampered_status,
        wrong_holder_status,
        agent_fetch_status,
        unsigned_fetch_status,
        substituted_reference_refused,
        unknown_operation_status,
        widened_grant_status,
        fetch_refused_status,
        resource_store_failure_status,
        audit_failure_status,
        untrusted_tls_refused,
    })
}
