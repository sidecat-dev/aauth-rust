//! Real TLS per-call R3: Rust Agent, Rust Person Server, Rust Resource.
//!
//! The class grant serves `records.read` and leaves `records.delete` per call.
//! A delete is challenged with a proposal for that concrete record. The PS
//! fetches it, applies parameter-sensitive consent and issues a one-operation
//! token. The call then completes once, first by `401` retry and then, after
//! the Resource is recomposed from its files, by a `202` held invocation.
//! Every refusal is checked against explicit application-effect counters.
//!
//! Host responsibilities shown here, not provided by the libraries:
//! - Resource custody: `FileDocuments` and `FileCalls` in one per-run
//!   directory. Recomposing the Resource from that directory stands in for a
//!   process restart; durability is the host filesystem's.
//! - PS issuance store, R3 audit log and consent: process memory and a fixed
//!   demonstration decision. They are volatile; there is no consent UI.
//! - PS egress admission and HTTPS transport: one admitted origin and prefix.
#[path = "../support/tls.rs"]
mod tls;

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy,
    PolicyError, R3AuthorizationRequest, R3Decision, R3IssuerConfig, R3Policy, R3ProposalDecision,
    R3ProposalRequest,
};
use aauth_rust_r3::{
    DefinitionRegistry, Display, FetchBody, FetchLimits, FetchResponse, FetchTransport,
    GrantedOperations, IssuanceError, IssuanceRecord, IssuanceStore, McpCodec, Operation,
    OperationSet, Parameter, Parameters, PresentedParameter, ProposalDisplay, Reference, Registry,
    ToolsListPage, ToolsListSnapshot, digest, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthPolicy, PsAuthorizationConfig, PsAuthorizationResource, R3CallDescription, R3CallResult,
    R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord, R3DocumentStore, R3HeldRequest,
    R3HostError, R3PerCallConfig, R3ProposalRecord, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock, mpsc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const RECORDS: &str = "https://records.example";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}}]}"#;
const R1: &[u8] = br#"{"record":"r-1"}"#;
const R2: &[u8] = br#"{"record":"r-2"}"#;

/// Observable statuses and effect counts, asserted by `tests/r3_per_call_tls.rs`.
#[derive(Debug, Default)]
pub struct Transcript {
    pub read_status: u16,
    pub challenge_status: u16,
    pub proposal_operation: String,
    pub substituted_parameters_status: u16,
    pub retry_status: u16,
    pub replay_status: u16,
    pub replay_matches_first: bool,
    pub replay_after_restart_status: u16,
    pub denied_parameters_ps_status: u16,
    pub held_status: u16,
    pub held_location_at_signed_origin: bool,
    pub held_completion_status: u16,
    pub held_replay_status: u16,
    pub foreign_token_at_pending_status: u16,
    pub wrong_holder_status: u16,
    pub deletes: Vec<String>,
    pub reads: usize,
    pub audit_records: usize,
    pub held_policy_denied_status: u16,
    pub held_policy_effect_delta: usize,
    pub held_policy_claim_consumed: bool,
    pub revocation_status: u16,
    pub revoked_completion_status: u16,
    pub revoked_completion_error: String,
    pub revocation_effect_delta: usize,
    pub revocation_claim_consumed: bool,
    pub revocation_retry_status: u16,
    pub revocation_claim_unchanged: bool,
    pub revocation_result_retained: bool,
}

/// Adversarial admission paths exercised over the same real TLS roles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionCase {
    HeldPolicy,
    Revocation,
    ClaimRevocation,
}

#[derive(Default)]
struct AdmissionControl {
    deny_delete: AtomicBool,
    revocation: bool,
    barrier: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    claim_barrier: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}
impl AdmissionControl {
    fn admit(&self, token: &VerifiedAuthToken, request: &Request<Vec<u8>>) -> bool {
        let barrier = self.barrier.lock().unwrap().take();
        if let Some((entered, released)) = barrier {
            if entered.send(()).is_err() || released.recv_timeout(Duration::from_secs(2)).is_err() {
                return false;
            }
        }
        token.claims().ps == PS
            && !(self.deny_delete.load(Ordering::SeqCst)
                && request.method() == http::Method::DELETE
                && request.uri().path() == "/records/delete"
                && request.body() == R1)
    }
}

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
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = server.send(&get(&uri)?)?;
        let snapshot =
            TrustedIssuerKeys::from_documents(issuer, dwk, metadata.body(), jwks.body())?;
        self.0
            .write()
            .map_err(|_| "trust lock poisoned")?
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
fn post(agent: &Agent, uri: &str, body: &[u8]) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.to_vec())?;
    agent.sign(&mut request, now())?;
    Ok(request)
}
fn member(response: &Response<Vec<u8>>, name: &str) -> Option<String> {
    serde_json::from_slice::<Value>(response.body())
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}
fn challenge(response: &Response<Vec<u8>>) -> Result<String> {
    match aauth_rust_agent::Requirement::from_headers(response.headers())? {
        Some(aauth_rust_agent::Requirement::AuthToken { resource_token }) => Ok(resource_token),
        _ => Err("expected an auth-token requirement".into()),
    }
}
fn mcp(tool: &str) -> std::result::Result<Operation, R3HostError> {
    let vocabulary = McpCodec::vocabulary().map_err(|e| R3HostError::new(e.to_string()))?;
    Operation::new(&vocabulary, format!(r#"{{"tool":"{tool}"}}"#).as_bytes())
        .map_err(|e| R3HostError::new(e.to_string()))
}

// ---- Resource custody: exact class documents and per-call proposals -------

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let pending = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&pending, path)
}
fn unavailable(error: impl ToString) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new(error.to_string()))
}
fn text(v: &Value, name: &str) -> Result<String> {
    Ok(v.get(name)
        .and_then(Value::as_str)
        .ok_or("missing stored string")?
        .to_owned())
}
fn optional(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(str::to_owned)
}
fn number(v: &Value, name: &str) -> Result<i64> {
    Ok(v.get(name)
        .and_then(Value::as_i64)
        .ok_or("missing stored integer")?)
}

/// Exact class documents, one file per URI, never overwritten.
struct FileDocuments(PathBuf, Mutex<()>);
impl R3DocumentStore for FileDocuments {
    fn commit(&self, r: &R3DocumentRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self.0.join(format!("c-{}.json", digest(r.reference.uri().as_bytes())));
        let bytes = json!({
            "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
            "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
            "auth_token_issuer_document": r.auth_token_issuer_document,
            "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
            "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
            "tenant": r.tenant, "account": r.account, "scope": r.scope,
            "issued_at": r.issued_at, "expires_at": r.expires_at,
        })
        .to_string()
        .into_bytes();
        match write_new(&path, &bytes).map_err(unavailable)? {
            true => Ok(()),
            false if fs::read(&path).map_err(unavailable)? == bytes => Ok(()),
            false => Err(R3StoreError::Conflict),
        }
    }
    fn load(&self, uri: &str) -> std::result::Result<Option<R3DocumentRecord>, R3StoreError> {
        let path = self.0.join(format!("c-{}.json", digest(uri.as_bytes())));
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        let decode = || -> Result<R3DocumentRecord> {
            let v: Value = serde_json::from_slice(&bytes)?;
            Ok(R3DocumentRecord {
                reference: Reference::new(text(&v, "uri")?, text(&v, "digest")?)?,
                exact_json: serde_json::from_value(v["exact_json"].clone())?,
                person_server: text(&v, "person_server")?,
                auth_token_issuer: text(&v, "auth_token_issuer")?,
                auth_token_issuer_document: text(&v, "auth_token_issuer_document")?,
                resource_token_jti: text(&v, "resource_token_jti")?,
                resource_token: text(&v, "resource_token")?,
                presented_jti: text(&v, "presented_jti")?,
                subject: text(&v, "subject")?,
                agent_jkt: text(&v, "agent_jkt")?,
                tenant: optional(&v, "tenant"),
                account: optional(&v, "account"),
                scope: optional(&v, "scope"),
                issued_at: number(&v, "issued_at")?,
                expires_at: number(&v, "expires_at")?,
            })
        };
        decode().map(Some).map_err(unavailable)
    }
}

/// Proposals, pending ids, claims and retained results. Create-only records;
/// one claim file per proposal, bound once and never re-opened for execution.
struct FileCalls(PathBuf, Mutex<()>, Arc<AdmissionControl>);
impl FileCalls {
    fn record_path(&self, uri: &str) -> PathBuf {
        self.0.join(format!("p-{}.json", digest(uri.as_bytes())))
    }
    fn claim_path(&self, uri: &str) -> PathBuf {
        self.0.join(format!("claim-{}.json", digest(uri.as_bytes())))
    }
    fn decode(bytes: &[u8]) -> Result<R3ProposalRecord> {
        let v: Value = serde_json::from_slice(bytes)?;
        let class = &v["class_reference"];
        let held = match v.get("held") {
            Some(held) if !held.is_null() => Some(R3HeldRequest {
                pending_id: text(held, "pending_id")?,
                method: text(held, "method")?,
                uri: text(held, "uri")?,
                headers: serde_json::from_value(held["headers"].clone())?,
                body: serde_json::from_value(held["body"].clone())?,
            }),
            _ => None,
        };
        Ok(R3ProposalRecord {
            reference: Reference::new(text(&v, "uri")?, text(&v, "digest")?)?,
            exact_json: serde_json::from_value(v["exact_json"].clone())?,
            person_server: text(&v, "person_server")?,
            auth_token_issuer: text(&v, "auth_token_issuer")?,
            resource_token_jti: text(&v, "resource_token_jti")?,
            resource_token: text(&v, "resource_token")?,
            class_reference: Reference::new(text(class, "uri")?, text(class, "digest")?)?,
            presented_jti: text(&v, "presented_jti")?,
            subject: text(&v, "subject")?,
            agent_jkt: text(&v, "agent_jkt")?,
            tenant: optional(&v, "tenant"),
            account: optional(&v, "account"),
            scope: optional(&v, "scope"),
            issued_at: number(&v, "issued_at")?,
            expires_at: number(&v, "expires_at")?,
            held,
        })
    }
    fn result(v: &Value) -> Result<R3CallResult> {
        Ok(R3CallResult {
            status: u16::try_from(number(v, "status")?)?,
            content_type: optional(v, "content_type"),
            body: serde_json::from_value(v["body"].clone())?,
        })
    }
}
impl R3CallStore for FileCalls {
    fn commit(&self, r: &R3ProposalRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let held = r.held.as_ref().map(|held| {
            json!({"pending_id": held.pending_id, "method": held.method, "uri": held.uri,
                   "headers": held.headers, "body": held.body})
        });
        let bytes = json!({
            "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
            "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
            "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
            "class_reference": {"uri": r.class_reference.uri(), "digest": r.class_reference.digest()},
            "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
            "tenant": r.tenant, "account": r.account, "scope": r.scope,
            "issued_at": r.issued_at, "expires_at": r.expires_at, "held": held,
        })
        .to_string()
        .into_bytes();
        if let Some(held) = &r.held {
            let index = self.0.join(format!("pending-{}", held.pending_id));
            if !write_new(&index, r.reference.uri().as_bytes()).map_err(unavailable)? {
                return Err(R3StoreError::Conflict);
            }
        }
        // Create-only, even for identical bytes: one record names one invocation.
        if !write_new(&self.record_path(r.reference.uri()), &bytes).map_err(unavailable)? {
            return Err(R3StoreError::Conflict);
        }
        #[cfg(unix)]
        fs::File::open(&self.0)
            .and_then(|directory| directory.sync_all())
            .map_err(unavailable)?;
        Ok(())
    }
    fn load(&self, uri: &str) -> std::result::Result<Option<R3ProposalRecord>, R3StoreError> {
        match fs::read(self.record_path(uri)) {
            Ok(bytes) => {
                let record = Self::decode(&bytes).map_err(unavailable)?;
                if record.reference.uri() != uri {
                    return Err(unavailable("stored key does not name this URI"));
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }
    fn load_pending(
        &self,
        pending_id: &str,
    ) -> std::result::Result<Option<R3ProposalRecord>, R3StoreError> {
        if pending_id.is_empty()
            || !pending_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Ok(None);
        }
        let uri = match fs::read(self.0.join(format!("pending-{pending_id}"))) {
            Ok(bytes) => String::from_utf8(bytes).map_err(unavailable)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        self.load(&uri)
    }
    fn claim(
        &self,
        uri: &str,
        token: &R3CallToken,
        now: i64,
    ) -> std::result::Result<R3Claim, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self.claim_path(uri);
        match fs::read(&path) {
            Ok(bytes) => {
                let v: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
                if v["compact_sha256"].as_str() != Some(token.compact_sha256.as_str()) {
                    return Ok(R3Claim::DifferentToken);
                }
                if v["result"].is_null() {
                    return Ok(R3Claim::Unfinished);
                }
                if now > number(&v, "retain_until").map_err(unavailable)? {
                    return Ok(R3Claim::Expired);
                }
                Ok(R3Claim::Replay(Self::result(&v["result"]).map_err(unavailable)?))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let fence = format!(
                    "{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(unavailable)?
                        .as_nanos()
                );
                let bytes = json!({"compact_sha256": token.compact_sha256, "jti": token.jti,
                                   "retain_until": token.retain_until, "fence": fence, "result": null})
                .to_string()
                .into_bytes();
                // Bound once: a lost race or an uncertain write never executes.
                if !write_new(&path, &bytes).map_err(unavailable)? {
                    return Ok(R3Claim::Unfinished);
                }
                // Optional control pauses after binding the claim, before the host
                // callback returns Execute. Revocation must suppress release without
                // rolling back that durable binding or dispatching the application.
                let barrier = self.2.claim_barrier.lock().unwrap().take();
                if let Some((entered, released)) = barrier {
                    entered.send(()).map_err(unavailable)?;
                    released.recv_timeout(Duration::from_secs(2)).map_err(unavailable)?;
                }
                Ok(R3Claim::Execute { fence })
            }
            Err(error) => Err(unavailable(error)),
        }
    }
    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> std::result::Result<R3CallResult, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self.claim_path(uri);
        let bytes = fs::read(&path).map_err(unavailable)?;
        let mut v: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if v["fence"].as_str() != Some(fence) || !v["result"].is_null() {
            return Err(R3StoreError::Conflict);
        }
        v["result"] = json!({"status": result.status, "content_type": result.content_type,
                             "body": result.body});
        replace(&path, v.to_string().as_bytes()).map_err(unavailable)?;
        Ok(result.clone())
    }
}

// ---- Person Server host: consent, audit, egress and transport -------------

struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        if request.agent.claims().sub != "aauth:clerk@ap.example" || request.resource != RECORDS {
            return Err(PolicyError::Denied);
        }
        Ok(Person {
            id: "host-internal-person".into(),
            subject: "records-pairwise-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

/// Demonstration consent: read is granted; delete is per call and approved
/// only for record `r-1`, after inspecting the proposal's parameters.
struct HostConsent;
impl R3Policy for HostConsent {
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> std::result::Result<R3Decision, PolicyError> {
        if request.core.resource.claims().iss != RECORDS {
            return Err(PolicyError::Denied);
        }
        let unavailable = |_| PolicyError::Unavailable;
        let vocabulary = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
        Ok(R3Decision {
            granted: GrantedOperations::new(&vocabulary, &[mcp("records.read").map_err(unavailable)?])
                .map_err(|_| PolicyError::Unavailable)?,
            per_call: Some(
                GrantedOperations::new(&vocabulary, &[mcp("records.delete").map_err(unavailable)?])
                    .map_err(|_| PolicyError::Unavailable)?,
            ),
            scopes: Vec::new(),
            lifetime: 600,
        })
    }
    fn authorize_proposal(
        &self,
        request: &R3ProposalRequest<'_>,
    ) -> std::result::Result<R3ProposalDecision, PolicyError> {
        let approved = request
            .proposal
            .parameters()
            .get("record")
            .and_then(|parameter| parameter.inline_json())
            .is_some_and(|value| value == br#""r-1""#);
        if !approved || request.core.resource.claims().iss != RECORDS {
            return Err(PolicyError::Denied);
        }
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime: 300,
        })
    }
}

#[derive(Default)]
struct AuditLog(Mutex<Vec<IssuanceRecord>>);
impl IssuanceStore for AuditLog {
    fn commit(&self, record: &IssuanceRecord) -> std::result::Result<(), IssuanceError> {
        let mut records = self
            .0
            .lock()
            .map_err(|_| IssuanceError::Store("audit lock poisoned".into()))?;
        if records.iter().any(|existing| {
            existing.auth_token_jti == record.auth_token_jti && existing != record
        }) {
            return Err(IssuanceError::Conflict);
        }
        records.push(record.clone());
        Ok(())
    }
}

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

// ---- Resource composition ---------------------------------------------------

type Resource = PsAuthorizationResource<Trust, BoxedAuthPolicy>;
fn record_parameter(request: &Request<Vec<u8>>) -> std::result::Result<Vec<u8>, R3HostError> {
    let value: Value = serde_json::from_slice(request.body())
        .map_err(|e| R3HostError::new(e.to_string()))?;
    let record = value
        .get("record")
        .ok_or_else(|| R3HostError::new("call names no record"))?;
    serde_json::to_vec(record).map_err(|e| R3HostError::new(e.to_string()))
}
/// One Resource instance over the shared custody directory.
fn compose(
    root: &Path,
    seed: [u8; 32],
    trust: &Trust,
    hold: bool,
    control: Arc<AdmissionControl>,
) -> Result<Resource> {
    let policy_control = control.clone();
    let resource = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: RECORDS.into(),
            signed_origin: RECORDS.into(),
            kid: "records-1".into(),
            signing_key: SigningKey::from_seed(seed),
            scopes: vec!["records.read".into()],
        },
        trust.clone(),
        Box::new(move |token: &VerifiedAuthToken, request: &Request<Vec<u8>>| {
            policy_control.admit(token, request)
        }) as BoxedAuthPolicy,
    )?
    .with_authorization_endpoint()
    .with_r3(R3Config {
        registry: standard_registry()?,
        definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
        vocabularies: vec![R3Vocabulary {
            definition: McpCodec::parse_definition(
                &format!("{RECORDS}/mcp"),
                &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
            )?,
            display: Some(Box::new(|_: &OperationSet| {
                Display::new("Read records; delete with per-call approval", None, None, None)
                    .map_err(|e| R3HostError::new(e.to_string()))
            })),
        }],
        documents: Arc::new(FileDocuments(root.to_path_buf(), Mutex::new(()))),
        operation_for_request: Box::new(|request: &Request<Vec<u8>>| match request.uri().path() {
            "/records/read" => mcp("records.read").map(Some),
            "/records/delete" => mcp("records.delete").map(Some),
            _ => Ok(None),
        }),
        require_core_scope: false,
    })?
    .with_r3_per_call(R3PerCallConfig {
        present: Box::new(|request: &Request<Vec<u8>>, _: &Operation| {
            let record = record_parameter(request)?;
            let presented = PresentedParameter::inline(&record)
                .map_err(|e| R3HostError::new(e.to_string()))?;
            Ok(BTreeMap::from([("record".to_owned(), presented)]))
        }),
        describe: Box::new(
            |_: &Operation, presented: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
                let value = presented
                    .get("record")
                    .and_then(PresentedParameter::inline_json)
                    .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                let parameters = Parameters::new([(
                    "record".to_owned(),
                    Parameter::inline(&value).map_err(|e| R3HostError::new(e.to_string()))?,
                )])
                .map_err(|e| R3HostError::new(e.to_string()))?;
                let shown = String::from_utf8_lossy(&value).into_owned();
                let display = ProposalDisplay::new(
                    &Display::new(
                        format!("Delete record {shown}"),
                        Some("The record is removed"),
                        None,
                        Some("Deletion cannot be undone"),
                    )
                    .map_err(|e| R3HostError::new(e.to_string()))?,
                    Some(&format!("## Action\nDelete a record\n\n## Details\nRecord {shown}")),
                )
                .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(R3CallDescription {
                    parameters,
                    display: Some(display),
                })
            },
        ),
        calls: Arc::new(FileCalls(root.to_path_buf(), Mutex::new(()), control.clone())),
        hold,
    })?;
    Ok(if control.revocation { resource.with_revocation() } else { resource })
}

/// The application: one effect per admitted call, recorded by the host.
struct Effects {
    reads: AtomicUsize,
    deletes: Mutex<Vec<String>>,
}
fn serve(resource: &Resource, effects: &Effects, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    let jti = format!(
        "rid-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = request.uri().path().to_owned();
    if path == "/.well-known/aauth-resource.json" {
        return json_response(200, serde_json::from_slice(&resource.metadata().unwrap()).unwrap());
    }
    if path == "/.well-known/jwks.json" {
        return json_response(200, serde_json::from_slice(&resource.jwks().unwrap()).unwrap());
    }
    if path == "/revoke" {
        return resource.revoke(&request, now());
    }
    if path == "/authorize" {
        return resource.authorize_endpoint(&request, now(), &jti).into_response();
    }
    if path.starts_with("/r3/") && !path.starts_with("/r3/pending/") {
        return resource.r3_document(&request, now());
    }
    match resource.authorize(&request, now(), &jti) {
        AuthDecision::Granted(admitted) => {
            let Some(grant) = admitted.r3_grant() else {
                return json_response(403, json!({"error":"access_denied"}));
            };
            // A held completion executes the original call, not the poll.
            let call = grant.held_request().unwrap_or(&request);
            let produced = match call.uri().path() {
                "/records/read" => {
                    effects.reads.fetch_add(1, Ordering::SeqCst);
                    json_response(200, json!({"read": true}))
                }
                "/records/delete" if grant.is_per_call() => match record_parameter(call) {
                    Ok(record) => {
                        let record = String::from_utf8_lossy(&record).into_owned();
                        effects.deletes.lock().unwrap().push(record.clone());
                        json_response(200, json!({"deleted": record}))
                    }
                    Err(_) => json_response(400, json!({"error":"invalid_request"})),
                },
                _ => json_response(403, json!({"error":"access_denied"})),
            };
            resource.r3_retain(grant, produced)
        }
        other => other.into_response(),
    }
}

/// Class Resource token, then the class grant.
fn class_grant(
    agent: &Agent,
    person: &str,
    api: &TlsServer,
    ps: &TlsServer,
    trust: &Trust,
    registry: &Registry,
) -> Result<String> {
    let operations = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.read"},{"tool":"records.delete"}]})
            .to_string()
            .as_bytes(),
    )?;
    let resource_token = agent.r3_authorize(
        |request| api.send(&request),
        &format!("{RECORDS}/authorize"),
        person,
        &operations,
        None,
        now(),
    )?;
    let verified =
        agent.verify_r3_resource_token(&resource_token, RECORDS, PS, person, None, trust, now())?;
    let body = json!({"resource_token": resource_token, "presented_token": person});
    let response = ps.send(&post(agent, &format!("{PS}/token"), body.to_string().as_bytes())?)?;
    let auth = member(&response, "auth_token").ok_or("class grant refused")?;
    agent.verify_r3_auth_delivery(&auth, RECORDS, &verified, person, registry, trust, now())?;
    Ok(auth)
}

/// The per-call challenge's PS exchange; returns the PS response.
fn approve(agent: &Agent, ps: &TlsServer, resource_token: &str, class: &str) -> Result<Response<Vec<u8>>> {
    let body = json!({"resource_token": resource_token, "presented_token": class});
    ps.send(&post(agent, &format!("{PS}/token"), body.to_string().as_bytes())?)
}

pub fn run() -> Result<Transcript> {
    run_case(None)
}

pub fn run_admission_case(case: AdmissionCase) -> Result<Transcript> {
    run_case(Some(case))
}

fn run_case(case: Option<AdmissionCase>) -> Result<Transcript> {
    let control = Arc::new(AdmissionControl {
        revocation: matches!(case, Some(AdmissionCase::Revocation | AdmissionCase::ClaimRevocation)),
        ..AdmissionControl::default()
    });
    let mut t = Transcript::default();
    let trust = Trust::default();
    let registry = standard_registry()?;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("aauth-r3-per-call-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&root)?;
    // Example-only identity seed: the recomposed Resource keeps its signing key.
    let mut seed = [7u8; 32];
    seed[..16].copy_from_slice(&nanos.to_le_bytes());

    let provider = Arc::new(AgentProvider::new(AP, "ap-1", SigningKey::generate())?);
    let agent_key = SigningKey::generate();
    let issued = now();
    let token = provider.issue(&AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:clerk@ap.example".into(),
        jti: "agent-1".into(),
        iat: issued,
        exp: issued + 1800,
        cnf: Confirmation {
            jwk: agent_key.public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let agent = Agent::new(agent_key, token)?;
    let serving = provider.clone();
    let ap_tls = TlsServer::start("ap.example", move |request| match request.uri().path() {
        "/.well-known/aauth-agent.json" => {
            json_response(200, serde_json::from_slice(&serving.metadata().unwrap()).unwrap())
        }
        "/.well-known/jwks.json" => {
            json_response(200, serde_json::from_slice(&serving.jwks().unwrap()).unwrap())
        }
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, AP, "aauth-agent.json")?;

    // Resource: swappable instance over one custody directory.
    let effects = Arc::new(Effects {
        reads: AtomicUsize::new(0),
        deletes: Mutex::new(Vec::new()),
    });
    let current = Arc::new(RwLock::new(Arc::new(compose(&root, seed, &trust, false, control.clone())?)));
    let (serving, serving_effects) = (current.clone(), effects.clone());
    let api = Arc::new(TlsServer::start("records.example", move |request| {
        let resource = serving.read().unwrap().clone();
        serve(&resource, &serving_effects, request)
    })?);
    trust.discover(&api, RECORDS, "aauth-resource.json")?;

    let audit = Arc::new(AuditLog::default());
    let ids = AtomicUsize::new(0);
    // Fixture key retained only to sign the genuine PS revocation control.
    let ps_seed = seed.map(|byte| byte ^ 0x5a);
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed(ps_seed)),
        trust.clone(),
        MemoryStore::default(),
        HostPolicy,
        now,
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(|uri: &str, _: Instant| -> io::Result<()> {
            if uri.starts_with(&format!("{RECORDS}/r3/c.")) || uri.starts_with(&format!("{RECORDS}/r3/p."))
            {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "egress refused"))
            }
        }),
        transport: Box::new(TlsFetch(api.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(HostConsent),
        audit: audit.clone(),
    })?;
    let ps_tls = TlsServer::start("ps.example", move |request| ps.handle(&request))?;
    trust.discover(&ps_tls, PS, "aauth-person.json")?;

    let person = member(
        &ps_tls.send(&post(
            &agent,
            &format!("{PS}/person"),
            json!({"resource": RECORDS}).to_string().as_bytes(),
        )?)?,
        "person_token",
    )
    .ok_or("person token refused")?;
    let class = class_grant(&agent, &person, &api, &ps_tls, &trust, &registry)?;
    let holder = agent.with_token(class.clone())?;

    // Class grant: read is served directly.
    t.read_status = api
        .send(&post(&holder, &format!("{RECORDS}/records/read"), R1)?)?
        .status()
        .as_u16();

    // Per call (401): challenge, verify, approve, verify.
    let challenged = api.send(&post(&holder, &format!("{RECORDS}/records/delete"), R1)?)?;
    t.challenge_status = challenged.status().as_u16();
    let proposal_token = challenge(&challenged)?;
    let proposal =
        agent.verify_r3_proposal_challenge(&proposal_token, RECORDS, PS, &class, &trust, now())?;
    let approved = approve(&agent, &ps_tls, &proposal_token, &class)?;
    let per_call = member(&approved, "auth_token").ok_or("per-call approval refused")?;
    let delivered = agent.verify_r3_per_call_delivery(
        &per_call, RECORDS, &proposal, &class, &registry, &trust, now(),
    )?;
    t.proposal_operation = delivered
        .operations()
        .granted_operations()
        .operations()?
        .first()
        .map(|operation| operation.json().map(|b| String::from_utf8_lossy(&b).into_owned()))
        .transpose()?
        .unwrap_or_default();
    let completing = agent.with_token(per_call.clone())?;
    // Substituted parameters are refused before any claim.
    t.substituted_parameters_status = api
        .send(&post(&completing, &format!("{RECORDS}/records/delete"), R2)?)?
        .status()
        .as_u16();
    // A different holder presenting the per-call token fails its proof.
    let mut stolen = Request::builder()
        .method("POST")
        .uri(format!("{RECORDS}/records/delete"))
        .header("content-type", "application/json")
        .body(R1.to_vec())?;
    sign_request(&mut stolen, &SigningKey::generate(), KeyMaterial::Jwt(per_call.clone()), now())?;
    t.wrong_holder_status = api.send(&stolen)?.status().as_u16();
    // The approved call runs once; the same exact token is answered from the retained result.
    let retry = post(&completing, &format!("{RECORDS}/records/delete"), R1)?;
    let first = api.send(&retry)?;
    t.retry_status = first.status().as_u16();
    let replay = api.send(&post(&completing, &format!("{RECORDS}/records/delete"), R1)?)?;
    t.replay_status = replay.status().as_u16();
    t.replay_matches_first = replay.body() == first.body();

    // Recompose the Resource from its files, now holding invocations (202).
    *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, true, control.clone())?);
    t.replay_after_restart_status = api
        .send(&post(&completing, &format!("{RECORDS}/records/delete"), R1)?)?
        .status()
        .as_u16();

    // Parameter-sensitive consent: the PS refuses a proposal for another record.
    let other = api.send(&post(&holder, &format!("{RECORDS}/records/delete"), R2)?)?;
    let other_token = challenge(&other)?;
    t.denied_parameters_ps_status = approve(&agent, &ps_tls, &other_token, &class)?
        .status()
        .as_u16();

    // Per call (202): the held invocation completes at its pending URL.
    let mut held_request = post(&holder, &format!("{RECORDS}/records/delete"), R1)?;
    if case == Some(AdmissionCase::HeldPolicy) {
        *held_request.method_mut() = http::Method::DELETE;
        holder.sign(&mut held_request, now())?;
    }
    let held = api.send(&held_request)?;
    t.held_status = held.status().as_u16();
    let location = held
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .ok_or("held response omitted Location")?
        .to_owned();
    t.held_location_at_signed_origin = location.starts_with(&format!("{RECORDS}/r3/pending/"));
    let held_token = challenge(&held)?;
    let held_proposal =
        agent.verify_r3_proposal_challenge(&held_token, RECORDS, PS, &class, &trust, now())?;
    let held_grant = member(&approve(&agent, &ps_tls, &held_token, &class)?, "auth_token")
        .ok_or("held approval refused")?;
    agent.verify_r3_per_call_delivery(
        &held_grant, RECORDS, &held_proposal, &class, &registry, &trust, now(),
    )?;
    // The earlier per-call token is not this pending invocation's approval.
    let mut foreign = get(&location)?;
    completing.sign(&mut foreign, now())?;
    t.foreign_token_at_pending_status = api.send(&foreign)?.status().as_u16();
    let poller = agent.with_token(held_grant)?;
    let mut poll = get(&location)?;
    poller.sign(&mut poll, now())?;
    if case == Some(AdmissionCase::HeldPolicy) {
        control.deny_delete.store(true, Ordering::SeqCst);
        let before = effects.deletes.lock().unwrap().len();
        t.held_policy_denied_status = api.send(&poll)?.status().as_u16();
        t.held_policy_effect_delta = effects.deletes.lock().unwrap().len() - before;
        t.held_policy_claim_consumed = FileCalls(root.clone(), Mutex::new(()), control.clone())
            .claim_path(held_proposal.reference().uri()).exists();
        control.deny_delete.store(false, Ordering::SeqCst);
        poller.sign(&mut poll, now())?;
    }
    t.held_completion_status = api.send(&poll)?.status().as_u16();
    let mut again = get(&location)?;
    poller.sign(&mut again, now())?;
    t.held_replay_status = api.send(&again)?.status().as_u16();

    if matches!(case, Some(AdmissionCase::Revocation | AdmissionCase::ClaimRevocation)) {
        // A fresh, unclaimed proposal: previously admitted effects remain separate.
        let held = api.send(&post(&holder, &format!("{RECORDS}/records/delete"), R1)?)?;
        let location = held.headers()["location"].to_str()?.to_owned();
        let proposal_token = challenge(&held)?;
        let proposal = agent.verify_r3_proposal_challenge(
            &proposal_token, RECORDS, PS, &class, &trust, now(),
        )?;
        let grant = member(&approve(&agent, &ps_tls, &proposal_token, &class)?, "auth_token")
            .ok_or("revocation-control approval refused")?;
        let verified = agent.verify_r3_per_call_delivery(
            &grant, RECORDS, &proposal, &class, &registry, &trust, now(),
        )?;
        let mut revoke = Request::builder().method("POST").uri(format!("{RECORDS}/revoke"))
            .header("content-type", "application/json")
            .body(json!({"jti": verified.claims().jti, "exp": verified.claims().exp})
                .to_string().into_bytes())?;
        sign_request(&mut revoke, &SigningKey::from_seed(ps_seed), KeyMaterial::JwksUri {
            id: PS.into(), dwk: "aauth-person.json".into(), kid: "ps-1".into(),
        }, now())?;
        let mut poll = get(&location)?;
        let revocation_holder = agent.with_token(grant)?;
        revocation_holder.sign(&mut poll, now())?;
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        if case == Some(AdmissionCase::ClaimRevocation) {
            *control.claim_barrier.lock().unwrap() = Some((entered, released));
        } else {
            *control.barrier.lock().unwrap() = Some((entered, released));
        }
        let before = effects.deletes.lock().unwrap().len();
        let sending = api.clone();
        let pending = std::thread::spawn(move || sending.send(&poll));
        observed.recv_timeout(Duration::from_secs(2))?;
        // The example transport is serial per listener. A second TLS listener
        // shares this exact Resource and ledger, permitting a concurrent revoke.
        let revoking = current.read().unwrap().clone();
        let revoke_api = TlsServer::start("records.example", move |request| {
            revoking.revoke(&request, now())
        })?;
        let revoked = revoke_api.send(&revoke);
        release.send(())?;
        let completion = pending.join().map_err(|_| "completion thread panicked")??;
        t.revocation_status = revoked?.status().as_u16();
        t.revoked_completion_status = completion.status().as_u16();
        t.revoked_completion_error = completion.headers().get("signature-error")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
        t.revocation_effect_delta = effects.deletes.lock().unwrap().len() - before;
        let claim_path = FileCalls(root.clone(), Mutex::new(()), control.clone())
            .claim_path(proposal.reference().uri());
        t.revocation_claim_consumed = claim_path.exists();
        if case == Some(AdmissionCase::ClaimRevocation) {
            let retained = fs::read(&claim_path)?;
            let value: Value = serde_json::from_slice(&retained)?;
            t.revocation_result_retained = !value["result"].is_null();
            let mut retry = get(&location)?;
            revocation_holder.sign(&mut retry, now())?;
            t.revocation_retry_status = api.send(&retry)?.status().as_u16();
            t.revocation_claim_unchanged = fs::read(&claim_path)? == retained;
            // Count again after retry, so redispatch cannot escape the control.
            t.revocation_effect_delta = effects.deletes.lock().unwrap().len() - before;
        }
    }

    t.reads = effects.reads.load(Ordering::SeqCst);
    t.deletes = effects.deletes.lock().unwrap().clone();
    t.audit_records = audit.0.lock().map_err(|_| "audit lock poisoned")?.len();
    let _ = fs::remove_dir_all(&root);
    Ok(t)
}
