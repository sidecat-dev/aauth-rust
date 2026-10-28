//! Cross-language HTTP/TLS R3 per-call interoperability:
//! 1. Go Agent (`gitlab.com/sidecat-dev/aauth-go/agent` + `r3` + `signaturekey`)
//!    against Rust Agent Provider, Rust Person Server, and Rust Resource over
//!    real TLS: Person token, class R3 authorization, direct class call, `401`
//!    per-call challenge, PS approval expiry (`expired_presented_token`) and
//!    single-use recorded-approval replacement without re-prompting, parameter
//!    substitution and PS parameter-denial refusals, single-use retry and
//!    replay, `202` held execution and foreign-token refusal, `202`
//!    side-effect-free release-gated query (`proposal.result`) without
//!    recomputation, and release retry after `expired_presented_token`: the
//!    re-requested query is answered from the held result without running
//!    again or re-prompting, and the original pending URL is refused.
//! 2. Converse direction: Rust Agent and Rust Resource against Go
//!    `agentprovider.Server` and Go `personserver.Server` (`DirectR3Config`)
//!    over real TLS: Go PS Person token, Rust Resource class R3 `/authorize`,
//!    Go PS signed fetch of the class document from Rust Resource over TLS and
//!    direct R3 Auth token issuance, Rust Agent `verify_r3_auth_delivery`,
//!    Rust Resource `200` admission of granted `records.read` and `403` refusal
//!    of ungranted `records.delete`, plus Go PS `DirectR3Config`'s `400
//!    invalid_resource_token` refusal when presented a per-call proposal
//!    Resource token fetched from Rust Resource.
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
    OperationSet, Parameter, Parameters, PresentedParameter, ProposalDisplay, ProposalResult,
    Reference, ToolsListPage, ToolsListSnapshot, digest, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthPolicy, BoxedR3Release, PsAuthorizationConfig, PsAuthorizationResource,
    R3CallDescription, R3CallResult, R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord,
    R3DocumentStore, R3HeldRequest, R3HostError, R3PerCallConfig, R3ProposalRecord, R3Release,
    R3StoreError, R3Vocabulary,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const GO_AP: &str = "https://go-ap.example";
const GO_PS: &str = "https://go-ps.example";
const RECORDS: &str = "https://records.example";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}},{"name":"records.query","inputSchema":{"type":"object"}}]}"#;
const R1: &[u8] = br#"{"record":"r-1"}"#;
const DRIVER_GO: &str = include_str!("interop_driver.go");

/// Observable cross-language interoperability statuses and effect counts.
#[derive(Debug, Default)]
pub struct InteropTranscript {
    pub go_to_rust_person_token_issued: bool,
    pub go_to_rust_class_read_status: u16,
    pub go_to_rust_401_challenge_status: u16,
    pub go_to_rust_approval_expiry_error: String,
    pub go_to_rust_approval_replacement_reused_without_reprompt: bool,
    pub go_to_rust_substituted_parameters_status: u16,
    pub go_to_rust_ps_denied_other_record_status: u16,
    pub go_to_rust_401_retry_status: u16,
    pub go_to_rust_401_replay_status: u16,
    pub go_to_rust_401_replay_matches_first: bool,
    pub go_to_rust_202_held_status: u16,
    pub go_to_rust_202_foreign_token_status: u16,
    pub go_to_rust_202_poll_status: u16,
    pub go_to_rust_202_replay_status: u16,
    pub go_to_rust_release_held_status: u16,
    pub go_to_rust_release_poll_status: u16,
    pub go_to_rust_release_replay_status: u16,
    pub go_to_rust_query_runs: usize,
    pub release_retry_expiry_error: String,
    pub release_retry_reused_without_reprompt: bool,
    pub release_retry_runs_before_challenge: usize,
    pub release_retry_runs_after_challenge: usize,
    pub release_retry_poll_status: u16,
    pub release_retry_old_pending_status: u16,
    pub release_retry_body_matches_original: bool,
    pub rust_to_go_person_status: u16,
    pub rust_to_go_class_exchange_status: u16,
    pub rust_to_go_ps_fetched_document: bool,
    pub rust_to_go_ps_issuance_records: usize,
    pub rust_to_go_class_read_status: u16,
    pub rust_to_go_ungranted_delete_status: u16,
    pub rust_to_go_proposal_exchange_status: u16,
    pub rust_to_go_proposal_exchange_error: String,
    pub reads: usize,
    pub deletes: Vec<String>,
    pub rust_ps_audit_records: usize,
}

struct AdmissionControl {
    base_now: i64,
    query_runs: AtomicUsize,
    consents: Mutex<Vec<String>>,
    clock_offset: AtomicI64,
    next_class_lifetime: AtomicI64,
    advance_on_approval: AtomicI64,
}
impl AdmissionControl {
    fn new(base_now: i64) -> Self {
        Self {
            base_now,
            query_runs: AtomicUsize::new(0),
            consents: Mutex::new(Vec::new()),
            clock_offset: AtomicI64::new(0),
            next_class_lifetime: AtomicI64::new(0),
            advance_on_approval: AtomicI64::new(0),
        }
    }
    fn now(&self) -> i64 {
        self.base_now + self.clock_offset.load(Ordering::SeqCst)
    }
    fn admit(&self, token: &VerifiedAuthToken, _: &Request<Vec<u8>>) -> bool {
        token.claims().ps == PS || token.claims().ps == GO_PS
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
    fn discover_external(
        &self,
        address: SocketAddr,
        host: &'static str,
        cert_der: &[u8],
        issuer: &str,
        dwk: &str,
    ) -> Result<()> {
        let metadata = TlsServer::send_external(
            address,
            host,
            cert_der,
            &get(&format!("{issuer}/.well-known/{dwk}"))?,
        )?;
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = TlsServer::send_external(address, host, cert_der, &get(&uri)?)?;
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
fn post_at(agent: &Agent, uri: &str, body: &[u8], signed_at: i64) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.to_vec())?;
    agent.sign(&mut request, signed_at)?;
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
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}
fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or("invalid hex")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("invalid hex")?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
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

struct FileDocuments(PathBuf, Mutex<()>);
impl R3DocumentStore for FileDocuments {
    fn commit(&self, r: &R3DocumentRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self
            .0
            .join(format!("c-{}.json", digest(r.reference.uri().as_bytes())));
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
                exact_json: serde_json::from_value(
                    v.get("exact_json").cloned().ok_or("missing bytes")?,
                )?,
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

/// Claim digest of a superseded release's tombstone. It is never a SHA-256
/// digest in base64url, so every later claim on that record is `DifferentToken`.
const SUPERSEDED: &str = "(superseded)";

// The control stays with the store for the same lifetime as the main example.
struct FileCalls(PathBuf, Mutex<()>, #[allow(dead_code)] Arc<AdmissionControl>);
impl FileCalls {
    fn record_path(&self, uri: &str) -> PathBuf {
        self.0.join(format!("p-{}.json", digest(uri.as_bytes())))
    }
    fn claim_path(&self, uri: &str) -> PathBuf {
        self.0
            .join(format!("claim-{}.json", digest(uri.as_bytes())))
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
            released: match v.get("released") {
                Some(released) if !released.is_null() => Some(Self::result(released)?),
                _ => None,
            },
            release_until: v.get("release_until").and_then(Value::as_i64),
            supersedes: optional(&v, "supersedes"),
        })
    }
    fn result(v: &Value) -> Result<R3CallResult> {
        Ok(R3CallResult {
            status: u16::try_from(number(v, "status")?)?,
            content_type: optional(v, "content_type"),
            body: serde_json::from_value(v["body"].clone())?,
        })
    }
    /// Create one record and its pending index. The caller holds the serial lock.
    fn create(&self, r: &R3ProposalRecord) -> std::result::Result<(), R3StoreError> {
        let held = r.held.as_ref().map(|held| {
            json!({"pending_id": held.pending_id, "method": held.method, "uri": held.uri,
                   "headers": held.headers, "body": held.body})
        });
        let released = r.released.as_ref().map(|result| {
            json!({"status": result.status, "content_type": result.content_type,
                   "body": result.body})
        });
        let bytes = json!({
            "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
            "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
            "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
            "class_reference": {"uri": r.class_reference.uri(), "digest": r.class_reference.digest()},
            "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
            "tenant": r.tenant, "account": r.account, "scope": r.scope,
            "issued_at": r.issued_at, "expires_at": r.expires_at, "held": held,
            "released": released, "release_until": r.release_until, "supersedes": r.supersedes,
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
    fn remove_successor(&self, record: &R3ProposalRecord) {
        let _ = fs::remove_file(self.record_path(record.reference.uri()));
        if let Some(held) = &record.held {
            let _ = fs::remove_file(self.0.join(format!("pending-{}", held.pending_id)));
        }
    }
}
impl R3CallStore for FileCalls {
    fn commit(&self, r: &R3ProposalRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        self.create(r)
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
        if let Some(record) = self.load(uri)? {
            if record.release_until.is_some_and(|until| now >= until) {
                return Ok(R3Claim::Expired);
            }
        }
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
                if now >= number(&v, "retain_until").map_err(unavailable)? {
                    return Ok(R3Claim::Expired);
                }
                Ok(R3Claim::Replay(
                    Self::result(&v["result"]).map_err(unavailable)?,
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if now >= token.retain_until {
                    return Ok(R3Claim::Expired);
                }
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
    fn held_releases(
        &self,
        agent_jkt: &str,
        subject: &str,
        now: i64,
    ) -> std::result::Result<Vec<R3ProposalRecord>, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let mut held = Vec::new();
        for entry in fs::read_dir(&self.0).map_err(unavailable)? {
            let name = entry.map_err(unavailable)?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("p-") || !name.ends_with(".json") {
                continue;
            }
            let bytes = fs::read(self.0.join(name)).map_err(unavailable)?;
            let record = Self::decode(&bytes).map_err(unavailable)?;
            // Unclaimed and not superseded: both bind the claim file.
            if record.released.is_some()
                && record.agent_jkt == agent_jkt
                && record.subject == subject
                && record.release_until.is_some_and(|until| now < until)
                && !self.claim_path(record.reference.uri()).exists()
            {
                held.push(record);
            }
        }
        Ok(held)
    }
    fn supersede(
        &self,
        prior_uri: &str,
        record: &R3ProposalRecord,
        now: i64,
    ) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let Some(prior) = self.load(prior_uri)? else {
            return Err(R3StoreError::Conflict);
        };
        let tombstone = self.claim_path(prior_uri);
        // Only an unclaimed, live held release is retired, and only for a
        // successor that commit would create; otherwise nothing changes.
        if prior.released.is_none()
            || prior.release_until.is_none_or(|until| now >= until)
            || tombstone.exists()
            || self.record_path(record.reference.uri()).exists()
            || record.held.as_ref().is_some_and(|held| {
                self.0.join(format!("pending-{}", held.pending_id)).exists()
            })
        {
            return Err(R3StoreError::Conflict);
        }
        if let Err(error) = self.create(record) {
            self.remove_successor(record);
            return Err(error);
        }
        let bytes = json!({"compact_sha256": SUPERSEDED, "jti": null,
                           "retain_until": prior.expires_at, "fence": null, "result": null,
                           "superseded_by": record.reference.uri(), "superseded_at": now})
        .to_string()
        .into_bytes();
        match write_new(&tombstone, &bytes) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.remove_successor(record);
                Err(R3StoreError::Conflict)
            }
            Err(error) => {
                self.remove_successor(record);
                Err(unavailable(error))
            }
        }
    }
}

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

struct HostConsent(Arc<AdmissionControl>);
fn record_r1(request: &R3ProposalRequest<'_>) -> bool {
    request
        .proposal
        .parameters()
        .get("record")
        .and_then(|parameter| parameter.inline_json())
        .is_some_and(|value| value == br#""r-1""#)
}
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
        let lifetime = match self.0.next_class_lifetime.swap(0, Ordering::SeqCst) {
            0 => 600,
            override_lifetime => override_lifetime,
        };
        Ok(R3Decision {
            granted: GrantedOperations::new(
                &vocabulary,
                &[mcp("records.read").map_err(unavailable)?],
            )
            .map_err(|_| PolicyError::Unavailable)?,
            per_call: Some(
                GrantedOperations::new(
                    &vocabulary,
                    &[
                        mcp("records.delete").map_err(unavailable)?,
                        mcp("records.query").map_err(unavailable)?,
                    ],
                )
                .map_err(|_| PolicyError::Unavailable)?,
            ),
            scopes: Vec::new(),
            lifetime,
        })
    }
    fn authorize_proposal(
        &self,
        request: &R3ProposalRequest<'_>,
    ) -> std::result::Result<R3ProposalDecision, PolicyError> {
        self.0.consents.lock().unwrap().push("execution".into());
        if request.proposal.result().is_some()
            || !record_r1(request)
            || request.core.resource.claims().iss != RECORDS
        {
            return Err(PolicyError::Denied);
        }
        let advance = self.0.advance_on_approval.swap(0, Ordering::SeqCst);
        if advance > 0 {
            self.0.clock_offset.fetch_add(advance, Ordering::SeqCst);
        }
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime: 300,
        })
    }
    fn authorize_release(
        &self,
        request: &R3ProposalRequest<'_>,
    ) -> std::result::Result<R3ProposalDecision, PolicyError> {
        self.0.consents.lock().unwrap().push("release".into());
        let Some(result) = request.proposal.result() else {
            return Err(PolicyError::Denied);
        };
        if !record_r1(request) || request.core.resource.claims().iss != RECORDS {
            return Err(PolicyError::Denied);
        }
        let _ = result.json();
        let advance = self.0.advance_on_approval.swap(0, Ordering::SeqCst);
        if advance > 0 {
            self.0.clock_offset.fetch_add(advance, Ordering::SeqCst);
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
        if records
            .iter()
            .any(|existing| existing.auth_token_jti == record.auth_token_jti && existing != record)
        {
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

type Resource = PsAuthorizationResource<Trust, BoxedAuthPolicy>;
fn record_parameter(request: &Request<Vec<u8>>) -> std::result::Result<Vec<u8>, R3HostError> {
    let value: Value =
        serde_json::from_slice(request.body()).map_err(|e| R3HostError::new(e.to_string()))?;
    let record = value
        .get("record")
        .ok_or_else(|| R3HostError::new("call names no record"))?;
    serde_json::to_vec(record).map_err(|e| R3HostError::new(e.to_string()))
}

fn query_release(control: Arc<AdmissionControl>) -> BoxedR3Release {
    Box::new(
        move |_: &Request<Vec<u8>>,
              operation: &Operation,
              presented: &BTreeMap<String, PresentedParameter>,
              _: Option<&str>| {
            if !matches!(operation.equal(&mcp("records.query")?), Ok(true)) {
                return Ok(None);
            }
            let record = presented
                .get("record")
                .and_then(PresentedParameter::inline_json)
                .ok_or_else(|| R3HostError::new("record parameter is required"))?;
            let shown = String::from_utf8_lossy(&record).into_owned();
            // The response, never the proposal, names which computation it is.
            let run = control.query_runs.fetch_add(1, Ordering::SeqCst) + 1;
            let response = json_response(
                200,
                json!({"record": shown, "name": "A. Person", "national_id": "000-00-0000",
                       "query_run_seq": run}),
            );
            let result = ProposalResult::new(br#"{"records":1,"contains":["national_id"]}"#)
                .map_err(|e| R3HostError::new(e.to_string()))?;
            let display = ProposalDisplay::new(
                &Display::new(
                    format!("Release the result of a query for record {shown}"),
                    None,
                    None,
                    None,
                )
                .map_err(|e| R3HostError::new(e.to_string()))?,
                Some(&format!(
                    "## Action\nThis query has already run. What you are approving is \
                     release of its result to the agent.\n\n## Details\nOne record \
                     ({shown}), including a national identifier."
                )),
            )
            .map_err(|e| R3HostError::new(e.to_string()))?;
            Ok(Some(R3Release {
                result,
                display,
                response,
            }))
        },
    )
}

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
        Box::new(
            move |token: &VerifiedAuthToken, request: &Request<Vec<u8>>| {
                policy_control.admit(token, request)
            },
        ) as BoxedAuthPolicy,
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
                Display::new(
                    "Read records; delete with per-call approval",
                    None,
                    None,
                    None,
                )
                .map_err(|e| R3HostError::new(e.to_string()))
            })),
        }],
        documents: Arc::new(FileDocuments(root.to_path_buf(), Mutex::new(()))),
        operation_for_request: Box::new(|request: &Request<Vec<u8>>| match request.uri().path() {
            "/records/read" => mcp("records.read").map(Some),
            "/records/delete" => mcp("records.delete").map(Some),
            "/records/query" => mcp("records.query").map(Some),
            _ => Ok(None),
        }),
        require_core_scope: false,
    })?
    .with_r3_per_call(R3PerCallConfig {
        present: Box::new(|request: &Request<Vec<u8>>, _: &Operation| {
            let record = record_parameter(request)?;
            let presented =
                PresentedParameter::inline(&record).map_err(|e| R3HostError::new(e.to_string()))?;
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
                    Some(&format!(
                        "## Action\nDelete a record\n\n## Details\nRecord {shown}"
                    )),
                )
                .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(R3CallDescription {
                    parameters,
                    display: Some(display),
                })
            },
        ),
        calls: Arc::new(FileCalls(
            root.to_path_buf(),
            Mutex::new(()),
            control.clone(),
        )),
        hold,
        release: hold.then(|| query_release(control.clone())),
        held_result_lifetime: 300,
    })?;
    Ok(resource)
}

struct Effects {
    reads: AtomicUsize,
    deletes: Mutex<Vec<String>>,
}
fn serve(
    resource: &Resource,
    effects: &Effects,
    clock: i64,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let jti = format!(
        "rid-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = request.uri().path().to_owned();
    if path == "/.well-known/aauth-resource.json" {
        return json_response(
            200,
            serde_json::from_slice(&resource.metadata().unwrap()).unwrap(),
        );
    }
    if path == "/.well-known/jwks.json" {
        return json_response(
            200,
            serde_json::from_slice(&resource.jwks().unwrap()).unwrap(),
        );
    }
    if path == "/authorize" {
        return resource
            .authorize_endpoint(&request, clock, &jti)
            .into_response();
    }
    if path.starts_with("/r3/") && !path.starts_with("/r3/pending/") {
        return resource.r3_document(&request, clock);
    }
    match resource.authorize(&request, clock, &jti) {
        AuthDecision::Granted(admitted) => {
            let Some(grant) = admitted.r3_grant() else {
                return json_response(403, json!({"error":"access_denied"}));
            };
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

fn resolve_go_reference() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--go-module" {
            let path = args.next().ok_or("--go-module requires a path")?;
            return Ok(fs::canonicalize(path)?);
        }
    }
    if let Ok(env_path) = std::env::var("AAUTH_GO_REFERENCE")
        && !env_path.is_empty()
    {
        return Ok(fs::canonicalize(env_path)?);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../../../inputs/go-reference"),
        manifest_dir.join("../../inputs/go-reference"),
        manifest_dir.join("../../../aauth-go"),
        PathBuf::from("../inputs/go-reference"),
        PathBuf::from("inputs/go-reference"),
        PathBuf::from("../aauth-go"),
    ];
    for candidate in candidates {
        if candidate.join("go.mod").is_file() {
            return Ok(fs::canonicalize(candidate)?);
        }
    }
    Err("could not locate aauth-go reference module; pass --go-module <path> or set AAUTH_GO_REFERENCE".into())
}

fn handle_converse(
    request: &Request<Vec<u8>>,
    root: &Path,
    seed: [u8; 32],
    trust: &Trust,
    control: &Arc<AdmissionControl>,
    current: &Arc<RwLock<Arc<Resource>>>,
    api: &Arc<TlsServer>,
) -> Result<Value> {
    let body: Value = serde_json::from_slice(request.body())?;
    let go_ap_addr: SocketAddr = text(&body, "go_ap_addr")?.parse()?;
    let go_ap_cert = hex_decode(&text(&body, "go_ap_cert_hex")?)?;
    let go_ps_addr: SocketAddr = text(&body, "go_ps_addr")?.parse()?;
    let go_ps_cert = hex_decode(&text(&body, "go_ps_cert_hex")?)?;
    let go_agent_seed_vec = hex_decode(&text(&body, "go_agent_seed_hex")?)?;
    let go_agent_seed: [u8; 32] = go_agent_seed_vec
        .try_into()
        .map_err(|_| "invalid go agent seed length")?;
    let go_agent_token = text(&body, "go_agent_token")?;

    trust.discover_external(go_ap_addr, "go-ap.example", &go_ap_cert, GO_AP, "aauth-agent.json")?;
    trust.discover_external(
        go_ps_addr,
        "go-ps.example",
        &go_ps_cert,
        GO_PS,
        "aauth-person.json",
    )?;
    *current.write().unwrap() = Arc::new(compose(root, seed, trust, false, control.clone())?);

    let registry = standard_registry()?;
    let go_agent = Agent::new(SigningKey::from_seed(go_agent_seed), go_agent_token)?;
    let clock = control.now();

    // 1. Rust Agent requests a Person token from Go PS over TLS.
    let person_req = post_at(
        &go_agent,
        &format!("{GO_PS}/person"),
        json!({"resource": RECORDS}).to_string().as_bytes(),
        clock,
    )?;
    let person_resp = TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &person_req)?;
    let person_status = person_resp.status().as_u16();
    let person_token = member(&person_resp, "person_token").ok_or("go ps person token refused")?;

    // 2. Rust Agent requests a class R3 Resource token from Rust Resource.
    let operations = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [
            {"tool":"records.read"},{"tool":"records.delete"},{"tool":"records.query"}
        ]})
        .to_string()
        .as_bytes(),
    )?;
    let resource_token = go_agent.r3_authorize(
        |req| api.send(&req),
        &format!("{RECORDS}/authorize"),
        &person_token,
        &operations,
        None,
        clock,
    )?;
    let verified = go_agent.verify_r3_resource_token(
        &resource_token,
        RECORDS,
        GO_PS,
        &person_token,
        None,
        trust,
        clock,
    )?;

    // 3. Rust Agent exchanges the class Resource token at Go PS (`DirectR3Config`).
    // Go PS fetches the class document from Rust Resource over TLS and issues a
    // direct-only R3 Auth token (`r3_granted=["records.read"]`).
    let exchange_req = post_at(
        &go_agent,
        &format!("{GO_PS}/token"),
        json!({"resource_token": resource_token, "presented_token": person_token})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let exchange_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &exchange_req)?;
    let class_exchange_status = exchange_resp.status().as_u16();
    let go_class_auth =
        member(&exchange_resp, "auth_token").ok_or("go ps class R3 grant refused")?;
    go_agent.verify_r3_auth_delivery(
        &go_class_auth,
        RECORDS,
        &verified,
        &person_token,
        &registry,
        trust,
        clock,
    )?;

    // 4. Rust Agent invokes `records.read` (200) and `records.delete` (403) at Rust Resource.
    let holder = go_agent.with_token(go_class_auth)?;
    let class_read_status = api
        .send(&post_at(&holder, &format!("{RECORDS}/records/read"), R1, clock)?)?
        .status()
        .as_u16();
    let ungranted_delete_status = api
        .send(&post_at(&holder, &format!("{RECORDS}/records/delete"), R1, clock)?)?
        .status()
        .as_u16();

    // 5. Obtain a class Auth token carrying `r3_per_call=["records.delete"]` signed by Go PS,
    // trigger a genuine 401 proposal challenge at Rust Resource, verify the challenge with
    // Rust Agent, and present the proposal Resource token to Go PS `DirectR3Config` (/token),
    // which fetches the proposal from Rust Resource over TLS and refuses it with
    // `400 invalid_resource_token` ("direct R3 supports class documents only").
    let mint_req = Request::builder()
        .method("POST")
        .uri(format!("{GO_PS}/__mint-per-call-class"))
        .header("content-type", "application/json")
        .body(b"{}".to_vec())?;
    let mint_resp = TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &mint_req)?;
    let per_call_class =
        member(&mint_resp, "auth_token").ok_or("failed to mint per-call class token")?;
    let per_call_holder = go_agent.with_token(per_call_class.clone())?;
    let challenged = api.send(&post_at(
        &per_call_holder,
        &format!("{RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let proposal_rt = challenge(&challenged)?;
    let _verified_proposal = go_agent.verify_r3_proposal_challenge(
        &proposal_rt,
        RECORDS,
        GO_PS,
        &per_call_class,
        trust,
        clock,
    )?;
    let proposal_exchange_req = post_at(
        &go_agent,
        &format!("{GO_PS}/token"),
        json!({"resource_token": proposal_rt, "presented_token": per_call_class})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let proposal_exchange_resp = TlsServer::send_external(
        go_ps_addr,
        "go-ps.example",
        &go_ps_cert,
        &proposal_exchange_req,
    )?;
    let proposal_status = proposal_exchange_resp.status().as_u16();
    let proposal_error = member(&proposal_exchange_resp, "error").unwrap_or_default();

    Ok(json!({
        "person_status": person_status,
        "class_exchange_status": class_exchange_status,
        "class_read_status": class_read_status,
        "ungranted_delete_status": ungranted_delete_status,
        "proposal_status": proposal_status,
        "proposal_error": proposal_error,
    }))
}

pub fn run() -> Result<InteropTranscript> {
    let go_ref = resolve_go_reference()?;
    let control = Arc::new(AdmissionControl::new(now()));
    let trust = Trust::default();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("aauth-r3-interop-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&root)?;

    let mut seed = [7u8; 32];
    seed[..16].copy_from_slice(&nanos.to_le_bytes());

    let provider = Arc::new(AgentProvider::new(AP, "ap-1", SigningKey::generate())?);
    let mut agent_seed = [0x11u8; 32];
    agent_seed[..16].copy_from_slice(&nanos.to_be_bytes());
    let agent_key = SigningKey::from_seed(agent_seed);
    let issued = control.now();
    let agent_token = provider.issue(&AgentClaims {
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

    let serving_ap = provider.clone();
    let ap_tls = TlsServer::start("ap.example", move |request| match request.uri().path() {
        "/.well-known/aauth-agent.json" => json_response(
            200,
            serde_json::from_slice(&serving_ap.metadata().unwrap()).unwrap(),
        ),
        "/.well-known/jwks.json" => json_response(
            200,
            serde_json::from_slice(&serving_ap.jwks().unwrap()).unwrap(),
        ),
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, AP, "aauth-agent.json")?;

    let effects = Arc::new(Effects {
        reads: AtomicUsize::new(0),
        deletes: Mutex::new(Vec::new()),
    });
    let current = Arc::new(RwLock::new(Arc::new(compose(
        &root,
        seed,
        &trust,
        false,
        control.clone(),
    )?)));
    let (serving_res, serving_effects, serving_control) =
        (current.clone(), effects.clone(), control.clone());
    let api = Arc::new(TlsServer::start("records.example", move |request| {
        let resource = serving_res.read().unwrap().clone();
        serve(
            &resource,
            &serving_effects,
            serving_control.now(),
            request,
        )
    })?);
    trust.discover(&api, RECORDS, "aauth-resource.json")?;

    let audit = Arc::new(AuditLog::default());
    let ids = AtomicUsize::new(0);
    let ps_seed = seed.map(|byte| byte ^ 0x5a);
    let ps_clock = control.clone();
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed(ps_seed)),
        trust.clone(),
        MemoryStore::default(),
        HostPolicy,
        move || ps_clock.now(),
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(|uri: &str, _: Instant| -> io::Result<()> {
            if uri.starts_with(&format!("{RECORDS}/r3/c."))
                || uri.starts_with(&format!("{RECORDS}/r3/p."))
            {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "egress refused",
                ))
            }
        }),
        transport: Box::new(TlsFetch(api.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(HostConsent(control.clone())),
        audit: audit.clone(),
    })?;
    let ps_tls = TlsServer::start("ps.example", move |request| ps.handle(&request))?;
    trust.discover(&ps_tls, PS, "aauth-person.json")?;

    let (
        interop_root,
        interop_trust,
        interop_control,
        interop_current,
        interop_effects,
        interop_audit,
        interop_api,
    ) = (
        root.clone(),
        trust.clone(),
        control.clone(),
        current.clone(),
        effects.clone(),
        audit.clone(),
        api.clone(),
    );
    let interop_tls = TlsServer::start("interop.example", move |request| {
        match (request.method().as_str(), request.uri().path()) {
            ("GET", "/state") => json_response(
                200,
                json!({
                    "now": interop_control.now(),
                    "reads": interop_effects.reads.load(Ordering::SeqCst),
                    "deletes": interop_effects.deletes.lock().unwrap().clone(),
                    "query_runs": interop_control.query_runs.load(Ordering::SeqCst),
                    "audit_records": interop_audit.0.lock().unwrap().len(),
                    "consents": interop_control.consents.lock().unwrap().clone(),
                }),
            ),
            ("POST", "/arm-approval-expiry") => {
                interop_control.next_class_lifetime.store(30, Ordering::SeqCst);
                interop_control.advance_on_approval.store(35, Ordering::SeqCst);
                json_response(200, json!({"armed": true}))
            }
            ("POST", "/hold-mode") => match compose(
                &interop_root,
                seed,
                &interop_trust,
                true,
                interop_control.clone(),
            ) {
                Ok(recomposed) => {
                    *interop_current.write().unwrap() = Arc::new(recomposed);
                    json_response(200, json!({"hold": true}))
                }
                Err(error) => json_response(500, json!({"error": error.to_string()})),
            },
            ("POST", "/converse") => match handle_converse(
                &request,
                &interop_root,
                seed,
                &interop_trust,
                &interop_control,
                &interop_current,
                &interop_api,
            ) {
                Ok(result) => json_response(200, result),
                Err(error) => json_response(500, json!({"error": error.to_string()})),
            },
            _ => json_response(404, json!({"error":"not_found"})),
        }
    })?;

    // Prepare temporary Go driver workspace without mutating `go_ref`.
    let driver_dir = root.join("go-driver");
    fs::create_dir_all(&driver_dir)?;
    let go_mod_src = fs::read_to_string(go_ref.join("go.mod"))?;
    let rewritten_mod = go_mod_src.replacen(
        "module gitlab.com/sidecat-dev/aauth-go",
        "module aauth-r3-interop",
        1,
    );
    let driver_go_mod = format!(
        "{rewritten_mod}\nrequire gitlab.com/sidecat-dev/aauth-go v0.0.0\n\nreplace gitlab.com/sidecat-dev/aauth-go => {}\n",
        go_ref.display()
    );
    fs::write(driver_dir.join("go.mod"), driver_go_mod)?;
    if go_ref.join("go.sum").is_file() {
        fs::copy(go_ref.join("go.sum"), driver_dir.join("go.sum"))?;
    }
    fs::write(driver_dir.join("main.go"), DRIVER_GO)?;
    let config_path = driver_dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "ap_addr": ap_tls.address().to_string(),
            "ap_cert_pem": ap_tls.cert_pem(),
            "ps_addr": ps_tls.address().to_string(),
            "ps_cert_pem": ps_tls.cert_pem(),
            "records_addr": api.address().to_string(),
            "records_cert_pem": api.cert_pem(),
            "interop_addr": interop_tls.address().to_string(),
            "interop_cert_pem": interop_tls.cert_pem(),
            "agent_seed_hex": hex_encode(&agent_seed),
            "agent_token": agent_token,
            "initial_now": issued,
        })
        .to_string(),
    )?;

    let output = Command::new("go")
        .args(["run", "-mod=readonly", ".", "config.json"])
        .current_dir(&driver_dir)
        .output();
    let _ = fs::remove_dir_all(&root);
    let output = output?;
    if !output.status.success() {
        return Err(format!(
            "go interop driver failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let raw: Value = serde_json::from_slice(output.stdout.trim_ascii())?;
    let t = InteropTranscript {
        go_to_rust_person_token_issued: raw["go_to_rust_person_token_issued"]
            .as_bool()
            .unwrap_or(false),
        go_to_rust_class_read_status: number(&raw, "go_to_rust_class_read_status")? as u16,
        go_to_rust_401_challenge_status: number(&raw, "go_to_rust_401_challenge_status")? as u16,
        go_to_rust_approval_expiry_error: text(&raw, "go_to_rust_approval_expiry_error")?,
        go_to_rust_approval_replacement_reused_without_reprompt: raw
            ["go_to_rust_approval_replacement_reused_without_reprompt"]
            .as_bool()
            .unwrap_or(false),
        go_to_rust_substituted_parameters_status: number(
            &raw,
            "go_to_rust_substituted_parameters_status",
        )? as u16,
        go_to_rust_ps_denied_other_record_status: number(
            &raw,
            "go_to_rust_ps_denied_other_record_status",
        )? as u16,
        go_to_rust_401_retry_status: number(&raw, "go_to_rust_401_retry_status")? as u16,
        go_to_rust_401_replay_status: number(&raw, "go_to_rust_401_replay_status")? as u16,
        go_to_rust_401_replay_matches_first: raw["go_to_rust_401_replay_matches_first"]
            .as_bool()
            .unwrap_or(false),
        go_to_rust_202_held_status: number(&raw, "go_to_rust_202_held_status")? as u16,
        go_to_rust_202_foreign_token_status: number(
            &raw,
            "go_to_rust_202_foreign_token_status",
        )? as u16,
        go_to_rust_202_poll_status: number(&raw, "go_to_rust_202_poll_status")? as u16,
        go_to_rust_202_replay_status: number(&raw, "go_to_rust_202_replay_status")? as u16,
        go_to_rust_release_held_status: number(&raw, "go_to_rust_release_held_status")? as u16,
        go_to_rust_release_poll_status: number(&raw, "go_to_rust_release_poll_status")? as u16,
        go_to_rust_release_replay_status: number(&raw, "go_to_rust_release_replay_status")?
            as u16,
        go_to_rust_query_runs: number(&raw, "go_to_rust_query_runs")? as usize,
        release_retry_expiry_error: text(&raw, "release_retry_expiry_error")?,
        release_retry_reused_without_reprompt: raw["release_retry_reused_without_reprompt"]
            .as_bool()
            .unwrap_or(false),
        release_retry_runs_before_challenge: number(&raw, "release_retry_runs_before_challenge")?
            as usize,
        release_retry_runs_after_challenge: number(&raw, "release_retry_runs_after_challenge")?
            as usize,
        release_retry_poll_status: number(&raw, "release_retry_poll_status")? as u16,
        release_retry_old_pending_status: number(&raw, "release_retry_old_pending_status")? as u16,
        release_retry_body_matches_original: raw["release_retry_body_matches_original"]
            .as_bool()
            .unwrap_or(false),
        rust_to_go_person_status: number(&raw, "rust_to_go_person_status")? as u16,
        rust_to_go_class_exchange_status: number(&raw, "rust_to_go_class_exchange_status")?
            as u16,
        rust_to_go_ps_fetched_document: raw["rust_to_go_ps_fetched_document"]
            .as_bool()
            .unwrap_or(false),
        rust_to_go_ps_issuance_records: number(&raw, "rust_to_go_ps_issuance_records")? as usize,
        rust_to_go_class_read_status: number(&raw, "rust_to_go_class_read_status")? as u16,
        rust_to_go_ungranted_delete_status: number(&raw, "rust_to_go_ungranted_delete_status")?
            as u16,
        rust_to_go_proposal_exchange_status: number(
            &raw,
            "rust_to_go_proposal_exchange_status",
        )? as u16,
        rust_to_go_proposal_exchange_error: text(&raw, "rust_to_go_proposal_exchange_error")?,
        reads: number(&raw, "reads")? as usize,
        deletes: serde_json::from_value(
            raw.get("deletes").cloned().ok_or("missing deletes")?,
        )?,
        rust_ps_audit_records: number(&raw, "rust_ps_audit_records")? as usize,
    };

    if !t.go_to_rust_person_token_issued
        || t.go_to_rust_class_read_status != 200
        || t.go_to_rust_401_challenge_status != 401
        || t.go_to_rust_approval_expiry_error != "expired_presented_token"
        || !t.go_to_rust_approval_replacement_reused_without_reprompt
        || t.go_to_rust_substituted_parameters_status != 403
        || t.go_to_rust_ps_denied_other_record_status != 403
        || t.go_to_rust_401_retry_status != 200
        || t.go_to_rust_401_replay_status != 200
        || !t.go_to_rust_401_replay_matches_first
        || t.go_to_rust_202_held_status != 202
        || t.go_to_rust_202_foreign_token_status != 403
        || t.go_to_rust_202_poll_status != 200
        || t.go_to_rust_202_replay_status != 200
        || t.go_to_rust_release_held_status != 202
        || t.go_to_rust_release_poll_status != 200
        || t.go_to_rust_release_replay_status != 200
        || t.go_to_rust_query_runs != 2
        || t.release_retry_expiry_error != "expired_presented_token"
        || !t.release_retry_reused_without_reprompt
        || t.release_retry_runs_after_challenge != t.release_retry_runs_before_challenge
        || t.release_retry_poll_status != 200
        || t.release_retry_old_pending_status != 403
        || !t.release_retry_body_matches_original
        || t.rust_to_go_person_status != 200
        || t.rust_to_go_class_exchange_status != 200
        || !t.rust_to_go_ps_fetched_document
        || t.rust_to_go_ps_issuance_records != 1
        || t.rust_to_go_class_read_status != 200
        || t.rust_to_go_ungranted_delete_status != 403
        || t.rust_to_go_proposal_exchange_status != 400
        || t.rust_to_go_proposal_exchange_error != "invalid_resource_token"
        || t.reads != 2
        || t.deletes != vec![r#""r-1""#.to_owned(), r#""r-1""#.to_owned()]
        || t.rust_ps_audit_records != 8
    {
        return Err(format!("unexpected cross-language interop transcript: {t:?}").into());
    }

    Ok(t)
}
