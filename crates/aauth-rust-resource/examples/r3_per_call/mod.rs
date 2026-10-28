//! Real TLS per-call R3: Rust Agent, Rust Person Server, Rust Resource.
//!
//! The class grant serves `records.read` and leaves `records.delete` per call.
//! A delete is challenged with a proposal for that concrete record. The PS
//! fetches it, applies parameter-sensitive consent and issues a one-operation
//! token. The call then completes once, first by `401` retry and then, after
//! the Resource is recomposed from its files, by a `202` held invocation.
//! Every refusal is checked against explicit application-effect counters.
//!
//! `records.query` is side-effect free and also per call. Under `202` the
//! Resource runs it before approval and proposes release of its result
//! (`draft-hardt-aauth-r3`, Approving Release Rather Than Execution): the PS
//! routes that proposal to release consent, and the stored result is released
//! once at the pending URL without recomputation. Deletion is never run first.
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
    OperationSet, Parameter, Parameters, PresentedParameter, ProposalDisplay, ProposalResult,
    Reference, Registry, ToolsListPage, ToolsListSnapshot, digest, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthPolicy, BoxedR3Release, PsAuthorizationConfig, PsAuthorizationResource,
    R3CallDescription, R3CallResult, R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord,
    R3DocumentStore, R3HeldRequest, R3HostError, R3PerCallConfig, R3ProposalRecord, R3Release,
    R3StoreError, R3Vocabulary,
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
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const RECORDS: &str = "https://records.example";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}},{"name":"records.query","inputSchema":{"type":"object"}}]}"#;
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
    /// Query computations, counted by the host release callback.
    pub query_runs: usize,
    /// Consent methods the PS called, in order: `execution` or `release`.
    pub consents: Vec<String>,
    /// `result` members the PS saw on the first release proposal.
    pub release_result_seen: String,
    pub release_held_status: u16,
    pub release_runs_at_challenge: usize,
    pub release_denied_ps_status: u16,
    pub declined_pending_status: u16,
    pub release_mismatch_status: u16,
    pub release_at_route_status: u16,
    pub release_status: u16,
    pub release_body: String,
    pub release_replay_status: u16,
    pub release_replay_matches: bool,
    pub release_runs_after_completion: usize,
    pub release_claim_consumed: bool,
    pub expired_presented_status: u16,
    pub expired_presented_error: String,
    pub substituted_replacement_ps_status: u16,
    pub replacement_approval_status: u16,
    pub replacement_consents_delta: usize,
    pub replacement_retry_status: u16,
    pub replacement_replay_status: u16,
    pub replacement_replay_matches: bool,
    pub consumed_approval_reprompted: bool,
    pub expired_per_call_status: u16,
    pub expired_per_call_error: String,
    pub release_expired_presented_status: u16,
    pub release_expired_presented_error: String,
    pub release_old_pending_expired_class_status: u16,
    pub release_old_pending_refreshed_class_status: u16,
    pub release_replacement_approval_status: u16,
    pub release_replacement_consents_delta: usize,
    pub release_old_pending_with_replacement_status: u16,
    pub release_replacement_status: u16,
    pub release_replacement_replay_status: u16,
    pub release_replacement_replay_matches: bool,
    pub release_expired_token_status: u16,
    pub release_expired_token_error: String,
    pub expired_recorded_approval_reprompted: bool,
    /// Release retry: query computations caused by re-requesting the held call.
    pub release_runs_at_replacement_challenge: usize,
    /// Query computations of the r-1 call from its original challenge through
    /// replacement release and replay; the r-2 control's own run is excluded.
    pub release_runs_since_original_challenge: usize,
    /// The replacement release is the original challenge's computation.
    pub release_replacement_body_matches_original: bool,
    /// The class token at the replacement pending URL before PS approval.
    pub release_poll_before_approval_status: u16,
    /// Changed parameters while the r-1 response is held: a fresh challenge.
    pub release_changed_params_runs_delta: usize,
    pub release_changed_params_ps_status: u16,
    /// Re-request after an expired recorded approval still reuses the held response.
    pub release_expired_approval_reuse_runs_delta: usize,
    /// Re-request past the held response's horizon: a fresh challenge and consent.
    pub release_expired_held_runs_delta: usize,
    pub release_expired_held_reprompted: bool,
    /// Supersede without expiry: the same call re-sent with the same class token.
    pub release_supersede_status: u16,
    pub release_supersede_runs_delta: usize,
    pub release_superseded_poll_status: u16,
    pub release_superseded_runs_delta: usize,
    /// Completion after `release_until` while the per-call token is unexpired.
    pub release_horizon_status: u16,
    pub release_horizon_error: String,
    pub release_horizon_runs_delta: usize,
    /// Recompute inside `[release_until, recorded-approval expiry)`.
    pub release_fresh_runs_delta: usize,
    pub release_fresh_consents_delta: usize,
    pub release_fresh_body_is_new: bool,
    pub release_successor_status: u16,
    pub release_successor_body_matches_original: bool,
    pub release_successor_runs_delta: usize,
}

/// Adversarial admission paths exercised over the same real TLS roles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionCase {
    HeldPolicy,
    #[allow(
        dead_code,
        reason = "Constructed by the policy-race integration control."
    )]
    Revocation,
    #[allow(
        dead_code,
        reason = "Constructed by the claim-race integration control."
    )]
    ClaimRevocation,
    /// Release gating: consent, denial, mismatch, single use and replay.
    Release,
    /// Revocation completed during host policy on a release completion.
    #[allow(
        dead_code,
        reason = "Constructed by the release policy-race integration control."
    )]
    ReleaseRevocation,
    /// Revocation completed during the store claim on a release completion.
    #[allow(
        dead_code,
        reason = "Constructed by the release claim-race integration control."
    )]
    ReleaseClaimRevocation,
    /// Presented class token expiry during approval, top-down refresh,
    /// single-use recorded-approval replacement, and expired-approval refusal.
    #[allow(
        dead_code,
        reason = "Constructed by the approval-expiry integration control."
    )]
    ApprovalExpiry,
    /// Release gating: a live same-token resubmit must not retire the in-flight
    /// challenge. The second call is a new computation.
    #[allow(
        dead_code,
        reason = "Constructed by the release-supersede integration control."
    )]
    ReleaseSupersede,
    /// Completion refuses once `release_until` has passed, even if the
    /// per-call Auth token is still unexpired.
    #[allow(
        dead_code,
        reason = "Constructed by the held-result horizon integration control."
    )]
    ReleaseHorizon,
    /// After the held result expires, a still-live recorded approval can
    /// release a freshly computed body. This is the unresolved D2 gap.
    #[allow(
        dead_code,
        reason = "Constructed by the fresh-bytes-under-prior-consent control."
    )]
    ReleaseFreshConsent,
}

#[derive(Default)]
struct AdmissionControl {
    deny_delete: AtomicBool,
    revocation: bool,
    barrier: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    claim_barrier: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    /// Release-callback computations of `records.query`.
    query_runs: AtomicUsize,
    /// PS consent methods called, and the first release `result` seen.
    consents: Mutex<Vec<String>>,
    release_result: Mutex<String>,
    /// Clock offset in seconds for deterministic expiry controls.
    clock_offset: AtomicI64,
    /// Optional lifetime override for the next class grant at the PS.
    next_class_lifetime: AtomicI64,
    /// Optional clock advance (seconds) during the next PS approval callback.
    advance_on_approval: AtomicI64,
    /// Optional lifetime override for the next per-call approval at the PS.
    next_proposal_lifetime: AtomicI64,
    /// Held-result retention in seconds. Zero selects the 300-second default.
    held_result_lifetime: AtomicI64,
    /// After the successor record is created, the next tombstone write fails.
    fail_supersede_tombstone: AtomicBool,
}
impl AdmissionControl {
    fn now(&self) -> i64 {
        now() + self.clock_offset.load(Ordering::SeqCst)
    }
    fn admit(&self, token: &VerifiedAuthToken, request: &Request<Vec<u8>>) -> bool {
        let barrier = self.barrier.lock().unwrap().take();
        if let Some((entered, released)) = barrier
            && (entered.send(()).is_err() || released.recv_timeout(Duration::from_secs(2)).is_err())
        {
            return false;
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
    post_at(agent, uri, body, now())
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
/// The `query_run_seq` a released query response was computed as.
fn query_run_seq(response: &Response<Vec<u8>>) -> Option<usize> {
    serde_json::from_slice::<Value>(response.body())
        .ok()?
        .get("query_run_seq")?
        .as_u64()
        .and_then(|seq| usize::try_from(seq).ok())
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

/// Exact class documents, one file per URI, never overwritten.
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

/// Claim digest of a superseded release's tombstone. It is never a SHA-256
/// digest in base64url, so every later claim on that record is `DifferentToken`.
const SUPERSEDED: &str = "(superseded)";

/// Proposals, pending ids, claims and retained results. Create-only records;
/// one claim file per proposal, bound once and never re-opened for execution.
/// A superseded release is retired by a tombstone claim file.
struct FileCalls(PathBuf, Mutex<()>, Arc<AdmissionControl>);
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
    /// Drop a successor that must not remain if retiring `prior` fails.
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
                // Optional control pauses after binding the claim, before the host
                // callback returns Execute. Revocation must suppress release without
                // rolling back that durable binding or dispatching the application.
                let barrier = self.2.claim_barrier.lock().unwrap().take();
                if let Some((entered, released)) = barrier {
                    entered.send(()).map_err(unavailable)?;
                    released
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(unavailable)?;
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
        // Successor first. A crash before the tombstone leaves `prior` usable.
        // A tombstone failure rolls the successor back so the retry still
        // finds the original held bytes and does not recompute.
        if let Err(error) = self.create(record) {
            self.remove_successor(record);
            return Err(error);
        }
        if self
            .2
            .fail_supersede_tombstone
            .swap(false, Ordering::SeqCst)
        {
            self.remove_successor(record);
            return Err(unavailable("injected tombstone failure"));
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

/// Demonstration consent: read is granted; delete and query are per call.
/// Execution of a delete, and release of a query result, are approved only
/// for record `r-1`, after inspecting the proposal's parameters. The two are
/// separate decisions and each is recorded.
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
        // Execution consent never covers a computed result.
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
        let lifetime = match self.0.next_proposal_lifetime.swap(0, Ordering::SeqCst) {
            0 => 300,
            override_lifetime => override_lifetime,
        };
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime,
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
        let mut seen = self.0.release_result.lock().unwrap();
        if seen.is_empty() {
            *seen = String::from_utf8_lossy(&result.json()).into_owned();
        }
        if !record_r1(request) || request.core.resource.claims().iss != RECORDS {
            return Err(PolicyError::Denied);
        }
        let advance = self.0.advance_on_approval.swap(0, Ordering::SeqCst);
        if advance > 0 {
            self.0.clock_offset.fetch_add(advance, Ordering::SeqCst);
        }
        let lifetime = match self.0.next_proposal_lifetime.swap(0, Ordering::SeqCst) {
            0 => 300,
            override_lifetime => override_lifetime,
        };
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime,
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

// ---- Resource composition ---------------------------------------------------

type Resource = PsAuthorizationResource<Trust, BoxedAuthPolicy>;
fn record_parameter(request: &Request<Vec<u8>>) -> std::result::Result<Vec<u8>, R3HostError> {
    let value: Value =
        serde_json::from_slice(request.body()).map_err(|e| R3HostError::new(e.to_string()))?;
    let record = value
        .get("record")
        .ok_or_else(|| R3HostError::new("call names no record"))?;
    serde_json::to_vec(record).map_err(|e| R3HostError::new(e.to_string()))
}
/// Release gating for `records.query`: nothing outside the result changes
/// when it runs (no audit, meter, bill or call to another party), so the
/// Resource runs it now and proposes release. Every other operation keeps
/// execution approval.
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
        // Only a held Resource gates release. Deletion changes state outside
        // its result and is never executed before approval.
        release: hold.then(|| query_release(control.clone())),
        held_result_lifetime: match control.held_result_lifetime.load(Ordering::SeqCst) {
            0 => 300,
            lifetime => lifetime,
        },
    })?;
    Ok(if control.revocation {
        resource.with_revocation()
    } else {
        resource
    })
}

/// The application: one effect per admitted call, recorded by the host.
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
    if path == "/revoke" {
        return resource.revoke(&request, clock);
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
    control: &AdmissionControl,
) -> Result<String> {
    let operations = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [
            {"tool":"records.read"},{"tool":"records.delete"},{"tool":"records.query"}
        ]})
        .to_string()
        .as_bytes(),
    )?;
    let clock = control.now();
    let resource_token = agent.r3_authorize(
        |request| api.send(&request),
        &format!("{RECORDS}/authorize"),
        person,
        &operations,
        None,
        clock,
    )?;
    let verified =
        agent.verify_r3_resource_token(&resource_token, RECORDS, PS, person, None, trust, clock)?;
    let body = json!({"resource_token": resource_token, "presented_token": person});
    let response = ps.send(&post_at(
        agent,
        &format!("{PS}/token"),
        body.to_string().as_bytes(),
        clock,
    )?)?;
    let auth = member(&response, "auth_token").ok_or("class grant refused")?;
    agent.verify_r3_auth_delivery(&auth, RECORDS, &verified, person, registry, trust, clock)?;
    Ok(auth)
}

/// The per-call challenge's PS exchange; returns the PS response.
fn approve(
    agent: &Agent,
    ps: &TlsServer,
    resource_token: &str,
    class: &str,
    control: &AdmissionControl,
) -> Result<Response<Vec<u8>>> {
    let body = json!({"resource_token": resource_token, "presented_token": class});
    ps.send(&post_at(
        agent,
        &format!("{PS}/token"),
        body.to_string().as_bytes(),
        control.now(),
    )?)
}

#[allow(
    dead_code,
    reason = "Shared entry point used by the ordinary example and TLS test."
)]
pub fn run() -> Result<Transcript> {
    run_case(None)
}

#[allow(
    dead_code,
    reason = "Shared entry point used by the admission integration tests."
)]
pub fn run_admission_case(case: AdmissionCase) -> Result<Transcript> {
    run_case(Some(case))
}

fn run_case(case: Option<AdmissionCase>) -> Result<Transcript> {
    let control = Arc::new(AdmissionControl {
        revocation: matches!(
            case,
            Some(
                AdmissionCase::Revocation
                    | AdmissionCase::ClaimRevocation
                    | AdmissionCase::ReleaseRevocation
                    | AdmissionCase::ReleaseClaimRevocation
            )
        ),
        ..AdmissionControl::default()
    });
    let mut t = Transcript::default();
    let trust = Trust::default();
    let registry = standard_registry()?;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("aauth-r3-per-call-{}-{nanos}", std::process::id()));
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
        "/.well-known/aauth-agent.json" => json_response(
            200,
            serde_json::from_slice(&serving.metadata().unwrap()).unwrap(),
        ),
        "/.well-known/jwks.json" => json_response(
            200,
            serde_json::from_slice(&serving.jwks().unwrap()).unwrap(),
        ),
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, AP, "aauth-agent.json")?;

    // Resource: swappable instance over one custody directory.
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
    let (serving, serving_effects, serving_control) =
        (current.clone(), effects.clone(), control.clone());
    let api = Arc::new(TlsServer::start("records.example", move |request| {
        let resource = serving.read().unwrap().clone();
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
    // Fixture key retained only to sign the genuine PS revocation control.
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

    let person = member(
        &ps_tls.send(&post(
            &agent,
            &format!("{PS}/person"),
            json!({"resource": RECORDS}).to_string().as_bytes(),
        )?)?,
        "person_token",
    )
    .ok_or("person token refused")?;
    let class = class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
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
    let approved = approve(&agent, &ps_tls, &proposal_token, &class, &control)?;
    let per_call = member(&approved, "auth_token").ok_or("per-call approval refused")?;
    let delivered = agent.verify_r3_per_call_delivery(
        &per_call,
        RECORDS,
        &proposal,
        &class,
        &registry,
        &trust,
        now(),
    )?;
    t.proposal_operation = delivered
        .operations()
        .granted_operations()
        .operations()?
        .first()
        .map(|operation| {
            operation
                .json()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        })
        .transpose()?
        .unwrap_or_default();
    let completing = agent.with_token(per_call.clone())?;
    // Substituted parameters are refused before any claim.
    t.substituted_parameters_status = api
        .send(&post(
            &completing,
            &format!("{RECORDS}/records/delete"),
            R2,
        )?)?
        .status()
        .as_u16();
    // A different holder presenting the per-call token fails its proof.
    let mut stolen = Request::builder()
        .method("POST")
        .uri(format!("{RECORDS}/records/delete"))
        .header("content-type", "application/json")
        .body(R1.to_vec())?;
    sign_request(
        &mut stolen,
        &SigningKey::generate(),
        KeyMaterial::Jwt(per_call.clone()),
        now(),
    )?;
    t.wrong_holder_status = api.send(&stolen)?.status().as_u16();
    // The approved call runs once; the same exact token is answered from the retained result.
    let retry = post(&completing, &format!("{RECORDS}/records/delete"), R1)?;
    let first = api.send(&retry)?;
    t.retry_status = first.status().as_u16();
    let replay = api.send(&post(
        &completing,
        &format!("{RECORDS}/records/delete"),
        R1,
    )?)?;
    t.replay_status = replay.status().as_u16();
    t.replay_matches_first = replay.body() == first.body();

    // Recompose the Resource from its files, now holding invocations (202).
    *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, true, control.clone())?);
    t.replay_after_restart_status = api
        .send(&post(
            &completing,
            &format!("{RECORDS}/records/delete"),
            R1,
        )?)?
        .status()
        .as_u16();

    // Parameter-sensitive consent: the PS refuses a proposal for another record.
    let other = api.send(&post(&holder, &format!("{RECORDS}/records/delete"), R2)?)?;
    let other_token = challenge(&other)?;
    t.denied_parameters_ps_status = approve(&agent, &ps_tls, &other_token, &class, &control)?
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
    let held_grant = member(
        &approve(&agent, &ps_tls, &held_token, &class, &control)?,
        "auth_token",
    )
    .ok_or("held approval refused")?;
    agent.verify_r3_per_call_delivery(
        &held_grant,
        RECORDS,
        &held_proposal,
        &class,
        &registry,
        &trust,
        now(),
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
            .claim_path(held_proposal.reference().uri())
            .exists();
        control.deny_delete.store(false, Ordering::SeqCst);
        poller.sign(&mut poll, now())?;
    }
    t.held_completion_status = api.send(&poll)?.status().as_u16();
    let mut again = get(&location)?;
    poller.sign(&mut again, now())?;
    t.held_replay_status = api.send(&again)?.status().as_u16();

    if case == Some(AdmissionCase::Release) {
        // Release gating (202): the query runs once at the challenge.
        let runs = || control.query_runs.load(Ordering::SeqCst);
        let before = runs();
        let held = api.send(&post(&holder, &format!("{RECORDS}/records/query"), R1)?)?;
        t.release_held_status = held.status().as_u16();
        t.release_runs_at_challenge = runs() - before;
        let location = held.headers()["location"].to_str()?.to_owned();
        let release_token = challenge(&held)?;
        let release_proposal = agent.verify_r3_proposal_challenge(
            &release_token,
            RECORDS,
            PS,
            &class,
            &trust,
            now(),
        )?;

        // Denial: release of another record's result is refused at the PS, and
        // the class token at that pending URL releases nothing.
        let other = api.send(&post(&holder, &format!("{RECORDS}/records/query"), R2)?)?;
        let other_location = other.headers()["location"].to_str()?.to_owned();
        let other_token = challenge(&other)?;
        t.release_denied_ps_status = approve(&agent, &ps_tls, &other_token, &class, &control)?
            .status()
            .as_u16();
        let mut declined = get(&other_location)?;
        holder.sign(&mut declined, now())?;
        t.declined_pending_status = api.send(&declined)?.status().as_u16();

        // Release consent for record r-1.
        let release_grant = member(
            &approve(&agent, &ps_tls, &release_token, &class, &control)?,
            "auth_token",
        )
        .ok_or("release approval refused")?;
        agent.verify_r3_per_call_delivery(
            &release_grant,
            RECORDS,
            &release_proposal,
            &class,
            &registry,
            &trust,
            now(),
        )?;
        let releasing = agent.with_token(release_grant)?;
        // Mismatch: this approval is not the r-2 proposal's, and a held
        // invocation never completes by re-sending the call.
        let mut mismatched = get(&other_location)?;
        releasing.sign(&mut mismatched, now())?;
        t.release_mismatch_status = api.send(&mismatched)?.status().as_u16();
        t.release_at_route_status = api
            .send(&post(&releasing, &format!("{RECORDS}/records/query"), R1)?)?
            .status()
            .as_u16();

        // Single use: the stored result is released, then answered again
        // identically; nothing is recomputed.
        let computed = runs();
        let mut poll = get(&location)?;
        releasing.sign(&mut poll, now())?;
        let first = api.send(&poll)?;
        t.release_status = first.status().as_u16();
        t.release_body = String::from_utf8_lossy(first.body()).into_owned();
        let mut again = get(&location)?;
        releasing.sign(&mut again, now())?;
        let replay = api.send(&again)?;
        t.release_replay_status = replay.status().as_u16();
        t.release_replay_matches = replay.body() == first.body();
        t.release_runs_after_completion = runs() - computed;
        t.release_claim_consumed = FileCalls(root.clone(), Mutex::new(()), control.clone())
            .claim_path(release_proposal.reference().uri())
            .exists();
    }

    if case == Some(AdmissionCase::ReleaseSupersede) {
        // A live same-token duplicate must not tombstone the in-flight challenge.
        let runs = || control.query_runs.load(Ordering::SeqCst);
        let first = api.send(&post(&holder, &format!("{RECORDS}/records/query"), R1)?)?;
        let original_runs = runs();
        let first_location = first.headers()["location"].to_str()?.to_owned();
        let first_token = challenge(&first)?;
        let first_proposal =
            agent.verify_r3_proposal_challenge(&first_token, RECORDS, PS, &class, &trust, now())?;
        let duplicate = api.send(&post(&holder, &format!("{RECORDS}/records/query"), R1)?)?;
        t.release_supersede_status = duplicate.status().as_u16();
        t.release_supersede_runs_delta = runs() - original_runs;
        let first_grant = member(
            &approve(&agent, &ps_tls, &first_token, &class, &control)?,
            "auth_token",
        )
        .ok_or("live challenge approval refused")?;
        agent.verify_r3_per_call_delivery(
            &first_grant,
            RECORDS,
            &first_proposal,
            &class,
            &registry,
            &trust,
            now(),
        )?;
        let first_holder = agent.with_token(first_grant)?;
        let before_poll = runs();
        let mut poll_first = get(&first_location)?;
        first_holder.sign(&mut poll_first, now())?;
        let released = api.send(&poll_first)?;
        t.release_superseded_poll_status = released.status().as_u16();
        t.release_superseded_runs_delta = runs() - before_poll;
        t.release_successor_body_matches_original =
            query_run_seq(&released) == Some(original_runs);
        t.release_successor_status = released.status().as_u16();
        t.release_successor_runs_delta = runs() - original_runs;
    }

    if case == Some(AdmissionCase::ReleaseHorizon) {
        control.held_result_lifetime.store(15, Ordering::SeqCst);
        *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, true, control.clone())?);
        let class = class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let holder = agent.with_token(class.clone())?;
        let runs = || control.query_runs.load(Ordering::SeqCst);
        let held = api.send(&post_at(
            &holder,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        let before = runs();
        let location = held.headers()["location"].to_str()?.to_owned();
        let proposal_token = challenge(&held)?;
        control.next_proposal_lifetime.store(300, Ordering::SeqCst);
        let approved = approve(&agent, &ps_tls, &proposal_token, &class, &control)?;
        let grant = member(&approved, "auth_token").ok_or("horizon approval refused")?;
        let completing = agent.with_token(grant)?;
        control.clock_offset.fetch_add(20, Ordering::SeqCst);
        let mut poll = get(&location)?;
        completing.sign(&mut poll, control.now())?;
        let response = api.send(&poll)?;
        t.release_horizon_status = response.status().as_u16();
        t.release_horizon_error = response
            .headers()
            .get("signature-error")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        t.release_horizon_runs_delta = runs() - before;
    }

    if case == Some(AdmissionCase::ReleaseFreshConsent) {
        // Held result lasts 10s. Class token lasts 8s, so approval records
        // `expired_presented_token`. Approval lifetime is 120s. The re-request
        // is after `release_until` and before that approval expires.
        control.held_result_lifetime.store(10, Ordering::SeqCst);
        control.next_class_lifetime.store(8, Ordering::SeqCst);
        *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, true, control.clone())?);
        let short = class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let holder = agent.with_token(short.clone())?;
        let runs = || control.query_runs.load(Ordering::SeqCst);
        let held = api.send(&post_at(
            &holder,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        let original_runs = runs();
        let proposal_token = challenge(&held)?;
        control.advance_on_approval.store(9, Ordering::SeqCst);
        control.next_proposal_lifetime.store(120, Ordering::SeqCst);
        let expired = approve(&agent, &ps_tls, &proposal_token, &short, &control)?;
        if expired.status().as_u16() != 400 {
            return Err(format!("expected recorded expiry, got {}", expired.status()).into());
        }
        control.clock_offset.fetch_add(5, Ordering::SeqCst);
        let refreshed = class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let refreshed_holder = agent.with_token(refreshed.clone())?;
        let before = runs();
        let again = api.send(&post_at(
            &refreshed_holder,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        t.release_fresh_runs_delta = runs() - before;
        let again_token = challenge(&again)?;
        let consents_before = control.consents.lock().unwrap().len();
        let approved = approve(&agent, &ps_tls, &again_token, &refreshed, &control)?;
        t.release_fresh_consents_delta = control.consents.lock().unwrap().len() - consents_before;
        let grant = member(&approved, "auth_token").ok_or("fresh approval refused")?;
        let completing = agent.with_token(grant)?;
        let location = again.headers()["location"].to_str()?.to_owned();
        let mut poll = get(&location)?;
        completing.sign(&mut poll, control.now())?;
        let released = api.send(&poll)?;
        t.release_fresh_body_is_new = query_run_seq(&released) != Some(original_runs)
            && query_run_seq(&released).is_some();
    }

    if case == Some(AdmissionCase::ApprovalExpiry) {
        // 1. 401 retry: class token expires during PS approval (`expired_presented_token`),
        //    Agent refreshes top-down and resubmits, PS applies the recorded approval once.
        *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, false, control.clone())?);
        control.next_class_lifetime.store(5, Ordering::SeqCst);
        let short_class =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let short_holder = agent.with_token(short_class.clone())?;
        let challenged_1 = api.send(&post_at(
            &short_holder,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        let proposal_token_1 = challenge(&challenged_1)?;
        agent.verify_r3_proposal_challenge(
            &proposal_token_1,
            RECORDS,
            PS,
            &short_class,
            &trust,
            control.now(),
        )?;
        control.advance_on_approval.store(6, Ordering::SeqCst);
        control.next_proposal_lifetime.store(20, Ordering::SeqCst);
        let expired_response =
            approve(&agent, &ps_tls, &proposal_token_1, &short_class, &control)?;
        t.expired_presented_status = expired_response.status().as_u16();
        t.expired_presented_error = member(&expired_response, "error").unwrap_or_default();

        // Top-down refresh: fresh class token at current time.
        let refreshed_class =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let refreshed_holder = agent.with_token(refreshed_class.clone())?;

        // Negative control: a different record (r-2) does not match the recorded r-1 approval.
        let other_challenged = api.send(&post_at(
            &refreshed_holder,
            &format!("{RECORDS}/records/delete"),
            R2,
            control.now(),
        )?)?;
        let other_proposal_token = challenge(&other_challenged)?;
        t.substituted_replacement_ps_status = approve(
            &agent,
            &ps_tls,
            &other_proposal_token,
            &refreshed_class,
            &control,
        )?
        .status()
        .as_u16();

        // Resubmit the r-1 call; the PS applies the recorded approval without calling consent again.
        let challenged_2 = api.send(&post_at(
            &refreshed_holder,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        let proposal_token_2 = challenge(&challenged_2)?;
        let proposal_2 = agent.verify_r3_proposal_challenge(
            &proposal_token_2,
            RECORDS,
            PS,
            &refreshed_class,
            &trust,
            control.now(),
        )?;
        let consents_before = control.consents.lock().unwrap().len();
        let replacement_approved = approve(
            &agent,
            &ps_tls,
            &proposal_token_2,
            &refreshed_class,
            &control,
        )?;
        t.replacement_approval_status = replacement_approved.status().as_u16();
        t.replacement_consents_delta = control.consents.lock().unwrap().len() - consents_before;
        let replacement_token =
            member(&replacement_approved, "auth_token").ok_or("replacement approval refused")?;
        agent.verify_r3_per_call_delivery(
            &replacement_token,
            RECORDS,
            &proposal_2,
            &refreshed_class,
            &registry,
            &trust,
            control.now(),
        )?;
        let replacement_completing = agent.with_token(replacement_token)?;
        let retry_first = api.send(&post_at(
            &replacement_completing,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        t.replacement_retry_status = retry_first.status().as_u16();
        let retry_replay = api.send(&post_at(
            &replacement_completing,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        t.replacement_replay_status = retry_replay.status().as_u16();
        t.replacement_replay_matches = retry_replay.body() == retry_first.body();

        // Negative control: the recorded approval is single-use; a new r-1 challenge prompts consent again.
        let challenged_3 = api.send(&post_at(
            &refreshed_holder,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        let proposal_token_3 = challenge(&challenged_3)?;
        let consents_before_second = control.consents.lock().unwrap().len();
        let _ = approve(
            &agent,
            &ps_tls,
            &proposal_token_3,
            &refreshed_class,
            &control,
        )?;
        t.consumed_approval_reprompted =
            control.consents.lock().unwrap().len() == consents_before_second + 1;

        // Negative control: an expired per-call Auth token is refused before policy, claim or replay.
        control.clock_offset.fetch_add(25, Ordering::SeqCst);
        let expired_retry = api.send(&post_at(
            &replacement_completing,
            &format!("{RECORDS}/records/delete"),
            R1,
            control.now(),
        )?)?;
        t.expired_per_call_status = expired_retry.status().as_u16();
        t.expired_per_call_error = expired_retry
            .headers()
            .get("signature-error")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        // 2. 202 release-gating: class token expires during release approval,
        //    original pending URL is refused, re-requested call applies recorded
        //    release approval once, and an expired approval/token releases nothing.
        *current.write().unwrap() = Arc::new(compose(&root, seed, &trust, true, control.clone())?);
        control.next_class_lifetime.store(5, Ordering::SeqCst);
        let short_release_class =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let short_release_holder = agent.with_token(short_release_class.clone())?;
        let runs = || control.query_runs.load(Ordering::SeqCst);
        let old_held = api.send(&post_at(
            &short_release_holder,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        // The held r-1 response is this computation, whose sequence is `original_runs`.
        let original_runs = runs();
        let old_location = old_held.headers()["location"].to_str()?.to_owned();
        let old_release_token = challenge(&old_held)?;
        agent.verify_r3_proposal_challenge(
            &old_release_token,
            RECORDS,
            PS,
            &short_release_class,
            &trust,
            control.now(),
        )?;
        control.advance_on_approval.store(6, Ordering::SeqCst);
        control.next_proposal_lifetime.store(20, Ordering::SeqCst);
        let release_expired = approve(
            &agent,
            &ps_tls,
            &old_release_token,
            &short_release_class,
            &control,
        )?;
        t.release_expired_presented_status = release_expired.status().as_u16();
        t.release_expired_presented_error =
            member(&release_expired, "error").unwrap_or_default();

        let refreshed_release_class =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let refreshed_release_holder = agent.with_token(refreshed_release_class.clone())?;

        // Negative control: polling the original pending URL with the expired or refreshed class token.
        let mut poll_old_expired = get(&old_location)?;
        short_release_holder.sign(&mut poll_old_expired, control.now())?;
        t.release_old_pending_expired_class_status =
            api.send(&poll_old_expired)?.status().as_u16();
        let mut poll_old_refreshed = get(&old_location)?;
        refreshed_release_holder.sign(&mut poll_old_refreshed, control.now())?;
        t.release_old_pending_refreshed_class_status =
            api.send(&poll_old_refreshed)?.status().as_u16();

        // Negative control: changed parameters while the r-1 response is held are a
        // fresh challenge that runs once; release consent refuses r-2.
        let changed_before = runs();
        let changed = api.send(&post_at(
            &refreshed_release_holder,
            &format!("{RECORDS}/records/query"),
            R2,
            control.now(),
        )?)?;
        t.release_changed_params_runs_delta = runs() - changed_before;
        let changed_token = challenge(&changed)?;
        t.release_changed_params_ps_status = approve(
            &agent,
            &ps_tls,
            &changed_token,
            &refreshed_release_class,
            &control,
        )?
        .status()
        .as_u16();

        // Re-request the held query with the refreshed class token: the held
        // response is proposed again without running the query; PS reuses
        // the recorded release approval.
        let replacement_before = runs();
        let new_held = api.send(&post_at(
            &refreshed_release_holder,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        t.release_runs_at_replacement_challenge = runs() - replacement_before;
        let new_location = new_held.headers()["location"].to_str()?.to_owned();
        let new_release_token = challenge(&new_held)?;
        let new_release_proposal = agent.verify_r3_proposal_challenge(
            &new_release_token,
            RECORDS,
            PS,
            &refreshed_release_class,
            &trust,
            control.now(),
        )?;
        // Negative control: the class token at the new pending URL before approval.
        let mut poll_new_early = get(&new_location)?;
        refreshed_release_holder.sign(&mut poll_new_early, control.now())?;
        t.release_poll_before_approval_status = api.send(&poll_new_early)?.status().as_u16();
        let release_consents_before = control.consents.lock().unwrap().len();
        let release_replacement = approve(
            &agent,
            &ps_tls,
            &new_release_token,
            &refreshed_release_class,
            &control,
        )?;
        t.release_replacement_approval_status = release_replacement.status().as_u16();
        t.release_replacement_consents_delta =
            control.consents.lock().unwrap().len() - release_consents_before;
        let release_replacement_grant = member(&release_replacement, "auth_token")
            .ok_or("release replacement approval refused")?;
        agent.verify_r3_per_call_delivery(
            &release_replacement_grant,
            RECORDS,
            &new_release_proposal,
            &refreshed_release_class,
            &registry,
            &trust,
            control.now(),
        )?;
        let release_completing = agent.with_token(release_replacement_grant)?;
        let mut poll_old_with_new = get(&old_location)?;
        release_completing.sign(&mut poll_old_with_new, control.now())?;
        t.release_old_pending_with_replacement_status =
            api.send(&poll_old_with_new)?.status().as_u16();

        let runs_before_poll = control.query_runs.load(Ordering::SeqCst);
        let mut poll_new = get(&new_location)?;
        release_completing.sign(&mut poll_new, control.now())?;
        let release_first = api.send(&poll_new)?;
        t.release_replacement_status = release_first.status().as_u16();
        let mut poll_new_again = get(&new_location)?;
        release_completing.sign(&mut poll_new_again, control.now())?;
        let release_replay = api.send(&poll_new_again)?;
        t.release_replacement_replay_status = release_replay.status().as_u16();
        t.release_replacement_replay_matches = release_replay.body() == release_first.body();
        t.release_runs_after_completion =
            control.query_runs.load(Ordering::SeqCst) - runs_before_poll;
        t.release_replacement_body_matches_original =
            query_run_seq(&release_first) == Some(original_runs);
        t.release_runs_since_original_challenge =
            runs() - original_runs - t.release_changed_params_runs_delta;

        // Negative control: after the release per-call Auth token expires, polling is 401 expired_jwt.
        control.clock_offset.fetch_add(25, Ordering::SeqCst);
        let mut poll_expired = get(&new_location)?;
        release_completing.sign(&mut poll_expired, control.now())?;
        let expired_poll_response = api.send(&poll_expired)?;
        t.release_expired_token_status = expired_poll_response.status().as_u16();
        t.release_expired_token_error = expired_poll_response
            .headers()
            .get("signature-error")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        // Negative control: a recorded approval whose own lifetime expires before replacement
        // is evicted and does not silently authorize disclosure without calling consent again.
        control.next_class_lifetime.store(5, Ordering::SeqCst);
        let short_class_3 =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let short_holder_3 = agent.with_token(short_class_3.clone())?;
        let held_3 = api.send(&post_at(
            &short_holder_3,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        let token_3 = challenge(&held_3)?;
        control.advance_on_approval.store(6, Ordering::SeqCst);
        control.next_proposal_lifetime.store(10, Ordering::SeqCst);
        let _ = approve(&agent, &ps_tls, &token_3, &short_class_3, &control)?;
        // Advance past the recorded approval's 10-second lifetime before submitting replacement.
        control.clock_offset.fetch_add(15, Ordering::SeqCst);
        let fresh_class_3 =
            class_grant(&agent, &person, &api, &ps_tls, &trust, &registry, &control)?;
        let fresh_holder_3 = agent.with_token(fresh_class_3.clone())?;
        let reuse_before = runs();
        let held_4 = api.send(&post_at(
            &fresh_holder_3,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        // The held response outlives the recorded approval and is reused.
        t.release_expired_approval_reuse_runs_delta = runs() - reuse_before;
        let token_4 = challenge(&held_4)?;
        let before_expired_recorded = control.consents.lock().unwrap().len();
        let _ = approve(&agent, &ps_tls, &token_4, &fresh_class_3, &control)?;
        t.expired_recorded_approval_reprompted =
            control.consents.lock().unwrap().len() == before_expired_recorded + 1;

        // Negative control: past the held response's horizon a re-request is a
        // fresh challenge that runs once, and release consent is asked again.
        control.clock_offset.fetch_add(301, Ordering::SeqCst);
        let expired_held_before = runs();
        let held_5 = api.send(&post_at(
            &fresh_holder_3,
            &format!("{RECORDS}/records/query"),
            R1,
            control.now(),
        )?)?;
        t.release_expired_held_runs_delta = runs() - expired_held_before;
        let token_5 = challenge(&held_5)?;
        let before_expired_held = control.consents.lock().unwrap().len();
        let _ = approve(&agent, &ps_tls, &token_5, &fresh_class_3, &control)?;
        t.release_expired_held_reprompted =
            control.consents.lock().unwrap().len() == before_expired_held + 1;
    }

    let release_case = matches!(
        case,
        Some(AdmissionCase::ReleaseRevocation | AdmissionCase::ReleaseClaimRevocation)
    );
    let claim_case = matches!(
        case,
        Some(AdmissionCase::ClaimRevocation | AdmissionCase::ReleaseClaimRevocation)
    );
    // Effects are deletes and query computations; a release never recomputes.
    let effect_count =
        || effects.deletes.lock().unwrap().len() + control.query_runs.load(Ordering::SeqCst);
    if control.revocation {
        // A fresh, unclaimed proposal: previously admitted effects remain separate.
        let path = if release_case {
            "/records/query"
        } else {
            "/records/delete"
        };
        let held = api.send(&post(&holder, &format!("{RECORDS}{path}"), R1)?)?;
        let location = held.headers()["location"].to_str()?.to_owned();
        let proposal_token = challenge(&held)?;
        let proposal = agent.verify_r3_proposal_challenge(
            &proposal_token,
            RECORDS,
            PS,
            &class,
            &trust,
            now(),
        )?;
        let grant = member(
            &approve(&agent, &ps_tls, &proposal_token, &class, &control)?,
            "auth_token",
        )
        .ok_or("revocation-control approval refused")?;
        let verified = agent.verify_r3_per_call_delivery(
            &grant,
            RECORDS,
            &proposal,
            &class,
            &registry,
            &trust,
            now(),
        )?;
        let mut revoke = Request::builder()
            .method("POST")
            .uri(format!("{RECORDS}/revoke"))
            .header("content-type", "application/json")
            .body(
                json!({"jti": verified.claims().jti, "exp": verified.claims().exp})
                    .to_string()
                    .into_bytes(),
            )?;
        sign_request(
            &mut revoke,
            &SigningKey::from_seed(ps_seed),
            KeyMaterial::JwksUri {
                id: PS.into(),
                dwk: "aauth-person.json".into(),
                kid: "ps-1".into(),
            },
            now(),
        )?;
        let mut poll = get(&location)?;
        let revocation_holder = agent.with_token(grant)?;
        revocation_holder.sign(&mut poll, now())?;
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        if claim_case {
            *control.claim_barrier.lock().unwrap() = Some((entered, released));
        } else {
            *control.barrier.lock().unwrap() = Some((entered, released));
        }
        let before = effect_count();
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
        t.revoked_completion_error = completion
            .headers()
            .get("signature-error")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        t.revocation_effect_delta = effect_count() - before;
        let claim_path = FileCalls(root.clone(), Mutex::new(()), control.clone())
            .claim_path(proposal.reference().uri());
        t.revocation_claim_consumed = claim_path.exists();
        if claim_case {
            let retained = fs::read(&claim_path)?;
            let value: Value = serde_json::from_slice(&retained)?;
            t.revocation_result_retained = !value["result"].is_null();
            let mut retry = get(&location)?;
            revocation_holder.sign(&mut retry, now())?;
            t.revocation_retry_status = api.send(&retry)?.status().as_u16();
            t.revocation_claim_unchanged = fs::read(&claim_path)? == retained;
            // Count again after retry, so redispatch cannot escape the control.
            t.revocation_effect_delta = effect_count() - before;
        }
    }

    t.query_runs = control.query_runs.load(Ordering::SeqCst);
    t.consents = control.consents.lock().unwrap().clone();
    t.release_result_seen = control.release_result.lock().unwrap().clone();
    t.reads = effects.reads.load(Ordering::SeqCst);
    t.deletes = effects.deletes.lock().unwrap().clone();
    t.audit_records = audit.0.lock().map_err(|_| "audit lock poisoned")?.len();
    let _ = fs::remove_dir_all(&root);
    Ok(t)
}

#[cfg(test)]
fn custody_record(uri: &str, pending: &str, body: &[u8]) -> R3ProposalRecord {
    R3ProposalRecord {
        reference: Reference::new(uri, digest(uri.as_bytes())).unwrap(),
        exact_json: b"{}".to_vec(),
        person_server: "https://ps.example".into(),
        auth_token_issuer: "https://ps.example".into(),
        resource_token_jti: pending.into(),
        resource_token: "token".into(),
        class_reference: Reference::new("https://records.example/r3/c.1", digest(b"class")).unwrap(),
        presented_jti: "ps-1".into(),
        subject: "subject".into(),
        agent_jkt: "jkt".into(),
        tenant: None,
        account: None,
        scope: None,
        issued_at: 1_000,
        expires_at: 1_005,
        held: Some(R3HeldRequest {
            pending_id: pending.into(),
            method: "POST".into(),
            uri: "https://records.example/records/query".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }),
        released: Some(R3CallResult {
            status: 200,
            content_type: None,
            body: body.to_vec(),
        }),
        release_until: Some(1_300),
        supersedes: None,
    }
}

#[cfg(test)]
fn custody_store(name: &str) -> (PathBuf, FileCalls) {
    let root = std::env::temp_dir().join(format!(
        "aauth-r3-supersede-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root).unwrap();
    let calls = FileCalls(root.clone(), Mutex::new(()), Arc::new(AdmissionControl::default()));
    (root, calls)
}

#[test]
fn supersede_keeps_the_prior_when_the_tombstone_cannot_be_written() {
    let (root, calls) = custody_store("fail");
    let prior = custody_record("https://records.example/r3/p.prior", "pend-prior", b"run-1");
    let successor = custody_record("https://records.example/r3/p.next", "pend-next", b"run-1");
    calls.commit(&prior).unwrap();
    calls.2.fail_supersede_tombstone.store(true, Ordering::SeqCst);
    assert!(calls.supersede(prior.reference.uri(), &successor, 1_100).is_err());
    assert!(!calls.claim_path(prior.reference.uri()).exists());
    assert!(!calls.record_path(successor.reference.uri()).exists());
    let held = calls.held_releases("jkt", "subject", 1_100).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].reference.uri(), prior.reference.uri());
    assert_eq!(held[0].released.as_ref().unwrap().body, b"run-1");
    // The same retry then retires the original without recomputing its bytes.
    assert!(calls.supersede(prior.reference.uri(), &successor, 1_100).is_ok());
    let held = calls.held_releases("jkt", "subject", 1_100).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].reference.uri(), successor.reference.uri());
    assert_eq!(held[0].released.as_ref().unwrap().body, b"run-1");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn concurrent_supersede_leaves_one_successor_and_the_original_bytes() {
    let (root, calls) = custody_store("race");
    let prior = custody_record("https://records.example/r3/p.prior", "pend-prior", b"run-1");
    calls.commit(&prior).unwrap();
    let store = Arc::new(calls);
    let mut handles = Vec::new();
    for name in ["a", "b"] {
        let store = store.clone();
        let prior_uri = prior.reference.uri().to_owned();
        let successor = custody_record(
            &format!("https://records.example/r3/p.{name}"),
            &format!("pend-{name}"),
            b"run-1",
        );
        handles.push(std::thread::spawn(move || {
            store.supersede(&prior_uri, &successor, 1_100)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
    assert!(store.claim_path(prior.reference.uri()).exists());
    let held = store.held_releases("jkt", "subject", 1_100).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].released.as_ref().unwrap().body, b"run-1");
    assert_ne!(held[0].reference.uri(), prior.reference.uri());
    let _ = fs::remove_dir_all(root);
}
