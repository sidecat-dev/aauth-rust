//! Signed revocation endpoint for an Access Server.
use super::*;
use aauth_rust_core::revocation::{
    covers_revocation_body, empty_ok, parse_revocation_body, pending as pending_response, problem,
    success_response, unknown_pending,
};
use aauth_rust_core::{
    CallOutcome, DownstreamReport, RevocationDirectory, RevocationLedger, RevocationLimits,
    RevocationSender, RevocationTarget,
};
use aauth_rust_signature_key::KeyMaterial;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub(super) struct Gate {
    ledger: RevocationLedger,
    pub(super) directory: Option<Arc<dyn RevocationDirectory>>,
    issued: Mutex<Vec<Issued>>,
    pending: Mutex<BTreeMap<String, Job>>,
    attempts: Mutex<BTreeMap<(String, String), Vec<TargetState>>>,
}
struct Issued {
    jti: String,
    resource: String,
    exp: i64,
    presented_issuer: String,
    presented_jti: String,
}
struct Job {
    caller: String,
    report: bool,
    key: (String, String),
    targets: Vec<Target>,
    /// The cascade reached its terminal response, so a later poll is `410`.
    done: bool,
}
#[derive(Clone)]
struct Target {
    recipient: String,
    jti: String,
    exp: i64,
}
#[derive(Clone)]
struct TargetState {
    recipient: String,
    jti: String,
    error: Option<&'static str>,
    deferred: bool,
}
impl Gate {
    fn new(limits: RevocationLimits) -> Self {
        Self {
            ledger: RevocationLedger::new(limits),
            directory: None,
            issued: Mutex::new(Vec::new()),
            pending: Mutex::new(BTreeMap::new()),
            attempts: Mutex::new(BTreeMap::new()),
        }
    }
    pub(super) fn note(&self, issued: IssuedAuth) {
        if let Ok(mut rows) = self.issued.lock() {
            rows.push(Issued {
                jti: issued.jti,
                resource: issued.resource,
                exp: issued.exp,
                presented_issuer: issued.presented_issuer,
                presented_jti: issued.presented_jti,
            });
        }
    }
}
pub(super) struct IssuedAuth {
    pub(super) jti: String,
    pub(super) resource: String,
    pub(super) exp: i64,
    pub(super) presented_issuer: String,
    pub(super) presented_jti: String,
}

impl<
    K: AgentKeyResolver,
    P: Fn(&AuthorizationRequest) -> Result<Decision, PolicyError>,
    C: Fn() -> i64,
    I: Fn() -> String,
> AccessServer<K, P, C, I>
{
    /// Accept signed revocations and advertise `revocation_endpoint`.
    ///
    /// When a Person Server revokes a person token here, every Auth token this
    /// server issued from it, step-ups included, is revoked at its Resource
    /// and refused from then on as a presented token.
    pub fn with_revocation(self) -> Self {
        self.with_revocation_limits(RevocationLimits::default())
    }
    /// [`Self::with_revocation`] with an explicit lifetime and rate limit.
    pub fn with_revocation_limits(mut self, limits: RevocationLimits) -> Self {
        let directory = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.directory.clone());
        let issued = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.issued.lock().ok().map(|rows| rows.clone()));
        let mut gate = Gate::new(limits);
        gate.directory = directory;
        if let Some(rows) = issued
            && let Ok(mut slot) = gate.issued.lock()
        {
            *slot = rows;
        }
        self.revocation = Some(gate);
        self
    }
    /// Deliver downstream auth-token revocations. Enables revocation when it was off.
    ///
    /// Each call names a Resource (`aauth-resource.json`) and is signed as this
    /// server: its issuer, `aauth-access.json`, its `kid` and signing key.
    /// `RevocationClient` in `aauth-rust-discovery` delivers them over HTTPS.
    pub fn with_revocation_directory(mut self, directory: Arc<dyn RevocationDirectory>) -> Self {
        if self.revocation.is_none() {
            self = self.with_revocation();
        }
        if let Some(gate) = self.revocation.as_mut() {
            gate.directory = Some(directory);
        }
        self
    }
    /// Stored `exp` for a revocation this server accepted.
    pub fn revocation_exp(&self, issuer: &str, jti: &str) -> Option<i64> {
        self.revocation
            .as_ref()
            .and_then(|gate| gate.ledger.expiration(issuer, jti))
    }
    pub(super) fn route_revocation(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Option<Response<Vec<u8>>>, Failure> {
        if self.revocation.is_none() {
            return Ok(None);
        }
        let path = request.uri().path();
        if request.method() == http::Method::POST && path == "/revoke" {
            return self.revoke_post(request, now).map(Some);
        }
        if request.method() == http::Method::GET && path.starts_with("/revoke/pending/") {
            return self.revoke_poll(request, now).map(Some);
        }
        Ok(None)
    }
    /// A presented or resource token whose signature is valid and whose `jti` is
    /// revoked is refused before policy, including when it has also expired.
    pub(super) fn refuse_revoked_parameter(
        &self,
        compact: &str,
        now: i64,
        parameter: &'static str,
    ) -> Result<(), Failure> {
        let Some(gate) = &self.revocation else {
            return Ok(());
        };
        let identity = if parameter == "resource" {
            signed_identity(ResourceToken::parse(compact), |token| {
                token.verify(&self.resolver(), now).map(|_| ())
            })
        } else {
            match signed_identity(PersonToken::parse(compact), |token| {
                token.verify(&self.resolver(), now).map(|_| ())
            }) {
                Signed::WrongType => signed_identity(AuthToken::parse(compact), |token| {
                    token.verify(&self.resolver(), now).map(|_| ())
                }),
                other => other,
            }
        };
        let Signed::Holds(issuer, jti) = identity else {
            return Ok(());
        };
        if gate.ledger.is_revoked(&issuer, &jti, now) {
            return Err(revoked_parameter(parameter));
        }
        Ok(())
    }
    pub(super) fn note_issued(&self, issued: IssuedAuth) {
        if let Some(gate) = &self.revocation {
            gate.note(issued);
        }
    }
    fn revoke_post(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let caller = self.verify_revocation_caller(request, now, true)?;
        let (report, cascade) = match caller.dwk.as_str() {
            "aauth-person.json" => (true, true),
            "aauth-resource.json" => (false, false),
            _ => return Ok(problem(StatusCode::FORBIDDEN, "unsupported_iss", None)),
        };
        if let Some(limited) = self.charge(&caller.id)? {
            return Ok(limited);
        }
        if request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let body = parse_revocation_body(request.body())
            .map_err(|_| Failure::parameter("invalid_request"))?;
        let gate = self.revocation.as_ref().expect("revocation is enabled");
        if !gate.ledger.exp_allowed(body.exp, now) {
            return Err(Failure::parameter("invalid_request"));
        }
        gate.ledger.remember(&caller.id, &body.jti, body.exp);
        let targets = if cascade {
            self.auth_targets(&caller.id, &body.jti)
        } else {
            Vec::new()
        };
        let issuer = caller.id.clone();
        Ok(self.finish(&issuer, (caller.id, body.jti), report, targets, None))
    }
    fn revoke_poll(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let caller = self.verify_revocation_caller(request, now, false)?;
        let id = request
            .uri()
            .path()
            .trim_start_matches("/revoke/pending/")
            .to_owned();
        if id.is_empty() || id.contains('/') {
            return Ok(unknown_pending());
        }
        let job = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.pending.lock().ok())
            .and_then(|pending| {
                pending.get(&id).map(|job| Job {
                    caller: job.caller.clone(),
                    report: job.report,
                    key: job.key.clone(),
                    targets: job.targets.clone(),
                    done: job.done,
                })
            });
        let Some(job) = job else {
            return Ok(unknown_pending());
        };
        if job.caller != caller.id {
            return Ok(unknown_pending());
        }
        if !request.body().is_empty() {
            return Err(Failure::parameter("invalid_request"));
        }
        if job.done {
            return Ok(problem(StatusCode::GONE, "gone", None));
        }
        Ok(self.finish(&job.caller, job.key, job.report, job.targets, Some(&id)))
    }
    /// The Auth tokens this server issued against the revoked token, and every
    /// step-up issued against one of those in turn, at their Resources. Each
    /// enters this server's ledger too, so none is accepted as a presented token
    /// again (Revocation Cascade: the AS MUST NOT issue further auth tokens
    /// against a revoked person token, and MUST revoke those it issued).
    fn auth_targets(&self, caller: &str, presented_jti: &str) -> Vec<Target> {
        let Some(gate) = &self.revocation else {
            return Vec::new();
        };
        let Ok(rows) = gate.issued.lock() else {
            return Vec::new();
        };
        let mut lineage = vec![(caller.to_owned(), presented_jti.to_owned())];
        let mut targets = Vec::new();
        let mut walked = 0;
        while let Some((issuer, jti)) = lineage.get(walked).cloned() {
            walked += 1;
            for row in rows
                .iter()
                .filter(|row| row.presented_issuer == issuer && row.presented_jti == jti)
            {
                let issued = (self.config.issuer.clone(), row.jti.clone());
                if lineage.contains(&issued) {
                    continue;
                }
                gate.ledger.remember(&issued.0, &issued.1, row.exp);
                lineage.push(issued);
                targets.push(Target {
                    recipient: row.resource.clone(),
                    jti: row.jti.clone(),
                    exp: row.exp,
                });
            }
        }
        targets
    }
    /// Dispatch the cascade and answer. `polled` is the pending id being polled,
    /// which a deferred answer keeps.
    fn finish(
        &self,
        caller: &str,
        key: (String, String),
        report: bool,
        targets: Vec<Target>,
        polled: Option<&str>,
    ) -> Response<Vec<u8>> {
        let Some(gate) = &self.revocation else {
            return problem(StatusCode::NOT_FOUND, "not_found", None);
        };
        let previous = gate
            .attempts
            .lock()
            .ok()
            .and_then(|attempts| attempts.get(&key).cloned())
            .unwrap_or_default();
        let sender = RevocationSender {
            issuer: &self.config.issuer,
            dwk: "aauth-access.json",
            kid: &self.config.kid,
            key: &self.config.signing_key,
        };
        let states = dispatch(gate, &sender, &targets, &previous);
        if let Ok(mut attempts) = gate.attempts.lock() {
            attempts.insert(key.clone(), states.clone());
        }
        if states.iter().any(|state| state.deferred) {
            let id = polled.map_or_else(
                aauth_rust_core::continuation::generate_pending_id,
                str::to_owned,
            );
            if let Ok(mut pending) = gate.pending.lock() {
                pending.insert(
                    id.clone(),
                    Job {
                        caller: caller.to_owned(),
                        report,
                        key,
                        targets,
                        done: false,
                    },
                );
            }
            return pending_response(
                &format!("{}/revoke/pending/{id}", self.config.issuer),
                gate.ledger.limits().retry_after,
            );
        }
        if let Ok(mut pending) = gate.pending.lock() {
            for job in pending.values_mut().filter(|job| job.key == key) {
                job.done = true;
            }
        }
        if !report {
            empty_ok()
        } else {
            success_response(&aggregate(&states), true)
        }
    }
    fn charge(&self, caller: &str) -> Result<Option<Response<Vec<u8>>>, Failure> {
        let gate = self.revocation.as_ref().expect("revocation is enabled");
        match gate.ledger.charge(caller, (self.clock)()) {
            Ok(()) => Ok(None),
            Err(Some(retry_after)) => Ok(Some(problem(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                Some(retry_after),
            ))),
            Err(None) => Err(Failure::internal()),
        }
    }
    fn verify_revocation_caller(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        body_required: bool,
    ) -> Result<Caller, Failure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(|error| Failure::proof(error, request, now))?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| Failure::proof(ProofError::InvalidInput, request, now))?;
        if body_required && !covers_revocation_body(base) {
            return Err(Failure::proof(ProofError::InvalidInput, request, now));
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(Failure::proof(ProofError::UnsupportedScheme, request, now));
        };
        validate_server_identifier(id)
            .map_err(|_| Failure::proof(ProofError::InvalidKey, request, now))?;
        let key = self
            .resolver()
            .key(id, dwk, kid)
            .map_err(Failure::credential)?;
        proof
            .verify(&key)
            .map_err(|error| Failure::proof(error, request, now))?;
        Ok(Caller {
            id: id.clone(),
            dwk: dwk.clone(),
        })
    }
}
struct Caller {
    id: String,
    dwk: String,
}

fn dispatch(
    gate: &Gate,
    sender: &RevocationSender<'_>,
    targets: &[Target],
    previous: &[TargetState],
) -> Vec<TargetState> {
    targets
        .iter()
        .map(|target| {
            if let Some(kept) = previous.iter().find(|state| {
                state.recipient == target.recipient
                    && state.jti == target.jti
                    && ((state.error.is_none() && !state.deferred)
                        || state.error == Some("revocation_unsupported"))
            }) {
                return kept.clone();
            }
            let outcome = gate
                .directory
                .as_ref()
                .map(|directory| {
                    directory.revoke(
                        sender,
                        &RevocationTarget {
                            recipient: &target.recipient,
                            dwk: "aauth-resource.json",
                            jti: &target.jti,
                            exp: target.exp,
                        },
                    )
                })
                .unwrap_or(CallOutcome::Unavailable);
            let report = DownstreamReport::from_outcome(&target.recipient, outcome);
            TargetState {
                recipient: target.recipient.clone(),
                jti: target.jti.clone(),
                error: report.error,
                deferred: report.deferred,
            }
        })
        .collect()
}
fn aggregate(states: &[TargetState]) -> Vec<DownstreamReport> {
    let mut recipients = Vec::new();
    for state in states {
        if !recipients.contains(&state.recipient) {
            recipients.push(state.recipient.clone());
        }
    }
    recipients
        .into_iter()
        .map(|recipient| {
            let group: Vec<_> = states
                .iter()
                .filter(|state| state.recipient == recipient)
                .collect();
            let deferred = group.iter().any(|state| state.deferred);
            let error = if deferred {
                None
            } else if group
                .iter()
                .any(|state| state.error == Some("revocation_unavailable"))
            {
                Some("revocation_unavailable")
            } else if group
                .iter()
                .any(|state| state.error == Some("revocation_unsupported"))
            {
                Some("revocation_unsupported")
            } else {
                None
            };
            DownstreamReport {
                recipient,
                error,
                deferred,
            }
        })
        .collect()
}
enum Signed {
    WrongType,
    Rejected,
    Holds(String, String),
}
fn signed_identity<T>(
    parsed: Result<T, TokenError>,
    verify: impl FnOnce(&T) -> Result<(), TokenError>,
) -> Signed
where
    T: Identity,
{
    let Ok(token) = parsed else {
        return Signed::WrongType;
    };
    let issuer = token.issuer().to_owned();
    let jti = token.jti().to_owned();
    match verify(&token) {
        Ok(()) | Err(TokenError::ExpiredJwt) => Signed::Holds(issuer, jti),
        Err(_) => Signed::Rejected,
    }
}
trait Identity {
    fn issuer(&self) -> &str;
    fn jti(&self) -> &str;
}
impl Identity for ResourceToken {
    fn issuer(&self) -> &str {
        &self.unverified_claims().iss
    }
    fn jti(&self) -> &str {
        &self.unverified_claims().jti
    }
}
impl Identity for PersonToken {
    fn issuer(&self) -> &str {
        &self.unverified_claims().iss
    }
    fn jti(&self) -> &str {
        &self.unverified_claims().jti
    }
}
impl Identity for AuthToken {
    fn issuer(&self) -> &str {
        &self.unverified_claims().iss
    }
    fn jti(&self) -> &str {
        &self.unverified_claims().jti
    }
}
fn revoked_parameter(parameter: &'static str) -> Failure {
    Failure::parameter(match parameter {
        "resource" => "revoked_resource_token",
        "upstream" => "revoked_upstream_token",
        _ => "revoked_presented_token",
    })
}

impl Clone for Issued {
    fn clone(&self) -> Self {
        Self {
            jti: self.jti.clone(),
            resource: self.resource.clone(),
            exp: self.exp,
            presented_issuer: self.presented_issuer.clone(),
            presented_jti: self.presented_jti.clone(),
        }
    }
}
