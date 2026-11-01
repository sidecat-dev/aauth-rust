//! Signed revocation endpoint and the cascades a Person Server initiates.
use super::*;
use crate::TokenReference;
use aauth_rust_core::revocation::{
    covers_revocation_body, empty_ok, parse_revocation_body, pending as pending_response, problem,
    success_response, unknown_pending,
};
use aauth_rust_core::{
    CallOutcome, DownstreamReport, RevocationDirectory, RevocationLedger, RevocationLimits,
    RevocationSender, RevocationTarget,
};
use aauth_rust_signature_key::KeyMaterial;
use http::StatusCode;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub(super) struct Gate {
    ledger: RevocationLedger,
    pub(super) directory: Option<Arc<dyn RevocationDirectory>>,
    pending: Mutex<BTreeMap<String, Job>>,
    attempts: Mutex<BTreeMap<(String, String), Vec<TargetState>>>,
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
    /// The recipient's metadata document, which names its `revocation_endpoint`.
    dwk: &'static str,
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
    pub(super) fn new(limits: RevocationLimits) -> Self {
        Self {
            ledger: RevocationLedger::new(limits),
            directory: None,
            pending: Mutex::new(BTreeMap::new()),
            attempts: Mutex::new(BTreeMap::new()),
        }
    }
    fn limits(&self) -> RevocationLimits {
        self.ledger.limits()
    }
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Accept signed revocations and advertise `revocation_endpoint`.
    ///
    /// The ledger is process memory. Downstream calls use a
    /// [`RevocationDirectory`] when one is installed; without it, each
    /// downstream target is `revocation_unavailable`. An Agent Provider's
    /// revocation of an Agent token revokes every person token issued to that
    /// Agent as [`Self::revoke_person_token`] does. With
    /// [`Self::with_supervision`], the supervision server deciding for the
    /// agent is told of an Agent token's revocation, and of a Resource
    /// token's that was in a request put to it (`revocation.received`).
    pub fn with_revocation(self) -> Self {
        self.with_revocation_limits(RevocationLimits::default())
    }
    /// [`Self::with_revocation`] with an explicit lifetime and rate limit.
    pub fn with_revocation_limits(mut self, limits: RevocationLimits) -> Self {
        let directory = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.directory.clone());
        let mut gate = Gate::new(limits);
        gate.directory = directory;
        self.revocation = Some(gate);
        self
    }
    /// Install the host that delivers downstream revocations.
    /// Enables revocation when it was off.
    ///
    /// Each call names its recipient's role document (`aauth-resource.json`
    /// or `aauth-access.json`) and is signed as this server: its issuer,
    /// `aauth-person.json`, its `kid` and signing key. `RevocationClient` in
    /// `aauth-rust-discovery` delivers them over HTTPS.
    pub fn with_revocation_directory(mut self, directory: Arc<dyn RevocationDirectory>) -> Self {
        if self.revocation.is_none() {
            self = self.with_revocation();
        }
        if let Some(gate) = self.revocation.as_mut() {
            gate.directory = Some(directory);
        }
        self
    }
    /// `exp` remembered for `(issuer, jti)`, if this server recorded it.
    pub fn revocation_exp(&self, issuer: &str, jti: &str) -> Option<i64> {
        self.revocation
            .as_ref()
            .and_then(|gate| gate.ledger.expiration(issuer, jti))
    }
    /// Revoke a person token this server issued, then cascade.
    ///
    /// The resource named in `aud` is called, and so is every access server
    /// this person token was presented to. Auth tokens this server issued
    /// against it, step-ups included, are revoked at their resources. Where it,
    /// or an auth token obtained with it, was later presented as
    /// `upstream_token`, the person tokens issued from it are revoked the same
    /// way, hop by hop. The response reports `downstream` when there is
    /// anything to report. The agent-person binding is left unchanged.
    pub fn revoke_person_token(&self, jti: &str) -> Response<Vec<u8>> {
        if self.revocation.is_none() {
            return problem(StatusCode::NOT_FOUND, "not_found", None);
        }
        let targets = match self.person_targets(jti) {
            Ok(targets) => targets,
            Err(error) => return error.response(),
        };
        let key = (self.config.issuer.clone(), jti.to_owned());
        self.finish(&self.config.issuer, key, true, targets, None)
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
    pub(super) fn token_revoked(&self, issuer: &str, jti: &str, now: i64) -> bool {
        self.revocation
            .as_ref()
            .is_some_and(|gate| gate.ledger.is_revoked(issuer, jti, now))
    }
    fn revoke_post(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let caller = self.verify_revocation_caller(request, now, true)?;
        if !matches!(
            caller.dwk.as_str(),
            "aauth-agent.json" | "aauth-resource.json"
        ) {
            return Ok(problem(StatusCode::FORBIDDEN, "unsupported_iss", None));
        }
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
        if caller.dwk == "aauth-agent.json" {
            self.report_agent_revocation(&caller.id, &body.jti, body.exp);
        } else {
            self.report_resource_revocation(&caller.id, &body.jti, body.exp);
        }
        let targets = if caller.dwk == "aauth-agent.json" {
            self.agent_targets(&caller.id, &body.jti)?
        } else {
            Vec::new()
        };
        let key = (caller.id.clone(), body.jti);
        Ok(self.finish(&caller.id, key, false, targets, None))
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
        let job = {
            let pending = self
                .revocation
                .as_ref()
                .expect("revocation is enabled")
                .pending
                .lock()
                .map_err(|_| Failure::internal())?;
            pending.get(&id).map(|job| Job {
                caller: job.caller.clone(),
                report: job.report,
                key: job.key.clone(),
                targets: job.targets.clone(),
                done: job.done,
            })
        };
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
        let _ = now;
        Ok(self.finish(&job.caller, job.key, job.report, job.targets, Some(&id)))
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
        let states = self.dispatch(&targets, &previous);
        if gate.attempts.lock().ok().is_some_and(|mut attempts| {
            attempts.insert(key.clone(), states.clone());
            true
        }) && states.iter().any(|state| state.deferred)
        {
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
                gate.limits().retry_after,
            );
        }
        if let Ok(mut pending) = gate.pending.lock() {
            for job in pending.values_mut().filter(|job| job.key == key) {
                job.done = true;
            }
        }
        let reports = aggregate(&states);
        if !report {
            empty_ok()
        } else {
            success_response(&reports, true)
        }
    }
    fn dispatch(&self, targets: &[Target], previous: &[TargetState]) -> Vec<TargetState> {
        let directory = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.directory.as_ref());
        let sender = RevocationSender {
            issuer: &self.config.issuer,
            dwk: "aauth-person.json",
            kid: &self.config.kid,
            key: &self.config.signing_key,
        };
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
                let outcome = directory
                    .map(|directory| directory.revoke(&sender, &target.as_call()))
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
    fn person_targets(&self, jti: &str) -> Result<Vec<Target>, Failure> {
        let reference = TokenReference {
            issuer: self.config.issuer.clone(),
            jti: jti.to_owned(),
        };
        let Some(person) = self
            .store
            .token(&reference)
            .map_err(|_| Failure::internal())?
        else {
            return Err(Failure::parameter("invalid_request"));
        };
        if !self.issued_person(&person) {
            return Err(Failure::parameter("invalid_request"));
        }
        let records = self.store.retained().map_err(|_| Failure::internal())?;
        let mut targets = Vec::new();
        self.cascade_people(&records, vec![person], &mut targets);
        Ok(targets)
    }
    fn issued_person(&self, record: &TokenRecord) -> bool {
        record.kind == TokenKind::Person && record.token.reference.issuer == self.config.issuer
    }
    /// Revoke each person token in `people` and what this server holds from it.
    ///
    /// Each one is revoked at its resource. Every token obtained with it, by
    /// exchange or step-up, enters the ledger, including an Auth token an Access
    /// Server issued through federation: such a token can still be presented
    /// here as upstream evidence. Each Access Server it was presented to is
    /// called once with the person token, and each Auth token this server issued
    /// is revoked at its resource. A person token issued with one of these as
    /// `upstream_token` joins `people`, so the cascade walks the call chain.
    fn cascade_people(
        &self,
        records: &[TokenRecord],
        mut people: Vec<TokenRecord>,
        targets: &mut Vec<Target>,
    ) {
        let mut revoked = std::collections::BTreeSet::new();
        let mut next = 0;
        while let Some(person) = people.get(next).cloned() {
            next += 1;
            if !revoked.insert(person.token.reference.clone()) {
                continue;
            }
            let jti = &person.token.reference.jti;
            self.remember(&self.config.issuer, jti, person.expires_at);
            targets.push(Target {
                recipient: person.resource.clone(),
                dwk: "aauth-resource.json",
                jti: jti.clone(),
                exp: person.expires_at,
            });
            let mut lineage = vec![person.token.reference.clone()];
            let mut access_servers = std::collections::BTreeSet::new();
            let mut walked = 0;
            while let Some(parent) = lineage.get(walked).cloned() {
                walked += 1;
                let children: Vec<&TokenRecord> = records
                    .iter()
                    .filter(|record| {
                        record.presented.as_ref().map(|tie| &tie.reference) == Some(&parent)
                            && !lineage.contains(&record.token.reference)
                    })
                    .collect();
                for record in children {
                    lineage.push(record.token.reference.clone());
                    self.remember(
                        &record.token.reference.issuer,
                        &record.token.reference.jti,
                        record.expires_at,
                    );
                    if record.person_server.is_some() {
                        if access_servers.insert(record.token.reference.issuer.clone()) {
                            targets.push(Target {
                                recipient: record.token.reference.issuer.clone(),
                                dwk: "aauth-access.json",
                                jti: jti.clone(),
                                exp: person.expires_at,
                            });
                        }
                    } else if record.kind == TokenKind::Auth
                        && record.token.reference.issuer == self.config.issuer
                    {
                        targets.push(Target {
                            recipient: record.resource.clone(),
                            dwk: "aauth-resource.json",
                            jti: record.token.reference.jti.clone(),
                            exp: record.expires_at,
                        });
                    }
                }
            }
            // Revocation Cascade: the person tokens issued with one of these
            // as `upstream_token` are revoked in the same cascade.
            people.extend(
                records
                    .iter()
                    .filter(|record| {
                        self.issued_person(record)
                            && record
                                .upstream
                                .as_ref()
                                .is_some_and(|tie| lineage.contains(&tie.reference))
                    })
                    .cloned(),
            );
        }
    }
    fn agent_targets(&self, caller: &str, agent_jti: &str) -> Result<Vec<Target>, Failure> {
        let records = self.store.retained().map_err(|_| Failure::internal())?;
        let subject = records.iter().find_map(|record| {
            (record.agent.issuer == caller
                && record.agent_token_jti == agent_jti
                && record.binding_issuer() == self.config.issuer)
                .then(|| record.agent.subject.clone())
        });
        let Some(subject) = subject else {
            return Ok(Vec::new());
        };
        let issued = |record: &TokenRecord| {
            record.agent.issuer == caller
                && record.agent.subject == subject
                && record.binding_issuer() == self.config.issuer
        };
        // Every token issued to the Agent enters the ledger, including an Auth
        // token an Access Server issued through federation: such a token can
        // still be presented to this Person Server as upstream evidence.
        for record in records.iter().filter(|record| issued(record)) {
            self.remember(
                &record.token.reference.issuer,
                &record.token.reference.jti,
                record.expires_at,
            );
        }
        // Each of its person tokens is revoked as `revoke_person_token` would:
        // at its Resource, at every Access Server it was presented to, for the
        // Auth tokens obtained with it, and down any chain built on them.
        let people = records
            .iter()
            .filter(|record| issued(record) && self.issued_person(record))
            .cloned()
            .collect();
        let mut targets = Vec::new();
        self.cascade_people(&records, people, &mut targets);
        Ok(targets)
    }
    fn remember(&self, issuer: &str, jti: &str, exp: i64) {
        if let Some(gate) = &self.revocation {
            gate.ledger.remember(issuer, jti, exp);
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
impl Target {
    fn as_call(&self) -> RevocationTarget<'_> {
        RevocationTarget {
            recipient: &self.recipient,
            dwk: self.dwk,
            jti: &self.jti,
            exp: self.exp,
        }
    }
}
pub(super) fn revoked_parameter(parameter: &'static str) -> Failure {
    Failure::parameter(match parameter {
        "resource" => "revoked_resource_token",
        "upstream" => "revoked_upstream_token",
        _ => "revoked_presented_token",
    })
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
