//! Signed revocation endpoint for a Resource, and the cascade it starts.
use super::*;
use aauth_rust_core::revocation::{
    covers_revocation_body, downstream_body, empty_ok, json_ok, parse_revocation_body, problem,
    unknown_pending,
};
use aauth_rust_core::{
    CallOutcome, DownstreamReport, RevocationDirectory, RevocationLedger, RevocationLimits,
};
use aauth_rust_signature_key::required_components;
use std::sync::Arc;

pub(super) struct Gate {
    ledger: RevocationLedger,
    directory: Option<Arc<dyn RevocationDirectory>>,
}

impl Gate {
    fn new(limits: RevocationLimits) -> Self {
        Self {
            ledger: RevocationLedger::new(limits),
            directory: None,
        }
    }
}

impl<K: AgentKeyResolver, P, O> PsAuthorizationResource<K, P>
where
    P: Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Accept signed revocations and advertise `revocation_endpoint`.
    ///
    /// The ledger is process memory. A Resource has nothing downstream of a
    /// revocation it receives, so the endpoint answers `200` at once and never
    /// `202`.
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

    /// Deliver revocations of resource tokens this Resource issued.
    /// Enables revocation when it was off.
    pub fn with_revocation_directory(mut self, directory: Arc<dyn RevocationDirectory>) -> Self {
        if self.revocation.is_none() {
            self = self.with_revocation();
        }
        if let Some(gate) = self.revocation.as_mut() {
            gate.directory = Some(directory);
        }
        self
    }

    /// Stored `exp` for a revocation this Resource accepted.
    pub fn revocation_exp(&self, issuer: &str, jti: &str) -> Option<i64> {
        self.revocation
            .as_ref()
            .and_then(|gate| gate.ledger.expiration(issuer, jti))
    }

    /// Verify one signed revocation or pending poll.
    ///
    /// A disabled endpoint, or any other path, is `404`. A signature failure is
    /// `401`. A Resource never defers: `POST /revoke` records `(caller, jti)`
    /// and returns an empty `200` with no `Content-Type`.
    pub fn revoke(&self, request: &Request<Vec<u8>>, now: i64) -> Response<Vec<u8>> {
        self.revoke_inner(request, now)
            .unwrap_or_else(|error| error.response(request, now))
    }

    /// Revoke a resource token this Resource issued.
    ///
    /// Three-party calls the party named in `audience` (the Person Server).
    /// Four-party also calls `person_server`. The body reports each recipient.
    /// A missing Person Server on the four-party path is `invalid_request`.
    pub fn revoke_issued_resource_token(
        &self,
        jti: &str,
        exp: i64,
        audience: &str,
        person_server: Option<&str>,
    ) -> Response<Vec<u8>> {
        if self.revocation.is_none() {
            return problem(StatusCode::NOT_FOUND, "not_found", None);
        }
        if jti.is_empty()
            || jti.len() > 1024
            || jti.chars().any(|c| c.is_whitespace() || c.is_control())
            || exp < 0
            || validate_server_identifier(audience).is_err()
        {
            return problem(StatusCode::BAD_REQUEST, "invalid_request", None);
        }
        let mut recipients = vec![audience.to_owned()];
        if self.access_server.is_some() {
            let Some(person_server) = person_server else {
                return problem(StatusCode::BAD_REQUEST, "invalid_request", None);
            };
            if validate_server_identifier(person_server).is_err() {
                return problem(StatusCode::BAD_REQUEST, "invalid_request", None);
            }
            if person_server != audience {
                recipients.push(person_server.to_owned());
            }
        }
        let directory = self
            .revocation
            .as_ref()
            .and_then(|gate| gate.directory.clone());
        let reports: Vec<DownstreamReport> = recipients
            .iter()
            .map(|recipient| {
                let outcome = directory
                    .as_ref()
                    .map(|directory| directory.revoke(recipient, jti, exp))
                    .unwrap_or(CallOutcome::Unavailable);
                DownstreamReport::from_outcome(recipient, outcome)
            })
            .collect();
        match downstream_body(&reports) {
            Some(bytes) => json_ok(bytes),
            None => empty_ok(),
        }
    }

    pub(super) fn presented_revoked(&self, issuer: &str, jti: &str, now: i64) -> bool {
        self.revocation
            .as_ref()
            .is_some_and(|gate| gate.ledger.is_revoked(issuer, jti, now))
    }

    fn revoke_inner(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, ProofFailure> {
        if self.revocation.is_none() {
            return Ok(problem(StatusCode::NOT_FOUND, "not_found", None));
        }
        let authority = canonical_authority(request.uri()).map_err(ProofFailure::Proof)?;
        if authority != self.authority {
            return Err(ProofFailure::Proof(Error::TargetMismatch));
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return Err(ProofFailure::Proof(Error::InvalidClock));
        }
        let path = request.uri().path();
        if request.method() == http::Method::POST && path == "/revoke" {
            return self.revoke_post(request, now);
        }
        if request.method() == http::Method::GET && path.starts_with("/revoke/pending/") {
            return self.revoke_poll(request, now);
        }
        Ok(problem(StatusCode::NOT_FOUND, "not_found", None))
    }

    fn revoke_post(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, ProofFailure> {
        let caller = self.verify_caller(request, now, true)?;
        if !matches!(
            caller.dwk.as_str(),
            "aauth-person.json" | "aauth-access.json"
        ) {
            return Ok(problem(StatusCode::FORBIDDEN, "unsupported_iss", None));
        }
        if let Some(limited) = self.charge(&caller.id, now) {
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
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_request", None));
        }
        let Ok(body) = parse_revocation_body(request.body()) else {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_request", None));
        };
        let gate = self.revocation.as_ref().expect("revocation is enabled");
        if !gate.ledger.exp_allowed(body.exp, now) {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_request", None));
        }
        gate.ledger.remember(&caller.id, &body.jti, body.exp);
        Ok(empty_ok())
    }

    fn revoke_poll(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, ProofFailure> {
        let _caller = self.verify_caller(request, now, false)?;
        if !request.body().is_empty() {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_request", None));
        }
        Ok(unknown_pending())
    }

    fn charge(&self, caller: &str, now: i64) -> Option<Response<Vec<u8>>> {
        let gate = self.revocation.as_ref().expect("revocation is enabled");
        match gate.ledger.charge(caller, now) {
            Ok(()) => None,
            Err(Some(retry_after)) => Some(problem(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                Some(retry_after),
            )),
            Err(None) => Some(problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            )),
        }
    }

    fn verify_caller(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        body_required: bool,
    ) -> Result<Caller, ProofFailure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(ProofFailure::Proof)?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| ProofFailure::Proof(Error::InvalidInput))?;
        if body_required && !covers_revocation_body(base) {
            return Err(ProofFailure::Proof(Error::InvalidInput));
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(ProofFailure::Proof(Error::UnsupportedScheme));
        };
        validate_server_identifier(id).map_err(|_| ProofFailure::Proof(Error::InvalidKey))?;
        let key = self.keys.key(id, dwk, kid).map_err(ProofFailure::Token)?;
        proof.verify(&key).map_err(ProofFailure::Proof)?;
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

enum ProofFailure {
    Proof(Error),
    Token(TokenError),
}

impl ProofFailure {
    fn response(self, request: &Request<Vec<u8>>, _now: i64) -> Response<Vec<u8>> {
        match self {
            Self::Token(error) => signature_problem(error.code(), None),
            Self::Proof(error) => {
                let required = matches!(error, Error::InvalidInput).then(|| {
                    let mut required = required_components(request);
                    for name in ["content-type", "content-digest"] {
                        if !required.contains(&name) {
                            required.push(name);
                        }
                    }
                    required
                });
                signature_problem(error.code(), required.as_deref())
            }
        }
    }
}

fn signature_problem(code: &str, required: Option<&[&str]>) -> Response<Vec<u8>> {
    let mut response = problem(StatusCode::UNAUTHORIZED, code, None);
    let mut signature = format!("error={code}");
    if let Some(required) = required {
        signature.push_str(&format!(
            ", required_input=({})",
            required
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    if let Ok(value) = signature.parse() {
        response.headers_mut().insert("signature-error", value);
    }
    response
}
