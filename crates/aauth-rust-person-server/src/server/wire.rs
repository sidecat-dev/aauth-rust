use super::PolicyError;
use aauth_rust_core::TokenError;
use aauth_rust_signature_key::{
    Error as ProofError, required_components, role_signature_alg_header,
};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};

pub(super) struct Failure {
    status: StatusCode,
    code: String,
    signature: Option<String>,
    date: Option<i64>,
    federation: Option<Box<crate::FederationFailure>>,
    mission_reason: Option<String>,
    detail: Option<&'static str>,
}
impl Failure {
    pub(super) fn mission_terminated(reason: &str) -> Self {
        let mut failure = Self::status(StatusCode::FORBIDDEN, "mission_terminated");
        failure.mission_reason = Some(reason.into());
        failure
    }
    pub(super) fn parameter(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            signature: None,
            date: None,
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn policy(error: PolicyError) -> Self {
        match error {
            PolicyError::Denied => Self::status(StatusCode::FORBIDDEN, "access_denied"),
            PolicyError::UserUnreachable => Self::status(StatusCode::FORBIDDEN, "user_unreachable"),
            PolicyError::Unavailable => Self::internal(),
        }
    }
    pub(super) fn status(status: StatusCode, code: &str) -> Self {
        Self {
            status,
            code: code.into(),
            signature: None,
            date: None,
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn internal() -> Self {
        Self::status(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    }
    pub(super) fn token(error: TokenError, parameter: &'static str, now: i64) -> Self {
        let code = match (parameter, error) {
            ("subagent", TokenError::ExpiredJwt) => "expired_subagent_token",
            ("subagent", _) => "invalid_subagent_token",
            ("resource", TokenError::ExpiredJwt) => "expired_resource_token",
            ("presented", TokenError::ExpiredJwt) => "expired_presented_token",
            ("upstream", TokenError::ExpiredJwt) => "expired_upstream_token",
            ("resource", _) => "invalid_resource_token",
            ("presented", _) => "invalid_presented_token",
            _ => "invalid_upstream_token",
        };
        let _ = now;
        Self::parameter(code)
    }
    pub(super) fn proof(error: ProofError, request: &Request<Vec<u8>>, now: i64) -> Self {
        let code = error.code();
        let mut signature = format!("error={code}");
        if matches!(error, ProofError::InvalidInput) {
            let mut required = required_components(request);
            for name in ["content-type", "content-digest"] {
                if !required.contains(&name) {
                    required.push(name);
                }
            }
            signature.push_str(&format!(
                ", required_input=({})",
                required
                    .iter()
                    .map(|value| format!("\"{value}\""))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            signature: Some(signature),
            date: matches!(error, ProofError::ClockSkew).then_some(now),
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn revoked_jwt() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "revoked_jwt".into(),
            signature: Some("error=revoked_jwt".into()),
            date: None,
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn credential(error: TokenError) -> Self {
        let code = error.code();
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            signature: Some(format!("error={code}")),
            date: None,
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn clock(now: i64) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "clock_skew".into(),
            signature: None,
            date: Some(now),
            federation: None,
            mission_reason: None,
            detail: None,
        }
    }
    pub(super) fn with_federation(mut self, diagnostic: crate::FederationFailure) -> Self {
        self.federation = Some(Box::new(diagnostic));
        self
    }
    pub(super) fn with_date(mut self, date: i64) -> Self {
        self.date = Some(date);
        self
    }
    /// The answer to a poll, host advance or release of a pending request.
    /// `revoked_upstream_token` names a request parameter; a chained request
    /// that is already waiting ends instead with the polling error `revoked`,
    /// whose `detail` says which token (Presenting a Revoked Token).
    pub(super) fn while_pending(self) -> Self {
        if self.code != "revoked_upstream_token" {
            return self;
        }
        let mut revoked = Self::status(StatusCode::FORBIDDEN, "revoked");
        revoked.detail = Some(
            "The upstream token of this chained request, or its calling agent's agent token or binding, was revoked.",
        );
        revoked.federation = self.federation;
        revoked
    }
    pub(super) fn response(self) -> Response<Vec<u8>> {
        // A body sent with Signature-Error names that error code as its type.
        let kind = if self.signature.is_some() {
            format!("urn:ietf:params:sig-error:{}", self.code)
        } else {
            "about:blank".into()
        };
        let mut body = json!({"type":kind,"title":self.status.canonical_reason().unwrap_or("Request refused"),"status":self.status.as_u16(),"error":self.code});
        if let Some(reason) = self.mission_reason {
            body["mission_status"] = json!("terminated");
            body["termination_reason"] = json!(reason);
        }
        if let Some(detail) = self.detail {
            body["detail"] = json!(detail);
        }
        let mut response = json_response(self.status, body);
        response
            .headers_mut()
            .insert("content-type", "application/problem+json".parse().unwrap());
        let local_signature_failure = self.signature.is_some();
        if let Some(signature) = self.signature {
            response
                .headers_mut()
                .insert("signature-error", signature.parse().unwrap());
        }
        if local_signature_failure && self.code == "unsupported_scheme" {
            response
                .headers_mut()
                .insert("accept-signature-scheme", "jwt".parse().unwrap());
        }
        if local_signature_failure && self.code == "unsupported_algorithm" {
            response.headers_mut().insert(
                "accept-signature-alg",
                role_signature_alg_header().parse().unwrap(),
            );
        }
        if let Some(now) = self.date {
            add_date(&mut response, now);
        }
        if let Some(diagnostic) = self.federation {
            response.extensions_mut().insert(*diagnostic);
        }
        response
    }
}
pub(super) fn json_response(status: StatusCode, value: Value) -> Response<Vec<u8>> {
    let mut response = bytes_response(value.to_string().into_bytes());
    *response.status_mut() = status;
    response
}
pub(super) fn bytes_response(bytes: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(bytes);
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
}
pub(super) fn token_response(name: &str, compact: String, expires_in: i64) -> Response<Vec<u8>> {
    let mut value = json!({"expires_in":expires_in});
    value[name] = json!(compact);
    let mut response = json_response(StatusCode::OK, value);
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
pub(super) fn add_date(response: &mut Response<Vec<u8>>, now: i64) {
    if let Ok(seconds) = u64::try_from(now)
        && let Some(time) =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds))
    {
        response
            .headers_mut()
            .insert("date", httpdate::fmt_http_date(time).parse().unwrap());
    }
}
