use crate::PolicyError;
use aauth_rust_core::TokenError;
use aauth_rust_signature_key::{
    Error as ProofError, required_components, role_signature_alg_header,
};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};

pub(crate) struct Failure {
    status: StatusCode,
    code: &'static str,
    signature: Option<String>,
    date: Option<i64>,
}
impl Failure {
    pub(crate) fn parameter(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            signature: None,
            date: None,
        }
    }
    pub(crate) fn policy(error: PolicyError) -> Self {
        match error {
            PolicyError::Denied => Self::status(StatusCode::FORBIDDEN, "access_denied"),
            PolicyError::Unavailable => Self::internal(),
        }
    }
    pub(crate) fn status(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            signature: None,
            date: None,
        }
    }
    pub(crate) fn internal() -> Self {
        Self::status(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    }
    pub(crate) fn token(error: TokenError, parameter: &'static str, now: i64) -> Self {
        let code = match (parameter, error) {
            ("agent", TokenError::ExpiredJwt) => "expired_agent_token",
            ("agent", _) => "invalid_agent_token",
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
    pub(crate) fn proof(error: ProofError, request: &Request<Vec<u8>>, now: i64) -> Self {
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
            code,
            signature: Some(signature),
            date: matches!(error, ProofError::ClockSkew).then_some(now),
        }
    }
    pub(crate) fn credential(error: TokenError) -> Self {
        let code = error.code();
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            signature: Some(format!("error={code}")),
            date: None,
        }
    }
    pub(crate) fn clock(now: i64) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "clock_skew",
            signature: None,
            date: Some(now),
        }
    }
    pub(crate) fn response(self) -> Response<Vec<u8>> {
        let mut response = json_response(
            self.status,
            json!({"type":"about:blank","title":self.status.canonical_reason().unwrap_or("Request refused"),"status":self.status.as_u16(),"error":self.code}),
        );
        response
            .headers_mut()
            .insert("content-type", "application/problem+json".parse().unwrap());
        if let Some(signature) = self.signature {
            response
                .headers_mut()
                .insert("signature-error", signature.parse().unwrap());
        }
        if self.code == "unsupported_scheme" {
            response
                .headers_mut()
                .insert("accept-signature-scheme", "jwks_uri".parse().unwrap());
        }
        if self.code == "unsupported_algorithm" {
            response.headers_mut().insert(
                "accept-signature-alg",
                role_signature_alg_header().parse().unwrap(),
            );
        }
        if let Some(now) = self.date {
            add_date(&mut response, now);
        }
        response
    }
}
pub(crate) fn json_response(status: StatusCode, value: Value) -> Response<Vec<u8>> {
    let mut response = bytes_response(value.to_string().into_bytes());
    *response.status_mut() = status;
    response
}
pub(crate) fn bytes_response(bytes: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(bytes);
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
}
pub(crate) fn token_response(name: &str, compact: String, expires_in: i64) -> Response<Vec<u8>> {
    let mut value = json!({"expires_in":expires_in});
    value[name] = json!(compact);
    let mut response = json_response(StatusCode::OK, value);
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
pub(crate) fn add_date(response: &mut Response<Vec<u8>>, now: i64) {
    if let Ok(seconds) = u64::try_from(now)
        && let Some(time) =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds))
    {
        response
            .headers_mut()
            .insert("date", httpdate::fmt_http_date(time).parse().unwrap());
    }
}
