use super::*;
use crate::{FederationFailure, FederationFailureReason as Reason};
use aauth_rust_signature_key::{MAX_BODY_BYTES, sign_request};

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    pub(super) fn federate(
        &self,
        agent: &VerifiedAgentToken,
        prepared: &PreparedAuthorization,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            ..
        } = prepared;
        let r = resource.claims();
        if presented.kind == TokenKind::Auth && presented.issuer != r.aud {
            return Err(Failure::parameter("invalid_presented_token"));
        }
        self.policy.consent(context).map_err(|error| {
            Failure::policy(error).with_federation(FederationFailure {
                access_server: r.aud.clone(),
                status: None,
                reason: Reason::ConsentRefused(error),
            })
        })?;
        let now = (self.clock)();
        self.inputs_current(agent, resource, presented, now)?;
        self.subagent_current(agent, context.subagent.as_ref(), now)?;
        self.binding(&retained.principal, BindingContext::Presented)?
            .ok_or_else(Failure::internal)?;
        let adapter = self.federation.as_ref().ok_or_else(Failure::internal)?;
        let endpoint = adapter
            .endpoint(&r.aud)
            .map_err(|_| unreachable(&r.aud, None, Reason::EndpointUnavailable))?;
        let invalid_endpoint = || unreachable(&r.aud, None, Reason::InvalidEndpoint);
        let uri: http::Uri = endpoint.parse().map_err(|_| invalid_endpoint())?;
        canonical_authority(&uri).map_err(|_| invalid_endpoint())?;
        if uri.query().is_some() || endpoint.contains('#') {
            return Err(invalid_endpoint());
        }
        let resource_compact = required_string(&context.parameters, "resource_token")?;
        let presented_compact = required_string(&context.parameters, "presented_token")?;
        let mut body = json!({"agent_token":agent.compact(),"resource_token":resource_compact,"presented_token":presented_compact});
        if let Some(child) = &context.subagent {
            body["subagent_token"] = json!(child.compact());
        }
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.to_string().into_bytes())
            .map_err(|_| Failure::internal())?;
        sign_request(
            &mut request,
            &self.config.signing_key,
            KeyMaterial::JwksUri {
                id: self.config.issuer.clone(),
                dwk: "aauth-person.json".into(),
                kid: self.config.kid.clone(),
            },
            now,
        )
        .map_err(|_| Failure::internal())?;
        let response = adapter
            .send(&request)
            .map_err(|_| unreachable(&r.aud, None, Reason::TransportUnavailable))?;
        self.accept_federation(response, agent, prepared, &endpoint)
    }
    pub(super) fn accept_federation(
        &self,
        response: Response<Vec<u8>>,
        agent: &VerifiedAgentToken,
        prepared: &PreparedAuthorization,
        endpoint: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            ..
        } = prepared;
        let r = resource.claims();
        if self.deferred.is_some()
            && [StatusCode::ACCEPTED, StatusCode::PAYMENT_REQUIRED].contains(&response.status())
        {
            return self.defer_federation(&response, agent, resource, presented, context, endpoint);
        }
        let current = (self.clock)();
        self.inputs_current(agent, resource, presented, current)?;
        self.subagent_current(agent, context.subagent.as_ref(), current)?;
        let holder = context.subagent.as_ref().unwrap_or(agent);
        let failed = |reason| unreachable(&r.aud, Some(response.status()), reason);
        if response.body().len() > MAX_BODY_BYTES {
            return Err(failed(Reason::ResponseTooLarge));
        }
        let relay_terminal = |error: &str,
                              signature_error: Option<String>,
                              detail: Option<String>|
         -> Result<Failure, Failure> {
            let diagnostic = FederationFailure {
                access_server: r.aud.clone(),
                status: Some(response.status()),
                reason: Reason::TerminalError {
                    error: error.into(),
                    signature_error,
                    detail,
                },
            };
            let mut failure = Failure::status(response.status(), error);
            if error == "clock_skew" {
                if ![StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED].contains(&response.status())
                {
                    return Err(failed(Reason::MalformedResponse(
                        "clock_skew has an invalid status",
                    )));
                }
                let date = response
                    .headers()
                    .get("date")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| httpdate::parse_http_date(v).ok())
                    .and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok())
                    .and_then(|v| i64::try_from(v.as_secs()).ok())
                    .ok_or_else(|| {
                        failed(Reason::MalformedResponse("clock_skew has no valid Date"))
                    })?;
                failure = failure.with_date(date);
            }
            Ok(failure.with_federation(diagnostic))
        };
        let terminal = response.status() != StatusCode::PAYMENT_REQUIRED
            && (response.status().is_client_error() || response.status().is_server_error());
        if response.status() != StatusCode::OK
            && terminal
            && let Some(header) = response.headers().get("signature-error")
        {
            let header = header
                .to_str()
                .map_err(|_| failed(Reason::MalformedResponse("invalid Signature-Error")))?;
            let error = aauth_rust_signature_key::signature_error_code(header)
                .ok()
                .filter(|code| problem_code(code))
                .ok_or_else(|| failed(Reason::MalformedResponse("invalid Signature-Error")))?;
            return Err(relay_terminal(
                &error,
                Some(bounded(header, 1024)),
                problem_detail(response.body()),
            )?);
        }
        let value = strict_json(response.body())
            .map_err(|_| failed(Reason::MalformedResponse("response is not strict JSON")))?;
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .ok_or_else(|| failed(Reason::MalformedResponse("missing or invalid Content-Type")))?;
        if response.status() != StatusCode::OK {
            if terminal && content_type.eq_ignore_ascii_case("application/problem+json") {
                let error = value
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|code| problem_code(code))
                    .ok_or_else(|| {
                        failed(Reason::MalformedResponse("invalid terminal problem error"))
                    })?;
                return Err(relay_terminal(
                    error,
                    response
                        .headers()
                        .get("signature-error")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| bounded(s, 1024)),
                    value
                        .get("detail")
                        .and_then(Value::as_str)
                        .map(|s| bounded(s, 4096)),
                )?);
            }
            return Err(failed(Reason::UnsupportedResponse));
        }
        if !content_type.eq_ignore_ascii_case("application/json") {
            return Err(failed(Reason::MalformedResponse(
                "Auth response is not application/json",
            )));
        }
        let compact = value
            .get("auth_token")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| failed(Reason::MalformedResponse("missing Auth token")))?;
        let token = AuthToken::parse(compact)
            .and_then(|t| t.verify(&self.resolver(), current))
            .map_err(|error| failed(Reason::TokenVerification(error)))?;
        let c = token.claims();
        let granted = parse_scopes(c.scope.as_deref().unwrap_or(""))
            .ok_or_else(|| failed(Reason::InvalidGrant))?;
        if c.iss != r.aud
            || c.dwk != "aauth-access.json"
            || c.aud != r.iss
            || c.ps != self.config.issuer
            || c.sub != r.sub
            || c.cnf.jwk.thumbprint().ok() != holder.claims().cnf.jwk.thumbprint().ok()
            || c.tenant != r.tenant
            || c.account != r.account
            || c.mission_s256 != r.mission_s256
            || unsupported(&c.extra)
            || c.exp > agent.claims().exp
            || c.exp > holder.claims().exp
            || c.exp > presented.exp
            || c.iat > current.saturating_add(60)
            || granted.iter().any(|s| !context.scopes.contains(s))
        {
            return Err(failed(Reason::InvalidGrant));
        }
        let mut record = self.record(
            compact,
            holder,
            &retained.principal,
            &retained.person_id,
            Issuance {
                parent_agent: context.subagent.as_ref().map(|_| Self::identity(agent)),
                kind: TokenKind::Auth,
                jti: &c.jti,
                resource: &c.aud,
                subject: &c.sub,
                tenant: c.tenant.clone(),
                issued_at: c.iat,
                expires_at: c.exp,
                presented: Some(retained.token.clone()),
                upstream: None,
            },
        )?;
        record.token.reference.issuer = c.iss.clone();
        record.person_server = Some(self.config.issuer.clone());
        self.store.commit(record, false).map_err(|e| match e {
            StoreError::Conflict => failed(Reason::InvalidGrant),
            other => store_issuance_failure(other, BindingContext::Presented),
        })?;
        self.subagent_current(agent, context.subagent.as_ref(), (self.clock)())?;
        self.binding(&retained.principal, BindingContext::Presented)?
            .ok_or_else(Failure::internal)?;
        let released = (self.clock)();
        self.inputs_current(agent, resource, presented, released)?;
        check_subagent_current(context.subagent.as_ref(), released)?;
        if c.exp <= released {
            return Err(Failure::internal().with_federation(FederationFailure {
                access_server: r.aud.clone(),
                status: Some(response.status()),
                reason: Reason::ExpiredBeforeRelease,
            }));
        }
        Ok(token_response(
            "auth_token",
            compact.into(),
            c.exp - released,
        ))
    }
}
pub(super) fn unreachable(
    access_server: &str,
    status: Option<StatusCode>,
    reason: Reason,
) -> Failure {
    Failure::status(StatusCode::BAD_GATEWAY, "as_unreachable").with_federation(FederationFailure {
        access_server: access_server.into(),
        status,
        reason,
    })
}
fn bounded(value: &str, max_bytes: usize) -> String {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn problem_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn problem_detail(body: &[u8]) -> Option<String> {
    strict_json(body)
        .ok()
        .and_then(|value| {
            value
                .get("detail")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .map(|detail| bounded(&detail, 4096))
}
