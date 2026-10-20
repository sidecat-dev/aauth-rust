use super::*;
use aauth_rust_signature_key::{MAX_BODY_BYTES, sign_request};

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    pub(super) fn federate(
        &self,
        agent: &VerifiedAgentToken,
        resource: &VerifiedResourceToken,
        presented: &Presented,
        retained: &TokenRecord,
        context: &AuthorizationRequest,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let r = resource.claims();
        if presented.kind == TokenKind::Auth && presented.issuer != r.aud {
            return Err(Failure::parameter("invalid_presented_token"));
        }
        self.policy.consent(context).map_err(Failure::policy)?;
        let now = (self.clock)();
        self.inputs_current(agent, resource, presented, now)?;
        self.binding(&retained.principal, BindingContext::Presented)?
            .ok_or_else(Failure::internal)?;
        let adapter = self.federation.as_ref().ok_or_else(Failure::internal)?;
        let endpoint = adapter.endpoint(&r.aud).map_err(|_| unreachable())?;
        let uri: http::Uri = endpoint.parse().map_err(|_| unreachable())?;
        canonical_authority(&uri).map_err(|_| unreachable())?;
        if uri.query().is_some() || endpoint.contains('#') {
            return Err(unreachable());
        }
        let resource_compact = required_string(&context.parameters, "resource_token")?;
        let presented_compact = required_string(&context.parameters, "presented_token")?;
        let mut request=Request::builder().method("POST").uri(uri).header("content-type","application/json")
            .body(json!({"agent_token":agent.compact(),"resource_token":resource_compact,"presented_token":presented_compact}).to_string().into_bytes())
            .map_err(|_|Failure::internal())?;
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
        let response = adapter.send(&request).map_err(|_| unreachable())?;
        let current = (self.clock)();
        self.inputs_current(agent, resource, presented, current)?;
        if response.body().len() > MAX_BODY_BYTES {
            return Err(unreachable());
        }
        let value = strict_json(response.body()).map_err(|_| unreachable())?;
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .ok_or_else(unreachable)?;
        if response.status() != StatusCode::OK {
            if response.status() != StatusCode::UNAUTHORIZED
                && (response.status().is_client_error() || response.status().is_server_error())
                && content_type.eq_ignore_ascii_case("application/problem+json")
            {
                let error = value
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= 128
                            && s.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    })
                    .ok_or_else(unreachable)?;
                if error == "clock_skew" {
                    if response.status() != StatusCode::BAD_REQUEST {
                        return Err(unreachable());
                    }
                    let date = response
                        .headers()
                        .get("date")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| httpdate::parse_http_date(v).ok())
                        .and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok())
                        .and_then(|v| i64::try_from(v.as_secs()).ok())
                        .ok_or_else(unreachable)?;
                    return Err(Failure::clock(date));
                }
                return Err(Failure::status(response.status(), error));
            }
            return Err(unreachable());
        }
        if !content_type.eq_ignore_ascii_case("application/json") {
            return Err(unreachable());
        }
        let compact = value
            .get("auth_token")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(unreachable)?;
        let token = AuthToken::parse(compact)
            .and_then(|t| t.verify(&self.resolver(), current))
            .map_err(|_| unreachable())?;
        let c = token.claims();
        let granted = parse_scopes(c.scope.as_deref().unwrap_or("")).ok_or_else(unreachable)?;
        if c.iss != r.aud
            || c.dwk != "aauth-access.json"
            || c.aud != r.iss
            || c.ps != self.config.issuer
            || c.sub != r.sub
            || c.cnf.jwk.thumbprint().ok() != agent.claims().cnf.jwk.thumbprint().ok()
            || c.tenant != r.tenant
            || c.account != r.account
            || c.mission_s256 != r.mission_s256
            || unsupported(&c.extra)
            || c.exp > agent.claims().exp
            || c.exp > presented.exp
            || c.iat > current.saturating_add(60)
            || granted.iter().any(|s| !context.scopes.contains(s))
        {
            return Err(unreachable());
        }
        let mut record = self.record(
            compact,
            agent,
            &retained.principal,
            &retained.person_id,
            Issuance {
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
        self.store
            .commit(record, false)
            .map_err(|e| store_issuance_failure(e, BindingContext::Presented))?;
        self.binding(&retained.principal, BindingContext::Presented)?
            .ok_or_else(Failure::internal)?;
        let released = (self.clock)();
        self.inputs_current(agent, resource, presented, released)?;
        if c.exp <= released {
            return Err(unreachable());
        }
        Ok(token_response(
            "auth_token",
            compact.into(),
            c.exp - released,
        ))
    }
}
fn unreachable() -> Failure {
    Failure::status(StatusCode::BAD_GATEWAY, "as_unreachable")
}
