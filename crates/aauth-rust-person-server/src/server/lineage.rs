use super::*;

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    pub(super) fn verify_presented(
        &self,
        compact: &str,
        now: i64,
        parameter: &'static str,
    ) -> Result<Presented, Failure> {
        let parsed =
            Jws::parse(compact).map_err(|error| Failure::token(error.into(), parameter, now))?;
        let value = match parsed.header().get("typ").and_then(Value::as_str) {
            Some("aa-person+jwt") => {
                let token = PersonToken::parse(compact)
                    .and_then(|token| token.verify(&self.resolver(), now))
                    .map_err(|error| Failure::token(error, parameter, now))?;
                let c = token.claims();
                if unsupported(&c.extra) {
                    return Err(Failure::token(TokenError::InvalidJwt, parameter, now));
                }
                Presented {
                    kind: TokenKind::Person,
                    issuer: c.iss.clone(),
                    jti: c.jti.clone(),
                    aud: c.aud.clone(),
                    ps: c.iss.clone(),
                    sub: c.sub.clone(),
                    tenant: c.tenant.clone(),
                    mission: c.mission_s256.clone(),
                    jkt: c.cnf.jwk.thumbprint().map_err(|_| Failure::internal())?,
                    iat: c.iat,
                    exp: c.exp,
                    scope: None,
                }
            }
            Some("aa-auth+jwt") => {
                let token = AuthToken::parse(compact)
                    .and_then(|token| token.verify(&self.resolver(), now))
                    .map_err(|error| Failure::token(error, parameter, now))?;
                let c = token.claims();
                let valid_role = if self.federation.is_some() {
                    c.dwk == "aauth-access.json" && c.ps == self.config.issuer
                } else {
                    c.dwk == "aauth-person.json"
                };
                if !valid_role || unsupported(&c.extra) {
                    return Err(Failure::token(TokenError::InvalidJwt, parameter, now));
                }
                Presented {
                    kind: TokenKind::Auth,
                    issuer: c.iss.clone(),
                    jti: c.jti.clone(),
                    aud: c.aud.clone(),
                    ps: c.ps.clone(),
                    sub: c.sub.clone(),
                    tenant: c.tenant.clone(),
                    mission: c.mission_s256.clone(),
                    jkt: c.cnf.jwk.thumbprint().map_err(|_| Failure::internal())?,
                    iat: c.iat,
                    exp: c.exp,
                    scope: c.scope.clone(),
                }
            }
            _ => {
                return Err(Failure::token(
                    TokenError::UnexpectedTokenType,
                    parameter,
                    now,
                ));
            }
        };
        check_parameter_iat(value.iat, now)?;
        if value.mission.is_some() {
            return Err(Failure::token(TokenError::InvalidJwt, parameter, now));
        }
        Ok(value)
    }
    pub(super) fn match_resource(
        &self,
        p: &Presented,
        r: &aauth_rust_core::ResourceClaims,
    ) -> Result<(), Failure> {
        if p.aud != r.iss || p.jkt != r.agent_jkt {
            return Err(Failure::parameter("invalid_presented_token"));
        }
        if p.jti != r.presented_jti
            || p.ps != r.ps
            || p.sub != r.sub
            || p.tenant != r.tenant
            || p.mission != r.mission_s256
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        Ok(())
    }
    pub(super) fn load_record(
        &self,
        p: &Presented,
        compact: &str,
        now: i64,
        parameter: &'static str,
    ) -> Result<TokenRecord, Failure> {
        let reference = TokenReference {
            issuer: p.issuer.clone(),
            jti: p.jti.clone(),
        };
        let record = self
            .store
            .token(&reference)
            .map_err(|_| Failure::internal())?
            .ok_or_else(|| Failure::token(TokenError::InvalidJwt, parameter, now))?;
        if record.binding_issuer() != self.config.issuer
            || record.token.reference != reference
            || record.token.compact_sha256 != digest(compact)
            || record.kind != p.kind
            || record.resource != p.aud
            || record.subject != p.sub
            || record.tenant != p.tenant
            || record.agent_jkt != p.jkt
            || record.issued_at != p.iat
            || record.expires_at != p.exp
            || record.retain_until <= now
            || record.person_id.is_empty()
            || record.agent_token_jti.is_empty()
        {
            return Err(Failure::token(TokenError::InvalidJwt, parameter, now));
        }
        Ok(record)
    }
    pub(super) fn record(
        &self,
        compact: &str,
        agent: &VerifiedAgentToken,
        principal: &AgentIdentity,
        person_id: &str,
        issuance: Issuance<'_>,
    ) -> Result<TokenRecord, Failure> {
        Ok(TokenRecord {
            person_server: None,
            token: TokenTie {
                reference: TokenReference {
                    issuer: self.config.issuer.clone(),
                    jti: issuance.jti.into(),
                },
                compact_sha256: digest(compact),
            },
            kind: issuance.kind,
            resource: issuance.resource.into(),
            subject: issuance.subject.into(),
            person_id: person_id.into(),
            tenant: issuance.tenant,
            agent: Self::identity(agent),
            principal: principal.clone(),
            agent_token_jti: agent.claims().jti.clone(),
            agent_jkt: agent
                .claims()
                .cnf
                .jwk
                .thumbprint()
                .map_err(|_| Failure::internal())?,
            issued_at: issuance.issued_at,
            expires_at: issuance.expires_at,
            retain_until: issuance
                .expires_at
                .saturating_add(self.config.max_resource_lifetime)
                .saturating_add(3660),
            presented: issuance.presented,
            upstream: issuance.upstream,
        })
    }
}
