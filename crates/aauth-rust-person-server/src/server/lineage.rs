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
        self.verify_presented_with(compact, now, parameter, false)
    }
    /// `allow_r3` admits R3 members on a presented Auth token only for the R3
    /// exchange path, which verifies those claims from the signed payload itself.
    pub(super) fn verify_presented_with(
        &self,
        compact: &str,
        now: i64,
        parameter: &'static str,
        allow_r3: bool,
    ) -> Result<Presented, Failure> {
        let parsed =
            Jws::parse(compact).map_err(|error| Failure::token(error.into(), parameter, now))?;
        let value = match parsed.header().get("typ").and_then(Value::as_str) {
            Some("aa-person+jwt") => {
                let parsed = PersonToken::parse(compact)
                    .map_err(|error| Failure::token(error, parameter, now))?;
                let issuer = parsed.unverified_claims().iss.clone();
                let jti = parsed.unverified_claims().jti.clone();
                let token = match parsed.verify(&self.resolver(), now) {
                    Ok(token) => token,
                    Err(TokenError::ExpiredJwt) if self.token_revoked(&issuer, &jti, now) => {
                        return Err(super::revocation::revoked_parameter(parameter));
                    }
                    Err(error) => return Err(Failure::token(error, parameter, now)),
                };
                if self.token_revoked(&issuer, &jti, now) {
                    return Err(super::revocation::revoked_parameter(parameter));
                }
                let c = token.claims();
                if extra_blocks(&c.extra, false, false, false) {
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
                let parsed = AuthToken::parse(compact)
                    .map_err(|error| Failure::token(error, parameter, now))?;
                let issuer = parsed.unverified_claims().iss.clone();
                let jti = parsed.unverified_claims().jti.clone();
                let token = match parsed.verify(&self.resolver(), now) {
                    Ok(token) => token,
                    Err(TokenError::ExpiredJwt) if self.token_revoked(&issuer, &jti, now) => {
                        return Err(super::revocation::revoked_parameter(parameter));
                    }
                    Err(error) => return Err(Failure::token(error, parameter, now)),
                };
                if self.token_revoked(&issuer, &jti, now) {
                    return Err(super::revocation::revoked_parameter(parameter));
                }
                let c = token.claims();
                let valid_role = if self.federation.is_some() {
                    c.dwk == "aauth-access.json" && c.ps == self.config.issuer
                } else {
                    c.dwk == "aauth-person.json"
                };
                let allow_budget = self.budgets.is_some();
                let mut core = c.extra.clone();
                if allow_r3 {
                    for name in ["r3_uri", "r3_s256", "r3_granted", "r3_per_call"] {
                        core.remove(name);
                    }
                }
                if !valid_role || extra_blocks(&core, allow_budget, false, false) {
                    return Err(Failure::token(TokenError::InvalidJwt, parameter, now));
                }
                if allow_budget && let Some(budget) = c.extra.get("budget") {
                    aauth_rust_budgets::parse_budget(budget)
                        .map_err(|_| Failure::parameter("invalid_budget"))?;
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
        if value.mission.is_some() && (parameter == "upstream" || self.federation.is_some()) {
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
            parent_agent: issuance.parent_agent,
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
