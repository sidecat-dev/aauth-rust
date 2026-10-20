//! Person, Resource and Auth JWT trust verification and local minting.
//!
//! These types verify issuer trust, signatures and token syntax/time. They do
//! not bind audience, request key, presented/upstream lineage, person records,
//! scopes or companion claims to a request. Role implementations must do so.
use crate::{
    AgentKeyResolver, Confirmation, TokenError, present_claim, validate_server_identifier,
};
use aauth_rust_jose::{Jws, SigningKey, strict_json};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Claims of an identity-only aa-person+jwt. Scope and account are forbidden.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonClaims {
    /// Canonical HTTPS server identifier of the issuer.
    pub iss: String,
    /// Exact well-known metadata document name for this issuer role.
    pub dwk: String,
    /// Canonical HTTPS identifier of the intended recipient.
    pub aud: String,
    /// Opaque Resource-directed person identifier; interpret with its issuer.
    pub sub: String,
    /// Issuer-assigned token identifier.
    pub jti: String,
    /// Issued-at Unix seconds. A future iat alone does not invalidate a token.
    pub iat: i64,
    /// Expiry Unix seconds; verification requires exp strictly greater than now.
    pub exp: i64,
    /// Public request-signing key of the token holder.
    pub cnf: Confirmation,
    /// Optional not-before Unix seconds.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<i64>,
    /// Optional organization identifier; it is not part of the person's identity.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub tenant: Option<String>,
    /// Optional canonical unpadded base64url SHA-256 mission digest.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub mission_s256: Option<String>,
    /// Additive claims retained without conferring companion or application authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Claims of an aa-resource+jwt requesting authorization from its PS or AS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceClaims {
    /// Canonical HTTPS server identifier of the issuer.
    pub iss: String,
    /// Exact well-known metadata document name for this issuer role.
    pub dwk: String,
    /// Canonical HTTPS identifier of the intended recipient.
    pub aud: String,
    /// Opaque Resource-directed person identifier; interpret with its issuer.
    pub sub: String,
    /// Issuer-assigned token identifier.
    pub jti: String,
    /// Issued-at Unix seconds. A future iat alone does not invalidate a token.
    pub iat: i64,
    /// Expiry Unix seconds; verification requires exp strictly greater than now.
    pub exp: i64,
    /// Person Server whose namespace contains sub.
    pub ps: String,
    /// Exact identifier of the Person/Auth token presented to the Resource.
    pub presented_jti: String,
    /// Canonical unpadded base64url SHA-256 thumbprint of the request key.
    pub agent_jkt: String,
    /// Optional not-before Unix seconds.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<i64>,
    /// Optional organization identifier; it is not part of the person's identity.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub tenant: Option<String>,
    /// Optional canonical unpadded base64url SHA-256 mission digest.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub mission_s256: Option<String>,
    /// Optional space-separated Core scopes; companion authority remains separate.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub scope: Option<String>,
    /// Optional account identifier; an empty string is distinct from absence.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub account: Option<String>,
    /// Optional Resource-supplied login hint, forwarded unchanged by the Agent.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub login_hint: Option<String>,
    /// Additive claims retained without conferring companion or application authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Claims of an aa-auth+jwt. JWT verification alone does not authorize a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthClaims {
    /// Canonical HTTPS server identifier of the issuer.
    pub iss: String,
    /// Exact well-known metadata document name for this issuer role.
    pub dwk: String,
    /// Canonical HTTPS identifier of the intended recipient.
    pub aud: String,
    /// Opaque Resource-directed person identifier; interpret with its issuer.
    pub sub: String,
    /// Issuer-assigned token identifier.
    pub jti: String,
    /// Issued-at Unix seconds. A future iat alone does not invalidate a token.
    pub iat: i64,
    /// Expiry Unix seconds; verification requires exp strictly greater than now.
    pub exp: i64,
    /// Person Server representing the person; equals iss for PS-issued tokens.
    pub ps: String,
    /// Public request-signing key of the token holder.
    pub cnf: Confirmation,
    /// Optional not-before Unix seconds.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<i64>,
    /// Optional organization identifier; it is not part of the person's identity.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub tenant: Option<String>,
    /// Optional canonical unpadded base64url SHA-256 mission digest.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub mission_s256: Option<String>,
    /// Optional space-separated Core scopes; companion authority remains separate.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub scope: Option<String>,
    /// Optional account identifier; an empty string is distinct from absence.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub account: Option<String>,
    /// Additive claims retained without conferring companion or application authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

struct CommonClaims<'a> {
    iss: &'a str,
    dwk: &'a str,
    aud: &'a str,
    sub: &'a str,
    jti: &'a str,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    tenant: Option<&'a str>,
    mission: Option<&'a str>,
}
fn validate_common(
    claims: CommonClaims<'_>,
    documents: &[&str],
    maximum: Option<i64>,
) -> Result<(), TokenError> {
    validate_server_identifier(claims.iss)?;
    validate_server_identifier(claims.aud)?;
    if !documents.contains(&claims.dwk) {
        return Err(TokenError::InvalidDiscoveryDocument);
    }
    if claims.sub.is_empty() || claims.jti.is_empty() || claims.tenant == Some("") {
        return Err(TokenError::InvalidJwt);
    }
    if claims.iat < 0
        || claims.exp <= claims.iat
        || claims.nbf.is_some_and(|t| t < 0)
        || maximum.is_some_and(|limit| claims.exp - claims.iat > limit)
    {
        return Err(TokenError::InvalidTokenLifetime);
    }
    if let Some(digest) = claims.mission {
        validate_digest(digest)?;
    }
    Ok(())
}
fn validate_digest(value: &str) -> Result<(), TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::InvalidJwt)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(TokenError::InvalidJwt);
    }
    Ok(())
}
fn reject_reserved(extra: &BTreeMap<String, Value>, reserved: &[&str]) -> Result<(), TokenError> {
    if reserved.iter().any(|name| extra.contains_key(*name)) {
        return Err(TokenError::InvalidJwt);
    }
    Ok(())
}
fn validate_scope(scope: Option<&str>) -> Result<(), TokenError> {
    if let Some(scope) = scope {
        let mut seen = std::collections::BTreeSet::new();
        for item in scope.split(' ') {
            if item.is_empty()
                || !item
                    .bytes()
                    .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
                || !seen.insert(item)
            {
                return Err(TokenError::InvalidJwt);
            }
        }
    }
    Ok(())
}

macro_rules! common_claims {
    ($claims:expr) => {
        CommonClaims {
            iss: &$claims.iss,
            dwk: &$claims.dwk,
            aud: &$claims.aud,
            sub: &$claims.sub,
            jti: &$claims.jti,
            iat: $claims.iat,
            exp: $claims.exp,
            nbf: $claims.nbf,
            tenant: $claims.tenant.as_deref(),
            mission: $claims.mission_s256.as_deref(),
        }
    };
}
impl PersonClaims {
    /// Validate identity-only syntax, public confirmation key and one-hour ceiling.
    /// This does not authenticate the issuer or establish any request context.
    ///
    /// # Errors
    /// Returns an error for malformed claims, forbidden scope/account or reserved extras.
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_common(common_claims!(self), &["aauth-person.json"], Some(3600))?;
        reject_reserved(
            &self.extra,
            &[
                "iss",
                "dwk",
                "aud",
                "sub",
                "jti",
                "iat",
                "exp",
                "cnf",
                "nbf",
                "tenant",
                "mission_s256",
                "scope",
                "account",
            ],
        )?;
        self.cnf.jwk.validate()?;
        Ok(())
    }
}
impl ResourceClaims {
    /// Validate Resource syntax and key thumbprint; no recipient/lineage binding.
    /// The draft's recommended five-minute lifetime is left to role policy.
    ///
    /// # Errors
    /// Returns an error for malformed claims, cnf or reserved extras.
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_common(common_claims!(self), &["aauth-resource.json"], None)?;
        validate_server_identifier(&self.ps)?;
        if self.presented_jti.is_empty() {
            return Err(TokenError::InvalidJwt);
        }
        validate_digest(&self.agent_jkt)?;
        validate_scope(self.scope.as_deref())?;
        reject_reserved(
            &self.extra,
            &[
                "iss",
                "dwk",
                "aud",
                "sub",
                "jti",
                "iat",
                "exp",
                "ps",
                "presented_jti",
                "agent_jkt",
                "nbf",
                "tenant",
                "mission_s256",
                "scope",
                "account",
                "login_hint",
                "cnf",
            ],
        )
    }
}
impl AuthClaims {
    /// Validate Auth syntax, public confirmation key and one-hour ceiling.
    /// Both PS and AS discovery roles are supported, without enabling federation.
    ///
    /// # Errors
    /// Returns an error for malformed claims, a PS issuer/ps mismatch or reserved extras.
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_common(
            common_claims!(self),
            &["aauth-person.json", "aauth-access.json"],
            Some(3600),
        )?;
        validate_server_identifier(&self.ps)?;
        if self.dwk == "aauth-person.json" && self.iss != self.ps {
            return Err(TokenError::IssuerMismatch);
        }
        self.cnf.jwk.validate()?;
        validate_scope(self.scope.as_deref())?;
        reject_reserved(
            &self.extra,
            &[
                "iss",
                "dwk",
                "aud",
                "sub",
                "jti",
                "iat",
                "exp",
                "ps",
                "cnf",
                "nbf",
                "tenant",
                "mission_s256",
                "scope",
                "account",
            ],
        )
    }
}

fn parse_claims<T: serde::de::DeserializeOwned>(
    compact: &str,
    typ: &str,
) -> Result<(Jws, T, String), TokenError> {
    let jws = Jws::parse(compact)?;
    if jws.header().get("typ").and_then(Value::as_str) != Some(typ) {
        return Err(TokenError::UnexpectedTokenType);
    }
    let kid = jws
        .header()
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TokenError::InvalidKeyId)?
        .to_owned();
    let claims =
        serde_json::from_value(strict_json(jws.payload()).map_err(|_| TokenError::InvalidJwt)?)
            .map_err(|_| TokenError::InvalidJwt)?;
    Ok((jws, claims, kid))
}
fn verify_signature(
    jws: &Jws,
    claims: CommonClaims<'_>,
    kid: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<(), TokenError> {
    let key = keys.key(claims.iss, claims.dwk, kid)?;
    jws.verify(&key)?;
    if now < 0 {
        return Err(TokenError::InvalidJwt);
    }
    if claims.exp <= now {
        return Err(TokenError::ExpiredJwt);
    }
    if claims.nbf.is_some_and(|nbf| nbf > now) {
        return Err(TokenError::InvalidJwt);
    }
    Ok(())
}
fn mint<T: Serialize>(
    key: &SigningKey,
    kid: &str,
    typ: &str,
    claims: &T,
    times: (i64, i64),
) -> Result<String, TokenError> {
    if kid.is_empty() {
        return Err(TokenError::InvalidKeyId);
    }
    if !(0..=(1_i64 << 33) - 1).contains(&times.0) || !(0..=(1_i64 << 33) - 1).contains(&times.1) {
        return Err(TokenError::InvalidTokenLifetime);
    }
    Jws::sign(
        &json!({"alg":"Ed25519","typ":typ,"kid":kid}),
        &serde_json::to_vec(claims).map_err(|_| TokenError::InvalidJwt)?,
        key,
    )
    .map_err(Into::into)
}

macro_rules! role_token {
    ($token:ident, $verified:ident, $claims:ident, $mint:ident, $typ:literal) => {
        /// Unverified role JWT. Parsing preserves exact bytes and grants no authority.
        pub struct $token {
            jws: Jws,
            claims: $claims,
            kid: String,
        }
        impl $token {
            /// Parse strict JSON and validate role syntax without authenticating it.
            ///
            /// # Errors
            /// Rejects malformed JWTs, wrong typ/dwk, invalid keys/claims and null optionals.
            pub fn parse(compact: &str) -> Result<Self, TokenError> {
                let (jws, claims, kid) = parse_claims::<$claims>(compact, $typ)?;
                claims.validate()?;
                Ok(Self { jws, claims, kid })
            }
            /// Inspect unauthenticated claims only for routing/discovery, never policy.
            pub fn unverified_claims(&self) -> &$claims {
                &self.claims
            }
            /// Authenticate issuer signature, exp and nbf at Unix seconds now.
            /// Audience, request-key, lineage and application/companion authority
            /// are deliberately not established by this method.
            ///
            /// # Errors
            /// Returns resolver/signature errors or expired/not-yet-valid JWT errors.
            pub fn verify(
                &self,
                keys: &dyn AgentKeyResolver,
                now: i64,
            ) -> Result<$verified, TokenError> {
                verify_signature(&self.jws, common_claims!(self.claims), &self.kid, keys, now)?;
                Ok($verified {
                    claims: self.claims.clone(),
                    compact: self.jws.compact().into(),
                })
            }
        }
        impl std::fmt::Debug for $token {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($token))
                    .field("unverified_issuer", &self.claims.iss)
                    .finish_non_exhaustive()
            }
        }
        /// Authenticated role claims and exact bytes. Request-context binding is separate.
        #[derive(Clone)]
        pub struct $verified {
            claims: $claims,
            compact: String,
        }
        impl $verified {
            /// Issuer-authenticated claims; role/request policy remains to be checked.
            pub fn claims(&self) -> &$claims {
                &self.claims
            }
            /// Exact authenticated compact bytes; forward without reserialization.
            pub fn compact(&self) -> &str {
                &self.compact
            }
        }
        impl std::fmt::Debug for $verified {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($verified))
                    .field("issuer", &self.claims.iss)
                    .finish_non_exhaustive()
            }
        }
        /// Mint a role JWT after host policy has approved its claims and parent bounds.
        /// Local iat/exp must be Unix seconds in 0..=8589934591.
        ///
        /// # Errors
        /// Rejects malformed role claims, empty kid, local timestamp overflow or signing errors.
        pub fn $mint(key: &SigningKey, kid: &str, claims: &$claims) -> Result<String, TokenError> {
            claims.validate()?;
            mint(key, kid, $typ, claims, (claims.iat, claims.exp))
        }
    };
}
role_token!(
    PersonToken,
    VerifiedPersonToken,
    PersonClaims,
    mint_person_token,
    "aa-person+jwt"
);
role_token!(
    ResourceToken,
    VerifiedResourceToken,
    ResourceClaims,
    mint_resource_token,
    "aa-resource+jwt"
);
role_token!(
    AuthToken,
    VerifiedAuthToken,
    AuthClaims,
    mint_auth_token,
    "aa-auth+jwt"
);
