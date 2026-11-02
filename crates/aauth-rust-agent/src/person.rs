//! A direct Agent's Person token: the request to its Person Server and the
//! check of the token it delivers (protocol, Person Token Endpoint).
use crate::Agent;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, PersonToken, TokenError, VerifiedPersonToken,
    validate_server_identifier,
};
use http::Request;
use serde_json::{Value, json};

impl Agent {
    /// Build and sign the Person token request for `resource`: a POST of
    /// `{"resource": resource}` to the Person Server's
    /// `person_token_endpoint`, signed with this Agent's Agent token
    /// (protocol, Person Token Endpoint).
    ///
    /// Send it when a Resource answers `requirement=person-token`
    /// ([`crate::Requirement::PersonToken`]). Check the `person_token` member
    /// of the `200` response with [`Self::verify_person_delivery`] on this
    /// same Agent, then retry the Resource with the Agent that
    /// [`Self::with_token`] returns for it. The request names no mission and
    /// declares no capabilities. The host admits `endpoint` from trusted
    /// Person Server metadata and sends the returned bytes unchanged. No
    /// transport or retry is performed.
    ///
    /// # Errors
    /// The token-type error when this Agent holds a Person or Auth token
    /// rather than its Agent token. `InvalidJwt` for a `resource` that is not
    /// a server identifier, an endpoint that is not an HTTPS URL without
    /// query, or failed signing.
    pub fn person_request(
        &self,
        endpoint: &str,
        resource: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, TokenError> {
        AgentToken::parse(self.token())?;
        validate_server_identifier(resource)?;
        self.sign_json_post(endpoint, &json!({ "resource": resource }), None, now)
    }

    /// Authenticate the Person token `person_server` delivered for
    /// `intended_resource` in answer to [`Self::person_request`].
    ///
    /// The token must verify under trusted `keys` at `now`, be issued by
    /// `person_server` for `intended_resource`, confirm this Agent's key,
    /// name no mission, as the request named none, and expire no later than
    /// the Agent token this Agent holds (protocol, Person Token Structure).
    /// When that Agent token names a `ps`, it must be `person_server`.
    ///
    /// # Errors
    /// The token-type error when this Agent holds no Agent token. Trust and
    /// time failures of the Person token. `InvalidJwt` for another issuer,
    /// audience, key or Person Server, a mission, or a later expiry.
    pub fn verify_person_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedPersonToken, TokenError> {
        validate_server_identifier(intended_resource)?;
        validate_server_identifier(person_server)?;
        let agent = AgentToken::parse(self.token())?;
        let agent = agent.unverified_claims();
        let token = PersonToken::parse(compact)?.verify(keys, now)?;
        let c = token.claims();
        if c.iss != person_server
            || c.aud != intended_resource
            || agent.ps.as_deref().is_some_and(|ps| ps != person_server)
            || c.cnf.jwk.thumbprint()? != self.public_jwk().thumbprint()?
            || c.mission_s256.is_some()
            || c.exp > agent.exp
        {
            return Err(TokenError::InvalidJwt);
        }
        Ok(token)
    }

    /// Sign a JSON POST to a Person Server endpoint with this Agent's token,
    /// declaring `capabilities` in `AAuth-Capabilities` when given.
    pub(crate) fn sign_json_post(
        &self,
        endpoint: &str,
        body: &Value,
        capabilities: Option<&str>,
        now: i64,
    ) -> Result<Request<Vec<u8>>, TokenError> {
        let uri: http::Uri = endpoint.parse().map_err(|_| TokenError::InvalidJwt)?;
        let authority = uri.authority().ok_or(TokenError::InvalidJwt)?;
        if uri.scheme_str() != Some("https")
            || authority.host().is_empty()
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || endpoint.contains('#')
        {
            return Err(TokenError::InvalidJwt);
        }
        let mut request = Request::post(uri).header("content-type", "application/json");
        if let Some(capabilities) = capabilities {
            request = request.header("aauth-capabilities", capabilities);
        }
        let mut request = request
            .body(serde_json::to_vec(body).map_err(|_| TokenError::InvalidJwt)?)
            .map_err(|_| TokenError::InvalidJwt)?;
        self.sign(&mut request, now)
            .map_err(|_| TokenError::InvalidJwt)?;
        Ok(request)
    }
}
