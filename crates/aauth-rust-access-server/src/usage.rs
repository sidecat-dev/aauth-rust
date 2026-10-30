//! Usage counters an Access Server reads from a resource
//! (`draft-hardt-aauth-budgets`, Usage Request and Usage Response).
use super::*;
use aauth_rust_budgets::{
    Error as BudgetError, KeyRole, UsageQuery, UsageResponse, parse_usage_response,
    validate_endpoint_url,
};
use aauth_rust_signature_key::sign_request;

impl<
    K: AgentKeyResolver,
    P: Fn(&AuthorizationRequest) -> Result<Decision, PolicyError>,
    C: Fn() -> i64,
    I: Fn() -> String,
> AccessServer<K, P, C, I>
{
    /// Build the signed POST that asks a resource's `usage_endpoint` for its
    /// counters. The Access Server signs as itself: `jwks_uri` with `id` its
    /// issuer and `dwk` `aauth-access.json`, covering `content-type` and
    /// `content-digest`. A query with a scope key names in `ps` the person
    /// server whose namespace that key belongs to. The host takes
    /// `usage_endpoint` from the resource's metadata, applies its egress
    /// admission, sends these exact bytes and passes the answer to
    /// [`Self::read_usage`]. Nothing here contacts the resource.
    ///
    /// # Errors
    /// [`BudgetError::Endpoint`] unless `endpoint` is an HTTPS URL without a
    /// query or fragment. [`BudgetError::Malformed`] for a query that breaks
    /// the request rules, such as a scope key without `ps`, or a request that
    /// cannot be signed at this clock.
    pub fn usage_request(
        &self,
        endpoint: &str,
        query: &UsageQuery,
    ) -> Result<Request<Vec<u8>>, BudgetError> {
        validate_endpoint_url(endpoint)?;
        let body = query.to_value(KeyRole::AccessServer)?;
        let mut request = Request::builder()
            .method("POST")
            .uri(endpoint)
            .header("content-type", "application/json")
            .body(body.to_string().into_bytes())
            .map_err(|_| BudgetError::Endpoint)?;
        sign_request(
            &mut request,
            &self.config.signing_key,
            KeyMaterial::JwksUri {
                id: self.config.issuer.clone(),
                dwk: "aauth-access.json".into(),
                kid: self.config.kid.clone(),
            },
            (self.clock)(),
        )
        .map_err(|_| BudgetError::Malformed)?;
        Ok(request)
    }

    /// Read the resource's answer to [`Self::usage_request`] for `query`.
    /// The response must be `200` and produced for this Access Server.
    ///
    /// # Errors
    /// [`BudgetError::Malformed`] for any other status, and the errors of
    /// [`aauth_rust_budgets::parse_usage_response`].
    pub fn read_usage(
        &self,
        response: &Response<Vec<u8>>,
        query: &UsageQuery,
    ) -> Result<UsageResponse, BudgetError> {
        if response.status() != StatusCode::OK {
            return Err(BudgetError::Malformed);
        }
        parse_usage_response(response.body(), &self.config.issuer, query)
    }
}
