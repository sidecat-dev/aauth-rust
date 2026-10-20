use super::wire::encode;
use super::*;
impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Explicitly perform one signed AS GET/POST/DELETE after host action. Reuse
    /// original consent and authenticate original context again; no token POST
    /// replay or direct-issuance fallback. Returns the actual AS pending response
    /// or verified/retained PS terminal response for diagnostics. This is not
    /// Agent delivery: the PS pending URL still owns its single terminal release.
    pub fn advance_federation(
        &self,
        reference: &str,
        input: FederationInput,
    ) -> Result<Response<Vec<u8>>, AdvanceError> {
        let d = self.deferred.as_ref().ok_or(AdvanceError::Unavailable)?;
        let id = self.reference(reference)?;
        let snapshot = d
            .store
            .load(&id)
            .map_err(|_| AdvanceError::Unavailable)?
            .ok_or(AdvanceError::Gone)?;
        let mut value = snapshot.value;
        let now = (self.clock)();
        if now >= number(&value, "deadline").map_err(|_| AdvanceError::Unavailable)? {
            return Err(AdvanceError::Expired);
        }
        if value["state"] != "waiting" {
            return Err(AdvanceError::NotReady);
        }
        let pending: PendingResponse = serde_json::from_value(value["as_pending"].clone())
            .map_err(|_| AdvanceError::Unavailable)?;
        let cancel = matches!(input, FederationInput::Cancel);
        let (method, body) = match input {
            FederationInput::Cancel => ("DELETE", None),
            FederationInput::Claims(claims) => {
                if !matches!(pending.requirement, Requirement::Claims(_))
                    || claims.contains_key("sub")
                {
                    return Err(AdvanceError::InvalidInput);
                }
                ("POST", Some(Value::Object(claims)))
            }
            FederationInput::Clarification(answer) => {
                if !matches!(pending.requirement, Requirement::Clarification { .. })
                    || answer.is_empty()
                    || answer.len() > 65536
                {
                    return Err(AdvanceError::InvalidInput);
                }
                (
                    "POST",
                    Some(
                        json!({"action":"clarification_response","clarification_response":answer}),
                    ),
                )
            }
            FederationInput::Poll => {
                if let Some(answer) = value["queued"].as_str() {
                    (
                        "POST",
                        Some(
                            json!({"action":"clarification_response","clarification_response":answer}),
                        ),
                    )
                } else {
                    if now < number(&value, "next_as").map_err(|_| AdvanceError::Unavailable)? {
                        return Err(AdvanceError::NotReady);
                    }
                    ("GET", None)
                }
            }
        };
        value["state"] = json!("advancing");
        if !d
            .store
            .replace(&id, snapshot.revision, Some(value.clone()))
            .map_err(|_| AdvanceError::Unavailable)?
        {
            return Err(AdvanceError::NotReady);
        }
        let mut waiting = false;
        let result = (|| -> Result<Response<Vec<u8>>, Failure> {
            let agent = AgentToken::parse(required_string(&value, "agent_token")?)
                .and_then(|t| t.verify(&self.resolver(), now))
                .map_err(Failure::credential)?;
            let prepared =
                self.prepare_authorization(&agent, value["parameters"].clone(), now, None)?;
            let adapter = self.federation.as_ref().ok_or_else(Failure::internal)?;
            let endpoint = required_string(&value, "endpoint")?;
            if adapter
                .endpoint(&prepared.resource.claims().aud)
                .ok()
                .as_deref()
                != Some(endpoint)
            {
                return Err(super::federation::unreachable(
                    &prepared.resource.claims().aud,
                    None,
                    crate::FederationFailureReason::EndpointUnavailable,
                ));
            }
            same_origin_location(endpoint, &pending.location).map_err(|_| Failure::internal())?;
            let mut builder = Request::builder().method(method).uri(&pending.location);
            if body.is_some() {
                builder = builder.header("content-type", "application/json");
            }
            let mut request = builder
                .body(body.map(|v| v.to_string().into_bytes()).unwrap_or_default())
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
            let response = adapter.send(&request).map_err(|_| {
                super::federation::unreachable(
                    &prepared.resource.claims().aud,
                    None,
                    crate::FederationFailureReason::TransportUnavailable,
                )
            })?;
            let current = (self.clock)();
            self.inputs_current(&agent, &prepared.resource, &prepared.presented, current)?;
            if cancel {
                if response.status() != StatusCode::OK && response.status() != StatusCode::GONE {
                    return Err(super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::UnsupportedResponse,
                    ));
                }
                return Ok(json_response(StatusCode::OK, json!({"status":"cancelled"})));
            }
            if [StatusCode::ACCEPTED, StatusCode::PAYMENT_REQUIRED].contains(&response.status()) {
                let next = PendingResponse::parse(endpoint, &response).map_err(|_| {
                    super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::MalformedResponse(
                            "invalid AS continuation",
                        ),
                    )
                })?;
                if next.location != pending.location {
                    return Err(super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::MalformedResponse(
                            "AS continuation Location changed",
                        ),
                    ));
                }
                let own: PendingResponse = serde_json::from_value(value["ps_pending"].clone())
                    .map_err(|_| Failure::internal())?;
                value["ps_pending"] =
                    serde_json::to_value(self.agent_pending(&own.location, &next)?)
                        .map_err(|_| Failure::internal())?;
                value["next_as"] = json!(current.saturating_add(next.retry_after as i64));
                value["as_pending"] =
                    serde_json::to_value(next).map_err(|_| Failure::internal())?;
                value["queued"] = Value::Null;
                waiting = true;
                return Ok(response);
            }
            if [
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ]
            .contains(&response.status())
            {
                let retry = if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    pending.retry_after.saturating_add(5)
                } else {
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(5)
                };
                if retry > 3600 {
                    return Err(Failure::internal());
                }
                value["next_as"] = json!(current.saturating_add(retry as i64));
                waiting = true;
                return Ok(response);
            }
            self.accept_federation(response, &agent, &prepared, endpoint)
        })();
        let mut response = result.unwrap_or_else(Failure::response);
        let current = (self.clock)();
        let held = d
            .store
            .load(&id)
            .map_err(|_| AdvanceError::Unavailable)?
            .ok_or(AdvanceError::Gone)?;
        if held.value["state"] != "advancing" {
            return Err(AdvanceError::Unavailable);
        }
        if cancel {
            if !d
                .store
                .replace(&id, held.revision, None)
                .map_err(|_| AdvanceError::Unavailable)?
            {
                return Err(AdvanceError::Unavailable);
            }
            return Ok(response);
        }
        if current >= number(&value, "deadline").map_err(|_| AdvanceError::Unavailable)? {
            response = Failure::status(StatusCode::REQUEST_TIMEOUT, "expired").response();
            value["state"] = json!("ready");
            value["terminal"] = encode(&response).map_err(|_| AdvanceError::Unavailable)?;
        } else if waiting {
            value["state"] = json!("waiting");
        } else {
            value["state"] = json!("ready");
            value["terminal"] = encode(&response).map_err(|_| AdvanceError::Unavailable)?;
            if response.status() == StatusCode::OK
                && let Ok(body) = strict_json(response.body())
                && let Some(token) = body
                    .get("auth_token")
                    .and_then(Value::as_str)
                    .and_then(|s| AuthToken::parse(s).ok())
            {
                value["deadline"] = json!(
                    number(&value, "deadline")
                        .map_err(|_| AdvanceError::Unavailable)?
                        .min(token.unverified_claims().exp)
                );
            }
        }
        // The lease is checked again at publication; no terminal response is
        // available to the Agent until this conditional write succeeds.
        if !d
            .store
            .replace(&id, held.revision, Some(value))
            .map_err(|_| AdvanceError::Unavailable)?
        {
            return Err(AdvanceError::Unavailable);
        }
        Ok(response)
    }
}
