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
        if expired(&value, now).map_err(|_| AdvanceError::Unavailable)? {
            return Err(AdvanceError::Expired);
        }
        if value["state"] != "waiting" {
            return Err(AdvanceError::NotReady);
        }
        let pending: PendingResponse = serde_json::from_value(value["as_pending"].clone())
            .map_err(|_| AdvanceError::Unavailable)?;
        let cancel = matches!(input, FederationInput::Cancel);
        if !cancel
            && value["retrying"] == true
            && now < number(&value, "next_as").map_err(|_| AdvanceError::Unavailable)?
        {
            return Err(AdvanceError::NotReady);
        }
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
                if value
                    .get("updated_request")
                    .is_some_and(|body| body.is_object())
                {
                    ("POST", Some(value["updated_request"].clone()))
                } else if let Some(answer) = value["queued"].as_str() {
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
        value["answering"] = json!(
            method == "POST" && matches!(pending.requirement, Requirement::Clarification { .. })
        );
        if value["answering"] == true {
            let own: PendingResponse = serde_json::from_value(value["ps_pending"].clone())
                .map_err(|_| AdvanceError::Unavailable)?;
            value["ps_pending"] = serde_json::to_value(
                PendingResponse::new(
                    &self.config.signed_origin,
                    &own.location,
                    d.retry_after,
                    Requirement::Approval,
                )
                .map_err(|_| AdvanceError::Unavailable)?,
            )
            .map_err(|_| AdvanceError::Unavailable)?;
        }
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
            let prepared = self.prepare_stored(&agent, value["parameters"].clone(), now)?;
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
            self.subagent_current(&agent, prepared.context.subagent.as_ref(), current)?;
            check_upstream_current(prepared.context.upstream.as_ref(), current)?;
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
                if matches!(next.requirement, Requirement::AuthToken { .. }) {
                    return Err(super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::MalformedResponse(
                            "auth-token delivery is not an AS continuation",
                        ),
                    ));
                }
                if next.location != pending.location {
                    return Err(super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::MalformedResponse(
                            "AS continuation Location changed",
                        ),
                    ));
                }
                let answered = method == "POST"
                    && matches!(pending.requirement, Requirement::Clarification { .. });
                let new_question =
                    answered || !same_question(&next.requirement, &pending.requirement);
                if new_question && matches!(next.requirement, Requirement::Clarification { .. }) {
                    value["rounds"] = json!(number(&value, "rounds")? + 1);
                    if number(&value, "rounds")? > 5 {
                        return Err(Failure::status(StatusCode::FORBIDDEN, "denied"));
                    }
                }
                if new_question {
                    value["question_deadline"] = json!(question_deadline(&next, current));
                } else if let Some(next_deadline) = question_deadline(&next, current) {
                    value["question_deadline"] = json!(
                        value["question_deadline"]
                            .as_i64()
                            .unwrap_or(next_deadline)
                            .min(next_deadline)
                    );
                }
                if expired(&value, current)? {
                    return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
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
                value["updated_request"] = Value::Null;
                value["retrying"] = json!(false);
                waiting = true;
                return Ok(response);
            }
            if [
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ]
            .contains(&response.status())
            {
                let invalid_retry = || {
                    super::federation::unreachable(
                        &prepared.resource.claims().aud,
                        Some(response.status()),
                        crate::FederationFailureReason::MalformedResponse("invalid AS Retry-After"),
                    )
                };
                let advertised =
                    schedule::retry_after(&response, current).map_err(|_| invalid_retry())?;
                let retry = if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    pending
                        .retry_after
                        .saturating_add(5)
                        .max(advertised.unwrap_or(0))
                } else {
                    advertised.unwrap_or(5)
                };
                if retry > 3600 {
                    return Err(invalid_retry());
                }
                value["next_as"] = json!(current.saturating_add(retry as i64));
                value["as_pending"]["retry_after"] = json!(retry);
                value["retrying"] = json!(true);
                waiting = true;
                return Ok(response);
            }
            self.accept_federation(
                response,
                &agent,
                &prepared,
                endpoint,
                stored_sent_budget(&value).map_err(|_| Failure::internal())?,
                None,
            )
        })();
        let mut response = result.unwrap_or_else(|error| error.while_pending().response());
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
        if !waiting {
            value["question_deadline"] = Value::Null;
        }
        value["answering"] = json!(false);
        // The lease is checked again at publication; no terminal response is
        // available to the Agent until this conditional write succeeds.
        if !d
            .store
            .replace(&id, held.revision, Some(value.clone()))
            .map_err(|_| AdvanceError::Unavailable)?
        {
            return Err(AdvanceError::Unavailable);
        }
        if let Err(error) = self.check_release(&value, &mut response) {
            // Agent delivery repeats the same validity checks; this trusted-host
            // preview must also refuse a grant invalidated during publication.
            response = error.while_pending().response();
        }
        Ok(response)
    }
}
