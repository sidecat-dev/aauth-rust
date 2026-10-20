use aauth_rust_core::{
    AgentKeyResolver,
    continuation::{PaymentChallenge, PendingResponse, Requirement},
};
use aauth_rust_person_server::{
    AdvanceError, FederationFailure, FederationInput, PersonServer, Policy, Store,
};
use http::StatusCode;
use std::{error::Error, time::Duration};

#[derive(Debug)]
pub enum HostStep {
    RetryAfter(Duration),
    NeedsClaims(Vec<String>),
    Terminal {
        status: StatusCode,
        diagnostic: Option<FederationFailure>,
    },
    Closed(AdvanceError),
}

// Run on a blocking worker. Serialize work for this reference, and make both
// callbacks idempotent: another AS response can repeat the same requirement.
pub fn host_step<K, S, P, C, I>(
    people: &PersonServer<K, S, P, C, I>,
    reference: &str,
    settle_payment: impl FnOnce(&PendingResponse, &PaymentChallenge) -> Result<bool, Box<dyn Error>>,
    approval_complete: impl FnOnce(&PendingResponse) -> Result<bool, Box<dyn Error>>,
) -> Result<HostStep, Box<dyn Error>>
where
    K: AgentKeyResolver,
    S: Store,
    P: Policy,
    C: Fn() -> i64,
    I: Fn() -> String,
{
    let pending = match people.federation_pending(reference) {
        Ok(pending) => pending,
        Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
            return Ok(HostStep::Closed(error));
        }
        Err(AdvanceError::NotReady) => return Ok(HostStep::RetryAfter(Duration::from_secs(1))),
        Err(error) => return Err(error.into()),
    };
    // Whole-second clocks can straddle a boundary; keep a scheduling margin.
    let retry = Duration::from_secs(pending.retry_after.saturating_add(1));
    let ready = match &pending.requirement {
        Requirement::Payment { .. } => {
            let payment = pending
                .payment_challenge()?
                .ok_or("AS payment requirement has no Payment challenge")?;
            // The host confirms settlement with its admitted provider/AS.
            // Key its billing cache by admitted AS identity plus payment.id.
            settle_payment(&pending, &payment)?
        }
        Requirement::Approval | Requirement::Interaction { .. } => {
            // The host checks its authenticated approver/interaction state.
            approval_complete(&pending)?
        }
        Requirement::Claims(names) => return Ok(HostStep::NeedsClaims(names.clone())),
        // Poll also sends an Agent clarification answer already queued at PS.
        Requirement::Clarification { .. } | Requirement::Waiting => true,
    };
    if !ready {
        return Ok(HostStep::RetryAfter(retry));
    }
    let response = match people.advance_federation(reference, FederationInput::Poll) {
        Ok(response) => response,
        Err(AdvanceError::NotReady) => return Ok(HostStep::RetryAfter(retry)),
        Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
            return Ok(HostStep::Closed(error));
        }
        Err(error) => return Err(error.into()),
    };
    let status = response.status();
    if [
        StatusCode::ACCEPTED,
        StatusCode::PAYMENT_REQUIRED,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&status)
    {
        // Read the persisted interval after 429/503 backoff changed it.
        let pending = match people.federation_pending(reference) {
            Ok(pending) => pending,
            Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
                return Ok(HostStep::Closed(error));
            }
            Err(AdvanceError::NotReady) => {
                return Ok(HostStep::RetryAfter(Duration::from_secs(1)));
            }
            Err(error) => return Err(error.into()),
        };
        return Ok(HostStep::RetryAfter(Duration::from_secs(
            pending.retry_after.saturating_add(1),
        )));
    }
    // Keep diagnostics before framework conversion. No token is logged here.
    // A terminal 200 is held at the PS pending URL for the Agent's next poll.
    Ok(HostStep::Terminal {
        status,
        diagnostic: response.extensions().get::<FederationFailure>().cloned(),
    })
}

fn main() {
    println!("host_step compiled; supply a configured PS and real host callbacks to use it");
}
