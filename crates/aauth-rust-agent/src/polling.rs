//! Explicit signed polling: no transport, sleeps or automatic original-request retries.
use crate::Agent;
use aauth_rust_core::continuation::{PendingResponse, Requirement};
use http::{Request, Response, StatusCode};
use serde_json::json;

/// Refusal to prepare a poll or accept untrusted continuation framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PollError {
    /// Required wait has not elapsed; times use Unix seconds.
    #[error("poll before Retry-After deadline {at}")]
    TooEarly {
        /// Earliest permitted next GET, in Unix seconds.
        at: i64,
    },
    /// Host's finite pending deadline has elapsed.
    #[error("pending request expired")]
    Expired,
    /// A terminal response was already accepted; do not retry this pending URL.
    #[error("pending request finished")]
    Finished,
    /// Invalid framing, changed Location, redirect, body or local deadline.
    #[error("invalid pending response or action")]
    InvalidResponse,
    /// The exact request could not be signed with the Agent's proof key.
    #[error("could not sign pending request")]
    Signing,
}
/// Host-driven continuation session. No request is dispatched by this value.
/// Only use an endpoint admitted by host trust and a response obtained over its
/// authenticated transport. Terminal Auth responses still require the existing
/// Agent credential-context verification before use at a Resource.
pub struct PollSession {
    pending: PendingResponse,
    next_at: i64,
    deadline: i64,
    question_deadline: Option<i64>,
    finished: bool,
    answering: bool,
}
impl PollSession {
    /// Parse initial202/402 and retain its stable same-origin Location.
    /// Host supplies a finite deadline no more than one hour from `now`.
    pub fn new(
        endpoint: &str,
        response: &Response<Vec<u8>>,
        now: i64,
        deadline: i64,
    ) -> Result<Self, PollError> {
        if now < 0 || deadline <= now || deadline > now.saturating_add(3600) {
            return Err(PollError::InvalidResponse);
        }
        let pending =
            PendingResponse::parse(endpoint, response).map_err(|_| PollError::InvalidResponse)?;
        let question_deadline = question_deadline(&pending, now);
        let next_at = now.saturating_add(pending.retry_after as i64);
        Ok(Self {
            pending,
            next_at,
            deadline,
            question_deadline,
            finished: false,
            answering: false,
        })
    }
    /// Latest requirement/body for the host to satisfy or present safely.
    pub fn pending(&self) -> &PendingResponse {
        &self.pending
    }
    fn current_lifetime(&self, now: i64) -> Result<(), PollError> {
        if self.finished {
            return Err(PollError::Finished);
        }
        if now < 0 || now >= self.deadline {
            return Err(PollError::Expired);
        }
        Ok(())
    }
    fn current(&self, now: i64) -> Result<(), PollError> {
        self.current_lifetime(now)?;
        if self.question_deadline.is_some_and(|at| now >= at) {
            return Err(PollError::Expired);
        }
        Ok(())
    }
    fn signed(
        &self,
        agent: &Agent,
        method: &str,
        body: Vec<u8>,
        now: i64,
    ) -> Result<Request<Vec<u8>>, PollError> {
        self.current(now)?;
        let mut builder = Request::builder()
            .method(method)
            .uri(&self.pending.location);
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        let mut request = builder.body(body).map_err(|_| PollError::InvalidResponse)?;
        agent
            .sign(&mut request, now)
            .map_err(|_| PollError::Signing)?;
        Ok(request)
    }
    /// Prepare exactly one signed GET after the server's required wait. It never
    /// resends the initial POST or its content. The host sends these exact bytes.
    pub fn request(&self, agent: &Agent, now: i64) -> Result<Request<Vec<u8>>, PollError> {
        self.current(now)?;
        if now < self.next_at {
            return Err(PollError::TooEarly { at: self.next_at });
        }
        self.signed(agent, "GET", Vec::new(), now)
    }
    /// Prepare a signed clarification_response POST for the active question.
    /// Answers are untrusted Markdown; the receiving host sanitizes presentation.
    /// The next `accept` must receive this exact POST's actual response. Preparing
    /// an answer does not dispatch it; discard the session if it is not sent.
    pub fn answer(
        &mut self,
        agent: &Agent,
        answer: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, PollError> {
        if !matches!(self.pending.requirement, Requirement::Clarification { .. })
            || answer.is_empty()
            || answer.len() > 65536
        {
            return Err(PollError::InvalidResponse);
        }
        let request = self.signed(
            agent,
            "POST",
            json!({"action":"clarification_response","clarification_response":answer})
                .to_string()
                .into_bytes(),
            now,
        )?;
        self.answering = true;
        Ok(request)
    }
    /// Prepare a signed cancellation. The server owns cancellation and informs
    /// any person reviewing it; the host must observe the actual DELETE result.
    pub fn cancel(&self, agent: &Agent, now: i64) -> Result<Request<Vec<u8>>, PollError> {
        self.signed(agent, "DELETE", Vec::new(), now)
    }
    /// Accept one actual buffered response. None means the host may schedule
    /// another poll; Some is the exact terminal response.429 adds five seconds
    /// to the interval;503 respects Retry-After (default five). Redirects and
    /// malformed/changed pending responses finish the session with an error.
    pub fn accept(
        &mut self,
        response: Response<Vec<u8>>,
        now: i64,
    ) -> Result<Option<Response<Vec<u8>>>, PollError> {
        if self.answering
            && ![
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ]
            .contains(&response.status())
        {
            // The question deadline bounds preparing the answer. Its actual
            // completed response may arrive after the old question
            // expires; the overall session deadline still bounds all delivery.
            self.current_lifetime(now)?;
        } else {
            self.current(now)?;
        }
        if response.body().len() > 1_048_576 {
            self.finished = true;
            return Err(PollError::InvalidResponse);
        }
        match response.status() {
            StatusCode::ACCEPTED | StatusCode::PAYMENT_REQUIRED => {
                let parsed = PendingResponse::parse(&self.pending.location, &response);
                let Ok(pending) = parsed else {
                    self.finished = true;
                    return Err(PollError::InvalidResponse);
                };
                if pending.location != self.pending.location {
                    self.finished = true;
                    return Err(PollError::InvalidResponse);
                }
                let next_deadline = question_deadline(&pending, now);
                self.question_deadline = if !self.answering
                    && same_question(&pending.requirement, &self.pending.requirement)
                {
                    match (self.question_deadline, next_deadline) {
                        (Some(old), Some(new)) => Some(old.min(new)),
                        (old, new) => old.or(new),
                    }
                } else {
                    next_deadline
                };
                self.answering = false;
                self.next_at = now.saturating_add(pending.retry_after as i64);
                self.pending = pending;
                Ok(None)
            }
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                self.answering = false;
                let interval = if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    self.pending.retry_after.saturating_add(5).max(
                        response
                            .headers()
                            .get("retry-after")
                            .map(|h| {
                                h.to_str()
                                    .ok()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .ok_or(PollError::InvalidResponse)
                            })
                            .transpose()?
                            .unwrap_or(0),
                    )
                } else {
                    response
                        .headers()
                        .get("retry-after")
                        .map(|v| {
                            v.to_str()
                                .ok()
                                .and_then(|s| s.parse::<u64>().ok())
                                .ok_or(PollError::InvalidResponse)
                        })
                        .transpose()?
                        .unwrap_or(5)
                };
                if interval > 3600 {
                    self.finished = true;
                    return Err(PollError::InvalidResponse);
                }
                self.pending.retry_after = interval;
                self.next_at = now.saturating_add(interval as i64);
                Ok(None)
            }
            status if status.is_redirection() || status.is_informational() => {
                self.finished = true;
                Err(PollError::InvalidResponse)
            }
            _ => {
                self.finished = true;
                Ok(Some(response))
            }
        }
    }
}

fn question_deadline(pending: &PendingResponse, now: i64) -> Option<i64> {
    match pending.requirement {
        Requirement::Clarification {
            timeout: Some(timeout),
            ..
        } => Some(now.saturating_add(i64::try_from(timeout).unwrap_or(i64::MAX))),
        _ => None,
    }
}

fn same_question(left: &Requirement, right: &Requirement) -> bool {
    matches!((left,right), (Requirement::Clarification{question:a,options:ao,..}, Requirement::Clarification{question:b,options:bo,..}) if a==b && ao==bo)
}
