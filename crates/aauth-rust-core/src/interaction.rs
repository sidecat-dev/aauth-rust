//! Browser redirects for a resource interaction.
//!
//! The resource accepts `code` and `callback` without recording whether an agent
//! or a Person Server sent them. When the flow ends it sends the browser to
//! `callback`. [`person_server_redirect`] and [`receive_callback`] are helpers;
//! no Person Server route calls them. Targets must be HTTPS without a query or
//! fragment. `http://localhost` and `http://127.0.0.1` are refused.

use http::{Response, StatusCode, Uri};

use crate::continuation::{
    PendingResponse, Requirement, canonical_interaction_code, generate_interaction_code,
    generate_pending_id, is_emitted_interaction_code,
};

/// The interaction URL or callback is not an HTTPS URL without a query or fragment,
/// the code cannot be emitted, or the host refused egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InteractionError;

impl std::fmt::Display for InteractionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("interaction redirect was refused")
    }
}

impl std::error::Error for InteractionError {}

/// `error` query value from an interaction callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackError {
    /// The user declined.
    AccessDenied,
    /// The user left the interaction unfinished.
    UserAbandoned,
    /// The interaction party failed.
    ServerError,
    /// The interaction party could not run the flow.
    TemporarilyUnavailable,
    /// The interaction session expired.
    InteractionExpired,
}

impl CallbackError {
    /// Polling error the Person Server returns to the agent.
    pub fn polling_error(self) -> &'static str {
        match self {
            Self::AccessDenied => "denied",
            Self::UserAbandoned => "abandoned",
            Self::InteractionExpired => "expired",
            Self::ServerError | Self::TemporarilyUnavailable => "server_error",
        }
    }

    fn query_value(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::UserAbandoned => "user_abandoned",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InteractionExpired => "interaction_expired",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "access_denied" => Self::AccessDenied,
            "user_abandoned" => Self::UserAbandoned,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "interaction_expired" => Self::InteractionExpired,
            _ => return None,
        })
    }
}

/// How the resource's own flow ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionOutcome {
    /// Finished. The redirect carries no `error` parameter.
    Completed,
    /// Did not finish. The redirect carries `error`.
    Failed(CallbackError),
}

/// What a Person Server does with the browser's return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackReceipt {
    /// No `error` parameter. The pending request may continue.
    Continue,
    /// An `error` parameter is present. The pending request is not completable.
    Abandoned {
        /// Polling error to surface to the agent.
        polling_error: &'static str,
    },
}

/// `code` and optional `callback` from one interaction URL query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteractionQuery {
    /// Code the redirect carried.
    pub code: String,
    /// Callback the redirect carried, when one was present.
    pub callback: Option<String>,
}

/// Read `code` and `callback` from a query with no leading `?`.
///
/// # Errors
/// Returns [`InteractionError`] when `code` is missing, repeated, or not an
/// interaction code in any case once aliases are folded, when `callback` is
/// repeated or not an HTTPS URL without a query or fragment, or when another
/// parameter is present.
pub fn parse_interaction_query(query: &str) -> Result<InteractionQuery, InteractionError> {
    let pairs = pairs(query)?;
    let mut code = None;
    let mut callback = None;
    for (name, value) in pairs {
        match name.as_str() {
            "code" if code.is_none() => code = Some(value),
            "callback" if callback.is_none() => callback = Some(value),
            _ => return Err(InteractionError),
        }
    }
    let code = code
        .filter(|code| canonical_interaction_code(code).is_some())
        .ok_or(InteractionError)?;
    if let Some(callback) = &callback {
        https_target(callback)?;
    }
    Ok(InteractionQuery { code, callback })
}

/// Redirect the browser to `callback` when the resource flow ends.
///
/// # Errors
/// Returns [`InteractionError`] when `callback` is not an HTTPS URL without a
/// query or fragment.
pub fn completion_redirect(
    callback: &str,
    outcome: InteractionOutcome,
) -> Result<Response<Vec<u8>>, InteractionError> {
    https_target(callback)?;
    let location = match outcome {
        InteractionOutcome::Completed => callback.to_owned(),
        InteractionOutcome::Failed(error) => {
            format!("{callback}?error={}", error.query_value())
        }
    };
    redirect(&location)
}

/// Redirect the browser from the Person Server to the resource interaction URL.
///
/// The URL is validated before this builds a redirect. `admitted` is the host's
/// egress decision for that URL. A refusal does not produce a `Location`.
///
/// # Errors
/// Returns [`InteractionError`] when the interaction URL or `callback` is not an
/// HTTPS URL without a query or fragment, when `code` cannot be emitted, or when
/// `admitted` is false.
pub fn person_server_redirect(
    interaction_url: &str,
    code: &str,
    callback: &str,
    admitted: bool,
) -> Result<Response<Vec<u8>>, InteractionError> {
    https_target(interaction_url)?;
    if !admitted || !is_emitted_interaction_code(code) {
        return Err(InteractionError);
    }
    https_target(callback)?;
    redirect(&format!(
        "{interaction_url}?code={}&callback={}",
        encode_component(code),
        encode_component(callback)
    ))
}

/// Classify the query on the Person Server's callback URL.
///
/// A query that contains `error` does not continue the pending request.
pub fn receive_callback(query: Option<&str>) -> CallbackReceipt {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return CallbackReceipt::Continue;
    };
    let Ok(pairs) = pairs(query) else {
        return CallbackReceipt::Abandoned {
            polling_error: "server_error",
        };
    };
    let mut error = None;
    for (name, value) in pairs {
        if name == "error" {
            if error.is_some() {
                return CallbackReceipt::Abandoned {
                    polling_error: "server_error",
                };
            }
            error = Some(value);
        }
    }
    let Some(error) = error else {
        return CallbackReceipt::Continue;
    };
    CallbackReceipt::Abandoned {
        polling_error: CallbackError::parse(&error)
            .map(CallbackError::polling_error)
            .unwrap_or("server_error"),
    }
}

/// One interaction propagated to the caller that started this resource.
///
/// The caller's pending response uses this resource's own pending URL and
/// interaction code, both drawn when the interaction opens.
/// [`ChainedInteraction::poll`] returns the stored result once to the opener,
/// at or before `exp`, and answers `410` after that. A different caller receives
/// an empty `404`.
pub struct ChainedInteraction {
    shown: PendingResponse,
    code: String,
    caller: String,
    expires_at: i64,
    downstream_url: String,
    downstream_code: String,
    result: Option<StoredResult>,
    delivered: bool,
}

struct StoredResult {
    content_type: Option<String>,
    body: Vec<u8>,
}

impl ChainedInteraction {
    /// Propagate a downstream interaction as this resource's own `202`.
    ///
    /// The pending URL is `pending_path` followed by `/` and an identifier from
    /// [`generate_pending_id`]. The code is drawn by [`generate_interaction_code`].
    /// Read them back with [`Self::location`] and [`Self::code`] to route polls
    /// and check the code at `interaction_url`.
    ///
    /// # Errors
    /// Returns [`InteractionError`] when `downstream` is not
    /// `requirement=interaction`, when `caller` is empty or not a single token,
    /// when `expires_at` is negative, or when this resource's URL or pending
    /// location cannot be emitted.
    ///
    /// `caller` is the opener's key thumbprint or the `jti` of an auth token
    /// the host already verified. This ledger does not verify that token.
    pub fn open(
        downstream: &PendingResponse,
        endpoint: &str,
        pending_path: &str,
        interaction_url: &str,
        caller: &str,
        expires_at: i64,
    ) -> Result<Self, InteractionError> {
        let Requirement::Interaction {
            url: downstream_url,
            code: downstream_code,
        } = &downstream.requirement
        else {
            return Err(InteractionError);
        };
        bound_caller(caller)?;
        if expires_at < 0 {
            return Err(InteractionError);
        }
        https_target(interaction_url)?;
        let code = generate_interaction_code();
        let location = format!("{pending_path}/{}", generate_pending_id());
        let shown = PendingResponse::new(
            endpoint,
            &location,
            downstream.retry_after,
            Requirement::Interaction {
                url: interaction_url.to_owned(),
                code: code.clone(),
            },
        )
        .map_err(|_| InteractionError)?;
        Ok(Self {
            shown,
            code,
            caller: caller.to_owned(),
            expires_at,
            downstream_url: downstream_url.clone(),
            downstream_code: downstream_code.clone(),
            result: None,
            delivered: false,
        })
    }

    /// Downstream interaction URL and code retained from `open`.
    pub fn downstream(&self) -> (&str, &str) {
        (&self.downstream_url, &self.downstream_code)
    }

    /// This resource's absolute pending URL, which the opener polls.
    pub fn location(&self) -> &str {
        &self.shown.location
    }

    /// This resource's own interaction code, shown to the opener.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The opener's next poll.
    ///
    /// A different `caller` gets an empty `404`. At or before `expires_at`, the
    /// opener gets the interaction `202` until [`Self::complete`], then the
    /// stored result once. A later poll, and any poll after `expires_at`, is
    /// empty `410`.
    ///
    /// # Errors
    /// Returns [`InteractionError`] when the interaction `202` cannot be rendered.
    pub fn poll(&mut self, caller: &str, now: i64) -> Result<Response<Vec<u8>>, InteractionError> {
        if caller != self.caller {
            return Ok(empty(StatusCode::NOT_FOUND));
        }
        if now > self.expires_at || self.delivered {
            return Ok(empty(StatusCode::GONE));
        }
        let Some(result) = &self.result else {
            return self.shown.response().map_err(|_| InteractionError);
        };
        self.delivered = true;
        let mut response = Response::builder().status(StatusCode::OK);
        if let Some(content_type) = &result.content_type {
            response = response.header("content-type", content_type);
        }
        response
            .body(result.body.clone())
            .map_err(|_| InteractionError)
    }

    /// Store the original request's result once the downstream interaction is done.
    ///
    /// # Errors
    /// Returns [`InteractionError`] when a result is already stored, the body is
    /// larger than 1 MiB, or `content_type` is empty or contains a control character.
    pub fn complete(
        &mut self,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(), InteractionError> {
        if self.result.is_some() || body.len() > 1_048_576 {
            return Err(InteractionError);
        }
        if let Some(content_type) = content_type
            && (content_type.is_empty()
                || content_type.len() > 256
                || content_type.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(InteractionError);
        }
        self.result = Some(StoredResult {
            content_type: content_type.map(str::to_owned),
            body,
        });
        Ok(())
    }
}

fn bound_caller(caller: &str) -> Result<(), InteractionError> {
    if caller.is_empty()
        || caller.len() > 256
        || caller
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(InteractionError);
    }
    Ok(())
}

fn empty(status: StatusCode) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .body(Vec::new())
        .expect("empty response")
}

fn redirect(location: &str) -> Result<Response<Vec<u8>>, InteractionError> {
    if location.len() > 8192 {
        return Err(InteractionError);
    }
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .header("cache-control", "no-store")
        .body(Vec::new())
        .map_err(|_| InteractionError)
}

fn https_target(value: &str) -> Result<(), InteractionError> {
    if value.len() > 2048 || value.contains('#') {
        return Err(InteractionError);
    }
    let uri: Uri = value.parse().map_err(|_| InteractionError)?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none()
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
        || uri.query().is_some()
    {
        return Err(InteractionError);
    }
    Ok(())
}

fn pairs(query: &str) -> Result<Vec<(String, String)>, InteractionError> {
    if query.is_empty() || query.len() > 8192 || query.starts_with('?') {
        return Err(InteractionError);
    }
    let mut pairs = Vec::new();
    for part in query.split('&') {
        let (name, value) = part.split_once('=').ok_or(InteractionError)?;
        if name.is_empty() {
            return Err(InteractionError);
        }
        pairs.push((decode_component(name)?, decode_component(value)?));
    }
    Ok(pairs)
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn decode_component(value: &str) -> Result<String, InteractionError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(InteractionError);
                }
                let high = hex(bytes[index + 1])?;
                let low = hex(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' | 0x00..=0x1f | 0x7f..=0xff => return Err(InteractionError),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| InteractionError)
}

fn hex(byte: u8) -> Result<u8, InteractionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(InteractionError),
    }
}
