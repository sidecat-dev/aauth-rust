//! Browser redirects for a resource interaction.
//!
//! The resource accepts `code` and `callback` without recording whether an agent
//! or a Person Server sent them. When the flow ends it sends the browser to
//! `callback`. [`person_server_redirect`] and [`receive_callback`] are helpers;
//! no Person Server route calls them. Targets must be HTTPS without a query or
//! fragment. `http://localhost` and `http://127.0.0.1` are refused.

use http::{Response, StatusCode, Uri};

use crate::continuation::is_emitted_interaction_code;

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
/// emitted interaction code, when `callback` is repeated or not an HTTPS URL
/// without a query or fragment, or when another parameter is present.
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
        .filter(|code| is_emitted_interaction_code(code))
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
