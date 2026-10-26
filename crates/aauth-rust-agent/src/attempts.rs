//! Resource tokens a caller must not present again.
use serde_json::Value;
use std::collections::BTreeSet;

/// Exact resource-token strings refused with `revoked_resource_token`.
///
/// [`crate::Subagent::auth_request`] consults this set and does not build a
/// request for a remembered token. Any other error leaves the token eligible.
/// A different token is unaffected. The host records the token-endpoint error
/// before the next build.
#[derive(Clone, Debug, Default)]
pub struct ResourceTokenAttempts {
    refused: BTreeSet<String>,
}

impl ResourceTokenAttempts {
    /// No tokens have been refused.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `token` when `error` is `revoked_resource_token`.
    pub fn observe_error(&mut self, token: &str, error: &str) {
        if error == "revoked_resource_token" {
            self.refused.insert(token.to_owned());
        }
    }

    /// Read a token-endpoint body. Only a JSON `error` string is considered.
    pub fn observe_token_response(&mut self, token: &str, body: &[u8]) {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return;
        };
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            self.observe_error(token, error);
        }
    }

    /// `false` after this exact token was refused as revoked.
    pub fn may_submit(&self, token: &str) -> bool {
        !self.refused.contains(token)
    }
}
