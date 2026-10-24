use aauth_rust_jose::strict_json;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Invalid exact-byte mission identity or current mandatory member shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid approved mission: verify the exact persisted bytes, canonical s256/base64url, nonempty description, Agent, nonnegative approval time, expiry after approval, and RFC3339 timestamps"
)]
pub struct MissionError;

/// Exact approved mission document (Core70d6737 Mission Approval/Identifier).
/// This verifies content identity, never Person approval or the approving PS.
/// Hosts authenticate the PS beside the digest and keep approval state separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedMission {
    s256: String,
    encoded: String,
    exact_json: Vec<u8>,
    agent: String,
    approved_at: i64,
    expires_at: Option<i64>,
    description: String,
}
impl ApprovedMission {
    /// Verify canonical unpadded base64url, exact SHA-256 and current members.
    /// Unknown members (including legacy approver) retain their exact bytes and
    /// confer no authority. RFC3339 offsets/fractions are accepted; expiry is
    /// floored to Unix seconds so integer JWTs cannot extend it.
    ///
    /// # Errors
    /// Rejects malformed encodings, mismatched bytes, duplicate JSON members,
    /// invalid Agent identifiers, a missing or empty description, a negative
    /// approval time, an expiry that is not strictly after approval, or
    /// malformed times.
    pub fn decode(s256: &str, encoded: &str) -> Result<Self, MissionError> {
        let digest = URL_SAFE_NO_PAD.decode(s256).map_err(|_| MissionError)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| MissionError)?;
        if digest.len() != 32
            || URL_SAFE_NO_PAD.encode(&digest) != s256
            || URL_SAFE_NO_PAD.encode(&bytes) != encoded
            || Sha256::digest(&bytes).as_slice() != digest.as_slice()
        {
            return Err(MissionError);
        }
        let value = strict_json(&bytes).map_err(|_| MissionError)?;
        let object = value.as_object().ok_or(MissionError)?;
        let string = |name: &str| {
            object
                .get(name)
                .and_then(|v| v.as_str())
                .ok_or(MissionError)
        };
        let agent = string("agent")?;
        crate::validate_agent_identifier(agent).map_err(|_| MissionError)?;
        let timestamp = |s: &str| {
            OffsetDateTime::parse(s, &Rfc3339)
                .map(|t| t.unix_timestamp())
                .map_err(|_| MissionError)
        };
        let approved_at = timestamp(string("approved_at")?)?;
        if approved_at < 0 {
            return Err(MissionError);
        }
        let expires_at = if object.contains_key("expires_at") {
            Some(timestamp(string("expires_at")?)?)
        } else {
            None
        };
        if expires_at.is_some_and(|expires_at| expires_at <= approved_at) {
            return Err(MissionError);
        }
        let description = string("description")?;
        if description.is_empty() {
            return Err(MissionError);
        }
        Ok(Self {
            s256: s256.into(),
            encoded: encoded.into(),
            agent: agent.into(),
            approved_at,
            expires_at,
            description: description.into(),
            exact_json: bytes,
        })
    }
    /// Hash identifying these exact bytes; pair it with the authenticated PS.
    pub fn s256(&self) -> &str {
        &self.s256
    }
    /// Original canonical unpadded base64url document.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
    /// Original JSON bytes, including additive/legacy members and whitespace.
    pub fn exact_json(&self) -> &[u8] {
        &self.exact_json
    }
    /// Agent named as owner by the document; host state must authenticate it.
    pub fn agent(&self) -> &str {
        &self.agent
    }
    /// Approval timestamp in Unix seconds (fractional part floored).
    pub fn approved_at(&self) -> i64 {
        self.approved_at
    }
    /// Optional conservative integer-second credential ceiling.
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }
    /// Approved display text; not an automatically enforced scope grant.
    pub fn description(&self) -> &str {
        &self.description
    }
}
