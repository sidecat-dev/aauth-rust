use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::Digest;
use sha2::Sha256;

/// Unpadded base64url SHA-256 of the exact caller bytes.
///
/// The function does not parse, canonicalize, or reserialize `source`.
pub fn digest(source: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(source))
}
