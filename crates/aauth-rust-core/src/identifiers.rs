use crate::TokenError;

/// Validate a lowercase HTTPS DNS origin without port, path or userinfo.
///
/// # Errors
/// Returns `InvalidServerIdentifier` for any spelling outside that profile.
pub fn validate_server_identifier(s: &str) -> Result<(), TokenError> {
    let host = s
        .strip_prefix("https://")
        .ok_or(TokenError::InvalidServerIdentifier)?;
    if host.len() > 253
        || !host.is_ascii()
        || host != host.to_ascii_lowercase()
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(TokenError::InvalidServerIdentifier);
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }) {
        return Err(TokenError::InvalidServerIdentifier);
    }
    Ok(())
}
/// Validate `aauth:local@domain` syntax without inferring delegation authority.
///
/// A local part is a top-level name without `+`, or a sub-agent's name: a
/// non-empty parent name, `+` and a non-empty discriminator without `+`.
/// Which parent a sub-agent has is never read from here; `parent_agent` says.
///
/// # Errors
/// Returns `InvalidAgentIdentifier` for invalid local characters/length, a
/// misplaced `+`, or an invalid domain.
pub fn validate_agent_identifier(s: &str) -> Result<(), TokenError> {
    let (local, domain) = s
        .strip_prefix("aauth:")
        .and_then(|s| s.split_once('@'))
        .ok_or(TokenError::InvalidAgentIdentifier)?;
    if local.is_empty()
        || local.len() > 255
        || !local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_+.".contains(&c))
    {
        return Err(TokenError::InvalidAgentIdentifier);
    }
    // Delegation is one level deep, so a parent name never holds `+` itself.
    if let Some((parent, discriminator)) = local.split_once('+')
        && (parent.is_empty() || discriminator.is_empty() || discriminator.contains('+'))
    {
        return Err(TokenError::InvalidAgentIdentifier);
    }
    validate_server_identifier(&format!("https://{domain}"))
        .map_err(|_| TokenError::InvalidAgentIdentifier)
}
