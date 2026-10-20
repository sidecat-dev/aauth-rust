use crate::TokenError;

pub fn validate_server_identifier(s:&str)->Result<(),TokenError>{
    let host=s.strip_prefix("https://").ok_or(TokenError::InvalidJwt)?;
    if host.len()>253 || !host.is_ascii() || host!=host.to_ascii_lowercase() || host.parse::<std::net::IpAddr>().is_ok(){return Err(TokenError::InvalidJwt)}
    if host.split('.').any(|label| label.is_empty() || label.len()>63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|c|c.is_ascii_lowercase() || c.is_ascii_digit() || c==b'-')) {return Err(TokenError::InvalidJwt)}
    Ok(())
}
pub fn validate_agent_identifier(s:&str)->Result<(),TokenError>{
    let (local,domain)=s.strip_prefix("aauth:").and_then(|s|s.split_once('@')).ok_or(TokenError::InvalidJwt)?;
    if local.is_empty() || local.len()>255 || !local.bytes().all(|c|c.is_ascii_alphanumeric() || b"-_+.".contains(&c)){return Err(TokenError::InvalidJwt)}
    validate_server_identifier(&format!("https://{domain}"))
}
