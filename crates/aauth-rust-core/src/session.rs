//! Opaque `token68` session credentials carried in `AAuth-Access` and
//! `Authorization: AAuth`. Parsing does not authenticate a request or reveal
//! the resource state wrapped by a token.

/// A session credential was empty, not `token68`, or not exactly one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "session credential must be one token68 value, with no whitespace, control characters, or second credential"
)]
pub struct SessionTokenError;

/// Validate one `AAuth-Access` field value and return the opaque token.
///
/// # Errors
/// Returns [`SessionTokenError`] when `values` is not exactly one `token68`
/// credential. Empty, whitespace, control characters, and a second field value
/// are rejected.
pub fn parse_aauth_access<I, S>(values: I) -> Result<String, SessionTokenError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut values = values.into_iter();
    let Some(value) = values.next() else {
        return Err(SessionTokenError);
    };
    if values.next().is_some() {
        return Err(SessionTokenError);
    }
    validate_token68(value.as_ref())?;
    Ok(value.as_ref().to_owned())
}

/// Validate an opaque token for use as an `AAuth-Access` field value.
///
/// # Errors
/// Returns [`SessionTokenError`] when `token` is not `token68`.
pub fn format_aauth_access(token: &str) -> Result<String, SessionTokenError> {
    validate_token68(token)?;
    Ok(token.to_owned())
}

/// Validate one `Authorization` field using the `AAuth` scheme.
///
/// # Errors
/// Returns [`SessionTokenError`] unless `values` is exactly one `AAuth`
/// credential whose token is `token68`. A second field value, a missing token,
/// whitespace, and control characters are rejected.
pub fn parse_session_authorization<I, S>(values: I) -> Result<String, SessionTokenError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut values = values.into_iter();
    let Some(value) = values.next() else {
        return Err(SessionTokenError);
    };
    if values.next().is_some() {
        return Err(SessionTokenError);
    }
    let value = value.as_ref();
    if value.is_empty()
        || value != value.trim()
        || value
            .chars()
            .any(|character| matches!(character, '\t' | '\r' | '\n'))
    {
        return Err(SessionTokenError);
    }
    let Some(separator) = value.find(' ') else {
        return Err(SessionTokenError);
    };
    if separator == 0 || !value[..separator].eq_ignore_ascii_case("aauth") {
        return Err(SessionTokenError);
    }
    let token = value[separator + 1..].trim_start_matches(' ');
    validate_token68(token)?;
    Ok(token.to_owned())
}

/// Format an `Authorization` value as `AAuth` plus one opaque token.
///
/// # Errors
/// Returns [`SessionTokenError`] when `token` is not `token68`.
pub fn format_session_authorization(token: &str) -> Result<String, SessionTokenError> {
    validate_token68(token)?;
    Ok(format!("AAuth {token}"))
}

fn validate_token68(token: &str) -> Result<(), SessionTokenError> {
    if token.is_empty() {
        return Err(SessionTokenError);
    }
    let mut padding = false;
    for character in token.chars() {
        if character == '=' {
            padding = true;
            continue;
        }
        if padding {
            return Err(SessionTokenError);
        }
        let token68 = character.is_ascii_alphanumeric()
            || matches!(character, '-' | '.' | '_' | '~' | '+' | '/');
        if !token68 {
            return Err(SessionTokenError);
        }
    }
    if token.starts_with('=') {
        Err(SessionTokenError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_aauth_access, format_session_authorization, parse_aauth_access,
        parse_session_authorization,
    };

    #[test]
    fn session_credentials_reject_empty_whitespace_control_and_duplicates() {
        for token in ["opaque-session-token", "AbC012._~+/=="] {
            assert_eq!(format_aauth_access(token).unwrap(), token);
            assert_eq!(
                parse_aauth_access([format_aauth_access(token).unwrap()]).unwrap(),
                token
            );
        }
        for values in [
            Vec::<&str>::new(),
            vec![""],
            vec!["first", "second"],
            vec![" token"],
            vec!["opaque token"],
            vec!["opaque\ttoken"],
            vec!["opaque\ntoken"],
            vec!["opaque?token"],
            vec!["=opaque"],
            vec!["opaque=token"],
        ] {
            assert!(parse_aauth_access(values).is_err());
        }

        let formatted = format_session_authorization("opaque-session-token").unwrap();
        assert_eq!(formatted, "AAuth opaque-session-token");
        for value in [
            formatted.as_str(),
            "aauth opaque-session-token",
            "AAuth   opaque-session-token",
        ] {
            assert_eq!(
                parse_session_authorization([value]).unwrap(),
                "opaque-session-token"
            );
        }
        assert_eq!(
            parse_session_authorization(["AAuth AbC012._~+/=="]).unwrap(),
            "AbC012._~+/=="
        );
        for values in [
            Vec::<&str>::new(),
            vec![""],
            vec!["AAuth first", "AAuth second"],
            vec!["AAuth"],
            vec!["Bearer opaque-session-token"],
            vec!["AAuth first second"],
            vec![" AAuth opaque-session-token"],
            vec!["AAuth opaque-session-token "],
            vec!["AAuth opaque token"],
            vec!["AAuth opaque\ttoken"],
            vec!["AAuth opaque?token"],
            vec!["AAuth\topaque-session-token"],
        ] {
            assert!(parse_session_authorization(values).is_err());
        }
    }
}
