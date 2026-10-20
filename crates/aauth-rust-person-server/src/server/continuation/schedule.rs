use super::*;

pub(super) fn agent_delay(value: &Value, now: i64, minimum: u64) -> Result<u64, Failure> {
    Ok(minimum.max(number(value, "next_as")?.saturating_sub(now).max(0) as u64))
}
pub(super) fn throttled_for(value: &Value, now: i64) -> Result<Response<Vec<u8>>, Failure> {
    let wait = number(value, "next_agent")?
        .max(number(value, "next_as")?)
        .saturating_sub(now)
        .max(1);
    let mut response = Failure::status(StatusCode::TOO_MANY_REQUESTS, "slow_down").response();
    response.headers_mut().insert(
        "retry-after",
        wait.to_string().parse().map_err(|_| Failure::internal())?,
    );
    Ok(response)
}

// RFC 9110 Retry-After admits delta seconds or an HTTP-date. Keep upstream
// framing failures distinct from local storage/policy failures.
pub(super) fn retry_after(response: &Response<Vec<u8>>, now: i64) -> Result<Option<u64>, ()> {
    let values = response.headers().get_all("retry-after");
    if values.iter().count() > 1 {
        return Err(());
    }
    let Some(value) = values.iter().next() else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?.trim();
    let seconds = if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        value.parse::<u64>().map_err(|_| ())?
    } else {
        let date = httpdate::parse_http_date(value).map_err(|_| ())?;
        let at = date
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs())
            .unwrap_or(0);
        at.saturating_sub(u64::try_from(now).map_err(|_| ())?)
    };
    if seconds > 3600 {
        return Err(());
    }
    Ok(Some(seconds))
}
