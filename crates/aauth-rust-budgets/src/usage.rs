//! Usage request, response, and the optional response signature.
use std::collections::BTreeMap;

use aauth_rust_jose::{Jwk, SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::ledger::{Caller, ChargeView, KeyRole, Ledger};
use crate::value::{Budget, Error, MAX_AMOUNT};

/// One usage query after the signature has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageQuery {
    /// Directed subject, when that is the scope key.
    pub sub: Option<String>,
    /// Tenant, when that is the scope key.
    pub tenant: Option<String>,
    /// Mission digest, when that is the scope key.
    pub mission: Option<String>,
    /// Person server named by an access server.
    pub ps: Option<String>,
    /// Thumbprints whose figures were requested.
    pub jkts: Option<Vec<String>>,
}

/// Calendar counters. `all_time` is always present when `usage` is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counters {
    /// Consumption since 00:00 UTC on `as_of`'s day.
    pub day: Option<i64>,
    /// Consumption since Monday 00:00 UTC of `as_of`'s ISO week.
    pub week: Option<i64>,
    /// Consumption since the first of the UTC month.
    pub month: Option<i64>,
    /// Consumption since the first of the UTC year.
    pub year: Option<i64>,
    /// Everything metered under this key.
    pub all_time: i64,
}

/// Usage response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageResponse {
    /// Time through which the figures are complete.
    pub as_of: i64,
    /// Caller the response was produced for.
    pub aud: String,
    /// Unit every figure uses.
    pub unit: String,
    /// Scale of every figure.
    pub decimals: i64,
    /// Echoed scope key, when the request carried one.
    pub scope: Option<(&'static str, String)>,
    /// Counters for the scope key. Omitted when the resource has no positive figure.
    pub usage: Option<Counters>,
    /// Per-key figures. Unknown thumbprints are absent, not zero.
    pub jkts: Option<BTreeMap<String, i64>>,
}

impl UsageResponse {
    /// JSON object. Optional members are omitted rather than null.
    pub fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("as_of".into(), Value::Number(self.as_of.into()));
        object.insert("aud".into(), Value::String(self.aud.clone()));
        object.insert("unit".into(), Value::String(self.unit.clone()));
        object.insert("decimals".into(), Value::Number(self.decimals.into()));
        if let Some((name, value)) = &self.scope {
            object.insert((*name).to_owned(), Value::String(value.clone()));
        }
        if let Some(usage) = &self.usage {
            let mut counters = Map::new();
            if let Some(day) = usage.day {
                counters.insert("day".into(), Value::Number(day.into()));
            }
            if let Some(week) = usage.week {
                counters.insert("week".into(), Value::Number(week.into()));
            }
            if let Some(month) = usage.month {
                counters.insert("month".into(), Value::Number(month.into()));
            }
            if let Some(year) = usage.year {
                counters.insert("year".into(), Value::Number(year.into()));
            }
            counters.insert("all_time".into(), Value::Number(usage.all_time.into()));
            object.insert("usage".into(), Value::Object(counters));
        }
        if let Some(jkts) = &self.jkts {
            let mut keys = Map::new();
            for (thumbprint, amount) in jkts {
                keys.insert(thumbprint.clone(), Value::Number((*amount).into()));
            }
            object.insert("jkts".into(), Value::Object(keys));
        }
        Value::Object(object)
    }
}

/// Covered components of a signed usage response, in signature-base order.
pub const USAGE_COVERAGE: [&str; 5] = [
    "\"@status\"",
    "\"content-type\"",
    "\"content-digest\"",
    "\"@authority\";req",
    "\"@path\";req",
];

/// A signed usage response. Signing is optional; parsers accept an unsigned body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUsage {
    /// Response body.
    pub body: Vec<u8>,
    /// `Content-Digest` field value.
    pub content_digest: String,
    /// `Signature-Input` field value.
    pub signature_input: String,
    /// `Signature` field value.
    pub signature: String,
    /// `Signature-Key` field value.
    pub signature_key: String,
}

/// Parse a usage request body.
///
/// # Errors
/// Returns [`Error::Malformed`] when the body has more than one scope key, has
/// neither a scope key nor `jkts`, or has a malformed member. An access server
/// that sends a scope key without `ps` is the same error.
pub fn parse_usage_query(value: &Value, role: KeyRole) -> Result<UsageQuery, Error> {
    let Value::Object(object) = value else {
        return Err(Error::Malformed);
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "sub" | "tenant" | "mission_s256" | "ps" | "jkts"
        )
    }) {
        return Err(Error::Malformed);
    }
    let sub = optional_string(object, "sub")?;
    let tenant = optional_string(object, "tenant")?;
    let mission = optional_string(object, "mission_s256")?;
    let ps = optional_string(object, "ps")?;
    let scope_count = [&sub, &tenant, &mission]
        .iter()
        .filter(|value| value.is_some())
        .count();
    if scope_count > 1 {
        return Err(Error::Malformed);
    }
    let jkts = match object.get("jkts") {
        None => None,
        Some(Value::Array(items)) => {
            let mut thumbprints = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(value) if !value.is_empty() => thumbprints.push(value.clone()),
                    _ => return Err(Error::Malformed),
                }
            }
            Some(thumbprints)
        }
        _ => return Err(Error::Malformed),
    };
    if scope_count == 0 && jkts.is_none() {
        return Err(Error::Malformed);
    }
    if role == KeyRole::AccessServer && scope_count == 1 && ps.is_none() {
        return Err(Error::Malformed);
    }
    if role == KeyRole::PersonServer && ps.is_some() {
        return Err(Error::Malformed);
    }
    Ok(UsageQuery {
        sub,
        tenant,
        mission,
        ps,
        jkts,
    })
}

fn optional_string(object: &Map<String, Value>, name: &str) -> Result<Option<String>, Error> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(Error::Malformed),
    }
}

/// Build the usage response from the ledger.
///
/// A scope key with no positive figure omits `usage`. A thumbprint with no
/// figure is omitted rather than reported as zero. A known key that consumed
/// nothing is reported as zero.
pub fn answer_usage(
    ledger: &Ledger,
    caller: &Caller,
    query: &UsageQuery,
    now: i64,
    report: &Budget,
) -> UsageResponse {
    let as_of = ledger.as_of(now);
    let scope = query
        .sub
        .as_ref()
        .map(|value| ("sub", value.clone()))
        .or_else(|| query.tenant.as_ref().map(|value| ("tenant", value.clone())))
        .or_else(|| {
            query
                .mission
                .as_ref()
                .map(|value| ("mission_s256", value.clone()))
        });
    let usage = scope
        .as_ref()
        .and_then(|(name, value)| counters(ledger, caller, name, value, report.unit(), as_of));
    let jkts = query.jkts.as_ref().map(|thumbprints| {
        let mut figures = BTreeMap::new();
        for thumbprint in thumbprints {
            if let Some(amount) = ledger.key_amount(thumbprint, caller) {
                figures.insert(thumbprint.clone(), amount);
            }
        }
        figures
    });
    UsageResponse {
        as_of,
        aud: caller.id.clone(),
        unit: report.unit().to_owned(),
        decimals: report.decimals(),
        scope,
        usage,
        jkts,
    }
}

fn counters(
    ledger: &Ledger,
    caller: &Caller,
    name: &str,
    value: &str,
    unit: &str,
    as_of: i64,
) -> Option<Counters> {
    let rows: Vec<ChargeView<'_>> = ledger
        .charges()
        .filter(|charge| {
            charge.unit == unit
                && charge.at <= as_of
                && visible(charge, caller)
                && matches_scope(charge, name, value)
        })
        .collect();
    if rows.is_empty() && !ledger.known_scope(caller, name, value) {
        return None;
    }
    let all_time: i64 = rows.iter().map(|charge| charge.amount).sum();
    if all_time == 0 {
        return None;
    }
    if all_time > MAX_AMOUNT {
        return None;
    }
    let day_start = start_of_utc_day(as_of);
    let week_start = start_of_iso_week(as_of);
    let (year, month, _) = civil_from_days(as_of.div_euclid(86_400));
    let month_start = days_from_civil(year, month, 1) * 86_400;
    let year_start = days_from_civil(year, 1, 1) * 86_400;
    Some(Counters {
        day: bounded(sum_since(&rows, day_start)),
        week: bounded(sum_since(&rows, week_start)),
        month: bounded(sum_since(&rows, month_start)),
        year: bounded(sum_since(&rows, year_start)),
        all_time,
    })
}

fn visible(charge: &ChargeView<'_>, caller: &Caller) -> bool {
    match caller.role {
        KeyRole::PersonServer => charge.iss == caller.id || charge.ps == caller.id,
        KeyRole::AccessServer => {
            charge.iss == caller.id && caller.ps.as_deref().is_none_or(|ps| charge.ps == ps)
        }
    }
}

fn matches_scope(charge: &ChargeView<'_>, name: &str, value: &str) -> bool {
    match name {
        "sub" => charge.sub == value,
        "tenant" => charge.tenant == Some(value),
        "mission_s256" => charge.mission == Some(value),
        _ => false,
    }
}

fn sum_since(rows: &[ChargeView<'_>], start: i64) -> i64 {
    rows.iter()
        .filter(|charge| charge.at >= start)
        .map(|charge| charge.amount)
        .sum()
}

fn bounded(amount: i64) -> Option<i64> {
    (amount <= MAX_AMOUNT).then_some(amount)
}

fn start_of_utc_day(timestamp: i64) -> i64 {
    timestamp - timestamp.rem_euclid(86_400)
}

fn start_of_iso_week(timestamp: i64) -> i64 {
    let day = timestamp.div_euclid(86_400);
    // 1970-01-01 was a Thursday. Monday is 0.
    let weekday = (day + 3).rem_euclid(7);
    (day - weekday) * 86_400
}

fn civil_from_days(day: i64) -> (i64, u32, u32) {
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn days_from_civil(mut year: i64, month: u32, day: u32) -> i64 {
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = (year - era * 400) as u64;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_index as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// True when `signature_input` lists every component a signed usage response covers.
pub fn usage_signature_covers(signature_input: &str) -> bool {
    USAGE_COVERAGE
        .iter()
        .all(|component| signature_input.contains(component))
}

/// Sign a usage response. The signature covers `@status`, `content-type`,
/// `content-digest`, and the request `@authority` and `@path`.
///
/// # Errors
/// Returns [`Error::Malformed`] when `created` is negative or the path is empty.
pub fn sign_usage_response(
    key: &SigningKey,
    issuer: &str,
    kid: &str,
    authority: &str,
    path: &str,
    body: &[u8],
    created: i64,
) -> Result<SignedUsage, Error> {
    if created < 0 || path.is_empty() || authority.is_empty() || kid.is_empty() {
        return Err(Error::Malformed);
    }
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)));
    let params = format!(
        "(\"@status\" \"content-type\" \"content-digest\" \"@authority\";req \"@path\";req);created={created}"
    );
    let base = format!(
        "\"@status\": 200\n\"content-type\": application/json\n\"content-digest\": {content_digest}\n\"@authority\";req: {authority}\n\"@path\";req: {path}\n\"@signature-params\": {params}"
    );
    let signature = STANDARD.encode(key.sign(base.as_bytes()));
    Ok(SignedUsage {
        body: body.to_vec(),
        content_digest,
        signature_input: format!("sig={params}"),
        signature: format!("sig=:{signature}:"),
        signature_key: format!(
            "sig=jwks_uri;id=\"{issuer}\";dwk=\"aauth-resource.json\";kid=\"{kid}\""
        ),
    })
}

/// Verify a usage response signature with the resource's public key.
///
/// # Errors
/// Returns [`Error::Malformed`] when coverage or the signature does not match.
pub fn verify_usage_signature(
    signed: &SignedUsage,
    key: &Jwk,
    authority: &str,
    path: &str,
    created: i64,
) -> Result<(), Error> {
    if !usage_signature_covers(&signed.signature_input) {
        return Err(Error::Malformed);
    }
    let digest = format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(&signed.body))
    );
    if signed.content_digest != digest {
        return Err(Error::Malformed);
    }
    let params = signed
        .signature_input
        .strip_prefix("sig=")
        .ok_or(Error::Malformed)?;
    let base = format!(
        "\"@status\": 200\n\"content-type\": application/json\n\"content-digest\": {digest}\n\"@authority\";req: {authority}\n\"@path\";req: {path}\n\"@signature-params\": {params}"
    );
    if !params.contains(&format!("created={created}")) {
        return Err(Error::Malformed);
    }
    let raw = signed
        .signature
        .strip_prefix("sig=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or(Error::Malformed)?;
    let bytes = STANDARD.decode(raw).map_err(|_| Error::Malformed)?;
    key.verify(base.as_bytes(), &bytes)
        .map_err(|_| Error::Malformed)
}
