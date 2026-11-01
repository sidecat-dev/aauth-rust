//! Budget object, unit declarations, narrowing, and consent display.
use std::collections::{BTreeMap, BTreeSet};

use aauth_rust_jose::strict_json;
use serde_json::{Map, Value};

/// Largest integer this profile will issue. Both JSON and Structured Field
/// Integers stay exact at fifteen digits.
pub const MAX_AMOUNT: i64 = 999_999_999_999_999;

/// A budget figure failed validation or a narrowing rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The object is not the three-member budget shape, or a required member is absent.
    #[error("budget value is malformed")]
    Malformed,
    /// `amount`, `consumed`, `decimals`, or `max` exceeds fifteen digits.
    #[error("budget integer exceeds 999999999999999")]
    Range,
    /// A later party changed `unit` or `decimals`.
    #[error("budget unit or decimals changed")]
    Denomination,
    /// A later party set `amount` above the previous stage.
    #[error("budget amount exceeds the previous stage")]
    Exceeds,
    /// Declared scale and the signed figure disagree.
    #[error("budget decimals do not match the resource declaration")]
    DecimalsMismatch,
    /// The unit is not in `budget_units`.
    #[error("budget unit is not declared")]
    UndeclaredUnit,
    /// The endpoint is not an HTTPS URL without a query or fragment.
    #[error("budget endpoint URL is not an HTTPS URL without a query or fragment")]
    Endpoint,
    /// Metering mode is not `auth-token`.
    #[error("budgets require access_mode auth-token")]
    AccessMode,
    /// The host ledger file could not be read or replaced. The wire is unchanged.
    #[error("budget ledger file is unavailable")]
    Unavailable,
    /// The resource's signing key could not sign: its external signer failed
    /// or returned a signature its public key does not verify.
    #[error("usage response signing failed")]
    Signing,
}

/// One non-negative budget amount in a resource-selected unit and scale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    amount: i64,
    unit: String,
    decimals: i64,
}

impl Budget {
    /// Validate `amount`, `unit`, and `decimals`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] or [`Error::Range`].
    pub fn new(amount: i64, unit: impl Into<String>, decimals: i64) -> Result<Self, Error> {
        let unit = unit.into();
        if unit.is_empty() || decimals < 0 {
            return Err(Error::Malformed);
        }
        check_amount(amount)?;
        check_amount(decimals)?;
        Ok(Self {
            amount,
            unit,
            decimals,
        })
    }

    /// Integer amount in [`Self::decimals`] scale.
    pub fn amount(&self) -> i64 {
        self.amount
    }

    /// Resource-declared unit identifier.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Scale of [`Self::amount`].
    pub fn decimals(&self) -> i64 {
        self.decimals
    }

    /// JSON object with `amount`, `unit`, and `decimals`.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "amount": self.amount,
            "unit": self.unit,
            "decimals": self.decimals,
        })
    }
}

/// One `budget_units` metadata entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitDeclaration {
    unit: String,
    decimals: i64,
    max: Option<i64>,
    description: String,
}

impl UnitDeclaration {
    /// A unit and scale, with no advertised maximum.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] or [`Error::Range`].
    pub fn new(
        unit: impl Into<String>,
        decimals: i64,
        description: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::build(unit, decimals, None, description)
    }

    /// A unit and scale with the largest amount accepted on one auth token.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] or [`Error::Range`].
    pub fn with_max(
        unit: impl Into<String>,
        decimals: i64,
        max: i64,
        description: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::build(unit, decimals, Some(max), description)
    }

    fn build(
        unit: impl Into<String>,
        decimals: i64,
        max: Option<i64>,
        description: impl Into<String>,
    ) -> Result<Self, Error> {
        let unit = unit.into();
        let description = description.into();
        if unit.is_empty() || decimals < 0 {
            return Err(Error::Malformed);
        }
        check_amount(decimals)?;
        if let Some(max) = max {
            check_amount(max)?;
        }
        Ok(Self {
            unit,
            decimals,
            max,
            description,
        })
    }

    /// Unit identifier.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Declared scale. Issued budgets for this unit use this value.
    pub fn decimals(&self) -> i64 {
        self.decimals
    }

    /// Advertised per-token maximum, when the resource published one.
    pub fn max(&self) -> Option<i64> {
        self.max
    }

    /// Resource-supplied description, as published on `budget_units`.
    ///
    /// The stored string is not display text. Show [`description_text`] of it.
    /// That result is plain text, not Markdown.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// JSON object for `budget_units`.
    pub fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("unit".into(), Value::String(self.unit.clone()));
        object.insert("decimals".into(), Value::Number(self.decimals.into()));
        if let Some(max) = self.max {
            object.insert("max".into(), Value::Number(max.into()));
        }
        if !self.description.is_empty() {
            object.insert(
                "description".into(),
                Value::String(self.description.clone()),
            );
        }
        Value::Object(object)
    }
}

/// Consumption of one prior auth token, in the same scale as the enclosing budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumptionRecord {
    jti: String,
    consumed: i64,
}

impl ConsumptionRecord {
    /// Validate `jti` and `consumed`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] or [`Error::Range`].
    pub fn new(jti: impl Into<String>, consumed: i64) -> Result<Self, Error> {
        let jti = jti.into();
        if jti.is_empty() {
            return Err(Error::Malformed);
        }
        check_amount(consumed)?;
        Ok(Self { jti, consumed })
    }

    /// Auth-token `jti` this record reports.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// Metered amount in the enclosing budget's scale.
    pub fn consumed(&self) -> i64 {
        self.consumed
    }

    /// JSON object with `jti` and `consumed`.
    pub fn to_value(&self) -> Value {
        serde_json::json!({"jti": self.jti, "consumed": self.consumed})
    }
}

/// Optional budget claims from one resource token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceBudget {
    /// Ceiling the resource is willing to have granted.
    pub budget: Option<Budget>,
    /// Spend of the presented auth token, when the resource reported it.
    pub consumed: Option<ConsumptionRecord>,
}

/// Human amount and a plain-text description, kept as separate fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentFigure {
    /// Plain-text amount such as `$5.00`, never the JSON object.
    pub amount: String,
    /// Unit description after [`description_text`]. Already HTML-escaped.
    pub description: String,
}

pub(crate) fn check_amount(amount: i64) -> Result<(), Error> {
    if amount < 0 {
        return Err(Error::Malformed);
    }
    if amount > MAX_AMOUNT {
        return Err(Error::Range);
    }
    Ok(())
}

fn json_amount(value: Option<&Value>) -> Result<i64, Error> {
    match value {
        Some(Value::Number(number)) => {
            if !number.is_i64() {
                return Err(Error::Malformed);
            }
            let amount = number.as_i64().ok_or(Error::Range)?;
            check_amount(amount)?;
            Ok(amount)
        }
        _ => Err(Error::Malformed),
    }
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, Error> {
    let Value::Object(object) = value else {
        return Err(Error::Malformed);
    };
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(Error::Malformed);
    }
    Ok(object)
}

/// Parse one budget object. Fractional JSON numbers and unknown members fail.
///
/// # Errors
/// Returns [`Error::Malformed`] or [`Error::Range`].
pub fn parse_budget(value: &Value) -> Result<Budget, Error> {
    let object = object(value, &["amount", "unit", "decimals"])?;
    let unit = match object.get("unit") {
        Some(Value::String(unit)) if !unit.is_empty() => unit.clone(),
        _ => return Err(Error::Malformed),
    };
    Budget::new(
        json_amount(object.get("amount"))?,
        unit,
        json_amount(object.get("decimals"))?,
    )
}

/// Parse one consumption record and require `jti` to equal `presented_jti`.
///
/// # Errors
/// Returns [`Error::Malformed`] or [`Error::Range`].
pub fn parse_consumption(value: &Value, presented_jti: &str) -> Result<ConsumptionRecord, Error> {
    let object = object(value, &["jti", "consumed"])?;
    let jti = match object.get("jti") {
        Some(Value::String(jti)) if !jti.is_empty() => jti.clone(),
        _ => return Err(Error::Malformed),
    };
    if jti != presented_jti {
        return Err(Error::Malformed);
    }
    ConsumptionRecord::new(jti, json_amount(object.get("consumed"))?)
}

/// Read `budget` and `budget_consumed` from token claims.
///
/// A consumption record without `budget` is rejected. Absent claims are `None`.
///
/// # Errors
/// Returns [`Error::Malformed`] or [`Error::Range`].
pub fn parse_resource_claims(
    extra: &BTreeMap<String, Value>,
    presented_jti: &str,
) -> Result<ResourceBudget, Error> {
    let budget = extra.get("budget").map(parse_budget).transpose()?;
    let consumed = extra
        .get("budget_consumed")
        .map(|value| parse_consumption(value, presented_jti))
        .transpose()?;
    if consumed.is_some() && budget.is_none() {
        return Err(Error::Malformed);
    }
    Ok(ResourceBudget { budget, consumed })
}

/// Parse a `budget_units` array. Duplicate unit names are rejected.
///
/// # Errors
/// Returns [`Error::Malformed`] or [`Error::Range`].
pub fn parse_declarations(value: &Value) -> Result<Vec<UnitDeclaration>, Error> {
    let Value::Array(items) = value else {
        return Err(Error::Malformed);
    };
    let mut seen = BTreeSet::new();
    let mut declarations = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(object) = item else {
            return Err(Error::Malformed);
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "unit" | "decimals" | "max" | "description"))
            || !object.contains_key("unit")
            || !object.contains_key("decimals")
        {
            return Err(Error::Malformed);
        }
        let unit = match object.get("unit") {
            Some(Value::String(unit)) if !unit.is_empty() => unit.clone(),
            _ => return Err(Error::Malformed),
        };
        if !seen.insert(unit.clone()) {
            return Err(Error::Malformed);
        }
        let decimals = json_amount(object.get("decimals"))?;
        let description = match object.get("description") {
            None => String::new(),
            Some(Value::String(text)) => text.clone(),
            _ => return Err(Error::Malformed),
        };
        let declaration = match object.get("max") {
            None => UnitDeclaration::new(unit, decimals, description)?,
            Some(_) => UnitDeclaration::with_max(
                unit,
                decimals,
                json_amount(object.get("max"))?,
                description,
            )?,
        };
        declarations.push(declaration);
    }
    Ok(declarations)
}

/// Parse a JSON document that is only a budget object or a `budget_units` array.
///
/// # Errors
/// Returns the underlying JSON or budget error.
pub fn parse_budget_bytes(bytes: &[u8]) -> Result<Budget, Error> {
    parse_budget(&strict_json(bytes).map_err(|_| Error::Malformed)?)
}

/// `usage_endpoint` uses HTTPS and has neither a query nor a fragment.
///
/// # Errors
/// Returns [`Error::Endpoint`] when the URL is outside that profile.
pub fn validate_endpoint_url(url: &str) -> Result<(), Error> {
    if url.contains('#') || url.contains(' ') {
        return Err(Error::Endpoint);
    }
    let uri: http::Uri = url.parse().map_err(|_| Error::Endpoint)?;
    let authority = uri.authority().ok_or(Error::Endpoint)?;
    if uri.scheme_str() != Some("https")
        || uri.query().is_some()
        || authority.as_str().contains('@')
        || uri.path().is_empty()
        || uri.path() == "/"
        || uri.host().is_none()
    {
        return Err(Error::Endpoint);
    }
    Ok(())
}

/// Budgets are enforced only on `auth-token` endpoints.
///
/// # Errors
/// Returns [`Error::AccessMode`] for any other access mode.
pub fn metered_access_mode(access_mode: &str) -> Result<(), Error> {
    if access_mode == "auth-token" {
        Ok(())
    } else {
        Err(Error::AccessMode)
    }
}

/// Same unit and scale, and `granted.amount <= offered.amount`.
///
/// # Errors
/// Returns [`Error::Denomination`] or [`Error::Exceeds`].
pub fn validate_narrowing(offered: &Budget, granted: &Budget) -> Result<(), Error> {
    if offered.unit != granted.unit || offered.decimals != granted.decimals {
        return Err(Error::Denomination);
    }
    if granted.amount > offered.amount {
        return Err(Error::Exceeds);
    }
    Ok(())
}

/// Resource offer. A request above `max` is narrowed. An unknown unit is rejected.
/// Omitting the request uses `default_offer`, capped by the first unit's `max`.
///
/// # Errors
/// Returns [`Error::UndeclaredUnit`], [`Error::DecimalsMismatch`], or a value error.
pub fn offer_budget(
    units: &[UnitDeclaration],
    requested: Option<&Budget>,
    default_offer: i64,
) -> Result<Budget, Error> {
    check_amount(default_offer)?;
    let Some(primary) = units.first() else {
        return Err(Error::Malformed);
    };
    match requested {
        None => {
            let amount = primary
                .max
                .map(|max| max.min(default_offer))
                .unwrap_or(default_offer);
            Budget::new(amount, primary.unit.clone(), primary.decimals)
        }
        Some(requested) => {
            let declared = units
                .iter()
                .find(|unit| unit.unit == requested.unit)
                .ok_or(Error::UndeclaredUnit)?;
            if declared.decimals != requested.decimals {
                return Err(Error::DecimalsMismatch);
            }
            let amount = declared
                .max
                .map(|max| requested.amount.min(max))
                .unwrap_or(requested.amount);
            Budget::new(amount, declared.unit.clone(), declared.decimals)
        }
    }
}

/// Check a signed budget against cached `budget_units`.
///
/// An empty declaration list means the host has no cache and accepts the
/// signed scale. A cached scale that disagrees is a hard error, not a narrowing.
///
/// # Errors
/// Returns [`Error::UndeclaredUnit`] or [`Error::DecimalsMismatch`].
pub fn check_declared(budget: &Budget, units: &[UnitDeclaration]) -> Result<(), Error> {
    if units.is_empty() {
        return Ok(());
    }
    let declared = units
        .iter()
        .find(|unit| unit.unit == budget.unit)
        .ok_or(Error::UndeclaredUnit)?;
    if declared.decimals != budget.decimals {
        return Err(Error::DecimalsMismatch);
    }
    Ok(())
}

/// Lower `amount` to `cap` when the cap is lower. Unit and scale are copied.
///
/// # Errors
/// Returns [`Error::Range`] when `cap` is outside the carrier.
pub fn narrow_to(offer: &Budget, cap: Option<i64>) -> Result<Budget, Error> {
    let amount = match cap {
        Some(cap) => {
            check_amount(cap)?;
            cap.min(offer.amount)
        }
        None => offer.amount,
    };
    let granted = Budget::new(amount, offer.unit.clone(), offer.decimals)?;
    validate_narrowing(offer, &granted)?;
    Ok(granted)
}

/// Plain-text amount in the unit. USD with scale 6 renders as `$5.00`.
pub fn human_amount(budget: &Budget) -> String {
    if budget.unit == "USD"
        && let Some((dollars, cents)) = usd_parts(budget.amount, budget.decimals)
    {
        return format!("${dollars}.{cents:02}");
    }
    if budget.decimals == 0 {
        return format!("{} {}", budget.amount, budget.unit);
    }
    let (whole, frac) = split_digits(budget.amount, budget.decimals);
    format!("{whole}.{frac} {}", budget.unit)
}

fn pow10(exp: i64) -> Option<i64> {
    if !(0..=15).contains(&exp) {
        return None;
    }
    let mut value = 1_i64;
    for _ in 0..exp {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

fn usd_parts(amount: i64, decimals: i64) -> Option<(i64, i64)> {
    let cents = if decimals >= 2 {
        let div = pow10(decimals - 2)?;
        let cents = amount / div;
        let remainder = amount % div;
        if div > 1 && remainder.saturating_mul(2) >= div {
            cents.checked_add(1)?
        } else {
            cents
        }
    } else {
        amount.checked_mul(pow10(2 - decimals)?)?
    };
    Some((cents / 100, cents % 100))
}

fn split_digits(amount: i64, decimals: i64) -> (String, String) {
    let digits = amount.to_string();
    let decimals = usize::try_from(decimals).unwrap_or(usize::MAX);
    if decimals == 0 {
        return (digits, String::new());
    }
    if digits.len() <= decimals {
        let frac = format!("{digits:0>decimals$}");
        ("0".into(), frac)
    } else {
        let split = digits.len() - decimals;
        (digits[..split].to_owned(), digits[split..].to_owned())
    }
}

/// Characters of normalized description text kept before HTML escaping.
///
/// The draft states no length. A consent screen keeps at most this many
/// Unicode scalar values. A longer description is cut and ends with `…`.
/// The bound is applied before escaping, so the returned string can be longer.
pub const DESCRIPTION_TEXT_LIMIT: usize = 1024;

/// Bidirectional formatting characters a consent line must not keep.
///
/// Overrides, embeddings, isolates, and marks. Any one of them lets a
/// resource spoof the direction of the surrounding text.
fn is_bidi_formatting(character: char) -> bool {
    matches!(
        character,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Plain text for a resource-supplied unit description.
///
/// The draft calls the description Markdown and says to sanitize it before
/// rendering. This profile does not render Markdown. The result is safe to
/// insert into HTML as text that is already escaped: `&`, `<`, `>`, `"`, and
/// `'` become character references. Control characters and bidi formatting
/// characters are removed. Whitespace, including control whitespace, collapses
/// to one space, with no leading or trailing space. The normalized text is at
/// most [`DESCRIPTION_TEXT_LIMIT`] scalar values; a longer description ends
/// with `…` inside that bound. There is no link rewrite, scheme filter, or
/// character-reference decode, and the function does not panic.
pub fn description_text(input: &str) -> String {
    let mut plain = String::new();
    let mut count = 0usize;
    let mut pending_space = false;
    for character in input.chars() {
        if character.is_whitespace() {
            if count > 0 {
                pending_space = true;
            }
            continue;
        }
        if character.is_control() || is_bidi_formatting(character) {
            continue;
        }
        let extra = usize::from(pending_space) + 1;
        if count + extra > DESCRIPTION_TEXT_LIMIT {
            if count >= DESCRIPTION_TEXT_LIMIT {
                let _ = plain.pop();
            }
            plain.push('\u{2026}');
            return escape_html(&plain);
        }
        if pending_space {
            plain.push(' ');
            pending_space = false;
        }
        plain.push(character);
        count += extra;
    }
    escape_html(&plain)
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

/// Amount and description a person server shows at consent.
///
/// The amount is plain text. The description is plain text from
/// [`description_text`], not Markdown. They are separate strings so the
/// figure is not part of the resource's description.
pub fn consent_figure(budget: &Budget, description: &str) -> ConsentFigure {
    ConsentFigure {
        amount: human_amount(budget),
        description: description_text(description),
    }
}
