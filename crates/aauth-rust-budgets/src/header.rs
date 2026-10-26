//! `AAuth-Budget` header and trailer.
use sfv::{BareItem, DictSerializer, Dictionary, Integer, KeyRef, ListEntry, Parser, StringRef};

use crate::value::{Budget, Error, check_amount};

/// Members a resource puts on `AAuth-Budget`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetHeader {
    /// What is left of this auth token's grant, net of reservations.
    pub remaining: i64,
    /// Cost of this request, when the resource knows it now.
    pub cost: Option<i64>,
    /// Amount held for this request and not yet committed.
    pub reserved: Option<i64>,
    /// Maximum cost of a request refused as `insufficient-budget`.
    pub required: Option<i64>,
    /// Unit, present only together with [`Self::decimals`].
    pub unit: Option<String>,
    /// Scale, present only together with [`Self::unit`].
    pub decimals: Option<i64>,
}

impl BudgetHeader {
    /// A served request whose cost is known. `cost` is present and `reserved` is not.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when the pair or the integers are invalid.
    pub fn final_cost(remaining: i64, cost: i64, unit: &str, decimals: i64) -> Result<Self, Error> {
        Self::build(
            remaining,
            Some(cost),
            None,
            None,
            Some(unit),
            Some(decimals),
        )
    }

    /// A streamed response: `reserved` is present and `cost` is not.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when `reserved` is missing or the integers are invalid.
    pub fn reserved_hold(
        remaining: i64,
        reserved: i64,
        unit: &str,
        decimals: i64,
    ) -> Result<Self, Error> {
        Self::build(
            remaining,
            None,
            Some(reserved),
            None,
            Some(unit),
            Some(decimals),
        )
    }

    /// A refusal. No `cost` and no `reserved`. `required` is set only for
    /// `insufficient-budget`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when the integers or the unit pair are invalid.
    pub fn refusal(
        remaining: i64,
        required: Option<i64>,
        unit: &str,
        decimals: i64,
    ) -> Result<Self, Error> {
        Self::build(remaining, None, None, required, Some(unit), Some(decimals))
    }

    fn build(
        remaining: i64,
        cost: Option<i64>,
        reserved: Option<i64>,
        required: Option<i64>,
        unit: Option<&str>,
        decimals: Option<i64>,
    ) -> Result<Self, Error> {
        check_amount(remaining)?;
        for value in [cost, reserved, required].into_iter().flatten() {
            check_amount(value)?;
        }
        match (unit, decimals) {
            (Some(unit), Some(decimals)) if !unit.is_empty() && decimals >= 0 => {
                check_amount(decimals)?;
            }
            (None, None) => {}
            _ => return Err(Error::Malformed),
        }
        Ok(Self {
            remaining,
            cost,
            reserved,
            required,
            unit: unit.map(str::to_owned),
            decimals,
        })
    }
}

/// A parsed field. Unknown members are dropped. `actionable` is false when the
/// header's unit pair disagrees with the auth token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedHeader {
    /// Parsed members the recipient understood.
    pub header: BudgetHeader,
    /// False when the recipient must not act on the field.
    pub actionable: bool,
}

/// Serialize one header. A metered response that is not a refusal must carry
/// `cost` or `reserved`.
///
/// # Errors
/// Returns [`Error::Malformed`] when a served request omits both figures or the
/// unit pair is incomplete.
pub fn sender_field(header: &BudgetHeader, served: bool) -> Result<String, Error> {
    if served && header.cost.is_none() && header.reserved.is_none() {
        return Err(Error::Malformed);
    }
    serialize(header)
}

/// Trailer carrying only `cost`. It does not restate a member the header carried.
///
/// # Errors
/// Returns [`Error::Malformed`] when the header already carried `cost` or any
/// other member would be repeated.
pub fn trailer_field(header: &BudgetHeader, cost: i64) -> Result<Trailer, Error> {
    check_amount(cost)?;
    if header.cost.is_some() {
        return Err(Error::Malformed);
    }
    let field = {
        let mut serializer = DictSerializer::new();
        let key = KeyRef::from_str("cost").map_err(|_| Error::Malformed)?;
        serializer.bare_item(key, Integer::try_from(cost).map_err(|_| Error::Range)?);
        serializer.finish().ok_or(Error::Malformed)?
    };
    Ok(Trailer {
        listed: "AAuth-Budget",
        name: "aauth-budget",
        field,
    })
}

/// `Trailer` header value and the trailer field value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trailer {
    /// Value of the HTTP `Trailer` header. The response lists `AAuth-Budget`.
    pub listed: &'static str,
    /// Trailer field name.
    pub name: &'static str,
    /// `AAuth-Budget` trailer field value.
    pub field: String,
}

/// Parse a field. Unknown members are ignored. A positive cache `current_age`
/// makes the field non-actionable. A unit pair that disagrees with `grant`
/// does too.
///
/// # Errors
/// Returns [`Error::Malformed`] for a missing `remaining` or a bad type.
pub fn parse_header(
    field: &str,
    grant: Option<&Budget>,
    current_age: Option<u64>,
) -> Result<ParsedHeader, Error> {
    let dictionary: Dictionary = Parser::new(field).parse().map_err(|_| Error::Malformed)?;
    let remaining = required_int(&dictionary, "remaining")?;
    let cost = optional_int(&dictionary, "cost")?;
    let reserved = optional_int(&dictionary, "reserved")?;
    let required = optional_int(&dictionary, "required")?;
    let unit = optional_string(&dictionary, "unit")?;
    let decimals = optional_int(&dictionary, "decimals")?;
    let header = BudgetHeader::build(
        remaining,
        cost,
        reserved,
        required,
        unit.as_deref(),
        decimals,
    )?;
    let fresh = current_age.is_none_or(|age| age == 0);
    let matches_grant = match (&header.unit, header.decimals, grant) {
        (None, None, _) => true,
        (Some(unit), Some(decimals), Some(grant)) => {
            unit == grant.unit() && decimals == grant.decimals()
        }
        (Some(_), Some(_), None) => true,
        _ => false,
    };
    Ok(ParsedHeader {
        header,
        actionable: fresh && matches_grant,
    })
}

/// Remaining balance the recipient may act on. `None` when the field is stale
/// or the unit pair disagrees with the auth token.
pub fn act_on_header(parsed: &ParsedHeader) -> Option<i64> {
    parsed.actionable.then_some(parsed.header.remaining)
}

fn serialize(header: &BudgetHeader) -> Result<String, Error> {
    let mut serializer = DictSerializer::new();
    write_int(&mut serializer, "remaining", header.remaining)?;
    if let Some(cost) = header.cost {
        write_int(&mut serializer, "cost", cost)?;
    }
    if let Some(reserved) = header.reserved {
        write_int(&mut serializer, "reserved", reserved)?;
    }
    if let Some(required) = header.required {
        write_int(&mut serializer, "required", required)?;
    }
    if let (Some(unit), Some(decimals)) = (&header.unit, header.decimals) {
        let key = KeyRef::from_str("unit").map_err(|_| Error::Malformed)?;
        let text = StringRef::from_str(unit).map_err(|_| Error::Malformed)?;
        serializer.bare_item(key, text);
        write_int(&mut serializer, "decimals", decimals)?;
    }
    serializer.finish().ok_or(Error::Malformed)
}

fn write_int(serializer: &mut DictSerializer<String>, name: &str, value: i64) -> Result<(), Error> {
    let key = KeyRef::from_str(name).map_err(|_| Error::Malformed)?;
    serializer.bare_item(key, Integer::try_from(value).map_err(|_| Error::Range)?);
    Ok(())
}

/// Parse an `AAuth-Max-Cost` field. The value is one structured-field integer.
///
/// # Errors
/// Returns [`Error::Malformed`] when the field is not a bare integer, and
/// [`Error::Range`] when it is outside the carrier.
pub fn parse_max_cost(field: &str) -> Result<i64, Error> {
    let item: sfv::Item = Parser::new(field).parse().map_err(|_| Error::Malformed)?;
    if !item.params.is_empty() {
        return Err(Error::Malformed);
    }
    match item.bare_item {
        BareItem::Integer(value) => {
            let amount = i64::from(value);
            check_amount(amount)?;
            Ok(amount)
        }
        _ => Err(Error::Malformed),
    }
}

fn member<'a>(dictionary: &'a Dictionary, name: &str) -> Result<Option<&'a sfv::Item>, Error> {
    match dictionary.get(name) {
        None => Ok(None),
        Some(ListEntry::Item(item)) if item.params.is_empty() => Ok(Some(item)),
        _ => Err(Error::Malformed),
    }
}

fn required_int(dictionary: &Dictionary, name: &str) -> Result<i64, Error> {
    optional_int(dictionary, name)?.ok_or(Error::Malformed)
}

fn optional_int(dictionary: &Dictionary, name: &str) -> Result<Option<i64>, Error> {
    match member(dictionary, name)? {
        None => Ok(None),
        Some(item) => match &item.bare_item {
            BareItem::Integer(value) => {
                let number = i64::from(*value);
                check_amount(number)?;
                Ok(Some(number))
            }
            _ => Err(Error::Malformed),
        },
    }
}

fn optional_string(dictionary: &Dictionary, name: &str) -> Result<Option<String>, Error> {
    match member(dictionary, name)? {
        None => Ok(None),
        Some(item) => match &item.bare_item {
            BareItem::String(value) if !value.as_str().is_empty() => {
                Ok(Some(value.as_str().to_owned()))
            }
            _ => Err(Error::Malformed),
        },
    }
}
