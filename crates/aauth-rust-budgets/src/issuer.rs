//! Issuer narrowing, delivery checks, and unreported-allocation accounting.
use std::collections::BTreeMap;

use crate::value::{Budget, ConsumptionRecord, Error, UnitDeclaration, check_declared, narrow_to};

/// Host ceiling and optional cached `budget_units` for one issuer.
#[derive(Clone, Debug, Default)]
pub struct IssuerPolicy {
    /// Largest amount this issuer will put on the next stage. `None` echoes the offer.
    pub cap: Option<i64>,
    /// Cached resource declarations. Empty means proceed on the signed scale.
    pub units: Vec<UnitDeclaration>,
    /// Latest Unix second an issued auth token may expire. A calendar-period
    /// ceiling passes the period boundary. `None` leaves the other lifetimes alone.
    pub period_end: Option<i64>,
}

impl IssuerPolicy {
    /// Echo the offer and do not cross-check a metadata cache.
    pub fn echo() -> Self {
        Self::default()
    }

    /// Cap issued amounts at `cap` and cross-check `units` when non-empty.
    pub fn capped(cap: i64, units: Vec<UnitDeclaration>) -> Self {
        Self {
            cap: Some(cap),
            units,
            period_end: None,
        }
    }

    /// Do not issue an auth token past `period_end`.
    ///
    /// Other lifetimes still apply. This bound does not extend an expiry.
    pub fn until(mut self, period_end: i64) -> Self {
        self.period_end = Some(period_end);
        self
    }
}

/// The auth-token `budget` an issuer may write.
///
/// `parameter` is the PS-to-AS budget. Three-party issuance passes the resource
/// offer as `parameter` as well, because there is no second ceiling on the wire.
/// Omitting `parameter` in four-party access issues no budget claim.
///
/// # Errors
/// Returns a denomination, range, or decimals error. The issued amount is never
/// above the resource offer or the PS parameter.
pub fn issue_auth_budget(
    resource: Option<&Budget>,
    parameter: Option<&Budget>,
    policy: &IssuerPolicy,
) -> Result<Option<Budget>, Error> {
    let Some(resource) = resource else {
        return if parameter.is_some() {
            Err(Error::Malformed)
        } else {
            Ok(None)
        };
    };
    check_declared(resource, &policy.units)?;
    let Some(parameter) = parameter else {
        return Ok(None);
    };
    check_declared(parameter, &policy.units)?;
    crate::value::validate_narrowing(resource, parameter)?;
    Ok(Some(narrow_to(parameter, policy.cap)?))
}

/// PS delivery check of the auth token the access server returned.
///
/// # Errors
/// Returns [`Error::Malformed`] when a sent parameter is missing or an omitted
/// parameter comes back as a claim, and [`Error::Denomination`] or
/// [`Error::Exceeds`] when the claim is broader than the parameter.
pub fn verify_delivered(sent: Option<&Budget>, issued: Option<&Budget>) -> Result<(), Error> {
    match (sent, issued) {
        (None, None) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(Error::Malformed),
        (Some(sent), Some(issued)) => crate::value::validate_narrowing(sent, issued),
    }
}

/// One allocation the issuer sized and has not necessarily seen a figure for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allocation {
    amount: i64,
    exp: i64,
    consumed: Option<i64>,
    revocation: Option<RevocationSettlement>,
    /// Subject and resource this allocation counts against. Absent on a book
    /// that only tracks a single ceiling.
    owner: Option<String>,
}

/// What the issuer learned from revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationSettlement {
    /// The resource recorded revocation at this Unix second.
    Recorded(i64),
    /// The resource will honor the token until `exp`.
    Unsupported,
    /// The issuer cannot tell whether spending has stopped.
    Unavailable,
}

/// Ledger of allocations. An allocation with no figure counts as fully consumed.
#[derive(Clone, Debug, Default)]
pub struct AllocationBook {
    items: BTreeMap<String, Allocation>,
}

impl AllocationBook {
    /// Empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember a new allocation as unreported.
    ///
    /// A repeated `jti` keeps the first amount and expiry.
    pub fn insert(&mut self, jti: impl Into<String>, amount: i64, exp: i64) {
        self.items.entry(jti.into()).or_insert(Allocation {
            amount,
            exp,
            consumed: None,
            revocation: None,
            owner: None,
        });
    }

    /// Remember a new allocation against one subject at one resource.
    ///
    /// A repeated `jti` keeps the first amount, expiry, and owner.
    pub fn insert_owned(
        &mut self,
        jti: impl Into<String>,
        amount: i64,
        exp: i64,
        owner: impl Into<String>,
    ) {
        self.items.entry(jti.into()).or_insert(Allocation {
            amount,
            exp,
            consumed: None,
            revocation: None,
            owner: Some(owner.into()),
        });
    }

    /// Replace the assumption for `jti` with the resource's figure.
    ///
    /// Applying the same record again does not add. An unknown `jti` is stored
    /// so a late record still replaces a missing assumption.
    ///
    /// # Errors
    /// Returns [`Error::Range`] when `consumed` is outside the carrier. The
    /// record's own constructor already enforces that.
    pub fn apply_record(&mut self, record: &ConsumptionRecord) -> Result<(), Error> {
        let entry = self
            .items
            .entry(record.jti().to_owned())
            .or_insert(Allocation {
                amount: record.consumed(),
                exp: 0,
                consumed: None,
                revocation: None,
                owner: None,
            });
        entry.consumed = Some(record.consumed());
        Ok(())
    }

    /// Record how revocation settled, or failed to settle, one allocation.
    pub fn note_revocation(&mut self, jti: &str, settlement: RevocationSettlement) {
        if let Some(allocation) = self.items.get_mut(jti) {
            allocation.revocation = Some(settlement);
        }
    }

    /// Sum used for the next ceiling: reported `consumed`, otherwise the full amount.
    pub fn accounted(&self) -> i64 {
        self.items
            .values()
            .map(|allocation| allocation.consumed.unwrap_or(allocation.amount))
            .sum()
    }

    /// `ceiling - metered - sum of amounts of allocations not yet settled`.
    ///
    /// An allocation is settled when its `exp` is at or before `as_of`, or when
    /// revocation was recorded at or before `as_of`. `revocation_unsupported`
    /// and `revocation_unavailable` stay reserved until `exp`.
    pub fn free(&self, ceiling: i64, metered: i64, as_of: i64) -> i64 {
        let reserved: i64 = self
            .items
            .values()
            .filter(|allocation| !settled(allocation, as_of))
            .map(|allocation| allocation.amount)
            .sum();
        ceiling - metered - reserved
    }

    /// [`Self::free`] counted only for allocations recorded with `owner`.
    pub fn free_owned(&self, ceiling: i64, metered: i64, as_of: i64, owner: &str) -> i64 {
        let reserved: i64 = self
            .items
            .values()
            .filter(|allocation| {
                allocation.owner.as_deref() == Some(owner) && !settled(allocation, as_of)
            })
            .map(|allocation| allocation.amount)
            .sum();
        ceiling - metered - reserved
    }
}

fn settled(allocation: &Allocation, as_of: i64) -> bool {
    match allocation.revocation {
        Some(RevocationSettlement::Recorded(at)) => as_of >= at,
        Some(RevocationSettlement::Unsupported | RevocationSettlement::Unavailable) | None => {
            allocation.exp <= as_of
        }
    }
}
