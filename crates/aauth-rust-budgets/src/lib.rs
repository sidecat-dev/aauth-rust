//! AAuth Budgets profile (`draft-hardt-aauth-budgets` at `70d67375`).
//!
//! Pure protocol rules for the budget object, narrowing, response header,
//! per-token cap, person ledger, and usage counters. Role crates call these
//! types when a host opts in. This crate does not fetch metadata or open a
//! network connection.
#![deny(missing_docs)]

mod agent;
mod header;
mod issuer;
mod ledger;
mod usage;
mod value;

pub use agent::{
    assume_lost_cost, balance_after, header_is_fresh, plan_from_grant, read_granted,
    recover_omitted_cost, response_complete_without_trailer, spend_plan, withhold_budget_header,
};
pub use header::{
    BudgetHeader, ParsedHeader, Trailer, act_on_header, parse_header, parse_max_cost, sender_field,
    trailer_field,
};
pub use issuer::{
    Allocation, AllocationBook, IssuerPolicy, RevocationSettlement, issue_auth_budget,
    verify_delivered,
};
pub use ledger::{Caller, ChargeError, KeyRole, Ledger, Refusal, Reservation, TokenAccount};
pub use usage::{
    Counters, SignedUsage, USAGE_COVERAGE, UsageQuery, UsageResponse, answer_usage,
    parse_usage_query, sign_usage_response, usage_signature_covers, verify_usage_signature,
};
pub use value::{
    Budget, ConsentFigure, ConsumptionRecord, Error, MAX_AMOUNT, ResourceBudget, UnitDeclaration,
    check_declared, consent_figure, human_amount, metered_access_mode, narrow_to, offer_budget,
    parse_budget, parse_budget_bytes, parse_consumption, parse_declarations, parse_resource_claims,
    sanitize_markdown, validate_endpoint_url, validate_narrowing,
};

/// Structured-field and JSON carrier limit from the range-limits section.
pub const DIGIT_LIMIT: i64 = MAX_AMOUNT;
