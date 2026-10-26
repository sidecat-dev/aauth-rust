//! Agent-side reading of a granted budget and of `AAuth-Budget`.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::value::{Budget, Error, parse_budget};

/// The budget the agent actually received, taken from the auth token.
///
/// The agent's request is not an input. A resource may have changed the unit,
/// so the request and the grant are not assumed to be comparable.
///
/// # Errors
/// Returns [`Error::Malformed`] when the claim is present and not a budget object.
pub fn read_granted(extra: &BTreeMap<String, Value>) -> Result<Option<Budget>, Error> {
    extra.get("budget").map(parse_budget).transpose()
}

/// What the agent may plan to spend: the granted amount, never the request.
///
/// `requested` is accepted so a caller can pass the figure it asked for, and is
/// ignored. The plan is the `budget` claim the agent actually received.
pub fn spend_plan(granted: &Budget, requested: Option<&Budget>) -> i64 {
    let _ = requested;
    granted.amount()
}

/// Plan from the auth token's `budget` claim. The request is not an input to the figure.
///
/// # Errors
/// Returns [`Error::Malformed`] when the claim is present and not a budget object.
pub fn plan_from_grant(
    extra: &BTreeMap<String, Value>,
    requested: Option<&Budget>,
) -> Result<Option<i64>, Error> {
    Ok(read_granted(extra)?
        .as_ref()
        .map(|grant| spend_plan(grant, requested)))
}

/// Cost to assume for a response that never arrived.
///
/// Uses `reserved` when the agent saw one, otherwise the request's maximum cost.
pub fn assume_lost_cost(reserved: Option<i64>, maximum_cost: i64) -> i64 {
    reserved.unwrap_or(maximum_cost)
}

/// Balance after a trailer: `remaining + reserved - cost`.
pub fn balance_after(remaining: i64, reserved: i64, cost: i64) -> i64 {
    remaining + reserved - cost
}

/// Cost recovered when the previous response omitted `cost`:
/// `previous remaining + reserved - current remaining`.
pub fn recover_omitted_cost(previous_remaining: i64, reserved: i64, current_remaining: i64) -> i64 {
    previous_remaining + reserved - current_remaining
}

/// A positive HTTP cache `current_age` means the field must be ignored.
pub fn header_is_fresh(current_age: Option<u64>) -> bool {
    current_age.is_none_or(|age| age == 0)
}

/// The resource does not withhold `AAuth-Budget` when the agent omitted the capability.
pub fn withhold_budget_header(_declared_budget_capability: bool) -> bool {
    false
}

/// A recipient must not treat the trailer as necessary.
///
/// A response that never delivers a trailer is complete. `true` means the
/// recipient accepts the response.
pub fn response_complete_without_trailer(trailer: Option<&str>) -> bool {
    let _ = trailer;
    true
}
