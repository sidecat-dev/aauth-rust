//! One token carrying an R3 class reference and a Budgets companion.
//!
//! Ported from Go `r3/budget_token.go`. The plain R3 wrappers keep refusing
//! Budgets members; only these functions accept both companions together.
//! Narrowing the budget against the offer and the issuer's cap is the issuer's
//! duty through `aauth_rust_budgets`, before minting.

use aauth_rust_budgets::{
    Budget, BudgetHeader, ConsumptionRecord, Error as BudgetError, parse_resource_claims,
    read_granted, sender_field,
};
use aauth_rust_core::{AgentKeyResolver, AuthClaims, AuthToken, ResourceClaims, ResourceToken};
use aauth_rust_jose::SigningKey;
use serde_json::Value;

use crate::digest::digest;
use crate::document::validate_document_account;
use crate::grant::Grant;
use crate::reference::Reference;
use crate::token::{
    AUTH_TOKEN, AuthTokenOperations, BUDGET, BUDGET_CONSUMED, R3_GRANTED, R3_PER_CALL, R3_S256,
    R3_URI, R3TokenError, RESOURCE_TOKEN, VerifiedR3AuthToken, VerifiedR3ResourceToken,
    claim_operations, empty_like, insert_reference, payload_members, r3_error,
    reference_from_members, referenced_document, reject_case_variants, reject_collisions,
    reject_folded, reject_removed_members, remove_members, require_members,
    signed_operations_value, wrap,
};
use crate::vocabulary::Registry;

const PER_CALL_REASON: &str = "the class-R3 Budget profile does not permit r3_per_call";

/// Mint one Resource token carrying an R3 class document reference, a budget
/// offer, and an optional consumption record for the presented auth token.
///
/// # Errors
/// Returns [`R3TokenError`] for an invalid document, account, URI, or member,
/// a consumption record for another `jti`, or a Core failure.
#[allow(clippy::too_many_arguments)]
pub fn mint_budget_resource_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &ResourceClaims,
    document_uri: &str,
    exact_document: &[u8],
    offer: &Budget,
    consumed: Option<&ConsumptionRecord>,
) -> Result<(String, Reference), R3TokenError> {
    let document = registry
        .parse_document(exact_document)
        .map_err(|err| wrap("r3: Budget resource-token document", err))?;
    validate_document_account(&document, claims.account.as_deref())
        .map_err(|err| wrap("r3: Budget resource-token account", err))?;
    let reference = Reference::new(document_uri, digest(exact_document))
        .map_err(|err| wrap("r3: Budget resource-token reference", err))?;
    if consumed.is_some_and(|record| record.jti() != claims.presented_jti) {
        return Err(R3TokenError::Budget(BudgetError::Malformed));
    }
    let mut prepared = claims.clone();
    reject_collisions(
        RESOURCE_TOKEN,
        &prepared.extra,
        &[R3_URI, R3_S256, BUDGET, BUDGET_CONSUMED],
    )?;
    reject_combined_resource_members(&prepared.extra)?;
    insert_reference(&mut prepared.extra, &reference);
    prepared.extra.insert(BUDGET.to_owned(), offer.to_value());
    if let Some(record) = consumed {
        prepared
            .extra
            .insert(BUDGET_CONSUMED.to_owned(), record.to_value());
    }
    let compact = aauth_rust_core::mint_resource_token(key, kid, &prepared)?;
    Ok((compact, reference))
}

/// Verify Core trust, one complete R3 class reference, a budget offer, and an
/// optional consumption record whose `jti` is the token's `presented_jti`.
///
/// # Errors
/// Returns [`R3TokenError`] for a Core failure, a missing or malformed claim,
/// a case variant, or an `r3_granted` or `r3_per_call` member.
pub fn verify_budget_resource_token(
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<(VerifiedR3ResourceToken, Budget, Option<ConsumptionRecord>), R3TokenError> {
    let verified = ResourceToken::parse(compact)?.verify(keys, now)?;
    let mut claims = verified.claims().clone();
    require_members(RESOURCE_TOKEN, &claims.extra, &[R3_URI, R3_S256, BUDGET])?;
    reject_case_variants(
        RESOURCE_TOKEN,
        &claims.extra,
        &[R3_URI, R3_S256, BUDGET, BUDGET_CONSUMED],
    )?;
    reject_combined_resource_members(&claims.extra)?;
    let members = payload_members(verified.compact())?;
    let reference = reference_from_members(&members)?;
    let budget = parse_resource_claims(&claims.extra, &claims.presented_jti)?;
    let offer = budget
        .budget
        .ok_or(R3TokenError::Budget(BudgetError::Malformed))?;
    remove_members(
        &mut claims.extra,
        &[R3_URI, R3_S256, BUDGET, BUDGET_CONSUMED],
    );
    Ok((
        VerifiedR3ResourceToken::new(claims, reference, verified.compact().to_owned()),
        offer,
        budget.consumed,
    ))
}

/// Mint one Auth token carrying a proven R3 class grant and a fixed budget grant.
///
/// The operation grant is re-proven against the exact document, and the
/// re-proven operations are what is signed. It carries no `r3_per_call`. The
/// budget unit must be representable in `AAuth-Budget`.
///
/// # Errors
/// Returns [`R3TokenError`] for a reference or digest mismatch, an account
/// mismatch, an unproven or broader grant, operations Core cannot sign
/// exactly, an unrepresentable unit, a colliding member, or a Core failure.
#[allow(clippy::too_many_arguments)]
pub fn mint_budget_auth_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &AuthClaims,
    reference: &Reference,
    exact_document: &[u8],
    operation_grant: &Grant,
    budget_grant: &Budget,
) -> Result<String, R3TokenError> {
    let document = referenced_document(registry, reference, exact_document, claims, "Budget")?;
    let grant_json = serde_json::to_vec(operation_grant)
        .map_err(|err| r3_error(format!("r3: Budget auth-token operation grant: {err}")))?;
    let proven = registry
        .parse_grant(&grant_json, &document)
        .map_err(|err| {
            wrap(
                "r3: Budget auth-token grant does not match referenced document",
                err,
            )
        })?;
    validate_feedback_unit(budget_grant)?;
    let granted = signed_operations_value(registry, &proven.granted_operations())?;
    let mut prepared = claims.clone();
    reject_collisions(
        AUTH_TOKEN,
        &prepared.extra,
        &[
            R3_URI,
            R3_S256,
            R3_GRANTED,
            R3_PER_CALL,
            BUDGET,
            BUDGET_CONSUMED,
        ],
    )?;
    reject_removed_members(AUTH_TOKEN, &prepared.extra)?;
    insert_reference(&mut prepared.extra, reference);
    prepared.extra.insert(R3_GRANTED.to_owned(), granted);
    prepared
        .extra
        .insert(BUDGET.to_owned(), budget_grant.to_value());
    Ok(aauth_rust_core::mint_auth_token(key, kid, &prepared)?)
}

/// Verify Core trust, one R3 class grant, and one fixed budget grant.
///
/// `r3_per_call` and `budget_consumed` are refused. The returned per-call set is empty.
///
/// # Errors
/// Returns [`R3TokenError`] for a Core failure, a missing or malformed claim,
/// a case variant, a refused member, or an unrepresentable unit.
pub fn verify_budget_auth_token(
    registry: &Registry,
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<(VerifiedR3AuthToken, Budget), R3TokenError> {
    let verified = AuthToken::parse(compact)?.verify(keys, now)?;
    let mut claims = verified.claims().clone();
    require_members(
        AUTH_TOKEN,
        &claims.extra,
        &[R3_URI, R3_S256, R3_GRANTED, BUDGET],
    )?;
    reject_case_variants(
        AUTH_TOKEN,
        &claims.extra,
        &[
            R3_URI,
            R3_S256,
            R3_GRANTED,
            R3_PER_CALL,
            BUDGET,
            BUDGET_CONSUMED,
        ],
    )?;
    reject_folded(
        AUTH_TOKEN,
        &claims.extra,
        "budget_consumed belongs only in a Resource token",
        &[BUDGET_CONSUMED],
    )?;
    reject_folded(AUTH_TOKEN, &claims.extra, PER_CALL_REASON, &[R3_PER_CALL])?;
    reject_removed_members(AUTH_TOKEN, &claims.extra)?;
    let members = payload_members(verified.compact())?;
    let reference = reference_from_members(&members)?;
    let granted = claim_operations(registry, &members, R3_GRANTED)?;
    let grant = read_granted(&claims.extra)?.ok_or(R3TokenError::Budget(BudgetError::Malformed))?;
    validate_feedback_unit(&grant)?;
    let per_call = empty_like(registry, &granted)?;
    remove_members(&mut claims.extra, &[R3_URI, R3_S256, R3_GRANTED, BUDGET]);
    Ok((
        VerifiedR3AuthToken::new(
            claims,
            reference,
            AuthTokenOperations::new(granted, per_call, false),
            verified.compact().to_owned(),
        ),
        grant,
    ))
}

fn reject_combined_resource_members(
    extra: &std::collections::BTreeMap<String, Value>,
) -> Result<(), R3TokenError> {
    reject_folded(
        RESOURCE_TOKEN,
        extra,
        "the claim belongs only in an Auth token",
        &[R3_GRANTED],
    )?;
    reject_folded(RESOURCE_TOKEN, extra, PER_CALL_REASON, &[R3_PER_CALL])?;
    reject_removed_members(RESOURCE_TOKEN, extra)
}

/// Go `budgets.ValidateFeedbackUnit`: the unit must serialize in `AAuth-Budget`.
fn validate_feedback_unit(budget: &Budget) -> Result<(), R3TokenError> {
    let header = BudgetHeader::final_cost(0, 0, budget.unit(), budget.decimals())?;
    sender_field(&header, true)?;
    Ok(())
}
