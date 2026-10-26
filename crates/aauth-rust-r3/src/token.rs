//! R3 claims in Resource and Auth tokens.
//!
//! Ported from Go `r3/token.go`. Core verifies trust, signature, and time and
//! keeps members it does not know in `extra`; it confers no R3 authority. These
//! wrappers re-prove the referenced artifact before minting, refuse to sign
//! operation claims that Core's `Value` claim map would change, read every R3
//! member from the verified payload bytes, and remove those members before a
//! caller sees the claims. Budgets members are refused here; the combined
//! profile is in [`crate::mint_budget_auth_token`] and its siblings. Binding a
//! verified token to one request, its proof key, and retained context remains
//! the role's duty.

use std::collections::BTreeMap;
use std::fmt;

use aauth_rust_core::{
    AgentKeyResolver, AuthClaims, AuthToken, ResourceClaims, ResourceToken, TokenError,
};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::Value;

use crate::digest::digest;
use crate::document::{Document, validate_document_account};
use crate::error::Error;
use crate::grant::{Authorization, Grant};
use crate::jsonvalue::{expect_json_string, parse_raw_object};
use crate::proposal::validate_proposal_account;
use crate::reference::Reference;
use crate::vocabulary::{GrantedOperations, Operation, Registry};

pub(crate) const R3_URI: &str = "r3_uri";
pub(crate) const R3_S256: &str = "r3_s256";
pub(crate) const R3_GRANTED: &str = "r3_granted";
pub(crate) const R3_PER_CALL: &str = "r3_per_call";
pub(crate) const BUDGET: &str = "budget";
pub(crate) const BUDGET_CONSUMED: &str = "budget_consumed";
const R3_CONDITIONAL: &str = "r3_conditional";
pub(crate) const RESOURCE_TOKEN: &str = "aa-resource+jwt";
pub(crate) const AUTH_TOKEN: &str = "aa-auth+jwt";

/// An R3 token wrapper refused a token or its inputs.
#[derive(Debug)]
pub enum R3TokenError {
    /// Core syntax, trust, signature, or time failure. Map it with [`TokenError::code`].
    Core(TokenError),
    /// A member this API will not interpret: a case variant or caller-supplied
    /// collision with a typed claim, or a companion claim outside this profile.
    UnsupportedClaim {
        /// `aa-resource+jwt` or `aa-auth+jwt`.
        token_type: &'static str,
        /// The member name exactly as supplied.
        claim: String,
        /// Why it is refused.
        reason: String,
    },
    /// An R3 claim, artifact, account, or operation check failed.
    R3(Error),
    /// A Budgets claim in the combined profile failed.
    Budget(aauth_rust_budgets::Error),
}

impl fmt::Display for R3TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(err) => write!(formatter, "r3: {err}"),
            Self::UnsupportedClaim {
                token_type,
                claim,
                reason,
            } => write!(
                formatter,
                "r3: {token_type} contains unsupported {claim} claim: {reason}"
            ),
            Self::R3(err) => write!(formatter, "{err}"),
            Self::Budget(err) => write!(formatter, "r3: {err}"),
        }
    }
}

impl std::error::Error for R3TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(err) => Some(err),
            Self::UnsupportedClaim { .. } => None,
            Self::R3(err) => Some(err),
            Self::Budget(err) => Some(err),
        }
    }
}

impl From<TokenError> for R3TokenError {
    fn from(err: TokenError) -> Self {
        Self::Core(err)
    }
}

impl From<Error> for R3TokenError {
    fn from(err: Error) -> Self {
        Self::R3(err)
    }
}

impl From<aauth_rust_budgets::Error> for R3TokenError {
    fn from(err: aauth_rust_budgets::Error) -> Self {
        Self::Budget(err)
    }
}

/// A Resource token whose Core trust and complete R3 reference were verified.
///
/// `claims().extra` no longer holds `r3_uri` or `r3_s256`. The artifact has not
/// been fetched: call [`Registry::parse_referenced_document`] or
/// [`Registry::parse_referenced_proposal`] after an entitled fetch, then check
/// the account before policy.
#[derive(Clone)]
pub struct VerifiedR3ResourceToken {
    claims: ResourceClaims,
    reference: Reference,
    compact: String,
}

impl VerifiedR3ResourceToken {
    pub(crate) fn new(claims: ResourceClaims, reference: Reference, compact: String) -> Self {
        Self {
            claims,
            reference,
            compact,
        }
    }

    /// Core claims with the R3 members removed.
    pub fn claims(&self) -> &ResourceClaims {
        &self.claims
    }

    /// The signed `r3_uri` and `r3_s256`.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// Exact verified compact bytes, for forwarding without reserialization.
    pub fn compact(&self) -> &str {
        &self.compact
    }
}

impl fmt::Debug for VerifiedR3ResourceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedR3ResourceToken")
            .field("issuer", &self.claims.iss)
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

/// How an R3 Auth token treats one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationAccess {
    /// In neither claim: reject the call.
    Denied,
    /// In `r3_granted`: serve the call.
    Granted,
    /// In `r3_per_call`: challenge with a per-call proposal.
    PerCall,
}

/// The disjoint `r3_granted` and `r3_per_call` sets of one verified Auth token.
#[derive(Clone)]
pub struct AuthTokenOperations {
    granted: GrantedOperations,
    per_call: GrantedOperations,
    per_call_present: bool,
}

impl AuthTokenOperations {
    pub(crate) fn new(
        granted: GrantedOperations,
        per_call: GrantedOperations,
        per_call_present: bool,
    ) -> Self {
        Self {
            granted,
            per_call,
            per_call_present,
        }
    }

    /// Copy of `r3_granted`, which may be empty.
    pub fn granted_operations(&self) -> GrantedOperations {
        self.granted.clone()
    }

    /// Copy of `r3_per_call`. Empty when the claim was absent.
    pub fn per_call_operations(&self) -> GrantedOperations {
        self.per_call.clone()
    }

    /// Whether the token carried an `r3_per_call` member, even an empty one.
    pub fn per_call_claim_present(&self) -> bool {
        self.per_call_present
    }

    /// Classify one call's operation for resource enforcement.
    ///
    /// # Errors
    /// Returns [`Error`] when the operation uses another registration, or when
    /// it is covered by both sets.
    pub fn access_for(&self, operation: &Operation) -> Result<OperationAccess, Error> {
        let granted = self.granted.contains(operation)?;
        let per_call = self.per_call.contains(operation)?;
        match (granted, per_call) {
            (true, true) => Err(Error::new(
                "r3: operation appears in both direct and per-call authorization",
            )),
            (true, false) => Ok(OperationAccess::Granted),
            (false, true) => Ok(OperationAccess::PerCall),
            (false, false) => Ok(OperationAccess::Denied),
        }
    }
}

/// An Auth token whose Core trust, R3 reference, and operation claims were verified.
///
/// `claims().extra` no longer holds the R3 members it consumed. Request,
/// proof-key, audience, and retained-context binding remain the caller's duty.
#[derive(Clone)]
pub struct VerifiedR3AuthToken {
    claims: AuthClaims,
    reference: Reference,
    operations: AuthTokenOperations,
    compact: String,
}

impl VerifiedR3AuthToken {
    pub(crate) fn new(
        claims: AuthClaims,
        reference: Reference,
        operations: AuthTokenOperations,
        compact: String,
    ) -> Self {
        Self {
            claims,
            reference,
            operations,
            compact,
        }
    }

    /// Core claims with the consumed R3 (and, for the Budget profile, Budgets) members removed.
    pub fn claims(&self) -> &AuthClaims {
        &self.claims
    }

    /// The signed `r3_uri` and `r3_s256`.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// The verified operation claims.
    pub fn operations(&self) -> &AuthTokenOperations {
        &self.operations
    }

    /// Exact verified compact bytes, for forwarding without reserialization.
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// Person Server delivery check for a class token: the reference is the one
    /// the Person Server sent, the account matches the document, and both sets
    /// are disjoint subsets of the exact document bytes.
    ///
    /// # Errors
    /// Returns [`R3TokenError`] when any of those fail.
    pub fn prove_against_document(
        &self,
        registry: &Registry,
        expected_reference: &Reference,
        exact_document: &[u8],
    ) -> Result<Authorization, R3TokenError> {
        if &self.reference != expected_reference {
            return Err(r3_error("r3: auth token changed the R3 document reference"));
        }
        let document = registry
            .parse_referenced_document(expected_reference, exact_document)
            .map_err(|err| wrap("r3: auth-token document", err))?;
        validate_document_account(&document, self.claims.account.as_deref())
            .map_err(|err| wrap("r3: auth-token account", err))?;
        Authorization::new(
            &self.operations.granted,
            &self.operations.per_call,
            &document,
        )
        .map_err(|err| wrap("r3: auth-token authorization", err))
    }
}

impl fmt::Debug for VerifiedR3AuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedR3AuthToken")
            .field("issuer", &self.claims.iss)
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

/// Mint an R3 Resource token for one exact class document.
///
/// The document must parse through `registry`, its `account` must match
/// `claims.account` in presence and value, and `r3_s256` is the digest of
/// `exact_document`. `scope` stays optional. `claims.extra` must not carry any
/// R3 or Budgets member, in any letter case.
///
/// # Errors
/// Returns [`R3TokenError`] for an invalid document, account, URI, or member,
/// or a Core claim or signing failure.
pub fn mint_resource_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &ResourceClaims,
    document_uri: &str,
    exact_document: &[u8],
) -> Result<(String, Reference), R3TokenError> {
    let document = registry
        .parse_document(exact_document)
        .map_err(|err| wrap("r3: resource-token document", err))?;
    validate_document_account(&document, claims.account.as_deref())
        .map_err(|err| wrap("r3: resource-token account", err))?;
    let reference = Reference::new(document_uri, digest(exact_document))
        .map_err(|err| wrap("r3: resource-token reference", err))?;
    mint_referenced_resource_token(key, kid, claims, reference)
}

/// Mint the Resource token that carries a per-call proposal reference.
///
/// The token never carries the proposal's parameters.
///
/// # Errors
/// Returns [`R3TokenError`] for an invalid proposal, account, URI, or member,
/// or a Core claim or signing failure.
pub fn mint_proposal_resource_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &ResourceClaims,
    proposal_uri: &str,
    exact_proposal: &[u8],
) -> Result<(String, Reference), R3TokenError> {
    let proposal = registry
        .parse_proposal(exact_proposal)
        .map_err(|err| wrap("r3: proposal resource-token proposal", err))?;
    validate_proposal_account(&proposal, claims.account.as_deref())
        .map_err(|err| wrap("r3: proposal resource-token account", err))?;
    let reference = Reference::new(proposal_uri, digest(exact_proposal))
        .map_err(|err| wrap("r3: proposal resource-token reference", err))?;
    mint_referenced_resource_token(key, kid, claims, reference)
}

fn mint_referenced_resource_token(
    key: &SigningKey,
    kid: &str,
    claims: &ResourceClaims,
    reference: Reference,
) -> Result<(String, Reference), R3TokenError> {
    let mut prepared = claims.clone();
    reject_collisions(RESOURCE_TOKEN, &prepared.extra, &[R3_URI, R3_S256])?;
    reject_unsupported_resource_members(RESOURCE_TOKEN, &prepared.extra)?;
    insert_reference(&mut prepared.extra, &reference);
    let compact = aauth_rust_core::mint_resource_token(key, kid, &prepared)?;
    Ok((compact, reference))
}

/// Verify Core trust and one complete R3 reference in a Resource token.
///
/// This validates reference syntax only. It does not fetch or hash the artifact.
///
/// # Errors
/// Returns [`R3TokenError`] for a Core failure, a missing or malformed
/// reference, a case variant, or an `r3_granted`, `r3_per_call`, or Budgets member.
pub fn verify_resource_token(
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<VerifiedR3ResourceToken, R3TokenError> {
    let verified = ResourceToken::parse(compact)?.verify(keys, now)?;
    let mut claims = verified.claims().clone();
    require_members(RESOURCE_TOKEN, &claims.extra, &[R3_URI, R3_S256])?;
    reject_case_variants(RESOURCE_TOKEN, &claims.extra, &[R3_URI, R3_S256])?;
    reject_unsupported_resource_members(RESOURCE_TOKEN, &claims.extra)?;
    let members = payload_members(verified.compact())?;
    let reference = reference_from_members(&members)?;
    remove_members(&mut claims.extra, &[R3_URI, R3_S256]);
    Ok(VerifiedR3ResourceToken {
        claims,
        reference,
        compact: verified.compact().to_owned(),
    })
}

/// Mint a direct-only Auth token after re-proving `grant` against the exact
/// document bytes `reference` names. It carries no `r3_per_call`.
///
/// # Errors
/// Returns [`R3TokenError`] for a reference or digest mismatch, an account
/// mismatch, an unproven or broader grant, operations Core cannot sign
/// exactly, a colliding member, or a Core failure.
pub fn mint_direct_auth_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &AuthClaims,
    reference: &Reference,
    exact_document: &[u8],
    grant: &Grant,
) -> Result<String, R3TokenError> {
    let document = referenced_document(registry, reference, exact_document, claims, "direct")?;
    let grant_json = serde_json::to_vec(grant)
        .map_err(|err| r3_error(format!("r3: direct auth-token grant: {err}")))?;
    registry
        .parse_grant(&grant_json, &document)
        .map_err(|err| {
            wrap(
                "r3: direct auth-token grant does not match referenced document",
                err,
            )
        })?;
    let empty = empty_operations(registry, &document)?;
    let authorization = Authorization::new(&grant.granted_operations(), &empty, &document)?;
    mint_auth_token(
        registry,
        key,
        kid,
        claims,
        reference,
        exact_document,
        &authorization,
    )
}

/// Mint a class Auth token after re-proving disjoint direct and per-call sets
/// against the exact document. `r3_per_call` is emitted only when non-empty.
///
/// # Errors
/// Returns [`R3TokenError`] for a reference or digest mismatch, an account
/// mismatch, an unproven or invalid authorization, operations Core cannot sign
/// exactly, a colliding member, or a Core failure.
pub fn mint_auth_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &AuthClaims,
    reference: &Reference,
    exact_document: &[u8],
    authorization: &Authorization,
) -> Result<String, R3TokenError> {
    let document = referenced_document(registry, reference, exact_document, claims, "class")?;
    if !authorization.is_proven() {
        return Err(r3_error("r3: class auth-token authorization is unproven"));
    }
    let proven = Authorization::new(
        &authorization.granted_operations(),
        &authorization.per_call_operations(),
        &document,
    )
    .map_err(|err| wrap("r3: class auth-token authorization", err))?;
    let granted = signed_operations_value(registry, &proven.granted_operations())?;
    let per_call_operations = proven.per_call_operations();
    let per_call = if per_call_operations.operations()?.is_empty() {
        None
    } else {
        Some(signed_operations_value(registry, &per_call_operations)?)
    };
    let mut prepared = claims.clone();
    prepare_auth_members(&mut prepared.extra, reference, granted, per_call)?;
    Ok(aauth_rust_core::mint_auth_token(key, kid, &prepared)?)
}

/// Mint the one-operation Auth token for an approved exact proposal.
///
/// It echoes the proposal reference, grants exactly the proposal's operation,
/// and never carries `r3_per_call`. Capping `exp` at the presented auth token's
/// `exp` is the issuer role's duty.
///
/// # Errors
/// Returns [`R3TokenError`] for a reference or digest mismatch, an account
/// mismatch, an operation Core cannot sign exactly, a colliding member, or a
/// Core failure.
pub fn mint_per_call_auth_token(
    registry: &Registry,
    key: &SigningKey,
    kid: &str,
    claims: &AuthClaims,
    reference: &Reference,
    exact_proposal: &[u8],
) -> Result<String, R3TokenError> {
    let proposal = registry
        .parse_referenced_proposal(reference, exact_proposal)
        .map_err(|err| wrap("r3: per-call auth-token proposal", err))?;
    validate_proposal_account(&proposal, claims.account.as_deref())
        .map_err(|err| wrap("r3: per-call auth-token account", err))?;
    let operation = proposal.operation();
    let vocabulary = registry
        .vocabulary(operation.vocabulary())
        .ok_or_else(|| r3_error("r3: per-call auth-token vocabulary is not registered"))?;
    let granted = GrantedOperations::new(&vocabulary, std::slice::from_ref(&operation))?;
    let granted = signed_operations_value(registry, &granted)?;
    let mut prepared = claims.clone();
    prepare_auth_members(&mut prepared.extra, reference, granted, None)?;
    Ok(aauth_rust_core::mint_auth_token(key, kid, &prepared)?)
}

/// Verify a direct-only Auth token: Core trust, one complete reference, and
/// `r3_granted`, with no `r3_per_call` and no Budgets member.
///
/// # Errors
/// Returns [`R3TokenError`] for a Core failure, a missing or malformed claim,
/// a case variant, an `r3_per_call` member, or a Budgets member.
pub fn verify_direct_auth_token(
    registry: &Registry,
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<VerifiedR3AuthToken, R3TokenError> {
    let token = verify_auth_token_claims(registry, compact, keys, now)?;
    if token.operations.per_call_present || !token.operations.per_call.operations()?.is_empty() {
        return Err(r3_error(
            "r3: direct auth token must not contain r3_per_call",
        ));
    }
    Ok(token)
}

/// Verify the signed R3 claim shape of an Auth token without classifying the
/// referenced artifact. A Resource must know whether the reference names its
/// class document or a proposal before choosing direct or single-use enforcement.
///
/// # Errors
/// Returns [`R3TokenError`] for a Core failure, a missing or malformed claim,
/// a case variant, overlapping or cross-vocabulary sets, or a Budgets member.
pub fn verify_auth_token_claims(
    registry: &Registry,
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<VerifiedR3AuthToken, R3TokenError> {
    let verified = AuthToken::parse(compact)?.verify(keys, now)?;
    let mut claims = verified.claims().clone();
    require_members(AUTH_TOKEN, &claims.extra, &[R3_URI, R3_S256, R3_GRANTED])?;
    reject_case_variants(
        AUTH_TOKEN,
        &claims.extra,
        &[R3_URI, R3_S256, R3_GRANTED, R3_PER_CALL],
    )?;
    reject_budget_members(AUTH_TOKEN, &claims.extra)?;
    reject_removed_members(AUTH_TOKEN, &claims.extra)?;
    let members = payload_members(verified.compact())?;
    let reference = reference_from_members(&members)?;
    let granted = claim_operations(registry, &members, R3_GRANTED)?;
    let per_call_present = members.contains_key(R3_PER_CALL);
    let per_call = if per_call_present {
        claim_operations(registry, &members, R3_PER_CALL)?
    } else {
        empty_like(registry, &granted)?
    };
    if !granted.is_disjoint(&per_call)? {
        return Err(r3_error("r3: r3_granted and r3_per_call overlap"));
    }
    remove_members(
        &mut claims.extra,
        &[R3_URI, R3_S256, R3_GRANTED, R3_PER_CALL],
    );
    Ok(VerifiedR3AuthToken {
        claims,
        reference,
        operations: AuthTokenOperations {
            granted,
            per_call,
            per_call_present,
        },
        compact: verified.compact().to_owned(),
    })
}

/// Verify a per-call Auth token against the exact proposal it approves.
///
/// The token must echo `expected_reference`, carry no `r3_per_call`, match the
/// proposal's account, and grant exactly the proposal's one operation.
///
/// # Errors
/// Returns [`R3TokenError`] when the proposal bytes do not match the reference
/// or any of those checks fail.
pub fn verify_per_call_auth_token(
    registry: &Registry,
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
    expected_reference: &Reference,
    exact_proposal: &[u8],
) -> Result<(VerifiedR3AuthToken, Operation), R3TokenError> {
    let proposal = registry
        .parse_referenced_proposal(expected_reference, exact_proposal)
        .map_err(|err| wrap("r3: verify per-call proposal", err))?;
    let token = verify_auth_token_claims(registry, compact, keys, now)?;
    if token.operations.per_call_present || !token.operations.per_call.operations()?.is_empty() {
        return Err(r3_error(
            "r3: per-call auth token must not contain r3_per_call",
        ));
    }
    if &token.reference != expected_reference {
        return Err(r3_error(
            "r3: per-call auth token changed the proposal reference",
        ));
    }
    validate_proposal_account(&proposal, token.claims.account.as_deref())
        .map_err(|err| wrap("r3: per-call auth-token account", err))?;
    let mut operations = token.operations.granted.operations()?;
    if operations.len() != 1 {
        return Err(r3_error(
            "r3: per-call auth token must grant exactly one operation",
        ));
    }
    let operation = operations.remove(0);
    if !operation.equal(&proposal.operation())? {
        return Err(r3_error(
            "r3: per-call auth token granted an operation other than the proposal",
        ));
    }
    Ok((token, operation))
}

pub(crate) fn referenced_document(
    registry: &Registry,
    reference: &Reference,
    exact_document: &[u8],
    claims: &AuthClaims,
    label: &str,
) -> Result<Document, R3TokenError> {
    let document = registry
        .parse_referenced_document(reference, exact_document)
        .map_err(|err| wrap(&format!("r3: {label} auth-token document"), err))?;
    validate_document_account(&document, claims.account.as_deref())
        .map_err(|err| wrap(&format!("r3: {label} auth-token account"), err))?;
    Ok(document)
}

fn prepare_auth_members(
    extra: &mut BTreeMap<String, Value>,
    reference: &Reference,
    granted: Value,
    per_call: Option<Value>,
) -> Result<(), R3TokenError> {
    reject_collisions(
        AUTH_TOKEN,
        extra,
        &[R3_URI, R3_S256, R3_GRANTED, R3_PER_CALL],
    )?;
    reject_budget_members(AUTH_TOKEN, extra)?;
    reject_removed_members(AUTH_TOKEN, extra)?;
    insert_reference(extra, reference);
    extra.insert(R3_GRANTED.to_owned(), granted);
    if let Some(per_call) = per_call {
        extra.insert(R3_PER_CALL.to_owned(), per_call);
    }
    Ok(())
}

pub(crate) fn reject_unsupported_resource_members(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
) -> Result<(), R3TokenError> {
    reject_folded(
        token_type,
        extra,
        "the claim belongs only in an Auth token",
        &[R3_GRANTED],
    )?;
    reject_folded(
        token_type,
        extra,
        "R3 defines no per-call claim in a Resource token",
        &[R3_PER_CALL],
    )?;
    reject_budget_members(token_type, extra)?;
    reject_removed_members(token_type, extra)
}

fn reject_budget_members(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
) -> Result<(), R3TokenError> {
    reject_folded(
        token_type,
        extra,
        "this R3 API does not validate the Budgets companion; use the Budget profile",
        &[BUDGET, BUDGET_CONSUMED],
    )
}

pub(crate) fn reject_removed_members(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
) -> Result<(), R3TokenError> {
    reject_folded(
        token_type,
        extra,
        "the claim was removed from the current specification",
        &[R3_CONDITIONAL],
    )
}

/// Go `strings.EqualFold` for the ASCII names R3 recognizes: ASCII case plus
/// the two non-ASCII letters that simple-fold onto ASCII letters.
fn folds_to(member: &str, name: &str) -> bool {
    fn fold(c: char) -> char {
        match c {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            c => c.to_ascii_lowercase(),
        }
    }
    member.chars().map(fold).eq(name.chars().map(fold))
}

fn unsupported(token_type: &'static str, claim: &str, reason: impl Into<String>) -> R3TokenError {
    R3TokenError::UnsupportedClaim {
        token_type,
        claim: claim.to_owned(),
        reason: reason.into(),
    }
}

pub(crate) fn reject_collisions(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
    names: &[&str],
) -> Result<(), R3TokenError> {
    for member in extra.keys() {
        if let Some(name) = names.iter().find(|name| folds_to(member, name)) {
            return Err(unsupported(
                token_type,
                member,
                format!("caller-supplied claim conflicts with typed {name}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn reject_folded(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
    reason: &str,
    names: &[&str],
) -> Result<(), R3TokenError> {
    match extra
        .keys()
        .find(|member| names.iter().any(|name| folds_to(member, name)))
    {
        Some(member) => Err(unsupported(token_type, member, reason)),
        None => Ok(()),
    }
}

pub(crate) fn reject_case_variants(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
    names: &[&str],
) -> Result<(), R3TokenError> {
    for member in extra.keys() {
        if let Some(name) = names
            .iter()
            .find(|name| member != *name && folds_to(member, name))
        {
            return Err(unsupported(
                token_type,
                member,
                format!("claim name is a noncanonical case variant of {name}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_members(
    token_type: &'static str,
    extra: &BTreeMap<String, Value>,
    names: &[&str],
) -> Result<(), R3TokenError> {
    match names.iter().find(|name| !extra.contains_key(**name)) {
        Some(name) => Err(r3_error(format!("r3: {token_type} requires {name}"))),
        None => Ok(()),
    }
}

pub(crate) fn remove_members(extra: &mut BTreeMap<String, Value>, names: &[&str]) {
    for name in names {
        extra.remove(*name);
    }
}

pub(crate) fn insert_reference(extra: &mut BTreeMap<String, Value>, reference: &Reference) {
    extra.insert(R3_URI.to_owned(), Value::String(reference.uri().to_owned()));
    extra.insert(
        R3_S256.to_owned(),
        Value::String(reference.digest().to_owned()),
    );
}

/// Exact member bytes of an already verified payload, so R3 claims are parsed
/// from what was signed rather than from Core's `Value` copy.
pub(crate) fn payload_members(compact: &str) -> Result<BTreeMap<String, Vec<u8>>, R3TokenError> {
    let jws = Jws::parse(compact).map_err(TokenError::from)?;
    let members = parse_raw_object(jws.payload()).map_err(|err| wrap("r3: token payload", err))?;
    Ok(members
        .into_iter()
        .map(|member| (member.name, member.raw))
        .collect())
}

pub(crate) fn reference_from_members(
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<Reference, R3TokenError> {
    let uri = string_member(members, R3_URI)?;
    let digest = string_member(members, R3_S256)?;
    Ok(Reference::new(uri, digest)?)
}

fn string_member(members: &BTreeMap<String, Vec<u8>>, name: &str) -> Result<String, R3TokenError> {
    let raw = members
        .get(name)
        .ok_or_else(|| r3_error(format!("r3: missing {name}")))?;
    expect_json_string(raw).map_err(|err| wrap(&format!("r3: invalid {name}"), err))
}

pub(crate) fn claim_operations(
    registry: &Registry,
    members: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<GrantedOperations, R3TokenError> {
    let raw = members
        .get(name)
        .ok_or_else(|| r3_error(format!("r3: missing {name}")))?;
    registry
        .parse_granted_operations(raw)
        .map_err(|err| wrap(&format!("r3: invalid {name}"), err))
}

pub(crate) fn empty_like(
    registry: &Registry,
    granted: &GrantedOperations,
) -> Result<GrantedOperations, R3TokenError> {
    let vocabulary = registry
        .vocabulary(granted.vocabulary())
        .ok_or_else(|| r3_error("r3: granted vocabulary is not registered"))?;
    Ok(GrantedOperations::new(&vocabulary, &[])?)
}

fn empty_operations(
    registry: &Registry,
    document: &Document,
) -> Result<GrantedOperations, R3TokenError> {
    let set = document.operation_set();
    let vocabulary = registry
        .vocabulary(set.vocabulary())
        .ok_or_else(|| r3_error("r3: document vocabulary is not registered"))?;
    Ok(GrantedOperations::new(&vocabulary, &[])?)
}

pub(crate) const UNREPRESENTABLE_OPERATIONS: &str = "r3: operation claim cannot be signed exactly through Core's JSON claim map; refusing to sign changed operations";

/// Claim value for Core's `extra`, only when it signs the proven operations.
///
/// Core mints from `serde_json::Value`, which keeps strings and 64-bit
/// integers but rounds other numbers. The bytes Core will sign are re-parsed
/// through `registry`; unless they yield the same vocabulary and the same
/// canonical operations in the same order, this refuses before signing.
/// Carrying every codec exactly needs a Core mint that accepts raw member bytes.
pub(crate) fn signed_operations_value(
    registry: &Registry,
    operations: &GrantedOperations,
) -> Result<Value, R3TokenError> {
    let encoded = serde_json::to_vec(operations)
        .map_err(|err| r3_error(format!("r3: encode operation claim: {err}")))?;
    let value: Value = serde_json::from_slice(&encoded)
        .map_err(|err| r3_error(format!("r3: encode operation claim: {err}")))?;
    let signed = serde_json::to_vec(&value)
        .map_err(|err| r3_error(format!("r3: encode operation claim: {err}")))?;
    let reparsed = registry
        .parse_granted_operations(&signed)
        .map_err(|err| wrap(UNREPRESENTABLE_OPERATIONS, err))?;
    if reparsed.vocabulary() != operations.vocabulary()
        || canonical_operations(&reparsed)? != canonical_operations(operations)?
    {
        return Err(r3_error(UNREPRESENTABLE_OPERATIONS));
    }
    Ok(value)
}

fn canonical_operations(operations: &GrantedOperations) -> Result<Vec<Vec<u8>>, R3TokenError> {
    let mut canonical = Vec::new();
    for operation in operations.operations()? {
        canonical.push(operation.json()?);
    }
    Ok(canonical)
}

pub(crate) fn r3_error(message: impl Into<String>) -> R3TokenError {
    R3TokenError::R3(Error::new(message))
}

pub(crate) fn wrap(context: &str, err: Error) -> R3TokenError {
    R3TokenError::R3(Error::wrap(context, err))
}
