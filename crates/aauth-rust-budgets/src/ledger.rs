//! Per-token hard cap and per-person consumption ledger.
use std::collections::BTreeMap;

use crate::header::{BudgetHeader, sender_field};
use crate::value::{Budget, Error, check_amount};

/// Identity of one auth-token grant.
#[derive(Clone, Debug)]
pub struct TokenAccount {
    /// Auth token `jti`.
    pub jti: String,
    /// Signed grant. Later metering uses this unit and scale, not live metadata.
    pub grant: Budget,
    /// Person server namespace (`ps`).
    pub ps: String,
    /// Directed subject.
    pub sub: String,
    /// Resource audience.
    pub aud: String,
    /// Token issuer. In four-party access this is the access server.
    pub iss: String,
    /// Thumbprint of the key that presents the token.
    pub jkt: String,
    /// Optional tenant.
    pub tenant: Option<String>,
    /// Optional mission digest.
    pub mission: Option<String>,
}

/// A hold against one auth token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    id: u64,
    iss: String,
    jti: String,
    amount: i64,
}

impl Reservation {
    /// Hold identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Issuer of the auth token this hold is against.
    pub fn iss(&self) -> &str {
        &self.iss
    }

    /// Auth token this hold is against.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// Reserved maximum.
    pub fn amount(&self) -> i64 {
        self.amount
    }
}

/// The request does not fit the remaining grant. Nothing was reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The grant is spent.
    Exhausted {
        /// Zero.
        remaining: i64,
        /// Header with `remaining=0` and no `cost`.
        header: String,
    },
    /// Remainder is positive and smaller than the request's maximum cost.
    Insufficient {
        /// What is left.
        remaining: i64,
        /// The maximum cost that did not fit.
        required: i64,
        /// Header with `remaining` and `required`.
        header: String,
    },
}

/// A reserve or commit could not be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChargeError {
    /// The request does not fit.
    Refused(Refusal),
    /// The token, hold, or amount is not usable.
    Protocol(Error),
}

/// Who is asking the usage endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    /// `dwk` is `aauth-person.json`.
    PersonServer,
    /// `dwk` is `aauth-access.json`.
    AccessServer,
}

/// Authenticated usage caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Signature-Key `id`.
    pub id: String,
    /// Role named by `dwk`.
    pub role: KeyRole,
    /// `ps` member, required for an access server that sent a scope key.
    pub ps: Option<String>,
}

#[derive(Clone, Debug)]
struct State {
    account: TokenAccount,
    committed: i64,
    reserved: i64,
}

#[derive(Clone, Debug)]
struct Charge {
    ps: String,
    sub: String,
    aud: String,
    iss: String,
    unit: String,
    tenant: Option<String>,
    mission: Option<String>,
    at: i64,
    amount: i64,
}

#[derive(Clone, Debug)]
struct KeyFigure {
    iss: String,
    ps: String,
    amount: i64,
    last: i64,
}

#[derive(Clone, Debug)]
struct Hold {
    iss: String,
    jti: String,
    amount: i64,
}

/// Process-memory meter. Callers that share it across threads wrap it in a mutex.
/// Each mutating method updates the token and the person ledger before it returns.
/// Token state is keyed by `(iss, jti)`, so two issuers that mint the same `jti`
/// do not share a grant or a person's counters.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    tokens: BTreeMap<(String, String), State>,
    holds: BTreeMap<u64, Hold>,
    next_hold: u64,
    charges: Vec<Charge>,
    keys: BTreeMap<String, Vec<KeyFigure>>,
    last_commit: Option<i64>,
    replays: BTreeMap<(String, String, String), i64>,
}

fn token_key(iss: &str, jti: &str) -> (String, String) {
    (iss.to_owned(), jti.to_owned())
}

impl Ledger {
    /// Empty meter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a grant. A second registration of the same `(iss, jti)` must carry the same grant.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when the same issuer and `jti` are registered with a different grant.
    pub fn open(&mut self, account: TokenAccount) -> Result<(), Error> {
        let key = token_key(&account.iss, &account.jti);
        if let Some(existing) = self.tokens.get(&key) {
            if existing.account.grant != account.grant
                || existing.account.ps != account.ps
                || existing.account.sub != account.sub
                || existing.account.aud != account.aud
            {
                return Err(Error::Malformed);
            }
            return Ok(());
        }
        let jkt = account.jkt.clone();
        let iss = account.iss.clone();
        let ps = account.ps.clone();
        let figures = self.keys.entry(jkt).or_default();
        if !figures
            .iter()
            .any(|figure| figure.iss == iss && figure.ps == ps)
        {
            figures.push(KeyFigure {
                iss,
                ps,
                amount: 0,
                last: 0,
            });
        }
        self.tokens.insert(
            key,
            State {
                account,
                committed: 0,
                reserved: 0,
            },
        );
        self.assert_caps();
        Ok(())
    }

    /// Atomically reserve `maximum` against the token identified by `(iss, jti)`.
    /// A refusal changes nothing. A zero maximum does not admit a spent grant.
    ///
    /// # Errors
    /// Returns [`ChargeError::Refused`] when the maximum does not fit, or
    /// [`ChargeError::Protocol`] when the token was not opened.
    pub fn reserve(
        &mut self,
        iss: &str,
        jti: &str,
        maximum: i64,
    ) -> Result<Reservation, ChargeError> {
        check_amount(maximum).map_err(ChargeError::Protocol)?;
        let key = token_key(iss, jti);
        let state = self
            .tokens
            .get(&key)
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let remaining = state.account.grant.amount() - state.committed - state.reserved;
        if remaining == 0 || maximum > remaining {
            let header = refusal_header(&state.account.grant, remaining, maximum)?;
            return Err(ChargeError::Refused(if remaining == 0 {
                Refusal::Exhausted { remaining, header }
            } else {
                Refusal::Insufficient {
                    remaining,
                    required: maximum,
                    header,
                }
            }));
        }
        let state = self.tokens.get_mut(&key).expect("token present");
        state.reserved += maximum;
        self.next_hold += 1;
        let id = self.next_hold;
        self.holds.insert(
            id,
            Hold {
                iss: iss.to_owned(),
                jti: jti.to_owned(),
                amount: maximum,
            },
        );
        self.assert_caps();
        Ok(Reservation {
            id,
            iss: iss.to_owned(),
            jti: jti.to_owned(),
            amount: maximum,
        })
    }

    /// Commit `actual`, release the rest of the hold, and post `actual` to the person ledger.
    ///
    /// # Errors
    /// Returns [`ChargeError::Protocol`] when the hold is unknown or `actual` exceeds it.
    pub fn commit(
        &mut self,
        reservation: &Reservation,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        self.finish(reservation, actual, at, true)
    }

    /// Header for a hold that has not been committed: `remaining` net of the hold, plus `reserved`.
    ///
    /// # Errors
    /// Returns [`ChargeError::Protocol`] when the hold is unknown.
    pub fn stream_header(&self, reservation: &Reservation) -> Result<String, ChargeError> {
        let hold = self
            .holds
            .get(&reservation.id)
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let state = self
            .tokens
            .get(&token_key(&hold.iss, &hold.jti))
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let remaining = state.account.grant.amount() - state.committed - state.reserved;
        let header = BudgetHeader::reserved_hold(
            remaining,
            hold.amount,
            state.account.grant.unit(),
            state.account.grant.decimals(),
        )
        .map_err(ChargeError::Protocol)?;
        sender_field(&header, true).map_err(ChargeError::Protocol)
    }

    /// Drop a hold without posting consumption.
    ///
    /// # Errors
    /// Returns [`ChargeError::Protocol`] when the hold is unknown.
    pub fn release(&mut self, reservation: &Reservation) -> Result<(), ChargeError> {
        let hold = self
            .holds
            .remove(&reservation.id)
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let state = self
            .tokens
            .get_mut(&token_key(&hold.iss, &hold.jti))
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        state.reserved -= hold.amount;
        self.assert_caps();
        Ok(())
    }

    /// Header for a refusal that holds an invocation. The presented token is not reserved.
    ///
    /// # Errors
    /// Returns [`ChargeError::Protocol`] when the token was not opened.
    pub fn held_refusal(
        &self,
        iss: &str,
        jti: &str,
        required: Option<i64>,
    ) -> Result<String, ChargeError> {
        let before = self.snapshot(iss, jti);
        let header = self.refusal_view(iss, jti, required)?;
        if self.snapshot(iss, jti) != before {
            return Err(ChargeError::Protocol(Error::Malformed));
        }
        Ok(header)
    }

    /// Meter a held invocation against the completing token exactly once.
    ///
    /// A replay returns the completing token's current remaining and the original
    /// cost, and does not add consumption. A completing token that does not fit
    /// is refused and the invocation stays unmetered.
    ///
    /// # Errors
    /// Returns [`ChargeError::Refused`] when the completing token cannot cover
    /// `maximum`, without recording a replay.
    pub fn complete_held(
        &mut self,
        pending: &str,
        iss: &str,
        jti: &str,
        maximum: i64,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        let key = (pending.to_owned(), iss.to_owned(), jti.to_owned());
        if let Some(cost) = self.replays.get(&key).copied() {
            return self.replay_header(iss, jti, cost);
        }
        let reservation = self.reserve(iss, jti, maximum)?;
        match self.commit(&reservation, actual, at) {
            Ok(header) => {
                self.replays.insert(key, actual);
                Ok(header)
            }
            Err(error) => {
                let _ = self.release(&reservation);
                Err(error)
            }
        }
    }

    /// Committed amount for one token.
    pub fn committed(&self, iss: &str, jti: &str) -> Option<i64> {
        self.tokens
            .get(&token_key(iss, jti))
            .map(|state| state.committed)
    }

    /// Committed and outstanding reservation for one opened token.
    pub fn outstanding(&self, iss: &str, jti: &str) -> Option<(i64, i64)> {
        self.tokens
            .get(&token_key(iss, jti))
            .map(|state| (state.committed, state.reserved))
    }

    /// Whether any accepted token names this caller as `iss` or `ps`.
    pub fn caller_seen(&self, caller: &Caller) -> bool {
        self.tokens
            .values()
            .any(|state| visible_token(state, caller))
            || self
                .charges
                .iter()
                .any(|charge| visible_charge(charge, caller))
    }

    /// Person total for `(ps, sub, aud)` in `unit`. This is not a second ceiling.
    pub fn person_total(&self, ps: &str, sub: &str, aud: &str, unit: &str) -> i64 {
        self.charges
            .iter()
            .filter(|charge| {
                charge.ps == ps && charge.sub == sub && charge.aud == aud && charge.unit == unit
            })
            .map(|charge| charge.amount)
            .sum()
    }

    /// Unix time through which committed figures are complete.
    ///
    /// An outstanding reservation keeps `as_of` at the newest commit time.
    /// A later commit whose timestamp is earlier does not move that mark backward.
    pub fn as_of(&self, now: i64) -> i64 {
        if self.holds.is_empty() {
            now
        } else {
            self.last_commit.unwrap_or(0)
        }
    }

    /// Drop key figures idle for at least `idle_seconds` before `now`.
    pub fn prune_keys(&mut self, now: i64, idle_seconds: i64) {
        for figures in self.keys.values_mut() {
            figures.retain(|figure| figure.last == 0 || now - figure.last < idle_seconds);
        }
        self.keys.retain(|_, figures| !figures.is_empty());
    }

    pub(crate) fn charges(&self) -> impl Iterator<Item = ChargeView<'_>> {
        self.charges.iter().map(|charge| ChargeView {
            ps: &charge.ps,
            sub: &charge.sub,
            iss: &charge.iss,
            unit: &charge.unit,
            tenant: charge.tenant.as_deref(),
            mission: charge.mission.as_deref(),
            at: charge.at,
            amount: charge.amount,
        })
    }

    pub(crate) fn key_amount(&self, jkt: &str, caller: &Caller) -> Option<i64> {
        let figures = self.keys.get(jkt)?;
        let visible: Vec<&KeyFigure> = figures
            .iter()
            .filter(|figure| visible_key(figure, caller))
            .collect();
        if visible.is_empty() {
            return None;
        }
        Some(visible.iter().map(|figure| figure.amount).sum())
    }

    pub(crate) fn known_scope(&self, caller: &Caller, kind: &str, value: &str) -> bool {
        self.tokens
            .values()
            .any(|state| visible_token(state, caller) && scope_matches(&state.account, kind, value))
            || self
                .charges
                .iter()
                .any(|charge| visible_charge(charge, caller) && charge_scope(charge, kind, value))
    }

    fn finish(
        &mut self,
        reservation: &Reservation,
        actual: i64,
        at: i64,
        record_key: bool,
    ) -> Result<String, ChargeError> {
        check_amount(actual).map_err(ChargeError::Protocol)?;
        let hold = self
            .holds
            .get(&reservation.id)
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        if actual > hold.amount {
            return Err(ChargeError::Protocol(Error::Exceeds));
        }
        let iss = hold.iss.clone();
        let jti = hold.jti.clone();
        let amount = hold.amount;
        let state = self
            .tokens
            .get_mut(&token_key(&iss, &jti))
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        state.reserved -= amount;
        state.committed += actual;
        if state.committed + state.reserved > state.account.grant.amount() {
            state.committed -= actual;
            state.reserved += amount;
            return Err(ChargeError::Protocol(Error::Exceeds));
        }
        let account = state.account.clone();
        self.holds.remove(&reservation.id);
        if actual > 0 {
            self.charges.push(Charge {
                ps: account.ps.clone(),
                sub: account.sub.clone(),
                aud: account.aud.clone(),
                iss: account.iss.clone(),
                unit: account.grant.unit().to_owned(),
                tenant: account.tenant.clone(),
                mission: account.mission.clone(),
                at,
                amount: actual,
            });
        }
        if record_key && let Some(figures) = self.keys.get_mut(&account.jkt) {
            for figure in figures.iter_mut() {
                if figure.iss == account.iss && figure.ps == account.ps {
                    figure.amount += actual;
                    figure.last = figure.last.max(at);
                }
            }
        }
        self.last_commit = Some(self.last_commit.map(|prev| prev.max(at)).unwrap_or(at));
        self.assert_caps();
        let state = self
            .tokens
            .get(&token_key(&iss, &jti))
            .expect("token present");
        let remaining = state.account.grant.amount() - state.committed - state.reserved;
        let header = BudgetHeader::final_cost(
            remaining,
            actual,
            state.account.grant.unit(),
            state.account.grant.decimals(),
        )
        .map_err(ChargeError::Protocol)?;
        sender_field(&header, true).map_err(ChargeError::Protocol)
    }

    fn refusal_view(
        &self,
        iss: &str,
        jti: &str,
        required: Option<i64>,
    ) -> Result<String, ChargeError> {
        let state = self
            .tokens
            .get(&token_key(iss, jti))
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let remaining = state.account.grant.amount() - state.committed - state.reserved;
        refusal_header_with(&state.account.grant, remaining, required)
    }

    fn replay_header(&self, iss: &str, jti: &str, cost: i64) -> Result<String, ChargeError> {
        let state = self
            .tokens
            .get(&token_key(iss, jti))
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let remaining = state.account.grant.amount() - state.committed - state.reserved;
        let header = BudgetHeader::final_cost(
            remaining,
            cost,
            state.account.grant.unit(),
            state.account.grant.decimals(),
        )
        .map_err(ChargeError::Protocol)?;
        sender_field(&header, true).map_err(ChargeError::Protocol)
    }

    fn snapshot(&self, iss: &str, jti: &str) -> Option<(i64, i64)> {
        self.tokens
            .get(&token_key(iss, jti))
            .map(|state| (state.committed, state.reserved))
    }

    fn assert_caps(&self) {
        for state in self.tokens.values() {
            debug_assert!(state.committed >= 0 && state.reserved >= 0);
            debug_assert!(state.committed + state.reserved <= state.account.grant.amount());
        }
    }
}

pub(crate) struct ChargeView<'a> {
    pub ps: &'a str,
    pub sub: &'a str,
    pub iss: &'a str,
    pub unit: &'a str,
    pub tenant: Option<&'a str>,
    pub mission: Option<&'a str>,
    pub at: i64,
    pub amount: i64,
}

fn refusal_header(grant: &Budget, remaining: i64, maximum: i64) -> Result<String, ChargeError> {
    let required = (remaining > 0).then_some(maximum);
    refusal_header_with(grant, remaining, required)
}

fn refusal_header_with(
    grant: &Budget,
    remaining: i64,
    required: Option<i64>,
) -> Result<String, ChargeError> {
    let header = BudgetHeader::refusal(remaining, required, grant.unit(), grant.decimals())
        .map_err(ChargeError::Protocol)?;
    sender_field(&header, false).map_err(ChargeError::Protocol)
}

fn visible_key(figure: &KeyFigure, caller: &Caller) -> bool {
    match caller.role {
        KeyRole::PersonServer => figure.iss == caller.id || figure.ps == caller.id,
        KeyRole::AccessServer => {
            figure.iss == caller.id && caller.ps.as_deref().is_none_or(|ps| figure.ps == ps)
        }
    }
}

fn visible_token(state: &State, caller: &Caller) -> bool {
    match caller.role {
        KeyRole::PersonServer => state.account.iss == caller.id || state.account.ps == caller.id,
        KeyRole::AccessServer => {
            state.account.iss == caller.id
                && caller.ps.as_deref().is_none_or(|ps| state.account.ps == ps)
        }
    }
}

fn visible_charge(charge: &Charge, caller: &Caller) -> bool {
    match caller.role {
        KeyRole::PersonServer => charge.iss == caller.id || charge.ps == caller.id,
        KeyRole::AccessServer => {
            charge.iss == caller.id && caller.ps.as_deref().is_none_or(|ps| charge.ps == ps)
        }
    }
}

fn scope_matches(account: &TokenAccount, kind: &str, value: &str) -> bool {
    match kind {
        "sub" => account.sub == value,
        "tenant" => account.tenant.as_deref() == Some(value),
        "mission_s256" => account.mission.as_deref() == Some(value),
        _ => false,
    }
}

fn charge_scope(charge: &Charge, kind: &str, value: &str) -> bool {
    match kind {
        "sub" => charge.sub == value,
        "tenant" => charge.tenant.as_deref() == Some(value),
        "mission_s256" => charge.mission.as_deref() == Some(value),
        _ => false,
    }
}
