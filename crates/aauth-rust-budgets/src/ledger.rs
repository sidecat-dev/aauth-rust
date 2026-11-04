//! Per-token hard cap and per-person consumption ledger.
//!
//! [`Ledger::new`] keeps the meter in process memory. [`Ledger::open_directory`]
//! writes the same meter to a host directory. A later process that opens that
//! directory continues the spend. The directory is not a wire document.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::header::{BudgetHeader, sender_field};
use crate::value::{Budget, Error, MAX_AMOUNT, check_amount};

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

impl From<Error> for ChargeError {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
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

/// Meter for one process, or for a directory when opened with [`Ledger::open_directory`].
/// Callers that share one process wrap it in a mutex.
/// Each mutating method updates the token and the person ledger before it returns.
/// A directory ledger publishes that update only after the new file is complete.
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
    directory: Option<PathBuf>,
    in_snapshot: bool,
    fail_next_write: bool,
}

fn token_key(iss: &str, jti: &str) -> (String, String) {
    (iss.to_owned(), jti.to_owned())
}

impl Ledger {
    /// Empty meter. This value is process memory until [`Self::open_directory`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the meter stored in `directory`, or an empty meter when the directory
    /// has no snapshot. The directory is created when it is missing.
    ///
    /// A complete `ledger.json` is the current spend. When that file is torn,
    /// `ledger.json.prev` is the last complete snapshot. A partial
    /// `ledger.json.tmp` is never the current spend. When the current file is
    /// torn and no complete snapshot remains, this returns [`Error::Unavailable`]
    /// and does not start an empty meter. This is a process exit and an
    /// interrupted write. It is not power loss.
    ///
    /// # Errors
    /// Returns [`Error::Unavailable`] when the directory cannot be created or
    /// the only snapshots are torn.
    pub fn open_directory(directory: impl AsRef<Path>) -> Result<Self, Error> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory).map_err(|_| Error::Unavailable)?;
        let mut ledger = match read_best(directory)? {
            Some(ledger) => ledger,
            None => Self::new(),
        };
        ledger.directory = Some(directory.to_path_buf());
        Ok(ledger)
    }

    /// The next successful mutation writes a partial temporary file and leaves
    /// the published snapshot unchanged. The in-memory meter is unchanged too.
    pub fn interrupt_next_write(&mut self) {
        self.fail_next_write = true;
    }

    /// `(iss, jti)` pairs this meter has opened, in order.
    pub fn token_ids(&self) -> Vec<(String, String)> {
        self.tokens.keys().cloned().collect()
    }

    /// Holds that survived in this meter. A restarted process uses these to
    /// commit or release a reservation whose handle it no longer has.
    pub fn reservations(&self) -> Vec<Reservation> {
        self.holds
            .iter()
            .map(|(id, hold)| Reservation {
                id: *id,
                iss: hold.iss.clone(),
                jti: hold.jti.clone(),
                amount: hold.amount,
            })
            .collect()
    }

    /// Register a grant. A second registration of the same `(iss, jti)` must carry the same grant.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when the same issuer and `jti` are registered with a different grant.
    /// Returns [`Error::Unavailable`] when a directory ledger cannot publish the new grant.
    pub fn open(&mut self, account: TokenAccount) -> Result<(), Error> {
        let key = token_key(&account.iss, &account.jti);
        if self.tokens.contains_key(&key) || self.directory.is_none() || self.in_snapshot {
            return self.open_in(account);
        }
        self.with_snapshot(|this| this.open_in(account))
    }

    fn open_in(&mut self, account: TokenAccount) -> Result<(), Error> {
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
    /// A maximum above 15 digits exceeds every remainder and is refused like any
    /// other maximum that does not fit; its refusal header omits `required`,
    /// which the header cannot carry.
    ///
    /// # Errors
    /// Returns [`ChargeError::Refused`] when the maximum does not fit, or
    /// [`ChargeError::Protocol`] when the maximum is negative, the token was not
    /// opened, or the directory ledger cannot publish the hold.
    pub fn reserve(
        &mut self,
        iss: &str,
        jti: &str,
        maximum: i64,
    ) -> Result<Reservation, ChargeError> {
        self.with_snapshot(|this| this.reserve_in(iss, jti, maximum))
    }

    fn reserve_in(
        &mut self,
        iss: &str,
        jti: &str,
        maximum: i64,
    ) -> Result<Reservation, ChargeError> {
        if maximum < 0 {
            return Err(ChargeError::Protocol(Error::Malformed));
        }
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
    /// Returns [`ChargeError::Protocol`] when the hold is unknown, `actual` exceeds it,
    /// or the directory ledger cannot publish the commit.
    pub fn commit(
        &mut self,
        reservation: &Reservation,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        self.with_snapshot(|this| this.finish(reservation, actual, at, true))
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
        let header = BudgetHeader::reserved_hold(&state.account.grant, remaining, hold.amount)
            .map_err(ChargeError::Protocol)?;
        sender_field(&header, true).map_err(ChargeError::Protocol)
    }

    /// Drop a hold without posting consumption.
    ///
    /// # Errors
    /// Returns [`ChargeError::Protocol`] when the hold is unknown or the directory
    /// ledger cannot publish the release.
    pub fn release(&mut self, reservation: &Reservation) -> Result<(), ChargeError> {
        self.with_snapshot(|this| this.release_in(reservation))
    }

    fn release_in(&mut self, reservation: &Reservation) -> Result<(), ChargeError> {
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
    /// `maximum`, without recording a replay. Returns [`ChargeError::Protocol`]
    /// when the directory ledger cannot publish the completion.
    pub fn complete_held(
        &mut self,
        pending: &str,
        iss: &str,
        jti: &str,
        maximum: i64,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        self.with_snapshot(|this| this.complete_held_in(pending, iss, jti, maximum, actual, at))
    }

    fn complete_held_in(
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
    ///
    /// A directory ledger that cannot publish the prune leaves the figures in place.
    pub fn prune_keys(&mut self, now: i64, idle_seconds: i64) {
        let _ = self.with_snapshot(|this| {
            this.prune_keys_in(now, idle_seconds);
            Ok::<(), Error>(())
        });
    }

    fn prune_keys_in(&mut self, now: i64, idle_seconds: i64) {
        for figures in self.keys.values_mut() {
            figures.retain(|figure| figure.last == 0 || now - figure.last < idle_seconds);
        }
        self.keys.retain(|_, figures| !figures.is_empty());
    }

    fn with_snapshot<T, E>(&mut self, body: impl FnOnce(&mut Self) -> Result<T, E>) -> Result<T, E>
    where
        E: From<Error>,
    {
        if self.directory.is_none() || self.in_snapshot {
            return body(self);
        }
        let interrupt = self.fail_next_write;
        self.fail_next_write = false;
        let mut next = self.clone();
        next.in_snapshot = true;
        next.fail_next_write = false;
        let value = body(&mut next)?;
        next.in_snapshot = false;
        next.store(interrupt)?;
        *self = next;
        Ok(value)
    }

    fn store(&self, interrupt: bool) -> Result<(), Error> {
        let directory = self.directory.as_ref().ok_or(Error::Unavailable)?;
        let bytes = encode_snapshot(self)?;
        let temporary = directory.join("ledger.json.tmp");
        let current = directory.join("ledger.json");
        let previous = directory.join("ledger.json.prev");
        {
            let mut file = File::create(&temporary).map_err(|_| Error::Unavailable)?;
            let written = if interrupt {
                &bytes[..bytes.len().min(1)]
            } else {
                &bytes[..]
            };
            file.write_all(written).map_err(|_| Error::Unavailable)?;
            file.sync_all().map_err(|_| Error::Unavailable)?;
        }
        if interrupt {
            return Err(Error::Unavailable);
        }
        if current.is_file() {
            let _ = fs::remove_file(&previous);
            fs::rename(&current, &previous).map_err(|_| Error::Unavailable)?;
        }
        fs::rename(&temporary, &current).map_err(|_| Error::Unavailable)?;
        sync_dir(directory)
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
        let header = BudgetHeader::final_cost(&state.account.grant, remaining, actual)
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
        let header = BudgetHeader::final_cost(&state.account.grant, remaining, cost)
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
    let required = (remaining > 0 && maximum <= MAX_AMOUNT).then_some(maximum);
    refusal_header_with(grant, remaining, required)
}

fn refusal_header_with(
    grant: &Budget,
    remaining: i64,
    required: Option<i64>,
) -> Result<String, ChargeError> {
    let header =
        BudgetHeader::refusal(grant, remaining, required).map_err(ChargeError::Protocol)?;
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

fn sync_dir(directory: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::Unavailable)?;
    }
    let _ = directory;
    Ok(())
}

fn read_best(directory: &Path) -> Result<Option<Ledger>, Error> {
    match read_snapshot(&directory.join("ledger.json")) {
        Ok(Some(ledger)) => Ok(Some(ledger)),
        Ok(None) => read_snapshot(&directory.join("ledger.json.prev")),
        Err(Error::Unavailable) => match read_snapshot(&directory.join("ledger.json.prev")) {
            Ok(Some(ledger)) => Ok(Some(ledger)),
            Ok(None) | Err(_) => Err(Error::Unavailable),
        },
        Err(error) => Err(error),
    }
}

fn read_snapshot(path: &Path) -> Result<Option<Ledger>, Error> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Unavailable),
    };
    decode_snapshot(&bytes).map(Some)
}

fn encode_snapshot(ledger: &Ledger) -> Result<Vec<u8>, Error> {
    let tokens: Vec<Value> = ledger
        .tokens
        .iter()
        .map(|((iss, jti), state)| {
            json!({
                "iss": iss,
                "jti": jti,
                "committed": state.committed,
                "reserved": state.reserved,
                "account": {
                    "jti": state.account.jti,
                    "grant": state.account.grant.to_value(),
                    "ps": state.account.ps,
                    "sub": state.account.sub,
                    "aud": state.account.aud,
                    "iss": state.account.iss,
                    "jkt": state.account.jkt,
                    "tenant": state.account.tenant,
                    "mission": state.account.mission,
                }
            })
        })
        .collect();
    let holds: Vec<Value> = ledger
        .holds
        .iter()
        .map(|(id, hold)| {
            json!({
                "id": id,
                "iss": hold.iss,
                "jti": hold.jti,
                "amount": hold.amount,
            })
        })
        .collect();
    let charges: Vec<Value> = ledger
        .charges
        .iter()
        .map(|charge| {
            json!({
                "ps": charge.ps,
                "sub": charge.sub,
                "aud": charge.aud,
                "iss": charge.iss,
                "unit": charge.unit,
                "tenant": charge.tenant,
                "mission": charge.mission,
                "at": charge.at,
                "amount": charge.amount,
            })
        })
        .collect();
    let keys: Vec<Value> = ledger
        .keys
        .iter()
        .map(|(jkt, figures)| {
            json!({
                "jkt": jkt,
                "figures": figures.iter().map(|figure| json!({
                    "iss": figure.iss,
                    "ps": figure.ps,
                    "amount": figure.amount,
                    "last": figure.last,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let replays: Vec<Value> = ledger
        .replays
        .iter()
        .map(|((pending, iss, jti), cost)| {
            json!({
                "pending": pending,
                "iss": iss,
                "jti": jti,
                "cost": cost,
            })
        })
        .collect();
    let body = json!({
        "v": 1,
        "next_hold": ledger.next_hold,
        "last_commit": ledger.last_commit,
        "tokens": tokens,
        "holds": holds,
        "charges": charges,
        "keys": keys,
        "replays": replays,
    });
    let body = serde_json::to_vec(&body).map_err(|_| Error::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let mut bytes = body;
    bytes.push(b'\n');
    bytes.extend(hex_encode(&hasher.finalize()).into_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<Ledger, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Unavailable)?;
    let mut lines = text.split('\n');
    let body = lines.next().ok_or(Error::Unavailable)?;
    let digest = lines.next().ok_or(Error::Unavailable)?;
    if lines.next() != Some("") || digest.len() != 64 {
        return Err(Error::Unavailable);
    }
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    if hex_encode(&hasher.finalize()) != digest {
        return Err(Error::Unavailable);
    }
    let value: Value = serde_json::from_slice(body.as_bytes()).map_err(|_| Error::Unavailable)?;
    if value.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(Error::Unavailable);
    }
    let mut ledger = Ledger::new();
    ledger.next_hold = value
        .get("next_hold")
        .and_then(Value::as_u64)
        .ok_or(Error::Unavailable)?;
    ledger.last_commit = match value.get("last_commit") {
        None | Some(Value::Null) => None,
        Some(stamp) => Some(stamp.as_i64().ok_or(Error::Unavailable)?),
    };
    for token in value
        .get("tokens")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?
    {
        let iss = text_field(token, "iss")?;
        let jti = text_field(token, "jti")?;
        let committed = i64_field(token, "committed")?;
        let reserved = i64_field(token, "reserved")?;
        let account = token.get("account").ok_or(Error::Unavailable)?;
        let grant = account.get("grant").ok_or(Error::Unavailable)?;
        let parsed = Budget::new(
            i64_field(grant, "amount")?,
            text_field(grant, "unit")?,
            i64_field(grant, "decimals")?,
        )?;
        let record = TokenAccount {
            jti: text_field(account, "jti")?,
            grant: parsed,
            ps: text_field(account, "ps")?,
            sub: text_field(account, "sub")?,
            aud: text_field(account, "aud")?,
            iss: text_field(account, "iss")?,
            jkt: text_field(account, "jkt")?,
            tenant: optional_text(account, "tenant")?,
            mission: optional_text(account, "mission")?,
        };
        if record.iss != iss || record.jti != jti {
            return Err(Error::Unavailable);
        }
        if committed < 0 || reserved < 0 || committed + reserved > record.grant.amount() {
            return Err(Error::Unavailable);
        }
        ledger.tokens.insert(
            (iss, jti),
            State {
                account: record,
                committed,
                reserved,
            },
        );
    }
    for hold in value
        .get("holds")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?
    {
        let id = hold
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(Error::Unavailable)?;
        ledger.holds.insert(
            id,
            Hold {
                iss: text_field(hold, "iss")?,
                jti: text_field(hold, "jti")?,
                amount: i64_field(hold, "amount")?,
            },
        );
    }
    for charge in value
        .get("charges")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?
    {
        ledger.charges.push(Charge {
            ps: text_field(charge, "ps")?,
            sub: text_field(charge, "sub")?,
            aud: text_field(charge, "aud")?,
            iss: text_field(charge, "iss")?,
            unit: text_field(charge, "unit")?,
            tenant: optional_text(charge, "tenant")?,
            mission: optional_text(charge, "mission")?,
            at: i64_field(charge, "at")?,
            amount: i64_field(charge, "amount")?,
        });
    }
    for entry in value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?
    {
        let jkt = text_field(entry, "jkt")?;
        let mut figures = Vec::new();
        for figure in entry
            .get("figures")
            .and_then(Value::as_array)
            .ok_or(Error::Unavailable)?
        {
            figures.push(KeyFigure {
                iss: text_field(figure, "iss")?,
                ps: text_field(figure, "ps")?,
                amount: i64_field(figure, "amount")?,
                last: i64_field(figure, "last")?,
            });
        }
        ledger.keys.insert(jkt, figures);
    }
    for replay in value
        .get("replays")
        .and_then(Value::as_array)
        .ok_or(Error::Unavailable)?
    {
        ledger.replays.insert(
            (
                text_field(replay, "pending")?,
                text_field(replay, "iss")?,
                text_field(replay, "jti")?,
            ),
            i64_field(replay, "cost")?,
        );
    }
    for ((iss, jti), state) in &ledger.tokens {
        let held: i64 = ledger
            .holds
            .values()
            .filter(|hold| hold.iss == *iss && hold.jti == *jti)
            .map(|hold| hold.amount)
            .sum();
        if held != state.reserved {
            return Err(Error::Unavailable);
        }
    }
    if ledger.holds.iter().any(|(id, hold)| {
        *id == 0
            || *id > ledger.next_hold
            || !ledger
                .tokens
                .contains_key(&(hold.iss.clone(), hold.jti.clone()))
    }) {
        return Err(Error::Unavailable);
    }
    ledger.assert_caps();
    Ok(ledger)
}

fn text_field(value: &Value, name: &str) -> Result<String, Error> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::Unavailable)
}

fn optional_text(value: &Value, name: &str) -> Result<Option<String>, Error> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(text) => text
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or(Error::Unavailable),
    }
}

fn i64_field(value: &Value, name: &str) -> Result<i64, Error> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(Error::Unavailable)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
