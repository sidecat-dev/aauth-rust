//! Opt-in budget metering for one resource. The ledger lives behind a mutex so
//! concurrent requests on one process cannot both spend the last unit. A host
//! may hand the same ledger to another Resource; that continues the spend.
//! The ledger is process memory.
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use aauth_rust_budgets::{
    Budget, BudgetHeader, ChargeError, ConsumptionRecord, Error, Ledger, Reservation, TokenAccount,
    UnitDeclaration, offer_budget, parse_max_cost, read_granted, sender_field, trailer_field,
};
use aauth_rust_core::VerifiedAuthToken;
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};

pub(super) struct BudgetGate {
    pub(super) units: Mutex<Vec<UnitDeclaration>>,
    pub(super) usage_endpoint: String,
    pub(super) default_bound: i64,
    pub(super) default_offer: i64,
    pub(super) omit_required: AtomicBool,
    pub(super) ledger: Arc<Mutex<Ledger>>,
}

impl BudgetGate {
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(super) fn declarations(&self) -> Vec<UnitDeclaration> {
        self.units
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    pub(super) fn offer(&self, requested: Option<&Budget>) -> Result<Budget, Error> {
        offer_budget(&self.declarations(), requested, self.default_offer)
    }

    pub(super) fn challenge_extra(
        &self,
        requested: Option<&Budget>,
        consumed: Option<&ConsumptionRecord>,
        locked: Option<&Budget>,
    ) -> Result<BTreeMap<String, Value>, Error> {
        // A step-up offers the scale declared now. A consumption record from a
        // grant whose unit or decimals differ is omitted rather than relabeled.
        let offer = self.offer(requested)?;
        let mut extra = BTreeMap::new();
        extra.insert("budget".into(), offer.to_value());
        if let Some(record) = consumed
            && locked.is_some_and(|grant| {
                grant.unit() == offer.unit() && grant.decimals() == offer.decimals()
            })
        {
            extra.insert("budget_consumed".into(), record.to_value());
        }
        Ok(extra)
    }

    /// Header for a verified budgeted token that this call will not meter.
    pub(super) fn untouched_header(
        &self,
        token: &VerifiedAuthToken,
        grant: &Budget,
    ) -> Result<String, Error> {
        let ledger = self.lock();
        let (committed, reserved) = ledger
            .outstanding(token.claims().iss.as_str(), token.claims().jti.as_str())
            .unwrap_or((0, 0));
        let remaining = grant.amount() - committed - reserved;
        let header = BudgetHeader::refusal(remaining, None, grant.unit(), grant.decimals())?;
        sender_field(&header, false)
    }

    /// Host bound, lowered by a client `AAuth-Max-Cost` when that figure is smaller.
    /// A client value above the host bound does not raise it.
    pub(super) fn admitted_cost(&self, request: &Request<Vec<u8>>) -> Result<i64, ()> {
        let host = self.default_bound;
        match request.headers().get("aauth-max-cost") {
            None => Ok(host),
            Some(value) => {
                let text = value.to_str().map_err(|_| ())?;
                let client = parse_max_cost(text).map_err(|_| ())?;
                Ok(client.min(host))
            }
        }
    }

    pub(super) fn remaining(
        &self,
        token: &VerifiedAuthToken,
        grant: &Budget,
    ) -> Result<i64, ChargeError> {
        let mut ledger = self.lock();
        ledger
            .open(account(token, grant).map_err(ChargeError::Protocol)?)
            .map_err(ChargeError::Protocol)?;
        let (committed, reserved) = ledger
            .outstanding(token.claims().iss.as_str(), token.claims().jti.as_str())
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        Ok(grant.amount() - committed - reserved)
    }

    pub(super) fn reserve(
        &self,
        token: &VerifiedAuthToken,
        grant: &Budget,
        maximum: i64,
    ) -> Result<Reservation, ChargeError> {
        let mut ledger = self.lock();
        ledger
            .open(account(token, grant).map_err(ChargeError::Protocol)?)
            .map_err(ChargeError::Protocol)?;
        ledger.reserve(
            token.claims().iss.as_str(),
            token.claims().jti.as_str(),
            maximum,
        )
    }

    pub(super) fn commit(
        &self,
        reservation: &Reservation,
        actual: i64,
        at: i64,
    ) -> Result<String, ()> {
        self.lock().commit(reservation, actual, at).map_err(|_| ())
    }

    pub(super) fn release(&self, reservation: &Reservation) {
        let _ = self.lock().release(reservation);
    }

    pub(super) fn stream_header(&self, reservation: &Reservation) -> Result<String, ChargeError> {
        self.lock().stream_header(reservation)
    }

    pub(super) fn trailer(
        &self,
        prior: &str,
        cost: i64,
    ) -> Result<(String, String, String), Error> {
        let parsed = aauth_rust_budgets::parse_header(prior, None, None)?;
        let trailer = trailer_field(&parsed.header, cost)?;
        Ok((trailer.listed.into(), trailer.name.into(), trailer.field))
    }

    pub(super) fn held_header(&self, token: &VerifiedAuthToken) -> Result<String, ChargeError> {
        let grant = read_granted(&token.claims().extra)
            .map_err(ChargeError::Protocol)?
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let mut ledger = self.lock();
        ledger
            .open(account(token, &grant).map_err(ChargeError::Protocol)?)
            .map_err(ChargeError::Protocol)?;
        let before = ledger.outstanding(token.claims().iss.as_str(), token.claims().jti.as_str());
        let header = ledger.held_refusal(
            token.claims().iss.as_str(),
            token.claims().jti.as_str(),
            None,
        )?;
        if ledger.outstanding(token.claims().iss.as_str(), token.claims().jti.as_str()) != before {
            return Err(ChargeError::Protocol(Error::Malformed));
        }
        Ok(header)
    }

    pub(super) fn complete_held(
        &self,
        pending: &str,
        token: &VerifiedAuthToken,
        maximum: i64,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        let grant = read_granted(&token.claims().extra)
            .map_err(ChargeError::Protocol)?
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        let mut ledger = self.lock();
        ledger
            .open(account(token, &grant).map_err(ChargeError::Protocol)?)
            .map_err(ChargeError::Protocol)?;
        ledger.complete_held(
            pending,
            token.claims().iss.as_str(),
            token.claims().jti.as_str(),
            maximum,
            actual,
            at,
        )
    }

    pub(super) fn open_grant(&self, token: &VerifiedAuthToken) -> Result<Budget, ChargeError> {
        let grant = read_granted(&token.claims().extra)
            .map_err(ChargeError::Protocol)?
            .ok_or(ChargeError::Protocol(Error::Malformed))?;
        self.lock()
            .open(account(token, &grant).map_err(ChargeError::Protocol)?)
            .map_err(ChargeError::Protocol)?;
        Ok(grant)
    }

    pub(super) fn reporting_budget(&self) -> Option<Budget> {
        let units = self.declarations();
        let unit = units.first()?;
        Budget::new(0, unit.unit(), unit.decimals()).ok()
    }
}

pub(super) fn metadata_units(units: &[UnitDeclaration]) -> Value {
    Value::Array(units.iter().map(UnitDeclaration::to_value).collect())
}

fn account(token: &VerifiedAuthToken, grant: &Budget) -> Result<TokenAccount, Error> {
    let claims = token.claims();
    Ok(TokenAccount {
        jti: claims.jti.clone(),
        grant: grant.clone(),
        ps: claims.ps.clone(),
        sub: claims.sub.clone(),
        aud: claims.aud.clone(),
        iss: claims.iss.clone(),
        jkt: claims.cnf.jwk.thumbprint().map_err(|_| Error::Malformed)?,
        tenant: claims.tenant.clone(),
        mission: claims.mission_s256.clone(),
    })
}

pub(super) fn problem(status: StatusCode, code: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(
        json!({"type":"about:blank","title":status.canonical_reason().unwrap_or("Request refused"),"status":status.as_u16(),"error":code})
            .to_string()
            .into_bytes(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        "application/problem+json".parse().expect("content type"),
    );
    response
}
