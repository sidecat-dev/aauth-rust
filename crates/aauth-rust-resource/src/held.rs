//! One held invocation result, keyed by the auth token `jti`.
//! The ledger draws each pending id. The first poll runs the invocation. A
//! later poll of that same token at the same pending id returns the stored
//! result through the token's `exp`.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use aauth_rust_core::continuation::generate_pending_id;
use http::{Response, StatusCode};

/// What a poll of a held invocation does.
pub enum HeldPoll {
    /// This poll ran the invocation once and stored its result.
    Executed(Response<Vec<u8>>),
    /// The same auth token is being presented again. The stored result is returned.
    Replayed(Response<Vec<u8>>),
    /// No invocation was opened at this pending id.
    Unknown,
    /// The pending id was completed by a different auth token `jti`.
    DifferentToken,
    /// The auth token's `exp` has passed. The invocation does not run again.
    Expired,
    /// An earlier poll claimed this token and has not stored a result yet.
    Unfinished,
}

#[derive(Clone, Debug)]
struct Stored {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct Record {
    pending_id: String,
    retain_until: i64,
    result: Option<Stored>,
}

/// Process-memory held invocations. Each auth token `jti` runs at most once.
#[derive(Debug, Default)]
pub struct HeldInvocations {
    open: Mutex<BTreeMap<String, Option<String>>>,
    by_jti: Mutex<BTreeMap<String, Record>>,
}

impl HeldInvocations {
    /// Empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a fresh pending id before the agent polls it, and return it.
    ///
    /// The id is [`generate_pending_id`]: 128 bits from the operating system's
    /// secure random source as 22 base64url characters. The host builds the
    /// pending URL from it, so that URL is unguessable. An id already open is
    /// never returned again.
    pub fn open(&self) -> String {
        let mut open = self.pending();
        loop {
            let pending_id = generate_pending_id();
            if !open.contains_key(&pending_id) {
                open.insert(pending_id.clone(), None);
                return pending_id;
            }
        }
    }

    /// Poll `pending_id` with the auth token `jti`.
    ///
    /// The first poll at or before `exp` calls `execute` once and retains that
    /// response through `exp`. A later poll with the same `jti` returns those
    /// bytes and does not call `execute`. A different `jti` does not receive
    /// the result and does not call `execute`.
    ///
    /// `jti` and `exp` must be the claims of an auth token this resource already
    /// verified, including the HTTP proof. The ledger does not verify a token.
    /// `jti` is `[A-Za-z0-9_-]{1,128}`.
    pub fn poll<F>(&self, pending_id: &str, jti: &str, exp: i64, now: i64, execute: F) -> HeldPoll
    where
        F: FnOnce() -> Response<Vec<u8>>,
    {
        if !valid_token(jti) {
            return HeldPoll::DifferentToken;
        }
        let claim = {
            let mut open = self.pending();
            let Some(bound) = open.get_mut(pending_id) else {
                return HeldPoll::Unknown;
            };
            if let Some(existing) = bound.clone() {
                if existing != jti {
                    return HeldPoll::DifferentToken;
                }
                drop(open);
                return self.replay(pending_id, jti, now);
            }
            if now > exp {
                return HeldPoll::Expired;
            }
            let mut by_jti = self.by_jti();
            if by_jti.contains_key(jti) {
                return HeldPoll::DifferentToken;
            }
            *bound = Some(jti.to_owned());
            by_jti.insert(
                jti.to_owned(),
                Record {
                    pending_id: pending_id.to_owned(),
                    retain_until: exp,
                    result: None,
                },
            );
            jti.to_owned()
        };
        let produced = execute();
        let stored = snapshot(&produced);
        let mut by_jti = self.by_jti();
        if let Some(record) = by_jti.get_mut(&claim)
            && record.pending_id == pending_id
            && record.result.is_none()
        {
            record.result = Some(stored);
        }
        HeldPoll::Executed(produced)
    }

    fn replay(&self, pending_id: &str, jti: &str, now: i64) -> HeldPoll {
        let by_jti = self.by_jti();
        let Some(record) = by_jti.get(jti) else {
            return HeldPoll::Unfinished;
        };
        if record.pending_id != pending_id {
            return HeldPoll::DifferentToken;
        }
        let Some(result) = &record.result else {
            return HeldPoll::Unfinished;
        };
        if now > record.retain_until {
            return HeldPoll::Expired;
        }
        HeldPoll::Replayed(restore(result))
    }

    fn pending(&self) -> MutexGuard<'_, BTreeMap<String, Option<String>>> {
        self.open.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn by_jti(&self) -> MutexGuard<'_, BTreeMap<String, Record>> {
        self.by_jti
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

fn valid_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn snapshot(response: &Response<Vec<u8>>) -> Stored {
    Stored {
        status: response.status(),
        content_type: response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: response.body().clone(),
    }
}

fn restore(stored: &Stored) -> Response<Vec<u8>> {
    let mut response = Response::new(stored.body.clone());
    *response.status_mut() = stored.status;
    if let Some(content_type) = &stored.content_type
        && let Ok(value) = content_type.parse()
    {
        response.headers_mut().insert("content-type", value);
    }
    response
}
