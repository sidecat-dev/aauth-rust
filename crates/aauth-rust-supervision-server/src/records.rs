//! Every record this server keeps, in one host [`ContinuationStore`].
//!
//! Keys are a short prefix and the SHA-256 of their parts, so identifiers a
//! Person Server chose never reach the store as keys.
use aauth_rust_core::continuation::{ContinuationStore, StoreError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::Response;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Connection of one person at one Person Server.
pub(crate) const CONNECTION: &str = "con";
/// A connect waiting for the person to confirm, by pending id.
pub(crate) const CONNECTING: &str = "cpend";
/// The pending id of a connect, by its canonical code.
pub(crate) const CONNECT_CODE: &str = "ccode";
/// One supervision decision, by Person Server and `sdi`.
pub(crate) const DECISION: &str = "dec";
/// The Person Server and `sdi` behind a pending URL.
pub(crate) const PENDING: &str = "pend";
/// A delivered event or report, by Person Server and `id`.
pub(crate) const SEEN: &str = "evt";
/// A mission, by Person Server, person and `s256`.
pub(crate) const MISSION: &str = "mis";
/// The person's standing answers for one agent.
pub(crate) const STANDING: &str = "std";

pub(crate) fn key(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// The store failed or a concurrent change kept winning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fault;

impl From<StoreError> for Fault {
    fn from(_: StoreError) -> Self {
        Fault
    }
}

pub(crate) fn load(store: &dyn ContinuationStore, id: &str) -> Result<Option<Value>, Fault> {
    Ok(store.load(id)?.map(|snapshot| snapshot.value))
}

/// Insert `value` unless `id` exists. `Ok(false)` means it already did.
pub(crate) fn insert_new(
    store: &dyn ContinuationStore,
    id: &str,
    value: Value,
) -> Result<bool, Fault> {
    match store.insert(id, value) {
        Ok(()) => Ok(true),
        Err(StoreError::Conflict) => Ok(false),
        Err(_) => Err(Fault),
    }
}

/// Apply `change` to the current value until it lands. `change` returns
/// the new value, or `None` to remove the record.
pub(crate) fn update(
    store: &dyn ContinuationStore,
    id: &str,
    mut change: impl FnMut(Option<&Value>) -> Option<Value>,
) -> Result<(), Fault> {
    for _ in 0..8 {
        match store.load(id)? {
            None => match change(None) {
                None => return Ok(()),
                Some(value) => match store.insert(id, value) {
                    Ok(()) => return Ok(()),
                    Err(StoreError::Conflict) => continue,
                    Err(_) => return Err(Fault),
                },
            },
            Some(snapshot) => {
                let next = change(Some(&snapshot.value));
                if store.replace(id, snapshot.revision, next)? {
                    return Ok(());
                }
            }
        }
    }
    Err(Fault)
}

pub(crate) fn remove(store: &dyn ContinuationStore, id: &str) -> Result<(), Fault> {
    update(store, id, |_| None)
}

/// A response as stored, so it can be returned again byte for byte.
pub(crate) fn encode_response(response: &Response<Vec<u8>>) -> Value {
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| Some(json!([name.as_str(), value.to_str().ok()?])))
        .collect::<Vec<_>>();
    json!({
        "status": response.status().as_u16(),
        "headers": headers,
        "body": URL_SAFE_NO_PAD.encode(response.body()),
    })
}

pub(crate) fn decode_response(value: &Value) -> Result<Response<Vec<u8>>, Fault> {
    let body = URL_SAFE_NO_PAD
        .decode(value["body"].as_str().ok_or(Fault)?)
        .map_err(|_| Fault)?;
    let mut builder = Response::builder().status(value["status"].as_u64().ok_or(Fault)? as u16);
    for header in value["headers"].as_array().ok_or(Fault)? {
        let name = header[0].as_str().ok_or(Fault)?;
        let value = header[1].as_str().ok_or(Fault)?;
        builder = builder.header(name, value);
    }
    builder.body(body).map_err(|_| Fault)
}
