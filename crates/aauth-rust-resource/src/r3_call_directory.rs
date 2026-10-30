//! Directory [`R3CallStore`](crate::R3CallStore).
//!
//! A published file is the record. The new bytes are written to a temporary
//! file, synchronized, and renamed. The previous complete file is kept beside
//! a replacement. A torn current file is not a new claim: a valid previous
//! file is read, and a torn file with no previous file is unavailable. This
//! is a process exit and an interrupted write. It is not power loss.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aauth_rust_r3::{Reference, digest};
use serde_json::{Value, json};

use super::r3_class::{
    R3CallResult, R3CallStore, R3CallToken, R3Claim, R3HeldRequest, R3HostError, R3PendingHeaders,
    R3ProposalRecord, R3StoreError,
};

/// Claim digest of a superseded release. It is not a token digest, so every
/// later claim on that record is [`R3Claim::DifferentToken`].
const SUPERSEDED: &str = "(superseded)";

/// Proposals and their single claim, one directory, one invocation per file.
pub struct DirectoryCallStore {
    directory: PathBuf,
    serial: Mutex<()>,
    interrupt: AtomicBool,
}

impl DirectoryCallStore {
    /// Open or create `directory`. Records already there stay in force.
    ///
    /// # Errors
    /// Returns the filesystem error when the directory cannot be created.
    pub fn open(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            serial: Mutex::new(()),
            interrupt: AtomicBool::new(false),
        })
    }

    /// Fail the next publish before its rename. The previous complete file
    /// stays the record. This is a host test hook and is not written down.
    pub fn interrupt_next_write(&self) {
        self.interrupt.store(true, Ordering::SeqCst);
    }

    fn record_path(&self, uri: &str) -> PathBuf {
        self.directory
            .join(format!("p-{}.json", digest(uri.as_bytes())))
    }

    fn claim_path(&self, uri: &str) -> PathBuf {
        self.directory
            .join(format!("claim-{}.json", digest(uri.as_bytes())))
    }

    fn create(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError> {
        let held = record.held.as_ref().map(|held| {
            json!({
                "pending_id": held.pending_id,
                "method": held.method,
                "uri": held.uri,
                "headers": held.headers,
                "body": held.body,
            })
        });
        let released = record.released.as_ref().map(stored_call_result);
        let bytes = json!({
            "uri": record.reference.uri(),
            "digest": record.reference.digest(),
            "exact_json": record.exact_json,
            "person_server": record.person_server,
            "auth_token_issuer": record.auth_token_issuer,
            "resource_token_jti": record.resource_token_jti,
            "resource_token": record.resource_token,
            "class_reference": {
                "uri": record.class_reference.uri(),
                "digest": record.class_reference.digest(),
            },
            "presented_jti": record.presented_jti,
            "subject": record.subject,
            "agent_jkt": record.agent_jkt,
            "tenant": record.tenant,
            "account": record.account,
            "scope": record.scope,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
            "held": held,
            "released": released,
            "release_until": record.release_until,
            "supersedes": record.supersedes,
        })
        .to_string()
        .into_bytes();
        if let Some(held) = &record.held {
            let index = self.directory.join(format!("pending-{}", held.pending_id));
            if !write_new(&index, record.reference.uri().as_bytes(), &self.interrupt)
                .map_err(unavailable)?
            {
                return Err(R3StoreError::Conflict);
            }
        }
        if !write_new(
            &self.record_path(record.reference.uri()),
            &bytes,
            &self.interrupt,
        )
        .map_err(unavailable)?
        {
            return Err(R3StoreError::Conflict);
        }
        sync_dir(&self.directory).map_err(unavailable)?;
        Ok(())
    }

    fn remove_successor(&self, record: &R3ProposalRecord) {
        let _ = fs::remove_file(self.record_path(record.reference.uri()));
        if let Some(held) = &record.held {
            let _ = fs::remove_file(self.directory.join(format!("pending-{}", held.pending_id)));
        }
    }

    fn decode(bytes: &[u8]) -> Result<R3ProposalRecord, R3StoreError> {
        let value: Value = serde_json::from_slice(bytes).map_err(unavailable)?;
        let class = &value["class_reference"];
        let held = match value.get("held") {
            Some(held) if !held.is_null() => Some(R3HeldRequest {
                pending_id: text(held, "pending_id")?,
                method: text(held, "method")?,
                uri: text(held, "uri")?,
                headers: serde_json::from_value(held["headers"].clone()).map_err(unavailable)?,
                body: serde_json::from_value(held["body"].clone()).map_err(unavailable)?,
            }),
            _ => None,
        };
        Ok(R3ProposalRecord {
            reference: reference(&value)?,
            exact_json: serde_json::from_value(value["exact_json"].clone()).map_err(unavailable)?,
            person_server: text(&value, "person_server")?,
            auth_token_issuer: text(&value, "auth_token_issuer")?,
            resource_token_jti: text(&value, "resource_token_jti")?,
            resource_token: text(&value, "resource_token")?,
            class_reference: reference(class)?,
            presented_jti: text(&value, "presented_jti")?,
            subject: text(&value, "subject")?,
            agent_jkt: text(&value, "agent_jkt")?,
            tenant: optional(&value, "tenant"),
            account: optional(&value, "account"),
            scope: optional(&value, "scope"),
            issued_at: number(&value, "issued_at")?,
            expires_at: number(&value, "expires_at")?,
            held,
            released: match value.get("released") {
                Some(released) if !released.is_null() => Some(call_result(released)?),
                _ => None,
            },
            release_until: value.get("release_until").and_then(Value::as_i64),
            supersedes: optional(&value, "supersedes"),
        })
    }
}

impl R3CallStore for DirectoryCallStore {
    fn commit(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        self.create(record)
    }

    fn load(&self, uri: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        match read_record(&self.record_path(uri)) {
            Ok(bytes) => {
                let record = Self::decode(&bytes)?;
                if record.reference.uri() != uri {
                    return Err(unavailable("stored key does not name this URI"));
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }

    fn load_pending(&self, pending_id: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        if pending_id.is_empty()
            || !pending_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Ok(None);
        }
        let uri = match fs::read(self.directory.join(format!("pending-{pending_id}"))) {
            Ok(bytes) => String::from_utf8(bytes).map_err(unavailable)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        self.load(&uri)
    }

    fn claim(&self, uri: &str, token: &R3CallToken, now: i64) -> Result<R3Claim, R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        if let Some(record) = self.load(uri)?
            && record.release_until.is_some_and(|until| now >= until)
        {
            return Ok(R3Claim::Expired);
        }
        let path = self.claim_path(uri);
        match read_record(&path) {
            Ok(bytes) => {
                let value: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
                if value["compact_sha256"].as_str() != Some(token.compact_sha256.as_str()) {
                    return Ok(R3Claim::DifferentToken);
                }
                if value["result"].is_null() {
                    return Ok(R3Claim::Unfinished);
                }
                if now >= number(&value, "retain_until")? {
                    return Ok(R3Claim::Expired);
                }
                Ok(R3Claim::Replay(call_result(&value["result"])?))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if now >= token.retain_until {
                    return Ok(R3Claim::Expired);
                }
                let fence = format!(
                    "{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(unavailable)?
                        .as_nanos()
                );
                let bytes = json!({
                    "compact_sha256": token.compact_sha256,
                    "jti": token.jti,
                    "retain_until": token.retain_until,
                    "fence": fence,
                    "result": null,
                })
                .to_string()
                .into_bytes();
                if !write_new(&path, &bytes, &self.interrupt).map_err(unavailable)? {
                    return Ok(R3Claim::Unfinished);
                }
                sync_dir(&self.directory).map_err(unavailable)?;
                Ok(R3Claim::Execute { fence })
            }
            Err(error) => Err(unavailable(error)),
        }
    }

    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> Result<R3CallResult, R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self.claim_path(uri);
        let bytes = read_record(&path).map_err(unavailable)?;
        let mut value: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if value["fence"].as_str() != Some(fence) || !value["result"].is_null() {
            return Err(R3StoreError::Conflict);
        }
        value["result"] = stored_call_result(result);
        replace(&path, value.to_string().as_bytes(), &self.interrupt).map_err(unavailable)?;
        Ok(result.clone())
    }

    fn held_releases(
        &self,
        agent_jkt: &str,
        subject: &str,
        now: i64,
    ) -> Result<Vec<R3ProposalRecord>, R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        let mut held = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(unavailable)? {
            let name = entry.map_err(unavailable)?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("p-") || !name.ends_with(".json") {
                continue;
            }
            let bytes = read_record(&self.directory.join(name)).map_err(unavailable)?;
            let record = Self::decode(&bytes)?;
            if record.released.is_some()
                && record.agent_jkt == agent_jkt
                && record.subject == subject
                && record.release_until.is_some_and(|until| now < until)
                && !self.claim_path(record.reference.uri()).exists()
            {
                held.push(record);
            }
        }
        Ok(held)
    }

    fn supersede(
        &self,
        prior_uri: &str,
        record: &R3ProposalRecord,
        now: i64,
    ) -> Result<(), R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        let Some(prior) = self.load(prior_uri)? else {
            return Err(R3StoreError::Conflict);
        };
        let tombstone = self.claim_path(prior_uri);
        if prior.released.is_none()
            || prior.release_until.is_none_or(|until| now >= until)
            || tombstone.exists()
            || self.record_path(record.reference.uri()).exists()
            || record.held.as_ref().is_some_and(|held| {
                self.directory
                    .join(format!("pending-{}", held.pending_id))
                    .exists()
            })
        {
            return Err(R3StoreError::Conflict);
        }
        if let Err(error) = self.create(record) {
            self.remove_successor(record);
            return Err(error);
        }
        let bytes = json!({
            "compact_sha256": SUPERSEDED,
            "jti": null,
            "retain_until": prior.expires_at,
            "fence": null,
            "result": null,
            "superseded_by": record.reference.uri(),
            "superseded_at": now,
        })
        .to_string()
        .into_bytes();
        match write_new(&tombstone, &bytes, &self.interrupt) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.remove_successor(record);
                Err(R3StoreError::Conflict)
            }
            Err(error) => {
                self.remove_successor(record);
                Err(unavailable(error))
            }
        }
    }
}

fn reference(value: &Value) -> Result<Reference, R3StoreError> {
    Reference::new(text(value, "uri")?, text(value, "digest")?).map_err(unavailable)
}

fn stored_call_result(result: &R3CallResult) -> Value {
    let mut value = json!({
        "status": result.status,
        "content_type": result.content_type,
        "body": result.body,
    });
    if let Some(pending) = &result.pending {
        value["pending"] = json!({
            "location": pending.location,
            "retry_after": pending.retry_after,
            "cache_control": pending.cache_control,
        });
    }
    value
}

fn call_result(value: &Value) -> Result<R3CallResult, R3StoreError> {
    Ok(R3CallResult {
        status: u16::try_from(number(value, "status")?).map_err(unavailable)?,
        content_type: optional(value, "content_type"),
        body: serde_json::from_value(value["body"].clone()).map_err(unavailable)?,
        pending: pending_headers(value)?,
    })
}

fn pending_headers(value: &Value) -> Result<Option<R3PendingHeaders>, R3StoreError> {
    match value.get("pending") {
        None | Some(Value::Null) => Ok(None),
        Some(pending) => {
            let items = pending
                .get("cache_control")
                .and_then(Value::as_array)
                .ok_or_else(|| unavailable("missing stored cache_control"))?;
            let mut cache_control = Vec::new();
            for item in items {
                cache_control.push(
                    item.as_str()
                        .ok_or_else(|| unavailable("stored cache_control"))?
                        .to_owned(),
                );
            }
            if cache_control.is_empty() {
                return Err(unavailable("stored cache_control"));
            }
            Ok(Some(R3PendingHeaders {
                location: text(pending, "location")?,
                retry_after: text(pending, "retry_after")?,
                cache_control,
            }))
        }
    }
}

fn text(value: &Value, name: &str) -> Result<String, R3StoreError> {
    Ok(value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable(format!("missing stored string {name}")))?
        .to_owned())
}

fn optional(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn number(value: &Value, name: &str) -> Result<i64, R3StoreError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| unavailable(format!("missing stored integer {name}")))
}

fn unavailable(error: impl ToString) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new(error.to_string()))
}

fn write_new(path: &Path, bytes: &[u8], interrupt: &AtomicBool) -> io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let pending = path.with_extension("tmp");
    let _ = fs::remove_file(&pending);
    let mut file = match File::options().write(true).create_new(true).open(&pending) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    };
    if take_interrupt(bytes, &mut file, interrupt)? {
        return Err(io::Error::other("interrupted write"));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::rename(&pending, path) {
        Ok(()) => {
            sync_parent(path)?;
            Ok(true)
        }
        Err(_error) if path.exists() => Ok(false),
        Err(error) => Err(error),
    }
}

fn replace(path: &Path, bytes: &[u8], interrupt: &AtomicBool) -> io::Result<()> {
    let pending = path.with_extension("tmp");
    {
        let mut file = File::create(&pending)?;
        if take_interrupt(bytes, &mut file, interrupt)? {
            return Err(io::Error::other("interrupted write"));
        }
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if path.is_file() {
        let previous = path.with_extension("prev");
        fs::copy(path, &previous)?;
        File::open(&previous)?.sync_all()?;
    }
    fs::rename(&pending, path)?;
    sync_parent(path)
}

fn take_interrupt(bytes: &[u8], file: &mut File, interrupt: &AtomicBool) -> io::Result<bool> {
    if interrupt.swap(false, Ordering::SeqCst) {
        let torn = if bytes.is_empty() { bytes } else { &bytes[..1] };
        file.write_all(torn)?;
        file.sync_all()?;
        return Ok(true);
    }
    let _ = (bytes, file);
    Ok(false)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()?;
    }
    let _ = directory;
    Ok(())
}

fn read_record(path: &Path) -> io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) if serde_json::from_slice::<Value>(&bytes).is_ok() => Ok(bytes),
        Ok(_) => previous_record(path),
        Err(error) => Err(error),
    }
}

fn previous_record(path: &Path) -> io::Result<Vec<u8>> {
    match fs::read(path.with_extension("prev")) {
        Ok(bytes) if serde_json::from_slice::<Value>(&bytes).is_ok() => Ok(bytes),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "torn record")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(io::Error::new(io::ErrorKind::InvalidData, "torn record"))
        }
        Err(error) => Err(error),
    }
}
