//! Directory [`R3DocumentStore`](crate::R3DocumentStore).
//!
//! A published file is the class document. The bytes are written to a
//! temporary file, synchronized, and renamed. An exact repeat is accepted.
//! A different record at the same URI is left untouched. A torn current file
//! is unavailable. Documents are create-only, so there is no previous file
//! to recover. This is a process exit and an interrupted write. It is not
//! power loss.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use aauth_rust_r3::{Reference, digest};
use serde_json::{Value, json};

use super::r3_class::{R3DocumentRecord, R3DocumentStore, R3HostError, R3StoreError};

/// Class documents, one immutable file per URI.
pub struct DirectoryDocumentStore {
    directory: PathBuf,
    serial: Mutex<()>,
    interrupt: AtomicBool,
}

impl DirectoryDocumentStore {
    /// Open or create `directory`. Documents already there stay in force.
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

    /// Fail the next new publish before its rename. An existing document
    /// stays the record. This is a host test hook and is not written down.
    pub fn interrupt_next_write(&self) {
        self.interrupt.store(true, Ordering::SeqCst);
    }

    fn record_path(&self, uri: &str) -> PathBuf {
        self.directory
            .join(format!("c-{}.json", digest(uri.as_bytes())))
    }

    fn encode(record: &R3DocumentRecord) -> Vec<u8> {
        json!({
            "uri": record.reference.uri(),
            "digest": record.reference.digest(),
            "exact_json": record.exact_json,
            "person_server": record.person_server,
            "auth_token_issuer": record.auth_token_issuer,
            "auth_token_issuer_document": record.auth_token_issuer_document,
            "resource_token_jti": record.resource_token_jti,
            "resource_token": record.resource_token,
            "presented_jti": record.presented_jti,
            "subject": record.subject,
            "agent_jkt": record.agent_jkt,
            "tenant": record.tenant,
            "account": record.account,
            "scope": record.scope,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        })
        .to_string()
        .into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<R3DocumentRecord, R3StoreError> {
        let value: Value = serde_json::from_slice(bytes).map_err(unavailable)?;
        Ok(R3DocumentRecord {
            reference: reference(&value)?,
            exact_json: serde_json::from_value(value["exact_json"].clone()).map_err(unavailable)?,
            person_server: text(&value, "person_server")?,
            auth_token_issuer: text(&value, "auth_token_issuer")?,
            auth_token_issuer_document: text(&value, "auth_token_issuer_document")?,
            resource_token_jti: text(&value, "resource_token_jti")?,
            resource_token: text(&value, "resource_token")?,
            presented_jti: text(&value, "presented_jti")?,
            subject: text(&value, "subject")?,
            agent_jkt: text(&value, "agent_jkt")?,
            tenant: optional(&value, "tenant"),
            account: optional(&value, "account"),
            scope: optional(&value, "scope"),
            issued_at: number(&value, "issued_at")?,
            expires_at: number(&value, "expires_at")?,
        })
    }
}

impl R3DocumentStore for DirectoryDocumentStore {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        let _serial = self.serial.lock().map_err(|_| unavailable("poisoned"))?;
        let bytes = Self::encode(record);
        let path = self.record_path(record.reference.uri());
        if !write_new(&path, &bytes, &self.interrupt).map_err(unavailable)? {
            match fs::read(&path) {
                Ok(existing) if existing == bytes => return Ok(()),
                Ok(_) => return Err(R3StoreError::Conflict),
                Err(error) => return Err(unavailable(error)),
            }
        }
        sync_dir(&self.directory).map_err(unavailable)?;
        Ok(())
    }

    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError> {
        let path = self.record_path(uri);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        if serde_json::from_slice::<Value>(&bytes).is_err() {
            return Err(unavailable("torn document"));
        }
        let record = Self::decode(&bytes)?;
        if record.reference.uri() != uri {
            return Err(unavailable("stored key does not name this URI"));
        }
        Ok(Some(record))
    }
}

fn unavailable(error: impl ToString) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new(error.to_string()))
}

fn reference(value: &Value) -> Result<Reference, R3StoreError> {
    Reference::new(text(value, "uri")?, text(value, "digest")?).map_err(unavailable)
}

fn text(value: &Value, name: &str) -> Result<String, R3StoreError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| unavailable(format!("missing stored string {name}")))
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
