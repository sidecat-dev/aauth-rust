#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[cfg(all(test, unix))]
mod failure_tests;
#[cfg(test)]
mod open_tests;
mod schema;
use aauth_rust_person_server::{
    AgentIdentity, Binding, MissionAudit, MissionAuditError, MissionEdit, Store, StoreError,
    TokenRecord, TokenReference,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction,
};
use schema::{BINDINGS, DIRECTED, MISSIONS, SUBJECTS, TOKENS};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io,
    panic::catch_unwind,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Maximum UTF-8 JSON bytes in one retained record, including field names and
/// escaping: 1 MiB. Larger fresh commits are InvalidRecord; oversized stored
/// values are Unavailable. This does not bound total database growth or memory
/// the caller already allocated for a record.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Local database-open failure, distinct from a caller's AAuth wire error.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Database bytes, path, permissions or a live competing owner prevent open.
    #[error(
        "store_unavailable: cannot open Person Server database; check path, permissions, health and other open owners: {0}"
    )]
    Database(#[from] redb::DatabaseError),
    /// Storage could not initialize the typed schema transaction.
    #[error(
        "store_unavailable: cannot initialize Person Server database; check storage health and write permissions"
    )]
    Unavailable,
    /// Integrity repair or an unwinding engine panic prevents trusted open.
    #[error(
        "store_unavailable: database integrity/open checks failed; preserve the file for diagnosis and restore a verified closed backup before resuming"
    )]
    Integrity,
    /// The platform or filesystem cannot durably synchronize the parent entry.
    #[error(
        "store_unavailable: cannot synchronize the database parent directory; use Unix with a filesystem supporting directory sync and check permissions/health: {0}"
    )]
    DirectoryDurability(#[source] io::Error),
    /// The database belongs to another application or an unsupported schema.
    #[error(
        "unsupported_store_schema: use an empty database or this adapter's schema version; preserve the existing file for supported migration"
    )]
    UnsupportedSchema,
}
impl OpenError {
    /// Stable local diagnostic code; never a Signature-Error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "unsupported_store_schema",
            _ => "store_unavailable",
        }
    }
}

/// Transactional file-backed Person Server storage. Clones share one database
/// and file lock. Every successful commit/revocation is immediately durable.
#[derive(Clone, Debug)]
pub struct RedbStore {
    database: Arc<Database>,
    path: PathBuf,
}
impl RedbStore {
    /// Open an existing supported database, or create one at an absent/empty file.
    /// The host must durably provision the parent directory; the database file
    /// must have one process owner. After initializing the file, every open
    /// synchronizes its parent before returning. A bare filename uses `.`.
    /// Startup scans engine integrity, then checks the schema. Its cost grows
    /// with retained pages; it does not verify every record's JSON or ancestry.
    /// Integrity repair, detected corruption and unwinding engine panics refuse
    /// open with store_unavailable. With panic=abort, panics cannot be caught.
    /// Integrity checks/recovery may modify the file even when open is refused;
    /// preserve a closed copy first when diagnosing suspected corruption.
    /// A schema commit can precede a failed directory sync: Err does not imply
    /// that no file was created or initialized, and no usable handle is returned.
    /// Unix with directory-sync support is required; other platforms are refused
    /// before database creation. The rest of the protocol workspace remains
    /// independent of this optional adapter's platform support.
    ///
    /// # Errors
    /// Returns a typed local failure for unavailable storage or a foreign schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        if !cfg!(unix) {
            return Err(OpenError::DirectoryDurability(io::Error::new(
                io::ErrorKind::Unsupported,
                "this adapter requires Unix directory synchronization",
            )));
        }
        let path = path.as_ref().to_owned();
        // redb can panic while opening damaged pages or parsing metadata, even
        // when its integrity check is used. No handle survives a failed open.
        catch_unwind(|| Self::from_database(Database::create(&path)?, path.clone()))
            .map_err(|_| OpenError::Integrity)?
    }
    fn from_database(database: Database, path: PathBuf) -> Result<Self, OpenError> {
        Self::from_database_with_sync(database, path, |parent| {
            std::fs::File::open(parent)?.sync_all()
        })
    }
    fn from_database_with_sync(
        mut database: Database,
        path: PathBuf,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<Self, OpenError> {
        if !database.check_integrity()? {
            // The engine reports false when it repaired something. Do not
            // silently admit possibly rolled-back state as an intact store.
            return Err(OpenError::Integrity);
        }
        schema::initialize(&database)?;
        sync_parent(parent_directory(&path)).map_err(OpenError::DirectoryDurability)?;
        Ok(Self {
            database: Arc::new(database),
            path,
        })
    }
    /// Configured database file path, useful for an explicit close/reopen.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn unavailable<E>(_: E) -> StoreError {
    StoreError::Unavailable
}
fn key(value: &impl Serialize) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(unavailable)
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(unavailable)
}
fn decode<T: DeserializeOwned>(value: &[u8]) -> Result<T, StoreError> {
    if value.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Unavailable);
    }
    serde_json::from_slice(value).map_err(unavailable)
}
struct RecordBuffer(Vec<u8>);
impl io::Write for RecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record exceeds MAX_RECORD_BYTES",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_record(record: &TokenRecord) -> Result<Vec<u8>, StoreError> {
    let mut buffer = RecordBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, record).map_err(|_| StoreError::InvalidRecord)?;
    Ok(buffer.0)
}
fn decode_binding(value: &[u8]) -> Result<Binding, StoreError> {
    let binding: Binding = decode(value)?;
    if binding.person_id.is_empty() {
        return Err(StoreError::Unavailable);
    }
    Ok(binding)
}
fn decode_record(value: &[u8], reference: &TokenReference) -> Result<TokenRecord, StoreError> {
    let record: TokenRecord = decode(value)?;
    record.validate_for_commit(false).map_err(unavailable)?;
    if record.token.reference != *reference {
        return Err(StoreError::Unavailable);
    }
    Ok(record)
}
fn get_bytes(
    transaction: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    let table = transaction.open_table(definition).map_err(unavailable)?;
    let value = table.get(key).map_err(unavailable)?;
    Ok(value.map(|v| v.value().to_vec()))
}
fn get_text(
    transaction: &WriteTransaction,
    definition: TableDefinition<&str, &str>,
    key: &str,
) -> Result<Option<String>, StoreError> {
    let table = transaction.open_table(definition).map_err(unavailable)?;
    let value = table.get(key).map_err(unavailable)?;
    Ok(value.map(|v| v.value().to_owned()))
}

// All checks and writes belong to the caller's one transaction. Keeping the
// staging operation separate also lets the unclosed-process test stop before
// the real commit, without an alternate serialization or test-only store path.
fn stage_issuance(
    transaction: &WriteTransaction,
    record: &TokenRecord,
    establish_binding: bool,
) -> Result<bool, StoreError> {
    let reference = &record.token.reference;
    let token_key = key(&(&reference.issuer, &reference.jti))?;
    if let Some(value) = get_bytes(transaction, TOKENS, &token_key)? {
        let existing = decode_record(&value, reference)?;
        return if existing == *record {
            Ok(false)
        } else {
            Err(StoreError::Conflict)
        };
    }
    record.validate_for_commit(establish_binding)?;
    let encoded = encode_record(record)?;
    if record.person_server.is_some() {
        let parent = &record
            .presented
            .as_ref()
            .ok_or(StoreError::InvalidRecord)?
            .reference;
        let parent_key = key(&(&parent.issuer, &parent.jti))?;
        let value =
            get_bytes(transaction, TOKENS, &parent_key)?.ok_or(StoreError::InvalidRecord)?;
        record.validate_federated_parent(&decode_record(&value, parent)?)?;
    }
    let issuer = record.binding_issuer();
    let binding_key = key(&(issuer, &record.principal.issuer, &record.principal.subject))?;
    let binding: Option<Binding> = get_bytes(transaction, BINDINGS, &binding_key)?
        .map(|v| decode_binding(&v))
        .transpose()?;
    match &binding {
        Some(binding) => binding.admits(record)?,
        None if !establish_binding => return Err(StoreError::MissingBinding),
        None if record.binding_generation != 0 => return Err(StoreError::InvalidRecord),
        None => {}
    }
    let directed_key = key(&(issuer, &record.person_id, &record.resource))?;
    let subject_key = key(&(issuer, &record.resource, &record.subject))?;
    if get_text(transaction, DIRECTED, &directed_key)?.is_some_and(|s| s != record.subject)
        || get_text(transaction, SUBJECTS, &subject_key)?.is_some_and(|p| p != record.person_id)
    {
        return Err(StoreError::Conflict);
    }
    if binding.is_none() {
        transaction
            .open_table(BINDINGS)
            .map_err(unavailable)?
            .insert(
                binding_key.as_str(),
                encode(&Binding::new(&record.person_id))?.as_slice(),
            )
            .map_err(unavailable)?;
    }
    transaction
        .open_table(DIRECTED)
        .map_err(unavailable)?
        .insert(directed_key.as_str(), record.subject.as_str())
        .map_err(unavailable)?;
    transaction
        .open_table(SUBJECTS)
        .map_err(unavailable)?
        .insert(subject_key.as_str(), record.person_id.as_str())
        .map_err(unavailable)?;
    transaction
        .open_table(TOKENS)
        .map_err(unavailable)?
        .insert(token_key.as_str(), encoded.as_slice())
        .map_err(unavailable)?;
    Ok(true)
}

impl Store for RedbStore {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        let key = key(&(issuer, &agent.issuer, &agent.subject))?;
        let read = self.database.begin_read().map_err(unavailable)?;
        let table = read.open_table(BINDINGS).map_err(unavailable)?;
        let value = table.get_owned(key.as_str()).map_err(unavailable)?;
        value.map(|v| decode_binding(v.value())).transpose()
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        let key = key(&(&reference.issuer, &reference.jti))?;
        let read = self.database.begin_read().map_err(unavailable)?;
        let table = read.open_table(TOKENS).map_err(unavailable)?;
        let value = table.get_owned(key.as_str()).map_err(unavailable)?;
        value
            .map(|v| decode_record(v.value(), reference))
            .transpose()
    }
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError> {
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        if stage_issuance(&transaction, &record, establish_binding)? {
            transaction.commit().map_err(unavailable)
        } else {
            Ok(())
        }
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        let binding_key = key(&(issuer, &agent.issuer, &agent.subject))?;
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        let mut binding: Binding = get_bytes(&transaction, BINDINGS, &binding_key)?
            .map(|v| decode_binding(&v))
            .transpose()?
            .ok_or(StoreError::MissingBinding)?;
        binding.revoked = true;
        transaction
            .open_table(BINDINGS)
            .map_err(unavailable)?
            .insert(binding_key.as_str(), encode(&binding)?.as_slice())
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)
    }
    fn replace_binding(
        &self,
        issuer: &str,
        agent: &AgentIdentity,
        person_id: &str,
    ) -> Result<Binding, StoreError> {
        let binding_key = key(&(issuer, &agent.issuer, &agent.subject))?;
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        let replacement = get_bytes(&transaction, BINDINGS, &binding_key)?
            .map(|v| decode_binding(&v))
            .transpose()?
            .ok_or(StoreError::MissingBinding)?
            .replacement(person_id)?;
        transaction
            .open_table(BINDINGS)
            .map_err(unavailable)?
            .insert(binding_key.as_str(), encode(&replacement)?.as_slice())
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        Ok(replacement)
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        let read = self.database.begin_read().map_err(unavailable)?;
        let table = read.open_table(TOKENS).map_err(unavailable)?;
        let mut records = Vec::new();
        for item in table.range::<&str>(..).map_err(unavailable)? {
            let (_key, value) = item.map_err(unavailable)?;
            let record: TokenRecord = decode(value.value())?;
            record
                .validate_for_commit(false)
                .map_err(|_| StoreError::Unavailable)?;
            records.push(record);
        }
        Ok(records)
    }
    fn write_mission_audit(&self, audit: &MissionAudit) -> Result<(), StoreError> {
        audit.validate()?;
        let encoded = encode(audit)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(StoreError::InvalidRecord);
        }
        let key = key(&(
            &audit.person_server,
            &audit.owner_issuer,
            &audit.owner_subject,
            &audit.s256,
        ))?;
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        if let Some(existing) = get_bytes(&transaction, MISSIONS, &key)? {
            let current: MissionAudit = decode(&existing)?;
            return if current == *audit {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        transaction
            .open_table(MISSIONS)
            .map_err(unavailable)?
            .insert(key.as_str(), encoded.as_slice())
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)
    }
    fn read_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
    ) -> Result<Option<MissionAudit>, StoreError> {
        let key = key(&(person_server, owner_issuer, owner_subject, s256))?;
        let read = self.database.begin_read().map_err(unavailable)?;
        let table = read.open_table(MISSIONS).map_err(unavailable)?;
        let Some(value) = table.get(key.as_str()).map_err(unavailable)? else {
            return Ok(None);
        };
        let audit: MissionAudit = decode(value.value())?;
        audit.validate()?;
        Ok(Some(audit))
    }
    fn edit_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
        edit: MissionEdit,
    ) -> Result<MissionAudit, MissionAuditError> {
        let key = key(&(person_server, owner_issuer, owner_subject, s256))
            .map_err(|_| MissionAuditError::Unavailable)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| MissionAuditError::Unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| MissionAuditError::Unavailable)?;
        let Some(existing) =
            get_bytes(&transaction, MISSIONS, &key).map_err(|_| MissionAuditError::Unavailable)?
        else {
            return Err(MissionAuditError::NotFound);
        };
        let mut audit: MissionAudit =
            decode(&existing).map_err(|_| MissionAuditError::Unavailable)?;
        audit.apply(edit)?;
        let encoded = encode(&audit).map_err(|_| MissionAuditError::Unavailable)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(MissionAuditError::Invalid);
        }
        transaction
            .open_table(MISSIONS)
            .map_err(|_| MissionAuditError::Unavailable)?
            .insert(key.as_str(), encoded.as_slice())
            .map_err(|_| MissionAuditError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| MissionAuditError::Unavailable)?;
        Ok(audit)
    }
}
