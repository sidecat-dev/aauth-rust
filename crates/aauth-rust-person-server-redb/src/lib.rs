//! Durable Person Server bindings and issuance through transactional redb storage.
//!
//! One database file has one process owner. Clone the store to share its database
//! with concurrent handlers; drop every clone before reopening. Successful writes
//! use immediate durability. Files retain internal person identity and all token
//! lineage indefinitely; hosts own filesystem permissions, backup and capacity.
//! No signing keys or compact credential bytes are stored.
//!
//! ```
//! use aauth_rust_person_server_redb::RedbStore;
//! let database_path = std::path::Path::new("person.redb");
//! # let directory = tempfile::tempdir()?;
//! # let database_path = directory.path().join("person.redb");
//! let store = RedbStore::open(&database_path)?;
//! // Give store.clone() to PersonServer::new; clones share transactions.
//! let path = store.path().to_owned();
//! drop(store);
//! let reopened = RedbStore::open(path)?;
//! # drop(reopened);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]

mod schema;
use aauth_rust_person_server::{
    AgentIdentity, Binding, Store, StoreError, TokenRecord, TokenReference,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction,
};
use schema::{BINDINGS, DIRECTED, SUBJECTS, TOKENS};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

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
    /// The parent directory must exist; the database file must have one process
    /// owner. Ordinary startup checks the schema, not all retained records.
    ///
    /// # Errors
    /// Returns a typed local failure for unavailable storage or a foreign schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref().to_owned();
        Self::from_database(Database::create(&path)?, path)
    }
    fn from_database(database: Database, path: PathBuf) -> Result<Self, OpenError> {
        schema::initialize(&database)?;
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
    serde_json::from_slice(value).map_err(unavailable)
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

impl Store for RedbStore {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        let key = key(&(issuer, &agent.issuer, &agent.subject))?;
        let read = self.database.begin_read().map_err(unavailable)?;
        let table = read.open_table(BINDINGS).map_err(unavailable)?;
        let value = table.get_owned(key.as_str()).map_err(unavailable)?;
        let binding: Option<Binding> = value.map(|v| decode(v.value())).transpose()?;
        if binding.as_ref().is_some_and(|b| b.person_id.is_empty()) {
            return Err(StoreError::Unavailable);
        }
        Ok(binding)
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
        let reference = &record.token.reference;
        let token_key = key(&(&reference.issuer, &reference.jti))?;
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        if let Some(value) = get_bytes(&transaction, TOKENS, &token_key)? {
            let existing = decode_record(&value, reference)?;
            return if existing == record {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        record.validate_for_commit(establish_binding)?;
        let issuer = &reference.issuer;
        let binding_key = key(&(issuer, &record.principal.issuer, &record.principal.subject))?;
        let binding: Option<Binding> = get_bytes(&transaction, BINDINGS, &binding_key)?
            .map(|v| decode(&v))
            .transpose()?;
        match &binding {
            Some(binding) if binding.revoked => return Err(StoreError::RevokedBinding),
            Some(binding) if binding.person_id != record.person_id => {
                return Err(StoreError::Conflict);
            }
            None if !establish_binding => return Err(StoreError::MissingBinding),
            _ => {}
        }
        let directed_key = key(&(issuer, &record.person_id, &record.resource))?;
        let subject_key = key(&(issuer, &record.resource, &record.subject))?;
        if get_text(&transaction, DIRECTED, &directed_key)?.is_some_and(|s| s != record.subject)
            || get_text(&transaction, SUBJECTS, &subject_key)?
                .is_some_and(|p| p != record.person_id)
        {
            return Err(StoreError::Conflict);
        }
        if binding.is_none() {
            transaction
                .open_table(BINDINGS)
                .map_err(unavailable)?
                .insert(
                    binding_key.as_str(),
                    encode(&Binding {
                        person_id: record.person_id.clone(),
                        revoked: false,
                    })?
                    .as_slice(),
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
            .insert(token_key.as_str(), encode(&record)?.as_slice())
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        let binding_key = key(&(issuer, &agent.issuer, &agent.subject))?;
        let mut transaction = self.database.begin_write().map_err(unavailable)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(unavailable)?;
        let mut binding: Binding = get_bytes(&transaction, BINDINGS, &binding_key)?
            .map(|v| decode(&v))
            .transpose()?
            .ok_or(StoreError::MissingBinding)?;
        if binding.person_id.is_empty() {
            return Err(StoreError::Unavailable);
        }
        binding.revoked = true;
        transaction
            .open_table(BINDINGS)
            .map_err(unavailable)?
            .insert(binding_key.as_str(), encode(&binding)?.as_slice())
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)
    }
}
