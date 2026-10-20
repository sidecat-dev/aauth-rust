use crate::OpenError;
use redb::{Database, Durability, ReadableTable, TableDefinition, TableHandle};
use std::collections::BTreeSet;

const META: TableDefinition<&str, u64> = TableDefinition::new("aauth_ps_metadata");
pub(super) const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("aauth_ps_tokens");
pub(super) const BINDINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("aauth_ps_bindings");
pub(super) const DIRECTED: TableDefinition<&str, &str> = TableDefinition::new("aauth_ps_directed");
pub(super) const SUBJECTS: TableDefinition<&str, &str> = TableDefinition::new("aauth_ps_subjects");

fn table_error(error: redb::TableError) -> OpenError {
    match error {
        redb::TableError::Storage(_) => OpenError::Unavailable,
        _ => OpenError::UnsupportedSchema,
    }
}
pub(super) fn initialize(database: &Database) -> Result<(), OpenError> {
    let mut transaction = database.begin_write().map_err(|_| OpenError::Unavailable)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| OpenError::Unavailable)?;
    let names: BTreeSet<_> = transaction
        .list_tables()
        .map_err(|_| OpenError::Unavailable)?
        .map(|t| t.name().to_owned())
        .collect();
    if transaction
        .list_multimap_tables()
        .map_err(|_| OpenError::Unavailable)?
        .next()
        .is_some()
    {
        return Err(OpenError::UnsupportedSchema);
    }
    let new = names.is_empty();
    let expected: BTreeSet<_> = [
        META.name(),
        TOKENS.name(),
        BINDINGS.name(),
        DIRECTED.name(),
        SUBJECTS.name(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if !new && names != expected {
        return Err(OpenError::UnsupportedSchema);
    }
    {
        let mut meta = transaction.open_table(META).map_err(table_error)?;
        if new {
            meta.insert("schema_version", 1)
                .map_err(|_| OpenError::Unavailable)?;
        } else if meta
            .get("schema_version")
            .map_err(|_| OpenError::Unavailable)?
            .map(|v| v.value())
            != Some(1)
        {
            return Err(OpenError::UnsupportedSchema);
        }
    }
    transaction.open_table(TOKENS).map_err(table_error)?;
    transaction.open_table(BINDINGS).map_err(table_error)?;
    transaction.open_table(DIRECTED).map_err(table_error)?;
    transaction.open_table(SUBJECTS).map_err(table_error)?;
    transaction.commit().map_err(|_| OpenError::Unavailable)
}
