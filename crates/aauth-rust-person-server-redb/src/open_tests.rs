use super::*;
#[cfg(unix)]
use std::{cell::Cell, io};

#[cfg(unix)]
#[test]
fn parent_directory_includes_the_current_directory_for_a_bare_relative_filename() {
    assert_eq!(parent_directory(Path::new("person.redb")), Path::new("."));
    assert_eq!(parent_directory(Path::new("./person.redb")), Path::new("."));
    assert_eq!(
        parent_directory(Path::new("state/person.redb")),
        Path::new("state")
    );
}

#[cfg(unix)]
#[test]
fn directory_sync_failure_refuses_open_after_schema_initialization_and_releases_the_owner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let called = Cell::new(false);
    let error = RedbStore::from_database_with_sync(
        Database::create(&path).unwrap(),
        path.clone(),
        |parent| {
            assert_eq!(parent, directory.path());
            called.set(true);
            Err(io::Error::other("injected parent-directory sync failure"))
        },
    )
    .unwrap_err();
    assert!(called.get());
    assert_eq!(error.code(), "store_unavailable");
    assert!(matches!(error, OpenError::DirectoryDurability(_)));
    assert!(error.to_string().contains("parent directory"));
    // The initialized schema is readable, but no usable store was acknowledged
    // until the directory step succeeded. The failed owner must have closed.
    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    let meta = read
        .open_table(TableDefinition::<&str, u64>::new("aauth_ps_metadata"))
        .unwrap();
    assert_eq!(meta.get("schema_version").unwrap().unwrap().value(), 1);
    drop(meta);
    drop(read);
    drop(database);
    RedbStore::open(path).unwrap();
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_is_refused_without_creating_a_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let error = RedbStore::open(&path).unwrap_err();
    assert!(matches!(error, OpenError::DirectoryDurability(_)));
    assert_eq!(error.code(), "store_unavailable");
    assert!(!path.exists());
}
