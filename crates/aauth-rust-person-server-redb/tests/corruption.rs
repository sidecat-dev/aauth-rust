#![cfg(unix)]

mod support;
use aauth_rust_person_server::Store;
use aauth_rust_person_server_redb::RedbStore;
use std::{fs, panic::catch_unwind};
use support::record;

#[test]
fn open_checks_data_pages_before_accepting_an_otherwise_readable_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let expected = record("retained");
    let store = RedbStore::open(&path).unwrap();
    store.commit(expected.clone(), true).unwrap();
    drop(store);
    let mut bytes = fs::read(&path).unwrap();
    let encoded = serde_json::to_vec(&expected).unwrap();
    let offset = bytes
        .windows(encoded.len())
        .position(|w| w == encoded)
        .unwrap();
    bytes[offset] ^= 1;
    fs::write(&path, bytes).unwrap();
    let outcome = catch_unwind(|| RedbStore::open(&path));
    let error = outcome
        .expect("corruption must not unwind past open")
        .unwrap_err();
    assert_eq!(error.code(), "store_unavailable");
}

#[test]
fn flipped_bits_and_zeroed_page_prefixes_never_escape_open_as_panics_or_bad_records() {
    let directory = tempfile::tempdir().unwrap();
    let pristine = directory.path().join("pristine.redb");
    let expected = record("retained");
    let store = RedbStore::open(&pristine).unwrap();
    store.commit(expected.clone(), true).unwrap();
    drop(store);
    let bytes = fs::read(pristine).unwrap();
    let mut panicked = Vec::new();
    let mut refused = 0;
    let mut intact = 0;
    for offset in (0..bytes.len()).step_by(4096) {
        for zero in [false, true] {
            let path = directory
                .path()
                .join(format!("damaged-{offset}-{zero}.redb"));
            let mut damaged = bytes.clone();
            if zero {
                let end = (offset + 512).min(damaged.len());
                damaged[offset..end].fill(0);
            } else {
                damaged[offset] ^= 1;
            }
            fs::write(&path, damaged).unwrap();
            let outcome = catch_unwind(|| match RedbStore::open(&path) {
                Ok(store) => {
                    assert_eq!(
                        store.token(&expected.token.reference).unwrap(),
                        Some(expected.clone())
                    );
                    false
                }
                Err(error) => {
                    assert_eq!(error.code(), "store_unavailable");
                    true
                }
            });
            match outcome {
                Ok(true) => refused += 1,
                Ok(false) => intact += 1,
                Err(_) => panicked.push((offset, zero)),
            }
        }
    }
    println!(
        "page mutations: refused={refused}, intact={intact}, escaped_panics={}",
        panicked.len()
    );
    assert!(
        refused >= 8,
        "fixture must exercise several damaged live pages"
    );
    // Changes confined to unused space can leave the retained state intact.
    assert!(
        panicked.is_empty(),
        "open/record access panicked at {panicked:?}"
    );
}
