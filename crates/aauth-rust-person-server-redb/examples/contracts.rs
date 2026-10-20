use aauth_rust_person_server::storetest;
use aauth_rust_person_server_redb::RedbStore;
use std::cell::Cell;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only disposable databases: these contracts intentionally change state.
    let directory = tempfile::tempdir()?;
    let sequence = Cell::new(0);
    let fresh = || {
        let id = sequence.get();
        sequence.set(id + 1);
        RedbStore::open(directory.path().join(format!("store-{id}.redb"))).unwrap()
    };
    storetest::check_store_contract(fresh).map_err(std::io::Error::other)?;
    storetest::check_persistence_contract(fresh, |store| {
        let path = store.path().to_owned();
        drop(store);
        RedbStore::open(path).map_err(|error| error.to_string())
    })
    .map_err(std::io::Error::other)?;
    println!("logical-store=pass reopen-store=pass");
    Ok(())
}
