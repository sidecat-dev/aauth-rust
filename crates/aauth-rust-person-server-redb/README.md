# aauth-rust-person-server-redb

Durable storage for an AAuth Person Server: the bindings between agents and
people, and the lineage of every token the server issued, kept in one
transactional [redb](https://crates.io/crates/redb) file. Use it in place of
`MemoryStore` when your Person Server must keep its records across restarts.
It works on Unix only.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-person-server@0.1.0-alpha.28 aauth-rust-person-server-redb@0.1.0-alpha.28
# used by the example to play the other parties
cargo add aauth-rust-agent@0.1.0-alpha.28 aauth-rust-agent-provider@0.1.0-alpha.28 aauth-rust-core@0.1.0-alpha.28 aauth-rust-jose@0.1.0-alpha.28 http@1 tempfile@3
```

The example issues a Person token, restarts, and finds the agent's binding
still there.

```rust
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Config, Grant, Person, PersonRequest, PersonServer,
    Policy, PolicyError, Store,
};
use aauth_rust_person_server_redb::RedbStore;
use http::Request;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PS: &str = "https://ps.example";

struct People;
impl Policy for People {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person { id: "person-1".into(), subject: "u-7f3c9a".into(), tenant: None })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?; // your service uses a directory it owns
    let path = directory.path().join("person.redb");

    let provider = AgentProvider::new("https://ap.example", "ap-1", SigningKey::generate())?;
    let agent = enroll(&provider)?;
    let providers =
        AgentProviderKeys::from_documents("https://ap.example", &provider.metadata()?, &provider.jwks()?)?;

    // Open the file and hand a clone to the Person Server; clones share it.
    let store = RedbStore::open(&path)?;
    let ids = AtomicU64::new(0); // a durable server keeps its token ids unique across restarts
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::generate()),
        providers,
        store.clone(),
        People,
        now,
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?;

    // The agent gets a Person token, which binds it to person-1.
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/person"))
        .header("content-type", "application/json")
        .body(br#"{"resource":"https://api.example"}"#.to_vec())?;
    agent.sign(&mut request, now())?;
    assert_eq!(ps.handle(&request).status(), 200);

    // While the file is open, a second owner is refused.
    assert!(RedbStore::open(&path).is_err());

    // Restart: drop every clone, then open the file again.
    drop(ps);
    drop(store);
    let reopened = RedbStore::open(&path)?;
    let assistant = AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:assistant@ap.example".into(),
    };
    let binding = reopened.binding(PS, &assistant)?.ok_or("binding lost")?;
    println!("{} still acts for {}", assistant.subject, binding.person_id);
    Ok(())
}

fn enroll(provider: &AgentProvider) -> Result<Agent, Box<dyn Error>> {
    let key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(), // the issuer's well-known metadata document
        sub: "aauth:assistant@ap.example".into(),
        jti: "assistant-1".into(),
        iat: now(),
        exp: now() + 3600,
        cnf: Confirmation { jwk: key.public_jwk() }, // binds the token to the agent's key
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
```

```text
aauth:assistant@ap.example still acts for person-1
```

## Why use it

- **Every write is durable when it returns.** Each commit and revocation is
  one redb transaction with immediate durability, and a crash never leaves a
  partial binding or token record visible.
- **It refuses rather than guesses.** Open checks the file's integrity and
  schema first. A damaged file, another application's database, or a second
  live owner fails with `store_unavailable` or `unsupported_store_schema`
  instead of starting empty.
- **No C dependencies, one file.** No database server to run. The tradeoff: one
  process owns the file, so the Person Server runs as one process per file.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- Unix only, on a filesystem that supports syncing a directory. `open` fails
  on other platforms; use another `Store` there.
- One process owns a file at a time. Drop every clone before reopening.
- Records are kept indefinitely, each up to 1 MiB, and total size has no
  bound or reclamation. Backups, permissions and disk space are yours.
- It stores no signing keys and no token bytes: only identities and lineage.

## Specifications

Stores the Person Server state of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e).
It passes the storage contract that `aauth-rust-person-server` ships for every
store.

## Links

- [API documentation](https://docs.rs/aauth-rust-person-server-redb)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::person_server_redb` in the umbrella crate, with the rest of the family
- [Person Server guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/roles/person-server.md)
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
