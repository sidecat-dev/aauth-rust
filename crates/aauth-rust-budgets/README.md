# aauth-rust-budgets

Spending caps for AAuth: the budget an Auth token grants an agent at an API,
the meter the API keeps against it, and the `AAuth-Budget` header that tells
the agent what is left. The Resource, Person Server and Access Server crates
use it when you turn budgets on; use it directly to meter calls in your API.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-budgets@0.1.0-alpha.29
```

```rust
use aauth_rust_budgets::{Budget, ChargeError, Ledger, Refusal, TokenAccount};
use std::error::Error;

const PS: &str = "https://ps.example";

fn main() -> Result<(), Box<dyn Error>> {
    let now = 1_793_000_000; // Unix seconds, from your clock

    // The verified Auth token "auth-1" grants 5.00 USD at this API.
    let mut ledger = Ledger::new();
    ledger.open(TokenAccount {
        jti: "auth-1".into(),
        grant: Budget::new(500, "USD", 2)?,
        ps: PS.into(),
        sub: "u-7f3c9a".into(),
        aud: "https://api.example".into(),
        iss: PS.into(),
        jkt: "thumbprint-of-the-agent-key".into(), // the agent key's JWK thumbprint
        tenant: None,
        mission: None,
    })?;

    // A call that may cost up to 2.00 holds that much, then costs 1.25.
    let hold = ledger.reserve(PS, "auth-1", 200).map_err(|e| format!("{e:?}"))?;
    let header = ledger.commit(&hold, 125, now).map_err(|e| format!("{e:?}"))?;
    println!("AAuth-Budget: {header}");

    // A call that may cost 4.00 does not fit in the 3.75 left; nothing is held.
    match ledger.reserve(PS, "auth-1", 400) {
        Err(ChargeError::Refused(Refusal::Insufficient { remaining, header, .. })) => {
            assert_eq!(remaining, 375);
            println!("AAuth-Budget: {header}");
        }
        other => return Err(format!("expected a refusal, got {other:?}").into()),
    }
    Ok(())
}
```

```text
AAuth-Budget: remaining=375, cost=125, unit="USD", decimals=2
AAuth-Budget: remaining=375, required=400, unit="USD", decimals=2
```

## Why use it

- **A hard cap.** A call reserves its maximum cost before it runs and commits
  the actual cost after. Two calls can never spend the same money, and a
  refused reservation changes nothing.
- **The headers are ready to send.** Commits and refusals return the exact
  `AAuth-Budget` value for the response. The crate also parses the header on
  the agent's side, narrows an offered budget to a cap, and answers usage
  queries from the Person Server or Access Server.
- **A meter that survives a restart.** `Ledger::new` keeps the meter in
  memory. `Ledger::open_directory` keeps it in a directory, and the next
  process continues the spend. That covers a process exit or an interrupted
  write, not power loss.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- Amounts are integers in the grant's own unit and decimal scale.
- A `Ledger` belongs to one process: share it behind a mutex. A directory
  ledger takes no file lock, so open each directory from one process at a
  time.
- It never opens a connection, and it does not verify tokens: open an
  account only for an Auth token your Resource has already verified.

## Specifications

Implements the Budgets draft (`draft-hardt-aauth-budgets`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e).

## Links

- [API documentation](https://docs.rs/aauth-rust-budgets)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::budgets` in the umbrella crate, with the rest of the family
- [Budgets guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/features/budgets.md): turning budgets on in each role
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
