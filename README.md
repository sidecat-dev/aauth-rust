# AAuth for Rust

Rust libraries for [AAuth](https://github.com/dickhardt/AAuth), a protocol that
tells an API which software agent is calling it and on whose behalf. The agent
signs every HTTP request with its own key. The API checks that signature and
the token sent with it. When the API needs more than the agent's identity, it
asks for a token that names the person the agent acts for and what that person
allowed.

There is one crate for each AAuth role: Agent, Agent Provider, Resource (the
API), Person Server, Access Server and Supervision Server. The crates implement
the core protocol and HTTP Signature Keys, and the R3, Budgets, Events and
Supervision drafts, each with the limits listed in
[CONFORMANCE.md](CONFORMANCE.md). The Bootstrap draft, which covers how an agent
enrolls with its provider, is not implemented.
[aauth-go](https://gitlab.com/sidecat-dev/aauth-go) implements the same drafts
in Go, makes the same choices where the drafts leave room, and is tested against
this library.

The libraries open no network connections. Your service sends and receives the
HTTP messages, fetches other servers' keys and stores state; the libraries sign,
verify and decide.

This is an alpha, version `v0.1.0-alpha.17`. The crates are not on crates.io:
you build against a checkout of a release tag. APIs can change from one release
to the next, and each release's notes list the changes.

## Install

You need [rustup](https://rustup.rs/) and a C compiler: `build-essential` on
Linux, the Xcode Command Line Tools on macOS, or the Visual Studio C++ Build
Tools on Windows. The examples' TLS library uses it; the libraries themselves
are pure Rust. The checkout pins Rust 1.99.1, which rustup downloads on first
use (several hundred MB).

```sh
git clone https://gitlab.com/sidecat-dev/aauth-rust.git
cd aauth-rust
git checkout v0.1.0-alpha.17
```

To use the crates in your own project, depend on them by path. The recipe below
starts in the checkout and creates a new project next to it,
`../aauth-service`, whose `src/main.rs` is this program. An Agent Provider
issues a token, an Agent signs a request with it, and a Resource verifies the
request, all in one process. You can run the same program in the checkout with
`cargo run --locked -p aauth-rust-resource --example library`.

```rust
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, Decision};
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let issuer = "https://ap.example";
    let provider = AgentProvider::new(issuer, "ap-1", SigningKey::generate())?;
    let agent_key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent@ap.example".into(),
        jti: "example-issuance-1".into(),
        iat: now,
        exp: now + 300,
        cnf: Confirmation {
            jwk: agent_key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    // This application trusts this provider; a network host supplies admitted documents.
    let keys = AgentProviderKeys::from_documents(issuer, &provider.metadata()?, &provider.jwks()?)?;
    let resource = AgentIdentityResource::new(
        "https://resource.example/whoami",
        keys,
        |token: &VerifiedAgentToken, _request: &Request<Vec<u8>>| {
            token.claims().sub == "aauth:Agent@ap.example"
        },
    )?;
    let agent = Agent::new(agent_key, token)?;
    let mut request = Request::builder()
        .uri("https://resource.example/whoami")
        .body(Vec::new())?;
    agent.sign(&mut request, now)?;
    match resource.authorize(&request, now) {
        Decision::Granted(token) => println!("verified {}", token.claims().sub),
        other => return Err(format!("request refused: {}", other.into_response().status()).into()),
    }
    Ok(())
}
```

The recipe assumes the checkout directory is named `aauth-rust`, and stops if
`../aauth-service` already exists. It copies the checkout's
`rust-toolchain.toml`, because a path dependency does not choose your toolchain,
and creates a lockfile, because your project does not use the checkout's.

<!-- consumer-bootstrap-setup:begin -->
```sh
(
set -eu
mkdir ../aauth-service
mkdir ../aauth-service/src
cp rust-toolchain.toml ../aauth-service/
cp crates/aauth-rust-resource/examples/library.rs ../aauth-service/src/main.rs
cat > ../aauth-service/Cargo.toml <<'TOML'
[package]
name = "aauth-service"
version = "0.1.0"
edition = "2024"
rust-version = "1.99"
publish = false

[workspace]

[dependencies]
aauth-rust-agent = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-agent" }
aauth-rust-agent-provider = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-agent-provider" }
aauth-rust-core = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-core" }
aauth-rust-jose = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-jose" }
aauth-rust-resource = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-resource" }
http = "1"
TOML
cd ../aauth-service
rustup show active-toolchain
test ! -e Cargo.lock
cargo generate-lockfile
)
```
<!-- consumer-bootstrap-setup:end -->

Then build it, and keep the new `Cargo.lock` with your source:

<!-- consumer-bootstrap-build:begin -->
```sh
(cd ../aauth-service && cargo build --locked --jobs 2)
```
<!-- consumer-bootstrap-build:end -->

The first build downloads crates from crates.io. To run a Person Server or an
Access Server as well, add these lines to the same `[dependencies]` table
before you generate the lockfile:

```toml
aauth-rust-person-server = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-person-server" }
aauth-rust-access-server = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-access-server" }
```

| Crate | What it does |
| --- | --- |
| `aauth-rust-agent` | Signs an agent's requests and checks the tokens it receives |
| `aauth-rust-agent-provider` | Issues Agent tokens and publishes the provider's keys |
| `aauth-rust-resource` | Checks requests to an API before your handler runs |
| `aauth-rust-person-server` | Binds agents to people and issues Person and Auth tokens |
| `aauth-rust-person-server-redb` | File-backed storage for a Person Server, on Unix |
| `aauth-rust-access-server` | Issues Auth tokens for a Resource from its own policy |
| `aauth-rust-supervision-server` | Decides an agent's requests in its person's place |
| `aauth-rust-r3`, `aauth-rust-budgets` | R3 documents and Budgets objects, used by the roles |
| `aauth-rust-core`, `aauth-rust-signature-key`, `aauth-rust-jose` | Tokens, HTTP signatures and keys, used by the roles |

## Get started

```sh
cargo run --locked -p aauth-rust-resource --example getting-started
```

This starts an Agent Provider and an API on loopback ports, with TLS, and has
an agent call the API. [Get started](docs/getting-started.md) walks through
the output and the code.

## Documentation

- [docs/](docs/README.md): how AAuth works, a guide for each role and each
  draft, and what to do about each error.
- [USE-IN-YOUR-SERVICE.md](USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](CONFORMANCE.md): what the libraries do and do not do, and
  the tests that show it.
- [INTERPRETATIONS.md](INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](SPECIFICATIONS.md): the exact draft text implemented.
- [SECURITY.md](SECURITY.md): how to report a vulnerability, and what your
  service is responsible for.
- [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRIBUTING.md](CONTRIBUTING.md):
  how the code is organized and how to change it.

## License

MIT; see [LICENSE](LICENSE). Every crate in the workspace carries the same
license file. Most direct dependencies are MIT OR Apache-2.0. These locked
direct dependencies are not MIT-only: `ed25519-dalek` 2.2.0 is BSD-3-Clause,
`ring` 0.17.14 is Apache-2.0 AND ISC, and `rustls-webpki` 0.103.15 is ISC.
