# AAuth for Rust

Rust libraries for [AAuth](https://github.com/dickhardt/AAuth), a protocol that
tells an API which software agent is calling it and on whose behalf. The agent
signs every HTTP request with its own key. The API checks that signature and
the token sent with it. When the API needs more than the agent's identity, it
asks for a token that names the person the agent acts for and what that person
allowed.

There is a crate for each party in the protocol: the agent, the Agent Provider
that vouches for it, the API (called a Resource), and the servers that speak
for the person or for the API. [How AAuth works](docs/how-aauth-works.md)
introduces them.

The protocol libraries open no network connections. Your service sends and
receives the HTTP messages, fetches other servers' keys and stores state; the
libraries sign, check and decide. One opt-in crate, `aauth-rust-discovery`,
does open connections: it fetches other servers' keys and delivers
revocations over HTTPS, refusing private addresses and other unsafe
destinations unless you allow them.

## Get started

You need [git](https://git-scm.com/), [rustup](https://rustup.rs/) and a C
compiler: `build-essential` on Linux, the Xcode Command Line Tools on macOS, or
the Visual Studio C++ Build Tools on Windows. The TLS library of the examples
and of `aauth-rust-discovery` uses the compiler; the other libraries are pure
Rust.

```sh
git clone https://gitlab.com/sidecat-dev/aauth-rust.git
cd aauth-rust
git checkout v0.1.0-alpha.26
cargo run --locked -p aauth-rust-resource --example getting-started
```

The first run downloads the pinned Rust 1.99.1 (several hundred MB) and the
dependencies. The example starts an Agent Provider and an API on loopback
ports, with TLS, and has an agent call the API.
[Get started](docs/getting-started.md) walks through the output and the code.

## Install

The crates are not on crates.io. Your project depends on a release tag, either
fetched by Cargo from git or in a checkout next to your project. Your project
needs Rust 1.99 or later.

From git, list each crate you use with the repository and the tag:

<!-- checked: git-dependencies -->
```toml
[dependencies]
aauth-rust-agent = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
aauth-rust-agent-provider = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
aauth-rust-core = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
aauth-rust-discovery = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
aauth-rust-jose = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
aauth-rust-resource = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.26" }
http = "1"
```

The other crates in the table below are added the same way.

From a checkout, by path: run the commands below from inside the checkout.
They create a new project next to it, `../aauth-service`, and copy
`crates/aauth-rust-resource/examples/library.rs` into it as `src/main.rs`.
That program, shown here, has an Agent Provider issue a token, an agent sign a
request with it, and a Resource check the request, all in one process. In a
real API, also serve `resource.metadata()` at
`/.well-known/aauth-resource.json`; the [Resource](docs/roles/resource.md)
guide shows how.

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
    // This program trusts this provider. A service fetches these documents over HTTPS.
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

The commands assume the checkout directory is named `aauth-rust`, and stop if
`../aauth-service` already exists. They copy the checkout's
`rust-toolchain.toml`, because a path dependency does not choose your
toolchain, and create a lockfile, because your project does not use the
checkout's.

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
aauth-rust-agent = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-agent" }
aauth-rust-agent-provider = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-agent-provider" }
aauth-rust-core = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-core" }
aauth-rust-jose = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-jose" }
aauth-rust-resource = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-resource" }
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
Access Server as well, and to fetch keys and deliver revocations over HTTPS,
add these lines to the `[dependencies]` table in
`../aauth-service/Cargo.toml`, run `cargo generate-lockfile` there again, and
build:

<!-- checked: role-crates -->
```toml
aauth-rust-person-server = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-person-server" }
aauth-rust-access-server = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-access-server" }
aauth-rust-discovery = { version = "0.1.0-alpha.26", path = "../aauth-rust/crates/aauth-rust-discovery" }
```

| Crate | What it does | Guide |
| --- | --- | --- |
| `aauth-rust-agent` | Signs an agent's requests and checks the tokens it receives | [Agent](docs/roles/agent.md) |
| `aauth-rust-agent-provider` | Issues Agent tokens and publishes the provider's keys | [Agent Provider](docs/roles/agent-provider.md) |
| `aauth-rust-resource` | Checks requests to an API before your handler runs | [Resource](docs/roles/resource.md) |
| `aauth-rust-person-server` | Knows which person an agent acts for, and issues tokens that say so | [Person Server](docs/roles/person-server.md) |
| `aauth-rust-person-server-redb` | File-backed storage for a Person Server, on Unix | [Person Server](docs/roles/person-server.md) |
| `aauth-rust-access-server` | Decides access for an API from the API's own rules | [Access Server](docs/roles/access-server.md) |
| `aauth-rust-supervision-server` | Approves or refuses an agent's requests for the person | [Supervision Server](docs/roles/supervision-server.md) |
| `aauth-rust-discovery` | Fetches other servers' keys and delivers revocations over HTTPS; the only crate that opens connections | [Discovery](docs/discovery.md) |
| `aauth-rust-r3`, `aauth-rust-budgets` | Operation lists and spending caps, used by the roles | [R3](docs/features/r3.md), [Budgets](docs/features/budgets.md) |
| `aauth-rust-core`, `aauth-rust-signature-key`, `aauth-rust-jose` | Tokens, HTTP signatures and keys, used by the roles | |

## Documentation

- [docs/](docs/README.md): how AAuth works, a guide for each role and each
  feature, and what to do about each error.
- [USE-IN-YOUR-SERVICE.md](USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](CONFORMANCE.md): how the conformance suite measures the
  libraries, and what its latest run says and does not say.
- [INTERPRETATIONS.md](INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](SPECIFICATIONS.md): the exact draft text implemented.
- [SECURITY.md](SECURITY.md): how to report a vulnerability, and what your
  service is responsible for.
- [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRIBUTING.md](CONTRIBUTING.md):
  how the code is organized and how to change it.

## Status

This is an alpha, version `v0.1.0-alpha.26`. APIs can change from one release
to the next, and each release's notes list the changes.

The crates implement the core AAuth protocol and HTTP Signature Keys, and the
R3, Budgets, Events, Supervision and Bootstrap drafts, each described, with its
limits, in its guide under [docs/features](docs/features).
[aauth-go](https://gitlab.com/sidecat-dev/aauth-go) implements the same drafts
in Go, makes the same choices where the drafts leave room except for the
differences listed in [INTERPRETATIONS.md](INTERPRETATIONS.md), and is tested
against this library.

## License

MIT; see [LICENSE](LICENSE). Every crate in the workspace carries the same
license file. Most direct dependencies are MIT OR Apache-2.0. These locked
direct dependencies are not MIT-only: `ed25519-dalek` 2.2.0 is BSD-3-Clause,
`ring` 0.17.14 is Apache-2.0 AND ISC, and `rustls-webpki` 0.103.15 is ISC.
`aauth-rust-discovery` adds `rustls` 0.23.46 and `rustls-native-certs` 0.8.3,
both Apache-2.0 OR ISC OR MIT. To find the platform's root certificates,
`rustls-native-certs` uses `openssl-probe` (MIT OR Apache-2.0) on Unix, which
only locates certificate files and links no OpenSSL, `security-framework`
(MIT OR Apache-2.0) on macOS, and `schannel` (MIT) on Windows.
