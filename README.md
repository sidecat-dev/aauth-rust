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
libraries sign, check and decide. The separate `aauth-rust-discovery` crate
fetches other servers' keys and delivers revocations over HTTPS, refusing
private addresses and other unsafe destinations unless you allow them. The
umbrella `aauth-rust` crate enables its `discovery` feature by default. Use
individual role crates, or disable default features and select roles, to omit
the network client dependency. The HTTP host must limit request bodies before
constructing the buffered request passed to a role.

## Install

The crates are on [crates.io](https://crates.io/crates/aauth-rust). Install Rust
with rustup, open a new terminal, and use `rustc --version` and `cargo --version`
to check that your toolchain is 1.99 or later. If rustup's stable toolchain is
too old, update it with `rustup update stable`. [Install Rust](https://rust-lang.org/tools/install/)

Rust needs a system linker. On Ubuntu or Debian, run
`sudo apt-get install build-essential`. On macOS, install the Xcode command
line tools. On Windows, install the MSVC build tools.

Start a project.

<!-- consumer-bootstrap-setup:begin -->
```sh
cargo new aauth-service
cd aauth-service
```
<!-- consumer-bootstrap-setup:end -->

Add the crates to the `[dependencies]` table of its `Cargo.toml`:

<!-- consumer-bootstrap-dependencies:begin -->
```toml
aauth-rust-agent = "0.1.0-alpha.29"
aauth-rust-agent-provider = "0.1.0-alpha.29"
aauth-rust-core = "0.1.0-alpha.29"
aauth-rust-jose = "0.1.0-alpha.29"
aauth-rust-resource = "0.1.0-alpha.29"
http = "1"
```
<!-- consumer-bootstrap-dependencies:end -->

Replace `src/main.rs` with this program. It has an Agent Provider issue a
token, an agent sign a request with it, and a Resource check the request, all
in one process. In a real API, also serve `resource.metadata()` at
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

Then run it, and keep the new `Cargo.lock` with your source:

<!-- consumer-bootstrap-build:begin -->
```sh
cargo run
```
<!-- consumer-bootstrap-build:end -->

```text
verified aauth:Agent@ap.example
```

To run a Person Server or an Access Server as well, and to fetch keys and
deliver revocations over HTTPS, add these lines too:

```toml
aauth-rust-person-server = "0.1.0-alpha.29"
aauth-rust-access-server = "0.1.0-alpha.29"
aauth-rust-discovery = "0.1.0-alpha.29"
```

`aauth-rust-discovery` uses a TLS library that also needs a C compiler,
which the same tools provide. The other crates have no C dependencies.
`aauth-rust = "0.1.0-alpha.29"` brings every crate in one dependency, one module each,
with a default-on feature per role.

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
| `aauth-rust` | All of the crates above in one dependency, one module each, with a default-on feature per role | |

## Build from source

The repository's example runs over TLS on your machine. In addition to rustup
and the system build tools above, you need Git. Checking out a release tag
puts Git in detached HEAD mode, which is expected when running an example from
that release. [Install Git](https://git-scm.com/)

```sh
git clone https://gitlab.com/sidecat-dev/aauth-rust.git
cd aauth-rust
git checkout v0.1.0-alpha.29
cargo run --locked -p aauth-rust-resource --example getting-started
```

On the first run, rustup downloads the pinned Rust 1.99.1 if needed, and Cargo
downloads and builds the dependencies. The example starts an Agent Provider
and an API on loopback ports, with TLS. It prints these results.

```text
metadata: 200 issuer=https://api.example
unsigned: 401 requirement=agent-token
signed: 200 hello, aauth:assistant@ap.example
not admitted: 403
```

[Get started](docs/getting-started.md) walks through the output and the code,
and [CONTRIBUTING.md](CONTRIBUTING.md) says how to change the code.

## Documentation

- [docs/](docs/README.md): how AAuth works, a guide for each role and each
  feature, and what to do about each error.
- [USE-IN-YOUR-SERVICE.md](USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](CONFORMANCE.md): how the conformance suite measures the
  libraries, and what the recorded run covers.
- [INTERPRETATIONS.md](INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](SPECIFICATIONS.md): the exact draft text implemented.
- [SECURITY.md](SECURITY.md): how to report a vulnerability, and what your
  service is responsible for.
- [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRIBUTING.md](CONTRIBUTING.md):
  how the code is organized and how to change it.

## Status

This is an alpha, version `v0.1.0-alpha.29`. APIs can change from one release
to the next, and each release's notes list the changes.

The crates implement the core AAuth protocol and HTTP Signature Keys, and the
R3, Budgets, Events, Supervision and Bootstrap drafts, each described, with its
limits, in its guide under [docs/features](docs/features).
[aauth-go](https://gitlab.com/sidecat-dev/aauth-go) implements the same drafts
in Go. [INTERPRETATIONS.md](INTERPRETATIONS.md) lists differences where the
drafts leave room. The recorded bidirectional HTTPS run used Rust alpha.17
and Go `0e2447b`. [Interop report](https://gitlab.com/sidecat-dev/aauth-interop/-/tree/f9ee96110e44cb54a9a77159a4c4c93a3a93cd00/reports/run-02-alpha17-0e2447b)

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

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
