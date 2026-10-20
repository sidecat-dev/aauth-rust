# AAuth for Rust

`aauth-rust` implements the AAuth protocol family (agent authorization: Agent, Agent Provider, Person Server, Resource, Access Server; R3, Events, Budgets, Bootstrap; HTTP Signature Keys) as a Rust workspace, developed alongside [aauth-go](https://gitlab.com/sidecat-dev/aauth-go) against the same pinned editor sources, so that findings can be checked in both before they are raised with the editors.

Status: first development cycle. The direct Agent-identity journey runs locally
over certificate-verified loopback TLS. This is a bounded implementation;
[CONFORMANCE.md](CONFORMANCE.md) lists the executing behavior and gaps.

Principles: local-first testing, then remote; easy to stand up and build on; small crates with clear boundaries; conformance stated only where a test executes it.

License: MIT.

## Try it

Install [Rust with rustup](https://rustup.rs/) and a platform C compiler for the
example's TLS provider (Linux: `build-essential`; macOS: Xcode Command Line Tools;
Windows: Visual Studio C++ Build Tools). Protocol library builds use pure Rust.
The checkout selects Rust 1.99.1; Cargo downloads dependencies on the first run.

```sh
git clone https://gitlab.com/sidecat-dev/sprint-gen6-20261020/wc-aauth-rust-01/aauth-rust.git
cd aauth-rust
git switch wc-aauth-rust-01
cargo test --locked
cargo run --locked -p aauth-resource --example direct-identity
```

The example starts an Agent Provider and Resource on randomly assigned loopback
ports, generates fresh keys and certificates, retrieves AP metadata/JWKS, and
executes 14 checks. No account, DNS change, privileged port, existing certificate
or external service is needed. Typical output includes:

```text
unsigned: 401 requirement=agent-token
valid-identity: 200 aauth:Agent@ap.example
tampered-signature: 401 error=invalid_signature
policy-denial: 403 no signature diagnostics
```

The full sequence also checks `hwk` proof, token expiry, missing key coverage,
future timestamps, a wrong confirmation key, and certificate refusal. It uses a
fixed protocol clock for reproducible boundary cases. All listeners and threads
close before it exits.

## Build on it

- `aauth-agent-provider`: issue a host-approved Agent token and publish discovery.
- `aauth-agent`: retain the exact token and sign an HTTP request once.
- `aauth-resource`: verify proof and token before calling your admission policy.
- `aauth-core`, `aauth-signature-key`, `aauth-jose`: reusable protocol layers.

The [example composition](crates/aauth-resource/examples/support/mod.rs) shows
these APIs together. Replace its transport, pinned issuer snapshot and policy
with your application's dependencies. Do not use its small HTTP codec as a
production server. Host applications own issuer trust, egress admission, JWKS
refresh/caching, replay policy, clocks, enrollment and key storage.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the crate boundaries and
[SPECIFICATIONS.md](SPECIFICATIONS.md) for exact sources and digests. Workcycle
status and unresolved questions are in [NOTES-wc-aauth-rust-01.md](NOTES-wc-aauth-rust-01.md).

## Portability

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --locked --target aarch64-unknown-linux-gnu
```

That command builds the library workspace without a cross C compiler. The
example uses rustls/ring as a development-only exception to pure Rust crypto;
cross-building the TLS executable needs the target C toolchain and linker.
[CI](.gitlab-ci.yml) defines native Linux x86_64/ARM64 test and executable-artifact
jobs. macOS and Windows jobs are available when `AAUTH_NATIVE_RUNNERS=1` and the
corresponding runners are enabled. Native Linux x86_64 and ARM64 tests and
optimized examples pass in [pipeline 2966578100](https://gitlab.com/sidecat-dev/sprint-gen6-20261020/wc-aauth-rust-01/aauth-rust/-/pipelines/2966578100).
macOS and Windows execution remains unverified. No release is published.
