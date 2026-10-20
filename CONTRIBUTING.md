# Contributing

Start with the [README](README.md), [architecture](ARCHITECTURE.md),
[pinned sources](SPECIFICATIONS.md), and [executing subset](CONFORMANCE.md).
Report ordinary bugs and propose changes in the
[canonical project](https://gitlab.com/sidecat-dev/aauth-rust/-/issues).
Use the [security policy](SECURITY.md) for vulnerabilities.

For protocol changes, name the exact document, revision and section. Add a
failing behavior test, implement the change, and check relevant refusal cases.
Keep cryptographic facts separate from application trust and policy. Preserve
the crate dependency direction and exact signed bytes. Use synthetic identities
and disposable keys in tests.

Run a focused test while developing. Before opening a merge request, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -p aauth-rust-resource --example library
cargo run --locked -p aauth-rust-resource --example axum
cargo run --locked -p aauth-rust-resource --example direct-identity
cargo run --locked -p aauth-rust-resource --example three-party
cargo run --locked -p aauth-rust-resource --example four-party
cargo run --locked -p aauth-rust-resource --example four-party -- --deferred
cargo run --locked -p aauth-rust-person-server --example mixed-grants
cargo check --locked -p aauth-rust-person-server --example deferred_host
cargo run --locked -p aauth-rust-person-server-redb --example contracts
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
git diff --check
```

Tests and the TLS example require a platform C compiler; library builds use
pure Rust dependencies. The README explains toolchain setup and ARM64 builds.
When changing packaging, also run `cargo publish --workspace --dry-run --locked`.
This verifies archives and dependency versions without uploading them. New
packages may need to be checked together because their dependencies are not
on crates.io yet.

Describe the observable change, source clause, tests, and any interpretation or
remaining limitation in the merge request. Update public docs when supported
behavior changes. Keep development diaries and review transcripts outside the
product repository. API and package names may change during the alpha series;
there are no supported releases yet.

Keep the service guide's host-step code identical to `examples/deferred_host.rs`
in the Person Server crate, and compile-check that example after editing it.
The helper needs host callbacks and a configured PS; the deferred four-party
example supplies the executable TLS journey. Documentation checks must preserve
the distinction between fixture settlement and a real payment provider, delivery
per continuation and cross-exchange replay, and memory recomposition and process
restart durability.

Before filing specification feedback with editors, reproduce the behavior in
both this implementation and [aauth-go](https://gitlab.com/sidecat-dev/aauth-go).
A useful report includes the exact text and the smallest wire example that
shows its effect. An implementation preference is not a protocol requirement.
