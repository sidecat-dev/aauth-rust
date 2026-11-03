# Contributing

Start with the [README](README.md), [architecture](ARCHITECTURE.md),
[pinned sources](SPECIFICATIONS.md), and [conformance](CONFORMANCE.md).
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
sh ci/check-docs.sh
cargo run --locked -p aauth-rust-resource --example getting-started
cargo run --locked -p aauth-rust-resource --example library
cargo run --locked -p aauth-rust-resource --example axum
cargo run --locked -p aauth-rust-resource --example direct-identity
cargo run --locked -p aauth-rust-resource --example three-party
cargo run --locked -p aauth-rust-resource --example r3-three-party
cargo run --locked -p aauth-rust-resource --example r3-per-call
cargo run --locked -p aauth-rust-resource --example four-party
cargo run --locked -p aauth-rust-resource --example four-party -- --deferred
cargo run --locked -p aauth-rust-person-server --example mixed-grants
cargo check --locked -p aauth-rust-person-server --example deferred_host
cargo run --locked -p aauth-rust-person-server-redb --example contracts
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
git diff --check
```

Resource TLS tests and examples require a platform C compiler for their TLS
provider; library builds and pure-Rust checks do not. The README explains the
pinned toolchain and ARM64/Windows library metadata checks; those checks do not
establish foreign-platform linking, execution or durable storage support.

When changing packaging, also run:

```sh
cargo publish --workspace --dry-run --locked
```

Keep `--dry-run`: this creates and compile-verifies the workspace crate archives
without uploading them. Check the workspace together so Cargo can stage the
unpublished sibling dependencies. The Docker CI job runs the same command.
It verifies archive builds, not registry publication, package tests, or a release.
Each archive includes its crate's own `README.md`, the page crates.io shows,
and its MIT license. The README is also the crate's documentation
(`#![doc = include_str!("../README.md")]`), so `cargo test --doc` runs its
examples. Keep it usable without the surrounding checkout: absolute links
only, no hidden `#` lines (crates.io shows them), and workspace-only commands
in the root `README.md`.

Describe the observable change, source clause, tests, and any interpretation or
remaining limitation in the merge request. Update public docs when supported
behavior changes. Keep development diaries and review transcripts outside the
product repository. API and package names may change during the alpha series;
there are no supported releases yet.

The guides in `docs/` hold two kinds of Rust sample. A plain `rust` block is a
complete program: the page is included as a doctest of `aauth-rust-resource` or
`aauth-rust-person-server`, so `cargo test` compiles and runs it. A `rust ignore`
block follows a `<!-- sample: PATH -->` line and quotes PATH unchanged;
`ci/check-docs.sh` checks the quote, the relative links and that every page
with a plain sample is included.

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
