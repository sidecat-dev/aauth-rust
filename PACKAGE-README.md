# AAuth for Rust crates

Development libraries for [AAuth](https://github.com/dickhardt/AAuth), version
`0.1.0-alpha.17`, licensed under the included [MIT license](LICENSE).
The [canonical project](https://gitlab.com/sidecat-dev/aauth-rust) is the project
home and issue tracker. An archive verification run is not a release or registry
publication; APIs and package names may change during the alpha series.

## Choose a crate

| Crate | Responsibility |
| --- | --- |
| `aauth-rust-jose` | Ed25519 public JWKs, thumbprints and compact JWS primitives. |
| `aauth-rust-core` | Protocol claims, discovery documents and token verification. |
| `aauth-rust-signature-key` | HTTP request signatures and Signature-Key proofs. |
| `aauth-rust-agent-provider` | Agent Provider discovery and Agent token issuance. |
| `aauth-rust-agent` | Agent request signing, credential verification and explicit polling helpers. |
| `aauth-rust-access-server` | Access Server grant issuance and deferred continuations. |
| `aauth-rust-person-server` | Person bindings, consent, credential issuance and federation custody. |
| `aauth-rust-person-server-redb` | Transactional file-backed Person Server storage on supported Unix filesystems. |
| `aauth-rust-budgets` | Budget objects, narrowing, metering, and usage counters. |
| `aauth-rust-r3` | Vocabularies, documents, grants, and proposals. |
| `aauth-rust-resource` | Resource request verification and application admission policy. |
| `aauth-rust-supervision-server` | Supervision server decisions, standing reach and event records. |

Each archive contains that crate's sources, tests and examples where present,
its normalized Cargo manifest, lockfile and license. It does not include the
other eleven crates or the workspace's complete service guides. The root
`README.md`, the `docs/` guides, `USE-IN-YOUR-SERVICE.md`, `CONFORMANCE.md` and
`SPECIFICATIONS.md` in the full development checkout describe executable
examples, host integration, the implemented subset and pinned protocol
sources. This is a partial protocol
implementation, not a full-profile conformance claim.

## Use and verify development sources

Internal dependencies declare version `0.1.0-alpha.17`. Until the sibling packages
are available in a registry, use versioned path dependencies from a complete
checkout. For example, in an application next to an `aauth-rust` checkout:

```toml
[dependencies]
aauth-rust-resource = { version = "0.1.0-alpha.17", path = "../aauth-rust/crates/aauth-rust-resource" }
```

Adjust the path to your checkout. Cargo can also fetch the crates from the
release tag instead:

```toml
[dependencies]
aauth-rust-resource = { git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "v0.1.0-alpha.17" }
```

A single archive cannot supply its unpublished sibling dependencies. To create and compile-verify all twelve archives together,
run this from the full workspace with its lockfile:

```sh
CARGO_BUILD_JOBS=2 cargo publish --workspace --dry-run --locked
```

Keep `--dry-run`: Cargo stages sibling archives locally and aborts every upload.
This verifies archive builds; it does not execute their tests/examples or prove
registry publication. The workspace CI separately runs the native test suites
and examples and retains the verified archives for inspection.

## Host and platform boundaries

Hosts supply admitted HTTPS transport and discovery documents, trusted issuers,
clocks, key custody, person authentication, consent and replay policy. Signing
and verification do not send requests or decide which issuers to trust. The
Person Server host explicitly advances deferred settlement; Agent polling does
not settle a payment. Choose storage and recovery policy for the host's actual
deployment; the in-memory examples are not durable storage.

The workspace pins Rust `1.99.1`; package metadata declares Rust `1.99` and
edition `2024`. Library builds use pure Rust dependencies. Resource TLS tests
and examples additionally need a platform C compiler for their TLS provider.
ARM64 Linux and Windows MSVC metadata checks do not establish foreign linking
or execution. The redb adapter refuses non-Unix open and needs Unix filesystem
directory synchronization; other deployments need another Person Server store.
