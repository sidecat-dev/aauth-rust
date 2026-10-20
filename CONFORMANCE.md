# Executing behavior

Development cycle `wc-aauth-rust-01`, 2026-10-20. This is not complete AAuth or
HTTP Signature Keys conformance. No percentage of either draft is claimed.
The exact editor-source pins are in [SPECIFICATIONS.md](SPECIFICATIONS.md).

Current engineer evidence: **26 Rust tests passed, 0 failed**, including one TLS
integration test with **14 wire/TLS checks**. The executable example runs that
same composition. A check is not counted as a separate Rust test.

| Source area | Executing subset | Evidence |
| --- | --- | --- |
| RFC 8032/8037, RFC 7638 | Ed25519 signing and strict verification; public-only OKP JWK; fully specified algorithm and key-shape checks; thumbprint | `aauth-jose/tests/jose.rs` (5 tests, including RFC 8032 empty-message signature vector) |
| RFC 7515 | Compact JWS, exact signed segments, no unsupported critical headers or unencoded payload profile; duplicate JSON members refused | Same JOSE tests |
| Signature-Key | `hwk`, `jwt`, selected-label correlation, required key coverage, unknown unselected scheme ignored, defined unsupported-scheme/algorithm errors | `aauth-signature-key/tests/proofs.rs` (8 tests), TLS journey |
| RFC 9421 / AAuth Signing | Bodyless requests covering method, authority, path, Signature-Key; query and Authorization coverage when present; exact ±60-second `created` window | Proof tests, independently stated signature-base fixture |
| Agent token / Common Verification | `aa-agent+jwt`, `Ed25519`, named issuer key, expected `dwk`, required claims, exact identifiers, `exp` without leeway, `nbf`, public confirmation key, optional PS syntax | `aauth-core/tests/agent_tokens.rs` (7 tests) |
| AP metadata and JWKS | Exact issuer binding; HTTPS JWKS location; select only named kid, tolerate unselected unsupported keys; host-retained snapshot | Core tests; AP discovery over TLS |
| Direct Agent identity | Unsigned request challenge; token plus proof before policy; `hwk` receives defined scheme rejection; wrong key refusal; denial after valid authentication | `aauth-resource/tests/identity.rs` (5 tests), TLS journey |
| Local composition | Fresh random AP/Agent keys; certificate-verified loopback TLS; AP metadata/JWKS retrieval; Resource outcomes | `aauth-resource/tests/loopback_tls.rs` (1 test, 14 checks) |

The 14 checks are AP metadata, AP JWKS, unsigned challenge, accepted identity,
accepted pseudonymous `hwk` proof, `hwk` identity scheme rejection, tampered signature,
expired token, uncovered Signature-Key, future `created`, future `iat`, wrong
confirmation key, policy denial without signature diagnostics, and untrusted TLS
certificate refusal. The proof endpoint is example infrastructure; it does not
turn an `hwk` key into an AAuth identity.

## Limits and choices

- Agent tokens and direct Agent identity only. Person/auth/resource tokens,
  session tokens, enrollment, revocation, sub-agent issuance/delegation, missions,
  permission, interaction, audit, call chaining and federation do not execute.
- No R3, Events, Budgets, Bootstrap or Supervision behavior. Pinning a document
  does not imply implementing it.
- Ed25519 only. Other algorithms, private/HSM signer adapters and other
  Signature-Key schemes are absent. Verifiers select the configured `sig` label;
  this is not general multiple-signature policy.
- The request profile is bodyless and supports only the named components.
  Content-Digest, component parameters, general field canonicalization, nonce
  replay storage, `keyid` and complete negotiation are absent. `keyid` is refused
  explicitly rather than guessed. The `alg` signature parameter is ignored.
- The Resource applies the optional future-`iat` refusal at its 60-second proof
  window. Core token verification alone does not treat `iat` as validity.
  Query coverage is an additional local requirement when a query is present.
- Hosts must supply trusted issuer resolution, DNS/redirect egress admission,
  JWKS cache lifetime, once-per-minute fetch floor and refresh policy. The local
  journey fetches one configured AP snapshot and reuses it; it is not an open
  Internet discovery/cache client.
- No remote or cross-implementation run, general security audit,
  different-vendor review or cold QA has passed yet. Findings must be checked in
  aauth-go before being filed with editors.

## Build evidence

Host: Linux x86_64, Rust 1.99.1. `cargo test --locked`, the runnable TLS example,
formatting and clippy are the engineer checks. ARM64 libraries are cross-built
with `cargo build --locked --target aarch64-unknown-linux-gnu`; that is not ARM64
execution or a linked ARM64 TLS executable. CI defines native builds and demo
artifacts per enabled target; a definition is not a successful CI run.
