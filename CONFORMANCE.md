# Executing behavior

As of 2026-10-20. This is not complete AAuth or
HTTP Signature Keys conformance. No percentage of either draft is claimed.
The exact editor-source pins are in [SPECIFICATIONS.md](SPECIFICATIONS.md).

Current engineer evidence: **56 integration tests passed, 0 failed**, 55 protocol/role tests plus one TLS
integration test with **14 wire/TLS checks**. The executable example runs that
same composition. A wire check is not counted as a separate Rust test. One additional rustdoc test
executes the unsigned Resource challenge.

| Source area | Executing subset | Evidence |
| --- | --- | --- |
| RFC 8032/8037, RFC 7638 | Ed25519 signing and strict verification; public-only OKP JWK; fully specified algorithm and key-shape checks; thumbprint | `aauth-rust-jose/tests/jose.rs` (9 tests, including RFC 8032 empty-message signature vector) |
| RFC 7515 | Compact JWS, exact signed segments, no unsupported critical headers or unencoded payload profile; duplicate JSON members refused | Same JOSE tests |
| Signature-Key | `hwk`, `jwt`, selected-label correlation, required key coverage, unknown unselected scheme ignored, defined unsupported-scheme/algorithm errors | `aauth-rust-signature-key/tests/proofs.rs` (16 tests), TLS journey |
| RFC 9421 / AAuth Signing | Bodyless requests covering method, authority, path, Signature-Key; query and Authorization coverage when present; exact ±60-second `created` window | Proof tests, independently stated signature-base fixture |
| Agent token / Common Verification | `aa-agent+jwt`, `Ed25519`, named issuer key, expected `dwk`, required claims, exact identifiers, `exp` without leeway, `nbf`, public confirmation key, optional PS syntax | `aauth-rust-core/tests/agent_tokens.rs` (14 tests) |
| AP metadata and JWKS | Exact issuer binding; HTTPS JWKS location; reject foreign issuer with invalid_key separately from rotation; select only named kid, tolerate unselected unsupported keys; host-retained snapshot | Core tests; AP discovery over TLS |
| Direct Agent identity | Unsigned request challenge; token plus proof before policy; `hwk` receives defined scheme rejection; wrong key refusal; configured authority/path binding before policy; denial after valid authentication | `aauth-rust-resource/tests/identity.rs` (16 tests), TLS journey |
| Local composition | Fresh random AP/Agent keys; certificate-verified loopback TLS; AP metadata/JWKS retrieval; Resource outcomes | `aauth-rust-resource/tests/loopback_tls.rs` (1 test, 14 checks) |

Snapshot ownership and absence of network fetching are architecture properties
checked by source inspection of `aauth-rust-core/src/discovery.rs`; they are not
additional protocol test results. The example's listener/thread cleanup follows
its owned Drop implementation, also checked by inspection.

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
  this is not general multiple-signature policy. Combined field lines and
  repeated dictionary/parameter names use RFC 9651 last-wins parsing. An identical
  repeated Signature-Input member preserves its signature base; changing the
  selected last member requires a new valid proof.
- The request profile is bodyless and supports only the named components.
  Content-Digest, component parameters, general field canonicalization, nonce
  replay storage, `keyid` and complete negotiation are absent. `keyid` is refused
  explicitly rather than guessed. The `alg` signature parameter is ignored.
  No Content-Digest is computed or verified; a nonempty POST body added after
  signing is refused before policy. Hosts must pass actual body bytes or reject
  bodies at transport, never authenticate an empty placeholder then forward a body.
  The Resource fixes label `sig`, a 60-second window and the jwt scheme; hosts
  needing a different profile compose the underlying Signature-Key API.
- The AP follows the Agent-token 24-hour lifetime SHOULD as an issuance limit.
  Core/Resource verification does not impose that recommendation as a hard
  ceiling on other issuers. Hosts can enforce a stricter lifetime in policy.
- The Resource applies the optional future-`iat` refusal at its 60-second proof
  window. Core token verification alone does not treat `iat` as validity.
  The Resource tests pin acceptance at `iat = now + 60` and refusal at `now + 61`.
  Query coverage is an additional local requirement when a query is present.
- Hosts must supply trusted issuer resolution, DNS/redirect egress admission,
  JWKS cache lifetime, once-per-minute fetch floor and refresh policy. The local
  journey fetches one configured AP snapshot and reuses it; it is not an open
  Internet discovery/cache client.
- No external-peer or cross-implementation run or general security audit has
  passed. Review findings are not conformance evidence unless executed by the
  cited tests. Findings must be checked in aauth-go before filing with editors.

## Build evidence

Local host: Linux x86_64, Rust 1.99.1. `cargo test --locked`, the optimized TLS
example, formatting and clippy with warnings denied pass. The library workspace
also cross-builds with `cargo build --locked --target aarch64-unknown-linux-gnu`.

[CI](.gitlab-ci.yml) runs the suite and optimized TLS example natively on Linux
x86_64 and ARM64 and retains per-target demo binaries for 14 days. These are
build artifacts, not a published release. macOS and Windows jobs are opt-in;
execution on those platforms remains unverified. To verify packaging without
uploading crates, run `cargo publish --workspace --dry-run --locked`.
