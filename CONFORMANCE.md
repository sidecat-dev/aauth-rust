# Executing behavior

As of 2026-10-20. This is not complete AAuth or
HTTP Signature Keys conformance. No percentage of either draft is claimed.
The exact editor-source pins are in [SPECIFICATIONS.md](SPECIFICATIONS.md).

Current engineer evidence: **89 integration tests passed, 0 failed**, 88 protocol/role/adapter tests plus one TLS
integration test with **14 wire/TLS checks**. The executable example runs that
same composition. A wire check is not counted as a separate Rust test. One additional rustdoc test
executes the unsigned Resource challenge.

| Source area | Executing subset | Evidence |
| --- | --- | --- |
| RFC 8032/8037, RFC 7638 | Ed25519 signing and strict verification; public-only OKP JWK; fully specified algorithm and key-shape checks; thumbprint | `aauth-rust-jose/tests/jose.rs` (9 tests, including RFC 8032 empty-message signature vector) |
| RFC 7515 | Compact JWS, exact signed segments, no unsupported critical headers or unencoded payload profile; duplicate JSON members refused | Same JOSE tests |
| Signature-Key | `hwk`, `jwt`, selected-label correlation, required key coverage, unknown unselected scheme ignored, defined unsupported-scheme/algorithm errors | `aauth-rust-signature-key/tests/proofs.rs` (25 tests), TLS journey |
| RFC 9421 / AAuth Signing | Buffered requests covering method, authority, path, Signature-Key; query and Authorization coverage when present; exact ±60-second `created` window; canonical field values (outer OWS trimmed, repeated lines combined) | Proof tests, independently stated signature-base fixture |
| Agent token / Common Verification | `aa-agent+jwt`, `Ed25519`, named issuer key, expected `dwk`, required claims, exact identifiers, `exp` without leeway, `nbf`, public confirmation key, optional PS syntax | `aauth-rust-core/tests/agent_tokens.rs` (17 tests) |
| AP metadata and JWKS | Exact issuer binding; HTTPS JWKS location with terminal invalid_key for unusable metadata; reject foreign issuer with invalid_key separately from rotation; select only named kid, tolerate unselected unsupported keys; host-retained snapshot | Core tests; AP discovery over TLS |
| Direct Agent identity | Unsigned request challenge; token plus proof before policy; `hwk` receives defined scheme rejection; wrong key refusal; exact endpoint or explicit origin binding before policy; denial after valid authentication; Date from verifier time on clock_skew | `aauth-rust-resource/tests/identity.rs` (30 tests), `response_mapping.rs` (2 tests), TLS journey |
| Resource metadata | Explicit published issuer separate from signed authority/port, agent-token access and 60-second window; no fictitious JWKS/authorization endpoints; invalid publication settings return a local configuration error | Resource and axum metadata tests |
| Framework adapter | Origin-form URI reconstruction from configured HTTPS origin, typed policy context, custom success response, wrong-origin proof refusal and bounded actual-body handling; canonical metadata publication with a nondefault signed port | `aauth-rust-resource/tests/axum_service.rs` (5 tests), executable axum example |
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
- The local buffered profile computes and verifies SHA-256 Content-Digest for
  nonempty content or a supplied digest, covering Content-Type when present on nonempty content. The hard limit is 1 MiB, checked at signing and verification. Tests pin a
  known digest, changed/removed body, altered type, malformed/missing digest,
  missing coverage and the inclusive limit. This Resource default is additional
  policy, not a claim that Core mandates it for every ordinary Resource API.
  Only a single unparameterized sha-256 digest member is supported. Streaming
  content/trailers, component parameters, general field canonicalization, nonce
  replay storage, keyid and complete negotiation are absent. keyid is refused;
  the alg signature parameter is ignored. Hosts must bound collection and pass
  actual content before decompression, never an empty placeholder for unread data.
  Identical proof bytes can be accepted repeatedly inside the window; no replay
  cache or application idempotency store is supplied. The Resource fixes label
  sig, a 60-second window and jwt scheme.
- Local signing/verifier clocks and AP-issued iat/exp use the supported range
  0..=8589934591 Unix seconds (through 2242), not contemporary milliseconds.
  This is a local profile bound, not a general NumericDate rule.
- **EMPTY-CONTENT-TYPE:** Content-Type on empty content is outside the conditional
  proof, including when a digest was supplied. A host assigning meaning to that
  field on an empty call must reject that form or use a different explicit
  profile. Ordinary empty requests retain their previous proof behavior.
- **ORIGIN-INPUT:** `for_origin` parses request-origin configuration and accepts
  a root slash. Published server identifiers use strict validation without a
  trailing slash; `metadata_for` never normalizes an invalid identifier.
- **BUFFER-LIMIT-WIRE:** buffered content over 1 MiB returns `invalid_request`,
  distinct from missing coverage (`invalid_input`) and a bad proof/digest
  (`invalid_signature`). The byte ceiling is documented, not negotiated in
  discovery. Hosts should bound collection first; the axum adapter returns 413.
  Covered empty field values follow RFC 9421; signing does not validate media
  type semantics, which remain the receiving application's responsibility.
- **AP-KEY-ROLLOVER:** AP JWKS publication contains exactly one active key.
  Retained old keys, overlap timing and automatic retirement are not implemented.
  The resolver accepts supplied multi-key JWKS and selects by kid; tests prove
  old/new verification during overlap and old-key refusal after removal. This
  resolver behavior is not an AP rotation lifecycle.
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
- These cases do not establish full cross-implementation compatibility or a
  general security audit. Review findings are conformance evidence only when
  executed by cited tests. Cross-check draft findings in other implementations
  before filing with editors.

## Build evidence

Local host: Linux x86_64, Rust 1.99.1. `cargo test --locked`, the optimized TLS
example, formatting and clippy with warnings denied pass. The library workspace
also cross-builds with `cargo build --locked --target aarch64-unknown-linux-gnu`.

[CI](.gitlab-ci.yml) runs the suite and optimized TLS example natively on Linux
x86_64 and ARM64 and retains per-target demo binaries for 14 days. These are
build artifacts, not a published release. macOS and Windows jobs are opt-in;
execution on those platforms remains unverified. To verify packaging without
uploading crates, run `cargo publish --workspace --dry-run --locked` with an
unused `CARGO_TARGET_DIR` for repeated checks of unchanged alpha versions.
