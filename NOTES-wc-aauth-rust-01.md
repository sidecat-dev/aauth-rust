# Workcycle wc-aauth-rust-01

## Direction and design

Implement the first direct Agent-identity journey in the assigned fork. The
long-term project is a full Rust sibling of aauth-go; this cycle demonstrates
only the slice stated in CONFORMANCE.md. Different-vendor review and cold QA
remain pending.

Use six crates: `aauth-jose`, `aauth-signature-key`, `aauth-core`, `aauth-agent`,
`aauth-agent-provider`, and `aauth-resource`. Role crates depend on protocol
crates, never on each other. Rust's workspace replaces Go's package tree.
Do not create empty Person Server, Access Server or companion crates: those
boundaries will be added with executing behavior. HTTP requests use `http`
values; networking, clocks, key discovery and Resource admission policy remain
with the host. No ambient network fetches in verification.

Pure Rust handles Ed25519, SHA-256, JSON and Structured Fields. Loopback TLS uses
rustls with ring as an explicit development-only native crypto exception;
protocol crates need neither OpenSSL nor a C compiler. The example trusts only
its generated certificate and routes test DNS names to 127.0.0.1. It never
disables certificate verification or relaxes production identifier syntax.

## Implementation plan

- [x] JOSE: write RFC 8037 vectors and rejection cases first, run red, implement
  Ed25519 JWK/thumbprint and compact JWS with exact bytes retained, then green.
- [x] Signature-Key and Core: tests first for `hwk`, `jwt`, RFC 9421 signature
  bases, label correlation, time, token type, issuer and confirmation key;
  implement the bounded profile and run the workspace suite.
- [x] Roles and journey: tests first for unsigned challenge, valid identity,
  tampering, expiry, coverage, future time and policy denial over loopback TLS;
  expose the same composition as a runnable example. Verify host tests, ARM64
  build, formatting and clippy; document exact results and push.

## Questions for the lead

1. Go's upstream manifest still uses AAuth a99d353 + overlays; the supplied
   current snapshot is 70d6737 (same six AAuth source files as 28e8258) and
   Signature-Key 69f5ba2. Preserve the complete Go pins/digests for comparison,
   but use the current snapshot for new Rust behavior. This choice is explicit
   in SPECIFICATIONS.md. A coordinated full Go repin remains separate work.
2. Different-vendor review and muse cold QA are pending lead scheduling after
   the engineer's evidence is ready. This branch will not claim release/merge.

## Status

2026-10-20: read CONTEXT.md and the cycle record, current design record, Go's
architecture rules, source manifest, relevant journey/conformance material and
the pinned editor clauses. Original bootstrap path is absent; read the archived
AGENTS.md and onboarding manifest in full. Their Gen5 commands are historical;
the direct operator assignment supplies this Gen6 fork and publication scope.
Verified clean branch wc-aauth-rust-01, origin the assigned workcycle fork.
Rust 1.99.1, host x86_64-unknown-linux-gnu; ARM64 standard library not installed
at start. Implementation not yet verified.

Engineering checkpoints: c05e504 JOSE (5 tests); 3dee630 proof/Core (12 more);
9ea7c0b roles (4 more). Tests were added before the new APIs, with initial
compilation failures for missing implementation, followed by passing runs.
Corrected one mistyped RFC 8032 signature fixture (an extra hex digit).
The loopback journey now executes 14 wire/TLS checks in one integration test.
The first ARM64 library build passed; final rerun follows the role changes.
Installed rustfmt/clippy because the host initially lacked them.

Resource register before creation: one read-only harness review agent, owned by
this cycle and ending when its findings return; it is an additional code review,
not the required different-vendor review. Local build artifacts stay in ignored
target/; loopback listeners and threads are owned by a per-run RAII guard,
joined and closed before the example/test returns. No remote services created.

## Engineer handoff, 02:23 MDT

Additional same-vendor review returned three concrete findings, all reproduced
before fixing: RFC 9421 authority normalization, defined rejection feedback for
non-jwt Agent requests, and unsupported selected-key algorithm feedback. The
fixes pass their regression tests. Also reproduced and fixed incomplete
`required_input` feedback for query/Authorization coverage. No critical proof
bypass was reported; this is not a security certification.

Current suite: **26 passed, 0 failed**, with **14 checks** in the loopback TLS
integration test. `cargo clippy --workspace --all-targets --locked -- -D warnings`
passes. ARM64 library build passed; final build and release-profile example
checks are being retained below. Eight current source SHA-256 values match the
retained snapshot; the seven Go baseline rows are preserved exactly in the main
manifest as well as the verbatim sibling snapshot.

Different-vendor review and muse cold QA remain the lead's gates before an MR
into the sprint fork. No merge or release has occurred. CI defines Linux x86_64
and ARM64 native jobs with executable artifacts, plus opt-in macOS/Windows jobs;
configuration alone is not execution evidence. Artifacts expire in 14 days.

Cross-check: aauth-go already normalizes authority in
`signaturekey/request.go:normalizedRequestAuthority`. Other feedback findings
are local implementation defects, not editor issues. No upstream feedback filed.

## Final engineer verification

Code commit **8dbf5c958d35b82576cf568349bb0cabc315da7f**, pushed to the assigned
workcycle branch. The final authority test also rejects a missing host,
nonnumeric/out-of-range ports and userinfo; failure was reproduced before the
fix. The local workspace is formatted, 26/26 tests pass, clippy is clean, the
ARM64 library build passes, and the optimized example runs all 14 checks.

**Native CI passed** in pipeline **2966578100**, for that exact code commit:

- Linux x86_64 job **17308800499**: success, 26 tests, optimized example executes;
  artifact `aauth-demo-x86_64-unknown-linux-gnu-8dbf5c95.zip`.
- Linux ARM64 job **17308800500**: success, the same suite and example execute
  natively; artifact `aauth-demo-aarch64-unknown-linux-gnu-8dbf5c95.zip`.

Both artifacts were uploaded and expire after 14 days. macOS and Windows have
not run. This status-only follow-up does not change the tested source.
The same-vendor review agent has returned and ended; no owned test listener or
worker thread remains. Different-vendor review, muse cold QA and the sprint MR
remain pending. No full-protocol or release claim is made.
