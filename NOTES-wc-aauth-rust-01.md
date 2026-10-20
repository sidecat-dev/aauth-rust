# Workcycle wc-aauth-rust-01

## Direction and design

Implement the first direct Agent-identity journey in the assigned fork. The
long-term project is a full Rust sibling of aauth-go; this cycle demonstrates
only the slice stated in CONFORMANCE.md. No independent review or cold QA has
run yet.

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

- [ ] JOSE: write RFC 8037 vectors and rejection cases first, run red, implement
  Ed25519 JWK/thumbprint and compact JWS with exact bytes retained, then green.
- [ ] Signature-Key and Core: tests first for `hwk`, `jwt`, RFC 9421 signature
  bases, label correlation, time, token type, issuer and confirmation key;
  implement the bounded profile and run the workspace suite.
- [ ] Roles and journey: tests first for unsigned challenge, valid identity,
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
