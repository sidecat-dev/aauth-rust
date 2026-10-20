# Security policy

## Report privately

Report suspected vulnerabilities in a **confidential issue** in the
[canonical GitLab project](https://gitlab.com/sidecat-dev/aauth-rust/-/issues/new).
Select the confidential option before submitting. Confidential issues limit
visibility to the reporter and project members with the appropriate role.
Do not post exploit details in an ordinary public issue.

Include the affected commit, specification clause, impact and preconditions,
and a minimal reproducer using disposable keys. Do not include live credentials,
private keys or personal data. Maintainers will reproduce the report and
coordinate fixes and disclosure with the reporter. There is no published
response-time guarantee.

## Integration responsibilities

The library does not fetch discovery documents. Applications explicitly trust
an Agent Provider, obtain its metadata and JSON Web Key Set (JWKS) over verified
HTTPS, and supply a retained snapshot or an `AgentKeyResolver` implementation.
Before fetching, admit destinations and redirects, bound response sizes and
timeouts, prevent DNS rebinding, and keep private network destinations outside
an Internet-facing resolver's allowed set. Apply the same checks on refresh.
Honor the pinned draft's cache and fetch-rate rules; this library supplies no
shared cache or refresh loop.

Keep signing keys in application-controlled storage, use fresh unique token
identifiers, and supply the correct Unix clock. A valid signature proves a key
and signed claims; the application's Resource policy decides access. Replay
storage, enrollment, revocation and sub-agent delegation are outside the
current implementation. This profile rejects nonempty bodies and does not
verify Content-Digest. Adapters must pass the actual body bytes or refuse bodies
at the transport; verifying an empty placeholder and then forwarding an unread
body defeats the profile's body check. The generated certificates and small HTTP codec in
the loopback example are test infrastructure.

## Supported code

Security fixes target the current development line. The crates are alpha code
against pinned editor drafts, with the tested subset and gaps recorded in
[CONFORMANCE.md](CONFORMANCE.md). No stable or security-audited release exists.
A release support policy will accompany supported releases.
