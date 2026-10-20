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
an Agent Provider, Person Server or Resource, obtain its role metadata and
JSON Web Key Set (JWKS) over verified
HTTPS, and supply a retained snapshot or an `AgentKeyResolver` implementation.
Before fetching, admit destinations and redirects, bound response sizes and
timeouts, prevent DNS rebinding, and keep private network destinations outside
an Internet-facing resolver's allowed set. Apply the same checks on refresh.
Honor the pinned draft's cache and fetch-rate rules; this library supplies no
shared cache or refresh loop.

Keep signing keys in application-controlled storage, use fresh unique token
identifiers, and supply the correct Unix clock. A valid signature proves a key
and signed claims; the application's Resource policy decides access. Replay
storage, enrollment, revocation transport and sub-agent delegation remain host
responsibilities or unimplemented. The PS store supports binding revocation;
it supplies no revocation endpoint or event delivery. The buffered profile signs and verifies SHA-256
Content-Digest for nonempty content or a supplied digest, up to 1 MiB. It also
covers Content-Type when present on nonempty content. Adapters must bound
collection and pass the actual bytes before decompression, or refuse bodies at
transport; an empty placeholder cannot authenticate unread downstream content.
Preserve covered field values through proxies. Content-Type on empty content is
outside the conditional proof even when a digest is supplied; applications that
assign it meaning must reject that form or use a different explicit profile.
The digest does not prevent replay, and streaming/trailer digests are absent.
The generated certificates and small HTTP codec in the loopback example are
test infrastructure.

For a Person Server, authenticate the person through host-owned evidence;
`login_hint`, tenant and other signed Agent assertions do not authenticate that
person. Supply stable opaque Resource-directed subjects and keep internal person
IDs private. Run the public `storetest` contract against each durable Store
adapter: binding checks and issuance must commit atomically, and retained
lineage must survive restart. `MemoryStore` is volatile and has no garbage
collection. Losing its records makes outstanding credentials unusable at that
PS. The PS verifies exact retained Person/Auth issuances in exchanges and chains;
a valid signature alone does not reconstruct missing state.

The optional `aauth-rust-person-server-redb` adapter durably retains bindings,
internal person IDs, tenant/Agent identity, credential hashes and lineage in a
local database file. It stores no signing keys or complete compact tokens and
provides no file encryption. Durably provision and protect the parent directory
and backups; retain
the issuer signing key and unique token-ID source separately across restart.
The adapter requires Unix and filesystem directory-sync support. Open
synchronizes the parent after file initialization and refuses a usable handle
if that step fails; non-Unix open is refused before file creation. One process
owns each file; cloned handles share that owner. Close every handle
before copying/restoring a database backup. The adapter has no cleanup API and
keeps records indefinitely, including after `retain_until`; there is no enforced
bound on file size or record count. Provision/monitor capacity and stop admission
before exhaustion. A 1 MiB encoded-JSON record limit does not bound total growth
or memory the caller already allocated.
Open checks engine page integrity before schema access and maps catchable
unwinding engine panics and detected corruption to store_unavailable. Checks
can modify a file during repair and cost a page scan at startup; preserve a closed
copy before diagnosing corruption. They do not authenticate coherently tampered
rows or cover external modification after open. panic=abort and process/allocation
aborts cannot be contained.
Logical refusals leave state unchanged. An operational I/O error can leave a
whole transaction's outcome uncertain, so the PS releases no credential on a
commit error. A failed engine commit prevents writes/revocation through every
clone until all handles close and the same file is reopened; reconstruct the PS
and do not use surviving reads to infer the durable outcome. No partial
binding/index/token transaction is exposed. Process-exit
tests and one controlled write failure do not simulate every storage failure or
physical power loss. This store is not an HTTP replay cache.

Person tokens establish identity, not access. Admit protected work only after
Auth-token verification and application policy. The PS's upstream hooks deny by
default: direct consent does not authorize an intermediary automatically. Use the
verified original-person context to decide downstream grants; never copy an
upstream public subject into a different Resource's identity namespace. The
three-party TLS example uses one pre-authenticated demo account; it is not a
login, enrollment or durable-storage service.

## Supported code

Security fixes target the current development line. The crates are alpha code
against pinned editor drafts, with the tested subset and gaps recorded in
[CONFORMANCE.md](CONFORMANCE.md). No stable or security-audited release exists.
A release support policy will accompany supported releases.
