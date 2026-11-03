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

The protocol and role crates do not fetch discovery documents. Applications
explicitly trust an Agent Provider, Person Server or Resource, obtain its role
metadata and JSON Web Key Set (JWKS) over verified
HTTPS, and supply a retained snapshot or an `AgentKeyResolver` implementation.
Before fetching, admit destinations and redirects, bound response sizes and
timeouts, prevent DNS rebinding, and keep private network destinations outside
an Internet-facing resolver's allowed set. Apply the same checks on refresh.
Honor the pinned draft's cache and fetch-rate rules.

The opt-in `aauth-rust-discovery` crate does this: `DiscoveryClient` admits
`https` only, resolves once and requires every address to be globally routable
unicast, connects to an admitted address, follows at most three same-host
redirects, reads at most 65536 bytes within ten seconds, and reads no proxy
setting from the environment. `KeyResolver` fetches only for the issuers and
roles you name with `trust` or admit with `trust_when`; every issuer a
`trust_when` predicate admits can make it fetch, within those rules.
`allow_restricted_addresses` is for development and tests; an Internet-facing
service keeps it off. A custom `resolver` or `transport` takes on the part of
these rules it replaces: a transport must connect only to the address it is
given and verify the certificate for the request's host. `RevocationClient`
signs each revocation with the key the role was configured with; protect that
key as the role's own. Its calls block for at most the client timeout per
exchange, and a role's cascade makes them one after another.

Keep signing keys in application-controlled storage, use fresh unique token
identifiers, and supply the correct Unix clock. `SigningKey::export_pkcs8_der`
returns the private key itself: write it only where the key's owner can read
it, or keep the key in a keystore or HSM behind `SigningKey::external`, which
never exports it. A valid signature proves a key
and signed claims; the application's Resource policy decides access. Replay
storage remains a host responsibility. Enrollment, refresh and sub-agent
issuance at a hosted Agent Provider run through `bootstrap::BootstrapService`
only with the host's `BootstrapPolicy` and `BootstrapStore`; the policy
verifies any platform attestation and binds it to a nonce it issued.
Revocation transport is the host's unless it installs
`aauth-rust-discovery`'s `RevocationClient`. The PS store supports binding revocation;
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

For federation, an admitted PS service proof is distinct from Agent person
identity. The AS verifies both, the Resource challenge and its actual presented
credential before resource policy. The PS independently verifies the returned
AS grant and commits exact retained ancestry before release. Use explicit
federated Resource/Agent APIs to pin AS issuer and `aauth-access.json`, including
when PS=AS. An AS 401 may refuse the PS service proof or another AS check. A
well-formed terminal AS problem relays its status/error, including 401, in a new
PS problem body. Its signature diagnostics stay host-side because they describe
the PS-to-AS request. Malformed or unverifiable delivery becomes
`502 as_unreachable`. The PS does not return unverified grants.

The host `Federation` adapter must admit the AS before discovery, validate exact
metadata issuer, enforce HTTPS certificates/SNI, bound request/response collection,
set deadlines, constrain DNS/egress and refuse credential-bearing redirects.
The library validates endpoint syntax and delivery but cannot enforce callback
network behavior. Consent is explicit and defaults to denial. AS grants and PS
retention do not prevent request replay or deduplicate application effects.
Merged JWKS and explicit dispatch are required when roles share an origin; do
not infer AS authority solely because an issuer string equals the PS identifier.

With deferred federation, AS Payment and Claims requirements stay with the
trusted PS host; the Agent receives Approval and cannot settle through its
pending URL. Confirm settlement and approval using admitted host evidence.
Make billing idempotent by admitted AS identity and bill ID, since another 402
can repeat the same payment challenge. The typed payment accessor parses strings;
it does not establish a payment provider's authority or prove settlement.

One terminal delivery is enforced per continuation. It does not prevent an AS
from reusing a byte-identical equivalent grant across exchanges that use the
same Person token and matching verified context: Auth has no Resource challenge
or continuation identifier. Reusing an issuer/JTI with a different retained
Person parent conflicts and is refused as `502 as_unreachable`. There is no
global grant replay cache. Hosts still own operation replay and idempotency.

There is also no pending-request replay cache. An Agent GET captured and replayed
within the accepted 60-second proof window can consume the single terminal
response, leaving the legitimate Agent with `410 Gone`. The token remains
proof-of-possession bound to that Agent's key; a captured GET alone does not let
another holder use it. Enforce any required replay refusal before the pending
handler consumes custody. Pending IDs and interaction codes come from the
operating system's secure random source (128 and 40 bits). Protect the
continuation store's compact credentials, and reconcile uncertain transitions
without blindly retrying settlement or delivery. Memory continuation stores
provide neither process restart durability nor automatic recovery.

## Supported code

Security fixes target the current development line. The crates are alpha code
against pinned editor drafts, with conformance results in
[CONFORMANCE.md](CONFORMANCE.md) and each feature described in its guide under
[docs/features](docs/features). No stable or security-audited release exists.
A release support policy will accompany supported releases.
