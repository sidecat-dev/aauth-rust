# Architecture

Small protocol crates establish wire facts. Role crates decide what to do with
those facts. Applications supply transport, trusted issuers, clocks, keys and
policy. This follows the sibling aauth-go architecture without reproducing its
unimplemented role surfaces as empty Rust crates.

| Crate | Owns | Depends on |
| --- | --- | --- |
| `aauth-rust-jose` | Public Ed25519 JWKs, RFC 7638 thumbprints, exact compact JWS bytes, strict JSON | Rust crypto and serialization |
| `aauth-rust-signature-key` | Buffered HTTP signature bases, SHA-256 Content-Digest, selected-label correlation, `hwk`/`jwt`/explicit `jwks_uri` key conveyance, proof time; response signatures with `;req` components and a `Signature-Key` response field | JOSE, `http`, `sfv`, `sha2` |
| `aauth-rust-core` | Identifiers; Agent, Person, Resource and Auth JWT syntax/minting/common verification; Events subscribe and event tokens; Supervision wire values; trusted issuer snapshots; bounded continuation wire types and atomic custody contract | JOSE |
| `aauth-rust-agent-provider` | Host-approved token issuance, AP metadata/JWKS bytes; opt-in Events subscribe tokens, inbox and file-backed event store | Core, Signature-Key, JOSE |
| `aauth-rust-agent` | Signed requests using caller-owned credentials; explicit bounded polling sessions; R3 `/authorize` preparation and class-grant verification; Events subscription signing and event verification | Core, Signature-Key, R3, JOSE |
| `aauth-rust-budgets` | Budget objects, narrowing, per-token metering, consumption records and usage counters | JOSE |
| `aauth-rust-r3` | Vocabulary grammar, documents, grants, and proposals | serialization, SHA-256 |
| `aauth-rust-resource` | Direct Agent identity, PS/AS authorization and signed Resource challenges, proof before policy, HTTP decisions, opt-in metering, opt-in immediate class R3, opt-in Events registration and signed delivery | Core, Signature-Key, Budgets, R3, JOSE |
| `aauth-rust-person-server` | Atomic person binding, retained issuance/lineage, direct Auth grants, explicit AS federation and opt-in deferred custody, immediate direct call chaining, opt-in budget issuance, opt-in direct class R3 issuance, opt-in supervision: relaying, recording and enforcing a supervision server's decisions, opt-in relay of an agent's interaction to a host person channel | Core, Signature-Key, Budgets, R3, JOSE |
| `aauth-rust-supervision-server` | Supervision server role: connect, signed decisions, deferral and clarification, idempotence by `sdi`, standing reach of the person's answers, event and mission records | Core, Signature-Key, JOSE |
| `aauth-rust-access-server` | Verified PS service proof and credential lineage before resource policy; verified call-chaining upstream tokens; bounded Core-scope AS grants and opt-in continuation policy; opt-in budget narrowing | Core, Signature-Key, Budgets, JOSE |
| `aauth-rust-person-server-redb` | Durable binding, exact issuance and directed-identity indexes in one file-backed transaction | Person Server, redb, serialization |
| `aauth-rust-discovery` | The one crate that opens connections, opt-in: an egress-admitted HTTPS client (rustls over `std::net`), a caching `AgentKeyResolver` for host-trusted issuers, and a `RevocationDirectory` that delivers cascades | Core, Signature-Key, JOSE, rustls, rustls-native-certs, httparse |

Normal role dependencies never import one another; Resource dev-dependencies
compose the roles for tests and examples. No role imports `aauth-rust-discovery`:
a host passes its `KeyResolver` and `RevocationClient` to a role through the
role's existing `AgentKeyResolver` and `RevocationDirectory` parameters. Examples import the roles and compose
them without a cross-role lifecycle abstraction. The storage adapter imports the
PS role; the role never imports a database engine. Bootstrap and R3 get
boundaries as executing journeys require them. Events tokens live in Core and
each role's Events behavior in its own crate. Budgets are the opt-in
`aauth-rust-budgets` crate. Unsupported vocabularies and the full-R3 gap are
recorded in CONFORMANCE.md.

## Facts before policy

Parsed JWT types are unverified. Their routing claims are explicitly named
`unverified_claims`. Only `verify` can construct the corresponding verified type.
Each Resource is configured with its own HTTPS endpoint and first checks the
request authority/path against that target. It obtains a token verification
result, verifies the HTTP signature
against its `cnf.jwk`, and then invokes host policy. A valid proof does not grant
access. `hwk` can prove a key but cannot satisfy an AAuth Agent-identity challenge.

`AgentKeyResolver` is the host's trust boundary. `AgentProviderKeys` is one
immutable snapshot of metadata and JWKS for an explicitly configured AP. It
checks exact metadata issuer equality and selects only the JWT's named key.
It performs no network requests and makes no trust decision for its host.
`TrustedIssuerKeys` adds exact role-document binding for PS and Resource snapshots.
Production hosts implement egress admission and bounded cache/refresh behavior
before supplying these snapshots or their own resolver, or use
`aauth-rust-discovery`'s `KeyResolver`, which builds a `TrustedIssuerKeys` from
each admitted fetch, keeps the Signature-Key cache rules through `KeyCache`, and
fetches only for issuers and roles the host trusts.

`PsAuthorizationResource` separates Person identity from authorization. It turns
a verified Person token into a signed Resource challenge, then admits only a
verified PS-issued Auth token, or the explicitly configured AS role/issuer,
with the right audience, holder key and route
scopes. Its origin-wide value has one fixed scope profile; the host router owns
route selection. Policy receives verified Auth claims and the actual request.

`with_r3` adds immediate class R3 to the direct PS path without a second
runtime. The host supplies authoritative definition snapshots, a mapping from
a verified request to at most one operation, and a durable immutable
`R3DocumentStore`; the role never selects a source or a database. Each
document URI is under the canonical signed origin, so the advertised `r3_uri`
is the URI fetched, while JWT `iss`/`aud` keep the published issuer. It binds
its digest, PS/issuer entitlement and Resource-token `jti`.
The record is committed before the token is released, and the signed document
endpoint and protected admission read only that record.

The Person Server verifies the requesting Agent's proof, token parameters and
exact retained lineage before policy. Its `Policy` authenticates a person,
assigns stable Resource-directed subjects and grants scopes. `Store` commits
issuance and binding atomically before a token is released. `MemoryStore` is a
volatile reference; `storetest` is the executable contract for durable host
implementations. The separate redb adapter passes that logical contract and a
consuming close/reopen contract. Its keyed tables hold complete issuance,
binding and both directed-identity indexes; one immediate-durable write
transaction updates them together. Startup scans engine page integrity, checks
table identity/types and schema version, then synchronizes the parent directory
after the database file. This optional adapter requires Unix directory-sync
support and a durably provisioned parent. It contains unwinding open/metadata
panics, caps encoded records at 1 MiB and retains an unbounded record count.
Failed engine commits require all clones to close and the file to reopen.
Backend process-exit and injected-I/O
tests are distinct from the protocol contract. Separate upstream hooks default to denial. An intermediary
uses its own self-issued Agent token while the retained upstream ties preserve
the original accountable Agent/person; it never acquires the caller's key.

`PersonServer::with_federation` selects an AS exchange for every token request,
including collocated PS=AS. Host consent precedes dispatch. The PS signs exact
Agent/Resource/presented credential bytes with its `jwks_uri` proof. Its host
adapter owns admitted metadata discovery and bounded HTTPS. The independent AS
verifies that service proof and all three credentials before resource policy,
then caps a scope grant at the Agent and presented credential expiries. The PS
verifies AS role/issuer, every context binding, scope and lifetime before commit
and release. A federated retained record keeps AS issuer/JTI token identity and
an explicit PS binding namespace. Old local records omit that optional field.
The memory/redb contracts check ancestry, exact retries, revocation and reopen.

AS and PS continuations use separate role-local stores. The PS exposes an AS
Payment or Claims requirement only to its trusted host; the Agent receives
Approval at the PS pending URL. The host confirms settlement, supplies trusted
claims or obtains approval, then explicitly advances the AS exchange. Agent
polls read PS custody without outbound AS I/O. Each continuation has one terminal
delivery, while cross-exchange equivalent-grant reuse and HTTP request replay
remain separate host concerns. The issued-token store is not a replay cache or
a durable continuation adapter.

## Bytes and consequences

JWS verification uses the original protected-header and payload segments. The
verified Agent token retains the original compact string. Unknown additive Agent
claims remain available to host policy; they are not rewritten as authority.
Protocol functions perform no network I/O themselves. PS federation invokes its
host transport callback during an explicit token request or continuation advance.
Each advance sends at most one signed AS request; there is no background polling,
automatic settlement or retry of application effects.

The Resource HTTP profile accepts absolute HTTPS requests with buffered actual content,
up to 1 MiB. It covers the four AAuth base components, query and Authorization
when present, and SHA-256 Content-Digest on nonempty content or a supplied digest.
Content-Type is also covered when present on nonempty content. The verifier
compares the digest with the actual bytes before policy, then verifies the proof.
Ordinary empty requests retain their previous coverage; a supplied empty-content
digest is checked, while Content-Type on empty content remains outside that
conditional rule. Hosts bound collection and supply bytes before decompression.
PS and AS POST endpoints additionally require covered Content-Type and Content-Digest
on their JSON content, as Core requires. General component processing,
streaming/trailers and application body interpretation remain outside this
buffered profile.

## Rust choices

The workspace is the distribution unit; crates are independently usable API
units. `http` types avoid coupling a role to a server framework or async runtime.
Ownership retains token bytes without a universal shared store. Ed25519 and
SHA-256 use Rust implementations; `sfv` owns Structured Fields grammar.

TLS appears in two places: example and test infrastructure, in
`aauth-rust-resource`'s dev-dependencies, and the opt-in `aauth-rust-discovery`
crate. Both use rustls with ring, because it is a supported, portable crypto
provider; ring includes native code. No crate links OpenSSL, and the protocol
and role crates have no TLS provider. `aauth-rust-discovery` keeps the egress
rules in `aauth-rust-signature-key`: it resolves a host, admits every address
with `admit_fetch` or `admit_redirect`, connects to an admitted address, checks
the peer with `accept_pinned_peer` and the body with `accept_response`. It speaks
one HTTP/1.1 request per connection with a bounded codec over `httparse`, and
blocks the calling thread; name resolution runs on a short-lived thread so the
fetch deadline covers it. The core `RevocationDirectory` call carries the
sender (issuer, `dwk`, `kid` and signing key) and the recipient's role document,
so a delivery is always signed as the role that computed the cascade. Native CI jobs build the executable on each
enabled target rather than inferring that a library cross-build ran the journey.

Discovery snapshots live in Core because they implement the AAuth token
profiles: an expected `dwk`, exact issuer identity and a host trust boundary.
Signature-Key remains generic: it extracts key material and verifies a proof
with the supplied key. The explicit `jwks_uri` scheme exposes unverified service references and
requires host-admitted resolution. `self-jwt` carries the Events delivery: the
AP verifies the event token and the HTTP signature with the one Resource key
its resolver returns. Core's minting helpers encode
and sign claims; they do not authorize issuance. The AP, PS, AS and Resource roles
own issuance policy, lifetime bounds and retained state where required.
Core owns claim syntax and common verification, including
the draft's distinction between `iat` and token validity. These boundaries
support independently usable Rust crates without importing a server runtime.

A one-level parent-mediated child uses two authenticated identities. Policy and
PS consent keep the parent in `.agent`; `.subagent` is the verified child, whose
key receives Person/Auth `cnf`. The parent signs PS requests and owns PS pending
polls, while the PS signs AS requests and owns AS pending polls. Exact parent and
child compact tokens remain retained across those transitions. Child proofs are
used at the Resource. `Subagent` verifies child-bound deliveries using public key
material, so the parent needs no child private key.

Retained child records name the holder in `agent`, the authoritative parent in
optional `parent_agent`, and the parent binding in `principal`. First-child Person
issuance establishes that binding atomically; revocation blocks new issuance and
pending delivery without invalidating credentials already delivered. Both memory
and redb stores execute the expanded logical and consuming reopen contracts.
Local AP issuance verifies the actual parent token; no identifier parsing grants
authority. This profile refuses recursive delegation and child/upstream chaining.

## Approved mission boundary

Core ApprovedMission verifies exact document identity and current member shape,
without authenticating approval. PS MissionRecord adds the trusted PS, complete
Agent owner, independently authenticated private person and permanent state.
Store::missions defaults to None. An implementation returning MissionStore must
share the SAME issuance transaction; a separate check followed by Store::commit
is insufficient. MemoryStore holds both under its existing mutex. redb remains
mission unsupported. Policy receives owned verified mission context; credential
release rechecks state, binding and current time after host work. A direct
Resource receives signed mission context only after `with_mission_context`;
otherwise it refuses the digest before policy. Host policy still admits the
payload. Core never imports the role or storage adapter.

## Supervision boundary

The Supervision wire values (metadata, envelope, decisions, reach, events and
the error table) live in Core, as the Events tokens do. The supervision server
is its own role crate; the Person Server side is an opt-in of the PS role, and
neither imports the other. Response signing is generic RFC 9421 in
Signature-Key: a response names its signer in `Signature-Key`, and `;req`
components bind it to the request it answers.

With supervision enabled, the PS routes each act through one decision point:
no deciding server leaves host policy in charge; a deciding server's `allow`,
`deny` or `ask` replaces it. Host policy still identifies the person. A held
act keeps the agent's exact request and is resumed through the same
verification as the original request, with the allowance injected instead
of asking again. The PS performs no background I/O: the agent's request, its
clarification answer, and explicit host calls each send at most the requests
they need, and every supervision request first delivers its pair's outbox, so
reports reach a server in the order the acts occurred. One host
`ContinuationStore` holds held acts, the decision log, outboxes, connections
and each agent's journal; the supervision server keeps its records in another.
