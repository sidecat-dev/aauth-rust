# Architecture

Small protocol crates establish wire facts. Role crates decide what to do with
those facts. Applications supply transport, trusted issuers, clocks, keys and
policy. This follows the sibling aauth-go architecture without reproducing its
unimplemented role surfaces as empty Rust crates.

| Crate | Owns | Depends on |
| --- | --- | --- |
| `aauth-rust-jose` | Public Ed25519 JWKs, RFC 7638 thumbprints, exact compact JWS bytes, strict JSON | Rust crypto and serialization |
| `aauth-rust-signature-key` | Buffered HTTP signature bases, SHA-256 Content-Digest, selected-label correlation, `hwk`/`jwt` key conveyance, proof time | JOSE, `http`, `sfv`, `sha2` |
| `aauth-rust-core` | Identifiers; Agent, Person, Resource and Auth JWT syntax/minting/common verification; trusted issuer snapshots | JOSE |
| `aauth-rust-agent-provider` | Host-approved token issuance, AP metadata/JWKS bytes | Core, JOSE |
| `aauth-rust-agent` | One signed request using caller-owned credentials | Core, Signature-Key, JOSE |
| `aauth-rust-resource` | Direct Agent identity, PS authorization and signed Resource challenges, proof before policy, HTTP decisions | Core, Signature-Key, JOSE |
| `aauth-rust-person-server` | Atomic person binding, retained issuance/lineage, direct Auth grants and immediate call chaining | Core, Signature-Key, JOSE |
| `aauth-rust-person-server-redb` | Durable binding, exact issuance and directed-identity indexes in one file-backed transaction | Person Server, redb, serialization |

Normal role dependencies never import one another; Resource dev-dependencies
compose the roles for tests and examples. Examples import the roles and compose
them without a cross-role lifecycle abstraction. The storage adapter imports the
PS role; the role never imports a database engine. Access
Server, Bootstrap, R3, Events and Budgets will get their own boundaries as
executing journeys require them; their absence is recorded in CONFORMANCE.md.

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
before supplying these snapshots or their own resolver.

`PsAuthorizationResource` separates Person identity from authorization. It turns
a verified Person token into a signed Resource challenge, then admits only a
verified PS-issued Auth token with the right audience, holder key and route
scopes. Its origin-wide value has one fixed scope profile; the host router owns
route selection. Policy receives verified Auth claims and the actual request.

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

## Bytes and consequences

JWS verification uses the original protected-header and payload segments. The
verified Agent token retains the original compact string. Unknown additive Agent
claims remain available to host policy; they are not rewritten as authority.
Protocol functions never send, poll, sleep, refresh credentials or retry effects.

The Resource HTTP profile accepts absolute HTTPS requests with buffered actual content,
up to 1 MiB. It covers the four AAuth base components, query and Authorization
when present, and SHA-256 Content-Digest on nonempty content or a supplied digest.
Content-Type is also covered when present on nonempty content. The verifier
compares the digest with the actual bytes before policy, then verifies the proof.
Ordinary empty requests retain their previous coverage; a supplied empty-content
digest is checked, while Content-Type on empty content remains outside that
conditional rule. Hosts bound collection and supply bytes before decompression.
PS POST endpoints additionally require covered Content-Type and Content-Digest
on their JSON content, as Core requires. General component processing,
streaming/trailers and application body interpretation remain outside this
buffered profile.

## Rust choices

The workspace is the distribution unit; crates are independently usable API
units. `http` types avoid coupling a role to a server framework or async runtime.
Ownership retains token bytes without a universal shared store. Ed25519 and
SHA-256 use Rust implementations; `sfv` owns Structured Fields grammar.

TLS is example/test infrastructure. rustls uses ring because it is a supported,
portable crypto provider; ring includes native code. The library dependency
graph has no TLS provider or OpenSSL dependency. This exception is isolated in
`aauth-rust-resource`'s dev-dependencies. Native CI jobs build the executable on each
enabled target rather than inferring that a library cross-build ran the journey.

Discovery snapshots live in Core because they implement the AAuth token
profiles: an expected `dwk`, exact issuer identity and a host trust boundary.
Signature-Key remains generic: it extracts key material and verifies a proof
with the supplied key. Supporting `jwks_uri` or `self-jwt` later may warrant a
shared discovery crate; they do not execute today. Core's minting helpers encode
and sign claims; they do not authorize issuance. The AP, PS and Resource roles
own issuance policy, lifetime bounds and retained state where required.
Core owns claim syntax and common verification, including
the draft's distinction between `iat` and token validity. These boundaries
support independently usable Rust crates without importing a server runtime.
