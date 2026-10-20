# Architecture

Small protocol crates establish wire facts. Role crates decide what to do with
those facts. Applications supply transport, trusted issuers, clocks, keys and
policy. This follows the sibling aauth-go architecture without reproducing its
unimplemented role surfaces as empty Rust crates.

| Crate | Owns | Depends on |
| --- | --- | --- |
| `aauth-jose` | Public Ed25519 JWKs, RFC 7638 thumbprints, exact compact JWS bytes, strict JSON | Rust crypto and serialization |
| `aauth-signature-key` | Bodyless HTTP signature bases, selected-label correlation, `hwk`/`jwt` key conveyance, proof time | JOSE, `http`, `sfv` |
| `aauth-core` | Agent identifiers, Agent-token claims and verification, retained AP discovery snapshot | JOSE |
| `aauth-agent-provider` | Host-approved token issuance, AP metadata/JWKS bytes | Core, JOSE |
| `aauth-agent` | One signed request using caller-owned credentials | Core, Signature-Key, JOSE |
| `aauth-resource` | Direct Agent identity, proof before policy, HTTP decision mapping | Core, Signature-Key |

Role crates never import one another. The example imports the roles and composes
them. It is not a new cross-role lifecycle abstraction. Person Server, Access
Server, Bootstrap, R3, Events and Budgets will get their own boundaries as
executing journeys require them; their absence is recorded in CONFORMANCE.md.

## Facts before policy

`AgentToken` is unverified. Its routing claims are explicitly named
`unverified_claims`. Only `verify` can construct `VerifiedAgentToken`.
The Resource obtains a token verification result, verifies the HTTP signature
against its `cnf.jwk`, and then invokes host policy. A valid proof does not grant
access. `hwk` can prove a key but cannot satisfy an AAuth Agent-identity challenge.

`AgentKeyResolver` is the host's trust boundary. `AgentProviderKeys` is one
immutable snapshot of metadata and JWKS for an explicitly configured AP. It
checks exact metadata issuer equality and selects only the JWT's named key.
It performs no network requests and makes no trust decision for its host.
Production hosts implement egress admission and bounded cache/refresh behavior
before supplying these snapshots or their own resolver.

## Bytes and consequences

JWS verification uses the original protected-header and payload segments. The
verified Agent token retains the original compact string. Unknown additive Agent
claims remain available to host policy; they are not rewritten as authority.
Protocol functions never send, poll, sleep, refresh credentials or retry effects.

The first HTTP profile accepts only bodyless absolute HTTPS request values.
It implements the four AAuth base components, query coverage when present and
authorization coverage when present. Unsupported components or body-bearing
requests fail explicitly. This keeps Content-Digest, general RFC 9421 component
processing and application body semantics outside the current claim.

## Rust choices

The workspace is the distribution unit; crates are independently usable API
units. `http` types avoid coupling a role to a server framework or async runtime.
Ownership retains token bytes without a universal shared store. Ed25519 and
SHA-256 use Rust implementations; `sfv` owns Structured Fields grammar.

TLS is example/test infrastructure. rustls uses ring because it is a supported,
portable crypto provider; ring includes native code. The library dependency
graph has no TLS provider or OpenSSL dependency. This exception is isolated in
`aauth-resource`'s dev-dependencies. Native CI jobs build the executable on each
enabled target rather than inferring that a library cross-build ran the journey.
