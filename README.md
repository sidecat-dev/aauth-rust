# AAuth for Rust

MIT-licensed Rust libraries for [AAuth](https://github.com/dickhardt/AAuth),
alongside [aauth-go](https://gitlab.com/sidecat-dev/aauth-go).
Showcase tag `v0.1.0-alpha.10`. The crates are not on crates.io.

```sh
git clone https://gitlab.com/sidecat-dev/aauth-rust.git
git checkout v0.1.0-alpha.10
cargo run --locked -p aauth-rust-resource --example direct-identity
```

That example needs Rust 1.99.1 and a C compiler for its TLS provider. It uses
loopback only: no account, DNS change, or external service. The checks it prints
are under Run the local example.

Every crate in this workspace is MIT, including `aauth-rust-budgets` and
`aauth-rust-r3`. The workspace `LICENSE` and each crate `LICENSE` are the same
text. Direct dependencies are mostly MIT OR Apache-2.0. These locked direct
dependencies are not MIT-only: `ed25519-dalek` 2.2.0 is BSD-3-Clause, `ring`
0.17.14 is Apache-2.0 AND ISC, and `rustls-webpki` 0.103.15 is ISC.

[CONFORMANCE.md](CONFORMANCE.md) is the behavior record. This tag does not claim
full R3, Events, Bootstrap, or Supervision. Directory recovery there is a process
exit, not power loss. Person Server, Access Server, budgets, and one-level
sub-agent guides remain in the sections below.

## Run the local example

Install [Rust with rustup](https://rustup.rs/) and a platform C compiler for the
test/example TLS provider: Linux `build-essential`, macOS Xcode Command Line
Tools, or Windows Visual Studio C++ Build Tools. Library builds use pure Rust
dependencies. The checkout pins Rust 1.99.1; on first use rustup downloads that
toolchain, rustfmt and clippy (several hundred MB), and Cargo downloads crates.

```sh
cargo test --workspace --locked
cargo run --locked -p aauth-rust-resource --example direct-identity
cargo run --locked -p aauth-rust-resource --example three-party
cargo run --locked -p aauth-rust-resource --example four-party
cargo run --locked -p aauth-rust-resource --example four-party -- --deferred
cargo test --locked -p aauth-rust-resource --example subagent
cargo run --locked -p aauth-rust-resource --example subagent
```

The direct-identity example generates fresh keys and certificates, starts an Agent Provider
and Resource on random loopback ports, retrieves public discovery documents,
and runs 14 wire/TLS checks. It needs no account, DNS change, privileged port,
existing certificate or external service. It uses a fixed clock for repeatable
boundary cases and closes its listeners and threads on exit. Output includes:

```text
unsigned: 401 requirement=agent-token
valid-identity: 200 aauth:Agent@ap.example
hwk-proof: 200 pseudonymous proof verified
hwk-identity: 401 error=unsupported_scheme
tampered-signature: 401 error=invalid_signature
policy-denial: 403 no signature diagnostics
untrusted-tls: 0 certificate refused
```

The proof-only endpoint accepts an inline public key; the identity endpoint
requires an Agent token. Thus `hwk-proof` and `hwk-identity` have different
outcomes. Status `0` means the TLS handshake failed before any HTTP response.

The three-party example runs an AP, Person Server, Orders and Inventory over
certificate-verified TLS. One pre-authenticated demo account obtains Person and
Auth tokens, posts an order, and lets Orders call Inventory with its own Agent
key and the original caller's upstream token. A changed body is refused before
either application runs. Its output includes:

```text
unsigned=401 person-challenge=401 tampered=401 authorized=200
orders=1 inventory=1 directed-subjects-differ=true downstream-within-upstream=true intermediary-binding=false untrusted-TLS-refused=true
```

The four-party example adds a separate Access Server. The Agent obtains a Person
credential, verifies the Resource's AS-directed challenge, and asks its PS for
consent. The PS signs a service request with `jwks_uri`, the AS verifies all three
credentials and issues its grant, and the PS verifies and retains that exact
grant before returning it. The Agent verifies delivery and signs a POST that
produces one effect. The example also refuses changed content, AS denial,
malformed delivery, an untrusted PS and an untrusted TLS certificate. Run the
[complete four-party source](crates/aauth-rust-resource/examples/four_party/mod.rs)
without accounts, public DNS, privileged ports or external services. It owns and
closes temporary listeners; its memory store and fixed demo person are disposable.
See [run an Access Server](USE-IN-YOUR-SERVICE.md#run-an-access-server-and-federated-person-server)
for the library integration and transport boundary.

See the [three-party source](crates/aauth-rust-resource/examples/three_party/mod.rs)
and the [Person Server service guide](USE-IN-YOUR-SERVICE.md#run-a-person-server).
The example supplies volatile state and one explicit demo policy. A real host
supplies person authentication, durable storage and consent policy.
For local durable storage, the separate
[`aauth-rust-person-server-redb`](crates/aauth-rust-person-server-redb) crate
implements the PS `Store` with transactional file-backed bindings and exact
issuance lineage on Unix filesystems supporting directory synchronization.
See [durable PS storage](USE-IN-YOUR-SERVICE.md#durable-person-server-storage)
for setup, restart and retention boundaries. The TLS example continues to use
disposable `MemoryStore` state.
`Requirement::from_headers` in the Agent crate extracts immediate challenges as
Structured Fields; the Agent then verifies them before exchanging credentials.
For a deferred PS `202`, use `PollSession` as described below.

For explicit client polling helpers and their current server-side limits, see
[prepare Agent polls](USE-IN-YOUR-SERVICE.md#prepare-explicit-agent-polls).

## Deferred grants and host settlement

With continuations enabled, an Access Server can wait for approval directly.
If it requests payment with `402 Payment`, the trusted **Person Server host
settles the payment**. The Agent receives `202` with an Approval requirement and
polls the PS pending URL using `PollSession`; the immediate
`Requirement::from_headers` parser returns `Unsupported` for approval. Claims
requests also stay host-side and appear to the Agent as Approval. This profile
provides no Agent payment hint or Agent settlement operation.

The host inspects `federation_pending`, obtains confirmed settlement, claims or
external approval, then explicitly calls `advance_federation`. Agent polls only
read PS custody and never advance the AS exchange. The
[service guide](USE-IN-YOUR-SERVICE.md#configure-as-and-ps-continuations) includes
a compile-checked host step, retry handling and the delivery/replay limits.
The deferred four-party example above executes payment, approval and one terminal
delivery over TLS with fixture settlement; it calls no payment provider.
For approval alone, follow the guide's
[approval-only composition](USE-IN-YOUR-SERVICE.md#approval-without-payment).
Host completion does not shorten the caller's current `Retry-After`. A consumed
PS delivery returns `410 gone`; it does not spend the delivered Auth token or
deduplicate a Resource effect. See
[delivery and Resource replay](USE-IN-YOUR-SERVICE.md#delivery-and-resource-replay).

## Use the libraries

The following complete program issues a token, signs a request, verifies it,
and applies admission policy in process. Run its exact source with
`cargo run --locked -p aauth-rust-resource --example library`.

```rust
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::{AgentIdentityResource, Decision};
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let issuer = "https://ap.example";
    let provider = AgentProvider::new(issuer, "ap-1", SigningKey::generate())?;
    let agent_key = SigningKey::generate();
    let token = provider.issue(&AgentClaims {
        iss: issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent@ap.example".into(),
        jti: "example-issuance-1".into(),
        iat: now,
        exp: now + 300,
        cnf: Confirmation {
            jwk: agent_key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    // This application trusts this provider; a network host supplies admitted documents.
    let keys = AgentProviderKeys::from_documents(issuer, &provider.metadata()?, &provider.jwks()?)?;
    let resource = AgentIdentityResource::new(
        "https://resource.example/whoami",
        keys,
        |token: &VerifiedAgentToken, _request: &Request<Vec<u8>>| {
            token.claims().sub == "aauth:Agent@ap.example"
        },
    )?;
    let agent = Agent::new(agent_key, token)?;
    let mut request = Request::builder()
        .uri("https://resource.example/whoami")
        .body(Vec::new())?;
    agent.sign(&mut request, now)?;
    match resource.authorize(&request, now) {
        Decision::Granted(token) => println!("verified {}", token.claims().sub),
        other => return Err(format!("request refused: {}", other.into_response().status()).into()),
    }
    Ok(())
}
```

### Build a separate application

Use versioned path dependencies until the alpha packages are published. The
following POSIX shell recipe starts in this checkout and creates an **unused**
sibling directory, `../aauth-service`. It assumes the checkout is named
`aauth-rust`; adjust the manifest's paths if you used another name. Paths are
relative to the application's `Cargo.toml`, not your shell's current directory.
Keep the application outside this checkout's Cargo workspace. The empty
`[workspace]` table also makes it independent of any containing workspace.

The application needs its own toolchain selection and lockfile: a path dependency
does not select its checkout's `rust-toolchain.toml` or adopt that checkout's
`Cargo.lock`. This copies the pinned Rust 1.99.1 selection and the unchanged
complete program above. Install rustup first; it may download that toolchain and
components. Initial dependency resolution/builds may also download registry
crates, even though the AAuth crates themselves come from local paths.

<!-- consumer-bootstrap-setup:begin -->
```sh
(
set -eu
mkdir ../aauth-service
mkdir ../aauth-service/src
cp rust-toolchain.toml ../aauth-service/
cp crates/aauth-rust-resource/examples/library.rs ../aauth-service/src/main.rs
cat > ../aauth-service/Cargo.toml <<'TOML'
[package]
name = "aauth-service"
version = "0.1.0"
edition = "2024"
rust-version = "1.99"
publish = false

[workspace]

[dependencies]
aauth-rust-agent = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-agent" }
aauth-rust-agent-provider = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-agent-provider" }
aauth-rust-core = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-core" }
aauth-rust-jose = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-jose" }
aauth-rust-resource = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-resource" }
http = "1"
TOML
cd ../aauth-service
rustup show active-toolchain
test ! -e Cargo.lock
cargo generate-lockfile
)
```
<!-- consumer-bootstrap-setup:end -->

The setup stops if `../aauth-service` already exists. Choose a new name rather
than overwriting an existing application. For an existing app, merge the package
and dependency settings into its own manifest instead. Add any optional role
dependencies below before generating its lockfile.

After initial resolution, keep the application's `Cargo.lock` with its source
and use locked builds. Starting again from the AAuth checkout:

<!-- consumer-bootstrap-build:begin -->
```sh
(cd ../aauth-service && cargo build --locked --jobs 2)
```
<!-- consumer-bootstrap-build:end -->

This compiles the consumer; it does not run the program. `--locked` refuses a
missing or outdated lockfile. `generate-lockfile` does not accept `--jobs`;
put `--jobs 2` on the build. After intentional dependency changes, regenerate the
lockfile and review its changes. Offline use additionally requires the toolchain
and all resolved registry dependencies to be cached; a lockfile alone does not
supply those bytes.

The program above uses the identity crates. If your application also hosts a
federated Person Server and Access Server, add these entries to the same
`[dependencies]` table:

```toml
aauth-rust-person-server = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-person-server" }
aauth-rust-access-server = { version = "0.1.0-alpha.10", path = "../aauth-rust/crates/aauth-rust-access-server" }
```

Use `SigningKey::generate()` for fresh keys. `from_seed` imports caller-owned
secret material; the constant seeds in tests are fixtures. Assign a unique `jti`
for each real issuance. Put the Agent key's public JWK in `cnf.jwk`, then move
the same private key into `Agent::new`. Call `sign` last, after the URI and other
headers are final. It replaces previous signature headers. Changing a covered
component's canonical value afterward invalidates the signature. RFC 9421
removes leading/trailing spaces and tabs from field values and combines field
lines with `, `; outer whitespace alone does not change the signed value.
Host policy must interpret Authorization consistently with that canonicalization
or reject forms it does not support. Signing never sends or retries.

Configure each Resource with its own HTTPS endpoint (authority and path);
never copy that configuration from the client Host header. The library refuses
requests for another endpoint before invoking policy, even if their signatures
are valid. Signed query values may vary at the configured path. Frameworks such as
axum usually give servers an origin-form URI (`/path?query`). Before verification,
reconstruct its absolute URI using your configured external HTTPS origin and
the original path/query. Keep the receiving method and covered header values.
Behind a TLS proxy, trust forwarded authority/scheme only under an explicitly
configured proxy trust boundary, not arbitrary client headers.

Policy receives both `&VerifiedAgentToken` and `&Request<Vec<u8>>`, after target,
token and proof checks, so it can decide from the authenticated method, query
and covered headers. For state stored in a server, use the named `BoxedPolicy`
type with `AgentIdentityResource<AgentProviderKeys, BoxedPolicy>`; a boxed closure
can capture application state. `VerifiedAgentToken` is Clone for handler state;
its Debug output omits the compact credential. A policy can also return
`Result<T, Deny>`; `Decision::Granted` carries `Authorized<T>`, whose `admitted()`
value reaches the handler without another verification. Boolean policies still
work. Use `Decision::into_result()` to obtain `(verified_token, admitted_value)`
or a boxed refusal response, instead of mapping a granted request to a demo body.
`Agent::with_token(new_token)` reuses its key for refresh without handling seed
bytes. Resolvers can be borrowed, boxed or shared with Arc; snapshots are Clone.
The [service guide](USE-IN-YOUR-SERVICE.md) covers request adaptation, Person
Server integration, trust, refresh, rotation, replay and local ports.
Run the [axum example](crates/aauth-rust-resource/examples/axum.rs)
with `cargo run --locked -p aauth-rust-resource --example axum` to see request
adaptation and a handler using typed policy context.

All times are **Unix seconds**, not milliseconds. Local signing/verifier clocks
and AP-issued iat/exp are limited to 0..=8589934591 (through 2242), rejecting
contemporary millisecond timestamps before signing or issuance. Expiry has no leeway; the
Resource accepts signature `created` within ±60 seconds and refuses `iat` more
than 60 seconds ahead. Core JWT verification alone does not use `iat` as a
validity check. The AP issues tokens lasting at most 24 hours; verification
does not turn that recommendation into a mandatory lifetime ceiling for other
issuers. Requests use absolute HTTPS URIs. The signer covers method, authority,
path, Signature-Key, query when present, and Authorization when present. On
nonempty content it automatically computes SHA-256 Content-Digest and covers it,
plus Content-Type when present. The Resource checks the digest against the
actual content before policy. Removing a signed body also fails verification.
A supplied digest on empty content is covered and checked too.

This is a local safe default for buffered Resource requests, not a universal
draft requirement for arbitrary Resource APIs. The limit is 1 MiB; hosts must
bound collection before allocating and supply actual content bytes before any
decompression. Streaming/trailer digests are not implemented. Passing an empty
Vec while forwarding unread content defeats body authentication. Missing required
coverage returns invalid_input with required_input; malformed/mismatched digest
or proof returns invalid_signature. Body integrity does not prevent replay.

For a multi-route service, `AgentIdentityResource::for_origin(origin, keys,
policy)` shares one verifier across paths; the exact-endpoint `new` constructor
remains available. Both verify the actual signed path before policy. The host
router/policy admits routes. `resource.metadata()` returns the verifier's
minimal `/.well-known/aauth-resource.json` document; the axum example serves it
publicly. See [service integration](USE-IN-YOUR-SERVICE.md).

## Trust and vocabulary

The application chooses trusted Agent Providers. It obtains metadata and public
keys over admitted, verified HTTPS, then gives the library those bytes as an
immutable snapshot. `from_documents` checks issuer equality and key selection;
it does not decide to trust an arbitrary issuer or fetch anything. A foreign
issuer yields terminal `UntrustedIssuer` (`invalid_key` on the wire); only an
unknown kid on a configured,
trusted issuer yields `UnknownKey`. Refresh the configured JWKS source after
checking issuer trust; never follow a token-supplied issuer on that error.
Metadata with a missing or unusable `jwks_uri` yields terminal
`InvalidDiscoveryMetadata` (`invalid_key`), not an unknown-key refresh hint.
Production hosts own destination admission, timeouts, cache lifetime and refresh (including
the draft's once-per-minute fetch floor), key storage, enrollment, revocation,
replay policy and clocks. This profile supplies no nonce: if you require replay
refusal, key the replay cache on the proof bytes within the accepted time window.
See [SECURITY.md](SECURITY.md).

| Name | Meaning here |
| --- | --- |
| AP, PS, AS | Agent Provider (issues Agent tokens), Person Server (binds a person and issues Person/Auth tokens), Access Server (evaluates Resource policy and issues federated Auth grants). |
| `dwk` | Discovery well-known document name; for example, `aauth-agent.json` locates AP metadata at `{iss}/.well-known/aauth-agent.json`. PS and Resource keys use their own role documents. |
| JWK, JWKS, JWS | JSON Web Key, set of public JWKs, JSON Web Signature. `kid` selects an issuer key from its JWKS. |
| `hwk`, `jwt`, `cnf.jwk` | Signature-Key schemes conveying an inline public key or a compact token; the token's confirmation JWK binds its holder's request-signing key. |
| `jwks_uri` | Service proof referring to an admitted signer origin, role document and exact key ID; the PS uses it to authenticate to the AS. Resolution is host-owned and precedes trust attribution. |
| `sig`, coverage, SFV | The selected signature label, the request values bound by its signature, and Structured Field Values used to encode signature headers. The same label correlates Signature-Key, Signature-Input and Signature. |
| Direct Agent identity | An Agent proves itself directly to a Resource, without a Person Server in the exchange. The loopback example executes this complete exchange. |
| Person, Resource, Auth tokens | A PS-signed identity for one Resource; a Resource-signed authorization challenge; and a PS- or AS-signed scoped authorization. Each binds its intended audience and holder key. |
| `presented_token`, `upstream_token` | The actual Person/Auth credential being exchanged; the caller's credential supplied by an intermediary for a downstream chain. Exact retained ties prevent replacement or omission. |
| R3 | Rich Resource Requests. Full compliance is postponed by vocabulary; general media/service vocabularies can grow on demand in both libraries. None executes in this Core-scope profile. |

A `Decision` grants verified identity, requests an Agent token (`401` with
`AAuth-Requirement`), reports a signature failure (`401` with `Signature-Error`),
or denies host policy (`403`). Algorithm/scheme failures include
`Accept-Signature-Alg`/`Accept-Signature-Scheme`. Failures have Problem Details
bodies; policy denials contain no signature diagnostics. The successful
`into_response()` convenience mapping writes the verified `sub` as its body;
use `into_result()` to call your own handler. A Resource `clock_skew` response
includes Date from the supplied verifier clock. Local Rust error
messages explain what to fix; `.code()` returns the stable protocol code.

## Build and contribute

[ARCHITECTURE.md](ARCHITECTURE.md) explains the nine crate boundaries;
[SPECIFICATIONS.md](SPECIFICATIONS.md) pins the source text and digests.
[CONTRIBUTING.md](CONTRIBUTING.md) gives the change and verification workflow.

```sh
rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-msvc
cargo check --workspace --lib --locked --target aarch64-unknown-linux-gnu
cargo check --workspace --lib --locked --target x86_64-pc-windows-msvc
cargo check -p aauth-rust-person-server-redb --tests --locked --target x86_64-pc-windows-msvc
```

These checks typecheck libraries for ARM64 Linux and Windows MSVC, plus the
redb adapter's Windows test code. They emit Rust metadata without a target C
compiler or foreign execution. They do not link an application or execute the
Windows refusal test. The redb adapter still refuses non-Unix open; a Windows
Person Server needs another `Store`. Resource TLS tests and examples use rustls/ring as development dependencies,
so building those targets requires the target C compiler and linker.
[CI](.gitlab-ci.yml) uses the Linux x86_64 Docker runner tagged `sprint-gen6`
and a pinned Rust 1.99.1 image, with two Cargo build jobs. It runs the workspace
checks/examples, these cross-target checks and the workspace package dry-run,
and retains the Linux demo binary and nine verified crate archives for 14 days. ARM64 and Windows checks do not qualify runtime behavior. macOS is
unverified; earlier platform evidence remains tied to its original revisions. The declared minimum toolchain is 1.99.
License: [MIT](LICENSE).

## Consuming a separately approved mission

The top-level immediate PS/Resource path supports Core scopes with a mission
that the host has already approved. Decode its exact persisted base64url bytes
and digest with `aauth_rust_core::ApprovedMission::decode`. Authenticate the
approving PS beside the digest and independently obtain the private person and
complete Agent identity. Install a `MissionRecord` through
`MemoryStore::install_approved_mission`, then use that same store in PersonServer.
The record includes `person_server`, `owner`, `person_id`, `document` and
`MissionState::Active`. A record in any other state is refused and does not
create a person binding. Installation is a host administration interface, never
proof of human approval or a login/mission-creation endpoint.

A signed `/person` request may include `mission_s256`. Policy receives a verified
`PersonRequest.mission`; its returned private person must match the approval.
The native PS caps the Person token. A direct Resource that calls
`with_mission_context` preserves the signed mission digest in its challenge;
redeem it at the PS with the exact presented token. Without that opt-in the
Resource refuses a mission-bearing credential before policy.
`AuthorizationRequest.mission` supplies the verified current host context, while
policy returns only requested scopes. The PS retains issuance atomically with
mission checks and caps Auth expiry. Resource host policy still enforces the
actual operation, revision and payload. A blob, Person token or waiting exchange
is not an Auth grant.

Existing stores default to mission unsupported. A custom MissionStore must share
the Store's atomic boundary; a two-store precheck is insufficient. The reference
store is volatile and terminates permanently, including expiry. The redb adapter
does not support this extension. AS, child/chained/federated missions, creation,
human review UI, automatic Resource revocation delivery and R3 remain excluded.
The public request/store controls are in the PS `tests/missions.rs`; scope and
interpretation details are in CONFORMANCE.md and INTERPRETATIONS.md.
