# Use AAuth in a service

The current profile supports direct Agent identity and Person Server (PS)
authorization, including an immediate downstream call. Your service supplies
issuer trust, HTTPS transport, person authentication, admission policy and state.
Replay/idempotency storage remains the application's responsibility.
Start with the README's library program, then run the framework example:

```sh
cargo run --locked -p aauth-rust-resource --example axum
```

It starts an axum service on a random loopback port, sends a signed request,
prints the verified identity and policy context, and shuts down. This demonstrates
the private HTTP hop behind a TLS proxy, using a configured external HTTPS
origin. For the certificate-verified TLS exchange, run `--example direct-identity`.
All framework/runtime dependencies belong to examples/tests, not the libraries.

## Adapt framework requests

The [axum adapter](crates/aauth-rust-resource/examples/framework/mod.rs) keeps
the received method, path/query and headers, reconstructs the absolute URI from
its configured external origin, and reads the actual body with a 1 KiB limit.
An oversized body gets 413 before verification. Within that adapter limit,
nonempty content reaches the gate and needs covered SHA-256 Content-Digest, plus
covered Content-Type when present. The Agent generates these from actual bytes;
the Resource verifies them before policy. The library itself permits up to 1 MiB.
Missing coverage gets invalid_input with the required fields; a malformed or
mismatched digest gets invalid_signature. Never verify an empty placeholder while
forwarding unread content, and verify content before decompression. Streaming or
trailer-based digests need a different adapter/profile; they are not implemented.
Direct library verification above its 1 MiB buffered ceiling reports
`invalid_request`, rather than a bad signature. Bound collection before calling
the library; the adapter's earlier 413 is preferable to allocating a large body.

Terminate TLS before this private hop. Take the external origin from service
configuration; accept forwarded scheme/authority only through an explicitly
trusted proxy boundary. An arbitrary Host or Forwarded header is not configuration.
Configure proxies to preserve the signed method, authority, path/query, body,
Content-Digest and Content-Type. Automatic Content-Type coverage means a proxy
that rewrites the media type after signing (for example, adding `charset=utf-8`)
breaks nonempty requests with a 401 signature failure. Make content and media
type decisions before the Agent signs, then preserve them through the proxy.

AgentIdentityResource::new(endpoint, keys, policy) retains exact authority/path
binding. For one gate shared by a router, use
AgentIdentityResource::for_origin(origin, keys, policy). Every request must still
use that configured authority and carry a valid proof over its actual path.
The router/policy decides which routes are allowed; origin mode is not a prefix
or route whitelist. The axum example shares one Arc<Resource> across /whoami and
/orders; keys are shared too, without fetching once per route.
The request-origin constructor accepts an optional root slash, so
`https://resource.example/` and `https://resource.example` configure the same
authority. Ports must be in 1..=65535; port zero is refused. This is transport
configuration; published server identifiers are separately validated below and
must have no trailing slash or port.
Resource discovery metadata is available through
`resource.metadata_for("https://resource.example")?`; the host serves it at
`/.well-known/aauth-resource.json` (the axum example does this). Configure that
published issuer separately from the signed request authority and listener
socket. For example, a Resource bound to `https://resource.example:8443` can
publish `https://resource.example` while still requiring `resource.example:8443`
in every signed request. The host supplies routing and TLS for both addresses;
publishing metadata does not change the verifier's authority/path binding.
The issuer must be a lowercase HTTPS DNS origin without port, path or trailing
slash. Invalid publication settings return `ConfigurationError::InvalidIssuer`
with local code `invalid_configuration`; fix the service configuration rather
than asking callers to refresh a token. Validate metadata at startup, as the
axum adapter does. The no-argument `metadata()` convenience uses the configured
request authority when it is also a valid published identity.

It reports agent-token access and the actual 60-second window. This verifier
publishes no signing keys, so no JWKS URL or authorization endpoint is invented.
The conditional nonempty-content coverage default is reported by required_input;
metadata does not falsely require digest/type on every empty call. A host may
add name/logo/documentation fields to its owned document while preserving the
configured issuer and actual protocol fields. A host that also signs server
calls or issues Resource tokens must add its actual required jwks_uri and role
metadata; the verifier helper does not supply those roles. Point agents at this document from landing/API pages with a Link header such as:
`Link: <https://resource.example/.well-known/aauth-resource.json>; rel="aauth-resource"`.
Use the configured canonical HTTPS identity; a caller-supplied Host is not that
identity. The Rust Agent does not fetch metadata automatically.

Only the named fields are authenticated. Content-Encoding and other headers
are not automatically covered. The library does not transform content; if your
host interprets an encoding, reject unsupported encodings or use a profile that
also authenticates those semantics. Verify raw content before decompression.

Covered header fields use RFC 9421 canonicalization: trim outer spaces/tabs and
combine field lines with `, `. Outer whitespace changes alone preserve a proof.
Present empty fields are signed as empty values, distinctly from missing fields.
This authenticates the field value without validating media type semantics;
reject an empty or unsupported Content-Type before interpreting content if your
application requires a media type. On empty content, Content-Type is not covered
by this conditional profile, even if Content-Digest was supplied. Reject that
form if the application would assign the unsigned type meaningful semantics.
Interpret Authorization consistently, or reject forms your application does not
support; do not treat signed coverage as a guarantee of raw header byte equality.

Use `Decision::into_result()` to send refusals or run your handler. Success yields
`(VerifiedAgentToken, admitted_context)`; refusal yields a boxed HTTP response.
A boolean policy carries `()`; `Result<T, Deny>` carries `T`. For example,
a policy can verify an upstream token once and pass that verified value to the
handler. `BoxedAdmissionPolicy<T>` gives that closure a name in application state.
The `Granted` payload also exposes `token()` and `admitted()` and dereferences to
the caller token for existing claim inspection. The demo `into_response()` success
mapping writes `sub`; use the extraction helper for an application response.

## Trust and refresh

Choose trusted issuers before inspecting a token. Fetch their metadata and JWKS
over admitted, certificate-verified HTTPS with deadlines, response bounds and
DNS/redirect controls. Construct `AgentProviderKeys` from those documents and
share it through Arc, references or Box. Snapshots are immutable and Clone;
a host resolver can replace a snapshot atomically after refresh.

`UntrustedIssuer` is terminal (`invalid_key` on the wire): never follow or refresh
a foreign token-named issuer. `UnknownKey` means a missing kid on a trusted
issuer. Refresh that issuer's configured JWKS source subject to cache lifetime
and the pinned draft's fetch-rate floor, then retry verification at most once.
Keep ordinary cache expiry/refresh independent from that recovery path. The
library does not fetch, cache or retry network effects for you.
Missing or invalid metadata `jwks_uri` is terminal `InvalidDiscoveryMetadata`
(`invalid_key`), so it must not trigger unknown-key retry logic.

## Keep Agent credentials fresh

Retain the Agent and obtain a new token before expiry, using the same confirmation
public key. `agent.with_token(new_token)` reuses the existing private key without
exporting its seed; earlier Agent values remain usable for in-flight requests.
If enrollment changes the confirmation key, create a new Agent with that key.
Use `agent.public_jwk()` for the renewed claims' `cnf.jwk`: it returns an owned
public-only value, so the host need not parse the previous token or retain seed
bytes. No background enrollment or refresh loop runs inside the library.

`Agent::new` checks syntax and key binding; it does **not** authenticate the AP's
signature. `AgentToken::parse(...).unverified_claims()` can inspect refresh hints,
but those claims confer no authority. A client that has a trusted AP key resolver
can call `AgentToken::verify(&resolver, now)` itself. It uses the same Core
verification API as a Resource; there is no prohibition on client verification.

All local clocks are Unix seconds in 0..=8589934591 (through 2242). Contemporary
millisecond timestamps are refused at signing/preparation and AP issuance. Values
inside the range cannot reveal their units, so convert explicitly. AP issuance
also caps lifetime at 24 hours; verification of another issuer does not turn the
recommendation into a mandatory ceiling. Expiry has no leeway. Resource proof
and optional future-iat bounds are 60 seconds.
Resource `clock_skew` responses include Date using the verifier clock you passed.

## Rotation and discovery documents

**AP-KEY-ROLLOVER is an explicit gap.** The AP convenience API publishes only its
active signing key. It has no retained-key list, overlap schedule or automatic
retirement lifecycle. Replacing the AP does not remove keys from existing verifier
snapshots. Old tokens fail after a refresh replaces the snapshot with a JWKS
that omits their key; do not describe that as seamless rotation. A host supplying
its own multi-key JWKS can retain public keys for its outstanding tokens; the
resolver selects by kid and tests cover old/new verification and later removal.
The host owns retention, refresh and retirement policy. Go shares this AP gap.

`metadata()` supplies minimal issuer/JWKS-location bytes. A host can publish its
own metadata with the same exact issuer and admitted HTTPS JWKS URL, plus the
draft's branding/policy fields. No AP branding builder is provided.
`AgentIdentityResource::metadata_for(issuer)` is a separate verifier-only Resource
document. Server identifiers have no port or path. In local deployments,
map those logical identities to admitted sockets while preserving HTTPS names,
SNI and certificate verification. Temporary loopback ports belong to that map,
not to the token's `iss`. JWKS endpoint URLs are distinct from server identifiers.

### Collocated AP and Resource keys

When a Resource is also its own AP, both default metadata documents name
`https://resource.example/.well-known/jwks.json`. Serve **one merged JWKS** there
containing the public keys for both roles, with unique `kid` values for distinct
keys. Serving only `resource.jwks()` makes the AP's Agent tokens unverifiable;
serving only `provider.jwks()` makes Resource challenges unverifiable. Each role
still has its own well-known metadata document and the same exact issuer.

The [three-party example](crates/aauth-rust-resource/examples/three_party/mod.rs)
composes the host-owned document this way, using its own validated helper outputs:

```rust
let mut combined: serde_json::Value = serde_json::from_slice(&resource.jwks()?)?;
let ap: serde_json::Value = serde_json::from_slice(&provider.jwks()?)?;
combined["keys"].as_array_mut().unwrap()
    .extend(ap["keys"].as_array().unwrap().iter().cloned());
let public_jwks = serde_json::to_vec(&combined)?;
```

Configure distinct kids before merging and publish the resulting bytes at the
shared route. Merging does not add rotation or retirement policy. A host can
instead publish separately admitted JWKS URLs in its owned role metadata; the
default helpers use the shared URL. Do not accept arbitrary external JWKS input
through this composition path.

## Replay and application effects

**Identical signed bytes can be accepted twice within the validity window.**
The replay test demonstrates two policy calls for the same proof. Authentication
is not once-only delivery. For operations that change state, use an application
idempotency key and atomically record the result with the operation. If you also
need exact replay refusal, retain a key derived from the selected key identity
and proof bytes for the proof's accepted window, including allowed future skew.
Token `jti` identifies issuance, not one request; many requests reuse a token.
A freshness tuple that omits query/authorization may intentionally reject more
than exact replays, so choose that policy with your application's concurrency in mind.

In a chain, replaying the same upstream POST can start a **whole second downstream
chain**: new PS Person/Auth issuances, another downstream call and another
application effect. The TLS replay regression sends the exact authorized POST
twice and observes two Orders effects and two Inventory effects. Establish
application idempotency at the intermediary
**before** requesting downstream credentials or dispatching work. Bind a signed
operation key to the authenticated caller and request content, atomically reserve
it, and retain the result for retries. Exact-proof replay detection is another
host option within the accepted proof window. An upstream token's `(iss, jti)`
identifies a credential, not an operation; using it alone would suppress different
legitimate requests made with that token. PS retained lineage does not deduplicate
application requests or provide exactly-once downstream delivery.

Forwarded Agent-token bytes prove what their issuer signed. They do not prove
that the original caller authorized this service or this downstream operation:
Agent tokens have no Resource audience binding in this slice. Carrying the bytes
in a covered Authorization header prevents substitution in that request; it does
not create AAuth delegation. Person binding and protocol call chaining require
Person/Auth tokens and the Person Server exchange described below.

## Run a Person Server

Add `aauth-rust-person-server` alongside the README's path dependencies. Its
[`PersonServer`](crates/aauth-rust-person-server/src/server.rs) accepts a `Config`,
trusted issuer resolver, `Store`, `Policy`, clock and token-ID source. The crate's
module rustdoc contains a complete constructor example. The role is synchronous
and framework-independent; adapt absolute HTTPS requests with bounded actual
bytes as above. The public routes are:

| Method and path | Purpose |
| --- | --- |
| GET `/.well-known/aauth-person.json` | PS issuer, JWKS and implemented endpoint URLs |
| GET `/.well-known/jwks.json` | Public active signing key |
| POST `/person` | Bind a verified Agent to an authenticated person and issue Resource-directed identity |
| POST `/token` | Verify a Resource challenge and presented credential, obtain a host grant, then issue Auth |

Set `Config.issuer` to the canonical PS identity, without port or trailing slash.
Set `signed_origin` separately when the request authority includes a port. The
host must route published endpoint URLs to the listener while preserving the
configured signed authority and verified TLS names. Invalid configuration fails
at construction with `invalid_configuration`. PS JSON POSTs require covered
Content-Type and Content-Digest. Send `application/json` and sign after populating
the actual bytes; the Agent helper supplies the digest and coverage automatically.
Media type matching ignores ASCII case and accepts parameters, such as
`Application/JSON; charset=utf-8`. Signature verification still covers the original
header bytes: changing only Content-Type case after signing invalidates the proof.

Implement `Policy::bind_person` using host-authenticated evidence and the verified
Agent identity. Login hints and tenant parameters are signed Agent assertions,
not person authentication. Return `Person.id` as a stable internal identifier,
and `Person.subject` as a stable opaque identifier directed to the requested
Resource. Do not publish the internal identifier or reuse the public subject at
another Resource. Tenant is organization context and may change without changing
the person. One Agent issuer/subject tuple binds to one accountable person;
conflicting or revoked bindings cannot be overwritten by policy.

This subset has no interaction endpoint or deferred login channel. Person
authentication therefore comes from evidence the host already has. Two patterns
are a prelinked directory entry for the exact verified Agent `(iss, sub)` tuple,
established through the person's existing authenticated account/onboarding flow;
or an explicit contract with a trusted AP that authenticates the person before
issuing its Agent token and signs a host-specific account claim such as `acct`.
In the latter pattern, `bind_person` checks the exact admitted AP issuer, reads
`request.agent.claims().extra.get("acct")`, validates the agreed claim shape and
maps it through the host's account directory. Generic AP trust alone does not
give an arbitrary custom claim person-authentication meaning. Never substitute
`parameters.login_hint`, tenant or the Agent token's routing `ps` claim for that
evidence. If the host lacks the evidence or needs fresh interaction, refuse;
`PolicyError::UserUnreachable` reports the absent channel rather than creating it.

`Policy::authorize` receives verified Agent and Resource claims, the exact
retained presented issuance, requested scopes and signed parameters. Return a
nonempty subset of those scopes and a positive lifetime up to one hour. Intentional
PS host-policy denial returns 403 with `access_denied`; an unavailable policy/store returns 500. Invalid token
parameters return typed 400 errors; HTTP proof/credential failures return 401
Signature-Error. The PS checks lineage before policy, caps parent lifetimes,
commits retained state, resamples its trusted clock and only then releases tokens.
A Resource challenge must still be current at exchange; its five-minute lifetime
does not cap the issued Auth token, whose other parent bounds still apply.

A Resource token is a signed challenge, not a one-use exchange code. The draft
does not require consuming it after an Auth grant. Repeating the same valid
`/token` request reruns host policy and can issue another Auth token with a fresh
`jti`, the same audience and scopes, and the same parent-expiry bounds. Both
issuances are retained. This does not make an application operation idempotent;
the host's operation key and stored result govern application retries.

A presented credential missing its exact retained issuance, changed after
issuance, or issued to another Agent returns `invalid_presented_token`. A
genuine mismatch between a valid credential and the Resource challenge's copied
claims returns `invalid_resource_token`. Revoking the original binding prevents
new Person issuance (`403 denied`); an exchange of its outstanding Person/Auth
credential returns `400 revoked_presented_token`, including revocation during
policy or commit. Chained requests instead use `revoked_upstream_token`. This
does not deliver revocations to Resources: already issued Auth tokens remain
valid there until expiry unless the host supplies additional revocation state.

Use a durable `Store` in a running service. Run
`storetest::check_store_contract(|| new_disposable_store())` against your adapter.
Each invocation creates fresh test stores; never point this destructive contract
at live data. Commit must atomically preserve binding, directed identity and the
complete issuance record, rejecting conflicts without changing the original.
Retain every record through its `retain_until` time. `MemoryStore` is a volatile
reference with no cleanup; cloning it shares state, restarting without it loses
outstanding-token lineage. This PS deliberately requires the exact retained
Person/Auth issuance in exchanges and chains. A valid JWT without its record is
refused, so retain state and preserve token bytes rather than reconstructing JWTs.

For named application state, the PS exports `BoxedPolicy = Box<dyn Policy>`,
`BoxedClock` and `BoxedTokenIds`. Boxed policy forwards direct/upstream and federation-consent
hooks; clock and ID closures can capture state and are Send + Sync. For example,
`PersonServer<K, S, BoxedPolicy, BoxedClock, BoxedTokenIds>` names the service type
without naming closures. The constructor rustdoc uses these aliases.

## Durable Person Server storage

Add `aauth-rust-person-server-redb` alongside the PS dependency. With local
checkouts, use `path = "../aauth-rust/crates/aauth-rust-person-server-redb"` in
your consumer's dependencies, adjusting the path to your checkout. It implements
the same `Store` as `MemoryStore` and adds no database dependency to the PS role.

In the complete PS constructor linked above, replace `MemoryStore` with
`RedbStore` in the `HostServer` type and pass this store argument:

```rust
use aauth_rust_person_server_redb::RedbStore;
let store = RedbStore::open("/var/lib/my-service/person.redb")?;
```

Durably provision the private parent directory first. This adapter requires
Unix and a filesystem supporting directory synchronization. `open` creates an
absent/empty file or reopens the supported schema, then synchronizes its parent
after initializing the database file and before returning a usable store. A
bare filename uses the current directory. A directory-sync failure returns
`OpenError::DirectoryDurability` with local code `store_unavailable`; non-Unix
platforms are refused before file creation. This restriction belongs to the
optional adapter; other platforms can supply a custom `Store`.

The schema commit precedes directory synchronization. If open fails between
those steps, the file can already contain an initialized schema, but no usable
store was acknowledged and its directory entry may not be durable. An open
error does not mean nothing was written. Diagnose the failure and reopen the
same file; do not delete it as an initialization workaround.

Open runs redb's page-integrity check before schema access. It refuses detected
corruption, a reported integrity repair, and catchable unwinding engine panics
with local code `store_unavailable`. The engine can modify a file during recovery
or integrity repair even when the adapter refuses open. If corruption is
suspected, stop the service and preserve a closed copy before diagnosing it;
restore a verified closed backup before resuming. Such restoration can roll back
issuances and revocations newer than the backup. The check costs a scan of
retained engine pages at each open; it does not verify every JSON record or
authenticate stored ancestry. The normal panic hook may still log a caught
engine panic. Panic containment requires Rust's unwinding panic
strategy; `panic=abort`, process signals and allocation aborts are not caught.

A locked or unreadable database also has local code `store_unavailable`;
an unrelated schema or unsupported version has
`unsupported_store_schema`. These are configuration/storage errors, never
Signature-Error codes. Unreadable stored records return `StoreError::Unavailable`,
which stops the PS operation rather than treating the identity as absent.

One process owns a database file. Clone `RedbStore` to share its transactions
among handlers; opening the same file independently while any clone lives fails.
The PS API is synchronous: run it on a blocking worker when adapting an async
server. The adapter atomically checks and stores the binding, exact complete
issuance and both directed-identity indexes before returning success. It uses
immediate durability. Composite keys preserve issuer/JTI namespacing without
scanning the database on ordinary Store calls. Startup separately scans engine
integrity and checks schema identity/types/version. The file contains internal identity and credential hashes/lineage,
with no encryption, signing key or compact token storage.

After every handle is closed, reopen the same file and supply the same issuer
signing key and a token-ID source that stays unique across restarts. Existing
Person/Auth credentials keep their retained ancestry; binding revocation stays
revoked. Never replace a missing database with an empty one to repair a token
error. Close all handles before copying/restoring a backup. An I/O error may
leave a whole commit's outcome uncertain; the PS releases no credential on a
commit error, and the database exposes no partial binding/index/token update.
After a redb commit fails, the live database refuses further writes, including
revocation, on every clone. Stop issuance/revocation, drop all store clones
(including the owning PersonServer and in-flight handlers), then reopen the
same file and reconstruct the service. A surviving handle's reads can show the
old in-memory snapshot; they do not resolve the failed commit's durable outcome.
The adapter does not recover or replace a live handle automatically. Logical
refusals such as Conflict or InvalidRecord do not require reopening.

There is **no adapter-enforced bound on total file size or record count**, and
no cleanup, quota, compaction or migration API. Records remain indefinitely,
including after `retain_until`. Provision capacity for every issuance, including
retained tokens that were never released; monitor growth and stop admission
before capacity is exhausted. A filesystem quota can stop writes but does not
reclaim records. Deleting/rotating the file or editing tables directly is not a
supported bounding mechanism: it can discard outstanding lineage or revocation.

Each retained record is capped at **1 MiB of encoded UTF-8 JSON**, including
field names and escaping (`MAX_RECORD_BYTES`). A fresh larger record returns
`StoreError::InvalidRecord` before any binding/index/token change; oversized
stored values return Unavailable. Existing-record comparison still comes first,
so a changed oversized retry of an existing JTI is Conflict. Serialization stops
at the cap; callers must still bound the strings they allocate and the subjects/
IDs supplied by policy. This local adapter limit differs from the PS HTTP body's
1 MiB limit and does not bound total growth or apply to every custom Store.
The adapter does not provide request replay detection or operation idempotency.

Custom adapters run `storetest::check_store_contract` with a fresh empty store
on every factory call. Its checks match the Go issued-token contract's exact
round-trip, issuer namespace, every-field conflict and concurrent winner/retry
guarantees, plus Rust's atomic binding/directed-identity rules. Run
the shared `TokenRecord::validate_for_commit` shape checks in custom adapters,
after the existing-record comparison. They check identifier syntax, nonempty
references/digests and Person/Auth parent shape; credential verification remains
the PS role's duty. Run
`storetest::check_persistence_contract` separately with a consuming callback
that drops the sole handle before reopening the same storage. Returning a live
object or leaving a clone open does not test persistence. Both contracts mutate
state and must use disposable databases. A complete runnable factory is in
[the adapter example](crates/aauth-rust-person-server-redb/examples/contracts.rs):

```sh
cargo run --locked -p aauth-rust-person-server-redb --example contracts
```

It prints `logical-store=pass reopen-store=pass` and removes its disposable files.
The adapter's tests additionally cover process exit without Rust destructors,
an abandoned real transaction, one injected native write failure, parent-directory
sync refusal and reconstructed
direct/chained PS exchanges. These are separate backend checks, not evidence of
physical power loss, every disk failure, distributed operation or other database
engines. The contract also retains AS Auth receipts in an explicit PS namespace;
this is not AS audit storage. Missions and token-revocation delivery remain
outside the supported PS profile; persistence does not add those roles.

## Protect a Resource with PS authorization

Use `PsAuthorizationResource` with a `PsAuthorizationConfig`: published Resource
issuer, independently configured signed origin, signing key/kid and a nonempty
scope list. Serve its metadata and JWKS through the host. One value serves paths
under that origin with one fixed scope profile; the router chooses which paths
use it. Use separate values for routes requiring different scopes. The host
resolver admits PS issuers and their `aauth-person.json` keys; a valid signature
from an arbitrary PS does not establish trust.

An unsigned request receives a Person-token requirement. Presenting a verified
Person token and holder proof produces an Auth-token requirement containing the
Resource-signed challenge. It does not execute protected work. Keep the original
Agent credential to sign PS requests and send the exact presented Person token
alongside that challenge. Verify the challenge with
`Agent::verify_resource_challenge`, then verify delivery with
`Agent::verify_auth_delivery`. These helpers authenticate issuer, audience,
holder key and exchange context, beyond Core JWT syntax/common verification.
`agent.with_token(person_or_auth)` reuses the same private proof key for Resource
requests; `Agent::new` initially accepts an Agent credential.

Read challenges with `Requirement::parse(&HeaderValue)` or
`Requirement::from_headers(response.headers())` from `aauth-rust-agent`. The latter
combines all field lines as an RFC 9651 dictionary and returns `None` only when
the field is absent. It handles parameters on the requirement member, ignores
unknown parameters and returns the exact decoded `resource_token` string for
`Requirement::AuthToken`. **Parsing does not authenticate that JWT**: pass it to
`verify_resource_challenge` before sending it to the PS. Malformed or unsupported
requirements are errors, never permission to retry. The parser supports the
immediate Agent/Person/Auth values; interaction, approval, clarification, claims
and extension values return `RequirementError::Unsupported`. The combined field
limit is 64 KiB and repeated names use RFC 9651 last-wins behavior. Status handling,
deferred/polling behavior and transport remain host decisions. The running
three-party example uses this parser instead of matching a serialized prefix.

Discover PS endpoints from the configured PS's admitted metadata, using its
`person_token_endpoint` and `auth_token_endpoint`, rather than assuming `/person`
and `/token` for every implementation. Check exact metadata issuer equality and
admit HTTPS endpoint destinations before network access. Restricting endpoints
to that PS origin is a reasonable host policy, not a rule imposed by these
helpers. Core's `TrustedIssuerKeys` handles issuer/role/JWKS verification; the
host reads endpoint URLs and owns fetching, cache and redirect policy.

`AuthDecision::into_result()` yields `(VerifiedAuthToken, admitted_context)` or a
boxed refusal response. Application policy sees the verified Auth token and
actual request only after audience, holder, expiry and configured scopes pass.
Return your own response after performing authorized work. Admission does not
freeze time: a long-running operation must decide whether to recheck expiry
before its eventual effect.

`BoxedAuthPolicy` names a captured boolean policy, and
`BoxedAuthAdmissionPolicy<T>` names one returning `Result<T, Deny>` for typed
application state. Wrong-audience Person/Auth tokens return local
`TokenError::AudienceMismatch` and a Problem Details audience diagnosis before
policy. Their wire code remains the pinned draft's `invalid_jwt`; obtain a
credential for the intended Resource instead of refreshing an otherwise valid JWT.

## Make an immediate downstream call

Run `cargo run --locked -p aauth-rust-resource --example three-party` for the
complete certificate-verified AP/PS/Orders/Inventory scene. The
[application source](crates/aauth-rust-resource/examples/three_party/mod.rs) shows
the requests, discovery snapshots, policy and handlers; it does not require a
framework or private test helpers.

The intermediary owns its own proof key and self-issued Agent token, whose
issuer is the upstream Resource audience. It supplies the exact caller credential
as `upstream_token` in both `/person` and `/token`. The PS uses retained lineage
and the original Agent/person binding; no intermediary-to-person binding is
created. Implement `bind_upstream` and `authorize_upstream` explicitly: both
default to denial. The hooks decide downstream purpose and directed identity;
scope names across Resources need not form a syntactic subset. Credential expiry
cannot outlive upstream authority. Omitting, replacing or adding an inconsistent
upstream tie fails, including when an Auth token is presented for step-up.

Route both downstream token requests to the PS named by the **verified upstream
credential**: `iss` for a Person token, `ps` for an Auth token. Read that PS's
admitted endpoint metadata. Never use the intermediary's own Agent-token `ps`
for this route; that would select the intermediary's person rather than the
original caller's. The PS verifies that the upstream names itself. The example
has one configured upstream PS and deliberately gives the intermediary another
`ps` value; a general host selects among its admitted PS transports.

Use a token as upstream evidence only from a request the intermediary actually
served. A Person-token request answered with an Auth challenge was not served
and must not start a downstream chain. `PsAuthorizationResource` reaches the
application handler only on a granted Auth token; start chaining there. A custom
Resource that serves on Person identity can use that served request's Person
token. The PS cannot observe which remote handler ran, so it cannot enforce this
caller duty with retained issuance records or a fabricated served flag.

The intermediary must publish its own Agent metadata on its origin with the same
issuer as Resource metadata. Host resolution must obtain keys through that
`aauth-agent.json`, with admitted verified discovery, to establish origin
ownership. An injected key resolver is a trust boundary, not proof by itself
that any network fetch occurred. Return stable, downstream-directed subjects
from host policy; the PS refuses copying the immediate upstream subject with
`403 access_denied` through the typed policy-denial path. It
does not derive pairwise IDs or prevent every cross-Resource reuse for the host.

The scoped, missionless profile requires a nonempty Core scope string and
rejects mission-bearing PS inputs and known companion authority claims. It does
not accept a companion claim in place of scope. First-use Resource metadata
presentation and distinct-resource-per-Agent rate limits belong to host policy.
If displaying `justification` or other Agent-provided Markdown, sanitize it and
label it as Agent-asserted content.

The direct constructor implements immediate, missionless PS authorization.
Explicit AS federation is described below. Missions, R3 vocabulary, Budget
semantics, sub-agent delegation, deferred consent/polling,
revocation transport and automatic step-up orchestration remain outside it.
The PS rejects unsupported parameters explicitly. Its discovery publishes only
implemented endpoints, with one active public key; it provides no key-overlap
lifecycle. Core token verification alone does not establish application consent,
account admission or exactly-once effects.


## Run an Access Server and federated Person Server

Add the independent `aauth-rust-access-server` crate. It has no HTTP client,
database, TLS provider or application dependency. `AccessServer::new` accepts
`Config`, an admitted issuer/role resolver, a resource-policy closure, a trusted
Unix-second clock and a unique ID source. Its [module rustdoc](crates/aauth-rust-access-server/src/lib.rs)
contains a complete constructor. `BoxedPolicy`, `BoxedClock` and `BoxedTokenIds`
name captured dependencies in application state. The AS serves:

| Method and path | Purpose |
| --- | --- |
| GET `/.well-known/aauth-access.json` | Issuer, JWKS and Auth endpoint |
| GET `/.well-known/jwks.json` | Public active AS signing key |
| POST `/token` | Verify PS service proof and three credentials, then evaluate Resource policy |

Set published `issuer` separately from `signed_origin` for a listener with a port.
The AS policy sees verified PS identity, Agent posture, Resource claims and Core
scopes after independent presented-token verification. Return `Decision` with a
nonempty requested-scope subset and lifetime1..3600 seconds. Denied is403,
Unavailable or an invalid grant is500. Issued Auth uses `aauth-access.json`, is
bound to the intended Resource/person/Agent key and cannot outlive the Agent or
presented credential. The challenge must be current but does not cap a
missionless grant's lifetime. The host supplies authorization policy; accepting
a valid PS proof alone does not grant access.

For the PS, construct the ordinary PersonServer then call
`server.with_federation(adapter)`. Implement `Policy::consent` explicitly; its
default is denied. It receives the complete verified exchange before dispatch.
The `Federation` adapter exposes:

```rust
fn endpoint(&self, access_server: &str) -> Result<String, FederationError>;
fn send(&self, request: &http::Request<Vec<u8>>)
    -> Result<http::Response<Vec<u8>>, FederationError>;
```

Admit the verified Resource token's AS audience before discovery. Check AS
metadata's exact issuer and obtain its HTTPS auth_token_endpoint; enforce size,
timeout, certificate, DNS/egress and redirect policy before network access.
The PS gives `send` already signed exact bytes: do not rewrite target, content,
Content-Type or signature headers, and do not follow redirects carrying the
credentials. The library imposes the 1 MiB buffered response check; the adapter
must bound collection before allocation. Use blocking workers for this synchronous
callback in an async server. Terminal AS error/status relays in the PS's own
problem body; AS401 is a service-proof failure mapped to502 as_unreachable.
Malformed/unverifiable results and unsupported deferred responses also yield
as_unreachable; automatic polling/payment/retry is not supplied. Parameter
clock_skew relays the AS Date so clients can judge that verifier's clock.

A federated PS always uses its adapter for `/token`, including AS=PS; it never
falls back to PS signing. Use a separate direct instance for three-party grants.
When PS and AS share an origin, publish distinct role metadata and one merged
JWKS with unique key IDs, or explicitly admitted separate JWKS URLs. A host may
route JWT Agent proofs to PS handling and jwks_uri PS proofs to AS handling;
both handlers still independently enforce their own accepted scheme and target.
Do not route the PS's own AS request back to the PS token handler.

Construct the Resource with
`PsAuthorizationResource::new_federated(config, expected_as, keys, policy)`.
It issues an AS-addressed challenge preserving the actual PS/person, then admits
only that AS issuer and discovery role, even under role collocation. Direct
`new` remains PS-only. The Agent uses `FederatedContext` with the intended
Resource, PS, AS and exact presented bytes, then
`verify_federated_resource_challenge` and `verify_federated_auth_delivery` before
exchanging/using credentials. These checks support AS Auth step-up. Keep the
Agent's original Agent credential for PS requests; `with_token` retains the same
proof key while switching Person/Auth credentials at the Resource.

Federated retention uses `TokenRecord.person_server=Some(PS)` to separate the
AS token's issuer/JTI from the PS binding namespace. None retains old local
behavior; old schema1 JSON rows decode unchanged. MemoryStore and RedbStore
validate the exact retained presented parent and commit the receipt atomically
before release. Custom adapters must honor this field and the updated storetest
contract; an older adapter is not federation-qualified. The PS's internal
accountable person and directed identity remain stable across this exchange.
Full R3 compliance remains a named vocabulary gap: general media/service
vocabularies grow in R3 and both libraries on demand, one test at a time.
Missions, AS call chaining, subagents and deferred federation remain named gaps
of this immediate Core-scope profile. See the complete
[four-party TLS example](crates/aauth-rust-resource/examples/four_party/mod.rs).
