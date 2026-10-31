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

When a Resource's metadata lists `additional_signature_components`, pass that
array to `agent.with_additional_signature_components(list)` and use the
returned Agent for that Resource. Every request it signs, including R3
authorization requests and polls, covers each listed component after the base
set, and `with_token` keeps the list. An entry must be a lowercase field name
present on the request, or `@method`, `@authority`, `@path` or `@query`. A
listed `content-digest` is computed from the actual content, even when empty.
Signing returns `InvalidInput` rather than omit a listed component, so a host
adds a listed field such as a tenant header before signing. The verifier
reconstructs any covered lowercase field. Lower-level callers use
`sign_requests_with_components`.

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

`metadata()` supplies minimal issuer/JWKS-location bytes, plus the display
members described in [Publish display metadata](#publish-display-metadata).
`AgentIdentityResource::metadata_for(issuer)` is a separate verifier-only Resource
document. Server identifiers have no port or path. In local deployments,
map those logical identities to admitted sockets while preserving HTTPS names,
SNI and certificate verification. Temporary loopback ports belong to that map,
not to the token's `iss`. JWKS endpoint URLs are distinct from server identifiers.

## Publish display metadata

The four metadata documents share seven optional display members: `name`,
`description`, `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri` and
`policy_uri`. Build them with `aauth_rust_core::MetadataDisplay` and pass the
value to `with_display` on `AgentProvider`, `PersonServer`, `AccessServer`,
`PsAuthorizationResource` or `AgentIdentityResource`:

```rust
use aauth_rust_core::MetadataDisplay;
let display = MetadataDisplay::new()
    .with_name("Example Calendar")?
    .with_description("Calendar access for **your** agents.")?
    .with_logo_uri("https://calendar.example/logo.png")?
    .with_policy_uri("https://calendar.example/privacy")?;
let person_server = person_server.with_display(display);
```

Each `with_` method checks its value as it is set. Every URL must be an
absolute `https` URL with a host and no userinfo; a fragment is allowed. `name`
is at most 256 bytes and `description` at most 16384, without control characters
other than line breaks and tabs in the description. `metadata()` writes exactly the
members you set, beside the protocol fields.

To show another server's members, for example an agent provider's name and logo
at a new-agent enrollment, read its fetched document with
`MetadataDisplay::from_metadata`. The `description` is Markdown from that server:
sanitize it before rendering. Key discovery (`metadata_jwks_uri`,
`AgentProviderKeys` and `TrustedIssuerKeys`) refuses a document whose display URL
is not `https` with `InvalidDiscoveryMetadata`, as aauth-go does.

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

## Read declared capabilities

An agent lists the requirements it can handle in `AAuth-Capabilities`.
`aauth_rust_core::capabilities::Capabilities::from_headers(request.headers())`
reads every field line as one List of Tokens. Unrecognized values and all
parameters are ignored. An absent field, or one that does not parse, declares
nothing: never assume a capability the agent did not state. Before raising a
requirement, check `capabilities.allows(&requirement)`. `interaction` needs the
`interaction` capability, `clarification` needs `clarification`, and payment
needs `payment`. `ChainedInteraction::open` takes the opener's declared
capabilities and refuses to raise an interaction to a caller that cannot reach a
person.

An agent builds its own declaration with `Capabilities::none().with(...)`, unions
it with the capabilities its Person Server returned at mission approval, and
writes it on each signed request to a resource with `insert_into`. Person Server
endpoints take the `capabilities` body parameter instead of the header.

## Serve clients outside AAuth

AAuth agents present the `jwt` scheme. A resource that also serves other signed
clients may accept further Signature-Key schemes, and must then list all of them
in `Accept-Signature-Scheme`. Call
`AgentIdentityResource::with_further_schemes(&["hwk", "jwks_uri"])`. A request
under `jwt` keeps the full verification and policy path. A request under a
further scheme returns `Decision::OtherScheme(proof)`: target, coverage, content
digest and signature time have been checked, but nothing is authenticated. Verify
it with the method for `proof.key()`, for example `proof.verify(&jwk)` with the
`hwk` key or `proof.verify_jwks(&resolver)`, then apply your own admission. If you
convert that decision to a response unhandled, it is refused with `403`. Every
`unsupported_scheme` refusal lists `jwt` first, then the further schemes in the
order you gave them.

## Sign with ECDSA or RSA keys

`SigningKey::generate()` and `SigningKey::from_seed(seed)` make Ed25519 keys,
which every AAuth role and token uses. A client of a verifier that accepts other
algorithms imports its key with `SigningKey::from_pkcs8_der(alg, der)`. `alg`
is `Ed25519`, `ES256`, `ES384`, `RS256` or `PS256`, and `der` is an unencrypted
PKCS #8 key, the body of a `PRIVATE KEY` PEM block. The algorithm is always
explicit, because an RSA key names neither padding nor hash. A key that does not
match `alg`, or an RSA modulus outside 256 to 512 bytes, is `InvalidKey`.
`key.algorithm()` names the algorithm the key signs with.

Sign an `hwk` request with `sign_request(&mut request, &key,
KeyMaterial::Hwk(key.public_jwk()), now)`. The member carries the members of
that key type and its `alg`, such as
`hwk;kty="EC";crv="P-256";x="...";y="...";alg="ES256"`. An inline key that is
not the signing key under its own algorithm is `InvalidKey` before anything is
sent. `jwk.thumbprint()` is the RFC 7638 thumbprint of an OKP, EC or RSA key;
`urn:jkt:sha-256:` followed by it names a pseudonymous signer, and an RSA key has
one thumbprint under RS256 and PS256. The same key signs an `x509` request whose
certificate holds it. Compact JWS stays Ed25519: `Jws::sign` refuses another key
with `UnsupportedAlgorithm`. AAuth tokens and their confirmation keys, and the
`jkt-jwt` and `self-jwt` assertions, stay Ed25519, and `ServerKeyBinding`
admits Ed25519 pseudonym keys only.

## Request a Signature-Key cache identifier

A `jwt` member asks the verifier to cache its assertion with
`KeyMaterial::Jwt { jwt, cache: true }`, as `KeyMaterial::JktJwt` does for
`jkt-jwt`. The member ends in the bare flag, `jwt;jwt="...";cache`, and the
request signature covers it. The assertion must carry `jti` and `exp`; without
them signing returns `InvalidJwt` before anything is sent, which is what the
verifier would answer. A verifier reads the flag with `proof.cache_requested()`
and may issue an identifier through `AssertionCache`. Until a
`Signature-Key-Cache` response names one, the client keeps sending the full
`jwt`; afterwards it presents that identifier unchanged with
`KeyMaterial::Cached { cid }`, and on `cache_miss` it resends the assertion.

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

The same replay limit applies to PS pending delivery. A captured signed Agent
GET replayed within the accepted 60-second proof window can consume the single
terminal response; the legitimate Agent's next GET then receives `410 Gone`.
The Auth token remains bound to the Agent's proof key, so the replay does not
give another holder a usable credential. There is no built-in request replay
cache for pending URLs. Hosts that require replay refusal must enforce it before
the PS consumes custody.

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
`PersonRequest::enrolls_agent()` is true when the request would bind the agent
for the first time. Present that consent as a new-agent enrollment, with the
agent provider's `name` and `logo_uri` from its metadata
(`MetadataDisplay::from_metadata`) beside the agent-asserted `platform` and
`device` parameters.

Apart from the opt-in [resource interaction](#resolve-a-resources-own-interaction)
flow, this subset has no interaction endpoint or deferred login channel. Person
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

When an agent's association has to change, for example because its person left
the organization, revoke the binding and then establish the new one as host
administration: `store.replace_binding(issuer, &agent, new_person_id)`. It
refuses an active binding with `Conflict` and a missing one with
`MissingBinding`, and returns the new active binding. Each replacement starts a
new binding generation, which every issued record carries as
`binding_generation`. Credentials issued under an earlier generation stay
revoked (`revoked_presented_token`, `revoked_upstream_token`), even when the
replacement binds the same person again. The token endpoints never replace a
binding themselves. A durable store implements `Store::replace_binding`; the
default refuses with `Unavailable`, and `storetest::check_store_contract`
checks it.

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
the PS role's duty. An R3 Auth issuance carries its R3 audit entry in
`TokenRecord.r3`: committing the record writes the entry atomically with the
issuance, so adapters persist that field with the rest of the record. Run
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
issuer, independently configured signed origin, signing key/kid, a nonempty
scope list and a description of each scope in `scope_descriptions`. The metadata
publishes those descriptions, and a Resource token carries only scopes described
there; a description missing, blank or for another scope is a configuration
error. Serve its metadata and JWKS through the host. One value serves paths
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
For an authenticated deferred PS `202` with approval, initialize
[`PollSession`](#prepare-explicit-agent-polls) instead. The immediate parser's
`Unsupported("approval")` describes its own subset, not a failed continuation.

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
before its eventual effect. When a budgeted Auth token is refused, the
`Forbidden`, `Revoked`, `MethodNotAllowed` and `Gone` decisions carry
`budget_header`; `into_response()` sends it as `AAuth-Budget`, and a host that
builds its own refusal must send it too.

`BoxedAuthPolicy` names a captured boolean policy, and
`BoxedAuthAdmissionPolicy<T>` names one returning `Result<T, Deny>` for typed
application state. Wrong-audience Person/Auth tokens return local
`TokenError::AudienceMismatch` and a Problem Details audience diagnosis before
policy. Their wire code remains the pinned draft's `invalid_jwt`; obtain a
credential for the intended Resource instead of refreshing an otherwise valid JWT.

## Resolve a Resource's own interaction

A Resource that needs its own user-facing flow before the Person Server can
issue, typically an OAuth authorization at a third-party service, names it in
the resource token's `interaction` claim. Open the claim for your interaction
endpoint and challenge with it:

```rust
use aauth_rust_core::interaction::ResourceInteraction;
let interaction = ResourceInteraction::open("https://calendar.example/connect")?;
let decision = resource.authorize_with_interaction(&request, now, &challenge_jti, &interaction);
```

Keep `interaction.code()` for that endpoint: single use, until the resource token
expires. Only a Person-token challenge carries the claim. The endpoint reads
`?code=...&callback=...` with `parse_interaction_query`, the same way whether an
agent or a Person Server sent the person. When the flow ends, successfully or not,
redirect with `completion_redirect(callback, outcome)`: an unfinished flow adds
`error` (`access_denied`, `user_abandoned`, `server_error`,
`temporarily_unavailable` or `interaction_expired`).

The Person Server resolves that flow before its own consent after
`with_resource_interaction(ResourceInteractionConfig::new(store, interaction_base,
callback_base, admit))`. `store` is a `ContinuationStore` of its own. The two bases
are HTTPS URLs your host routes, and `admit` is your egress admission for a
resource's interaction URL. The agent's `/token` request must list `interaction`
in `capabilities`, or the answer is `403 user_unreachable`. The request is then
answered `202` with `requirement=interaction`, the URL
`{interaction_base}/{id}`, a fresh code, and a pending URL under
`/token/interaction/` that the agent polls through `PersonServer::handle`. Your
host serves four steps:

1. At `{interaction_base}/{id}`, authenticate the person and show an interstitial
   saying the resource requires additional permissions.
   `resource_interaction(id)` returns the resource, agent, scopes and the
   agent-asserted justification to show.
2. Call `redirect_to_resource(id, query)` with the page's query. It checks and
   consumes the code (three mismatches end the request), checks the resource's
   URL is HTTPS, applies `admit`, and returns the `302` to
   `{interaction.url}?code={interaction.code}&callback={callback_base}/{flow}`.
   The per-flow `flow` is fresh and never shown to the agent.
3. At `{callback_base}/{flow}`, call `resource_interaction_callback(flow, query)`.
   A callback with `error` is never completable. The request ends, and the
   agent's next poll receives the mapped polling error: `access_denied` as
   `denied`, `user_abandoned` as `abandoned`, `interaction_expired` as `expired`,
   and the other two as `server_error`. Without `error` you get `Consent { id }`.
4. Show your consent and call `decide_resource_interaction(id, approved)` with the
   authenticated person's decision. Approval re-verifies the stored tokens and
   runs `Policy::authorize` and issuance as an immediate `/token` request does.

The agent's next poll receives the token or the refusal once, and `410` after
that. When the agent appended its own `callback` to the interaction URL, steps 3
and 4 return the redirect back to it, with `error` when the request did not
complete. This flow is three-party only: with AS federation the claim is still
refused as `invalid_resource_token`, and it refuses call chaining, sub-agents and
budget offers with `invalid_request`.

## Compose one R3 document across definitions

A Resource may organize its R3 authorization into several internal definitions,
for example one per scope or operation group, each with its own consent text.
Group them with `R3Definitions::new(vec![(operations, display), ...])`. Each
operation belongs to exactly one group, and all groups share one vocabulary.
Install the result as the vocabulary's display:

```rust
vocabulary.display = Some(definitions.into_display());
```

A resource token always references one document whose `operations` are exactly
the requested set. When those operations come from more than one group, that
document's `display` is the merge of the groups' displays (`Display::merged`):
summaries joined with `; `, `implications` and `irreversible` concatenated one per
line, and the distinct `data_accessed` values joined with `; `. A request inside
one group gets that group's display unchanged. The composed bytes are committed
like any other document before the token is released, so an identical
combination always has the same digest. A requested operation outside every
group is a host error, and the request is refused without a token.

## Hold a side-effect-free call for release

Use this when the Resource can run a query before the person approves disclosure.
Set `R3PerCallConfig::hold` and `release`. A held call is answered `202` with a
pending URL `{signed_origin}/r3/pending/{id}`; the Resource draws `id` from
`aauth_rust_core::continuation::generate_pending_id` (128 random bits), so read
the URL from `Location`. `HeldInvocations::open` draws its ids the same way. The
`release` callback must change nothing outside the result it returns. Audited, billed, or third-party work
needs execution consent instead: return `None` for it. The Resource does not
call `release` for an operation its definition annotates `budget: true`.

The proposal's `display` comes from `R3Release::display`, and the Resource opens
its `detail` with an `## Action` section saying the operation has already run and
that what is approved is release of its result. Put your own `detail` sections,
such as `## Details`, after that; do not repeat it.

`held_result_lifetime` is your retention, in seconds. It is not extended when a
refreshed class token re-requests the call. The Resource returns the held
bytes only while that horizon is still ahead, the prior proposal token has
expired, and the new class token has a different `jti`. A still-live challenge
stays in place. After the horizon, the same call may run again. The R3 draft
has no invocation id and does not carry a digest of the result, so a Person
Server approval that is still live can release the new bytes when the proposal
document is unchanged. That limit is described in
[CONFORMANCE.md](CONFORMANCE.md). The executable scene is
`cargo run --locked -p aauth-rust-resource --example r3-per-call`.

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

The upstream token is the Person token or Auth token the calling Agent
presented. An Auth token may come from this PS or from an AS it federated with;
either way the PS accepts it only with its own retained record of that exact
token. It refuses the chain with `revoked_upstream_token` when it has revoked
the calling Agent's binding, its Agent token, or the upstream token itself.

When the upstream token carries `mission_s256`, the PS loads that mission for
the calling Agent, the upstream record's `principal`, not for the intermediary.
`bind_upstream` and `authorize_upstream` receive it as `mission`. The downstream
Person token and Auth token carry the same `mission_s256`, and their expiry is
capped at the mission's `expires_at`. The intermediary sends no `mission_s256`
of its own; a request that does is `invalid_request`. Once the mission is
terminated or expired, both endpoints refuse the chain with `403
mission_terminated`. A `MissionStore` commits these records with the
intermediary as holder and the mission owner as principal. Missions need a
direct PS: a federated PS refuses mission-bound tokens, chained or not.

Revoking a Person token with `PersonServer::revoke_person_token`, or an Agent
token at `/revoke`, walks the chain. Every token obtained from the revoked one
enters the PS's ledger, step-ups and federated Auth tokens included. Each Person
token this PS issued with one of them as `upstream_token` is then revoked with
its own cascade: at its Resource, at each AS it was presented to, and for the
Auth tokens obtained with it.

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

The scoped profile requires a nonempty Core scope string and rejects known
companion authority claims. It does not accept a companion claim in place of scope. First-use Resource metadata
presentation and distinct-resource-per-Agent rate limits belong to host policy.
If displaying `justification` or other Agent-provided Markdown, sanitize it and
label it as Agent-asserted content.

The direct constructor implements immediate, missionless PS authorization.
Explicit AS federation is described below. Missions, R3 vocabulary, Budget
semantics, deferred consent/polling, revocation transport and automatic step-up
orchestration remain outside that direct configuration. One-level parent-mediated
child issuance is described in the sub-agent section below.
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
nonempty requested-scope subset and lifetime 1..3600 seconds. The current
`PsAuthorizationResource` helper requires every scope in its configured profile.
A correctly narrowed AS grant can therefore be valid but still receive 403 at that
Resource. Keep the AS policy and the per-operation Resource profiles consistent;
the helper does not turn a partial grant into a new challenge automatically.
Denied is 403,
Unavailable or an invalid grant is 500. Issued Auth uses `aauth-access.json`, is
bound to the intended Resource/person/Agent key and cannot outlive the Agent or
presented credential. The challenge must be current but does not cap a
missionless grant's lifetime. The host supplies authorization policy; accepting
a valid PS proof alone does not grant access. This AS profile additionally requires
the Agent token's optional `ps` claim to be present and equal to the signing PS.
Missing/different `ps` is 400 `invalid_agent_token` before policy; this is the named
`AS-AGENT-PS-PROFILE` limit shared with the Go sibling. A call-chaining request
is the exception: it carries the passed-through `upstream_token`, and the
intermediary's own `ps`, if any, names its Person Server rather than the person's.
The AS verifies that token per Upstream Token Verification before policy: a person
token's `iss` or an auth token's `ps` is the signing PS, its `aud` is the `iss` of
the intermediary's Agent token, and it is neither expired nor revoked here
(`invalid_upstream_token`, `expired_upstream_token`, `revoked_upstream_token`).
Policy sees it as `AuthorizationRequest::upstream`; the grant ends no later than it.
A deferred chained request whose upstream token this AS has since recorded as
revoked ends at its next poll with the polling error `403 revoked`, its `detail`
naming the upstream token.

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
`endpoint` returns the URL the PS will sign for. Apply any admitted local
listener/port map there, before signing; mapping the target later in `send`
invalidates the PS proof. The PS gives `send` already signed exact bytes: do not rewrite target, content,
Content-Type or signature headers, and do not follow redirects carrying the
credentials. The library imposes the 1 MiB buffered response check; the adapter
must bound collection before allocation. Use blocking workers for this synchronous
callback in an async server. Every well-formed terminal AS problem, including
401, relays its AS status and `error` in the PS's own problem body. An AS 401
can refuse the PS service proof or another AS check; it is not automatically a
transport failure. The PS does not copy AS Signature-Error/Accept-Signature headers
onto the Agent response: they describe a different request and verifier.
Malformed/unverifiable results and transport failure return 502 `as_unreachable`.
The default immediate profile also rejects deferred responses with that error.
Opt-in continuation handling is described below; host advancement remains explicit.
Terminal `clock_skew` at 400 or 401 preserves the AS Date.

Inspect host-only diagnostics on the returned response before handing it to a
framework. Response extensions are local Rust data and do not go on the wire:

```rust
let response = server.handle(&request);
if let Some(failure) = response.extensions()
    .get::<aauth_rust_person_server::FederationFailure>()
{
    // Your host logger can record failure.access_server, failure.status and
    // failure.reason. TerminalError retains the AS error, Signature-Error and
    // bounded problem detail. Decide how to log untrusted/private AS text.
}
// Return response to the Agent; extensions are not serialized into its body.
```

`FederationFailureReason` distinguishes endpoint admission, transport, malformed
response, unsupported continuation, token verification, grant mismatch and
terminal AS refusal. `ConsentRefused(PolicyError)` identifies local consent
refusal before AS contact: `access_server` is the verified AS identity and
`status` is `None`; neither endpoint discovery nor transport was called. Check
this diagnostic when a new route is refused before any AS activity.

A token that expires after its successful retention but before release is a
local 500 `server_error` in both direct and federated paths.
Neither path releases it or deletes its already committed receipt; cleanup must
respect `retain_until`. The federated diagnostic is `ExpiredBeforeRelease`, with
the AS's successful status retained for the operator.

A federated PS always uses its adapter for `/token`, including AS=PS; it never
falls back to PS signing. Use a separate direct instance for three-party grants.
When PS and AS share an origin, publish distinct role metadata and one merged
JWKS with unique key IDs, or explicitly admitted separate JWKS URLs. Token IDs
must also be unique across the collocated roles: retained identity is `(iss,jti)`,
not `(iss,dwk,jti)`. Use a shared ID source or disjoint role prefixes. A host may
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
behavior; old schema 1 JSON rows decode unchanged. MemoryStore and RedbStore
validate the exact retained presented parent and commit the receipt atomically
before release. A receipt for a chained request also keeps `upstream`, equal to
that of the Person token presented for it; `TokenRecord::validate_federated_parent`
refuses one that drops or changes the tie. Custom adapters must honor these
fields and the updated storetest contract; an older adapter is not
federation-qualified. The PS's internal
accountable person and directed identity remain stable across this exchange.
If an AS reuses an issuer/JTI whose retained receipt names a different Person
parent, the PS refuses the conflicting answer with `502 as_unreachable` and a
host diagnostic. With the same Person token and otherwise identical verified
context, a byte-identical equivalent grant may be accepted in another exchange.
Auth carries neither a Resource challenge identifier nor a continuation
identifier, so there is no cross-exchange binding check or global grant replay
cache. Single terminal delivery applies to each continuation. Hosts own operation
replay protection and application idempotency.
Full R3 compliance remains a named vocabulary gap: general media/service
vocabularies grow in R3 and both libraries on demand, one test at a time.
Missions and recursive sub-agent delegation remain named gaps of this Core-scope
profile. One-level parent-mediated children execute. Deferred federation requires the explicit configuration below. See the complete
[four-party TLS example](crates/aauth-rust-resource/examples/four_party/mod.rs).

A federated PS chains calls through its AS. It verifies `upstream_token` exactly
as a direct PS does, then asks `Policy::consent_upstream` rather than
`Policy::consent`. That hook defaults to denial, so a policy that consents to
direct federation does not consent to delegation through it; implement it
explicitly. The PS passes `upstream_token` through in its PS-to-AS request,
whose `agent_token` is then the intermediary's. It refuses a returned Auth token
that outlives the upstream token with `502 as_unreachable`, and retains the
receipt with the upstream tie described above. A step-up repeats the same
`upstream_token`. With deferred federation, the intermediary that started the
request polls it; its Agent token need not name this PS. The request ends with
`408 expired` no later than the upstream token's `exp`. Once that token, or the
calling Agent's Agent token or binding, is revoked, it ends at the next poll or
host advance with the polling error `403 revoked`, whose `detail` names the
upstream token. A new request carrying the same token still gets the parameter
error `revoked_upstream_token`. An AS
`requirement=interaction` reaches the intermediary unchanged; the intermediary
raises it to its own caller with `aauth_rust_core::interaction::ChainedInteraction`,
under its own code and pending URL.


## Serve direct and federated grants from one Person Server origin

Run the complete [mixed-grants example](crates/aauth-rust-person-server/examples/mixed_grants/mod.rs):

```sh
cargo run --locked -p aauth-rust-person-server --example mixed-grants
cargo test --locked -p aauth-rust-person-server --test mixed_grants_example
```

It executes real Agent/PS/AS signatures and JWT verification with an in-process AS
adapter, fixed fixture time and public fixture keys. The four-party example
above separately exercises TLS. One `ps.example` publishes one PS metadata/JWKS,
one `/person` endpoint and one `/token` router. Orders asks for PS-signed
`orders.quote` or AS-signed `orders.write` grants for the same directed person.

The host builds two `PersonServer` values with the same issuer, signed origin,
`kid`, key, shared store, person/consent policy and issuance-ID source. The example
provisions one seed in host memory and uses `SigningKey::from_seed(ps_seed)` for
each value; `SigningKey` itself is not Clone. Production code loads the same
protected key for both values, never a fresh key under the same `kid`. Both must
use the same lifetime limits and policy dependencies as well. Its construction
is:

```rust
let store = MemoryStore::default();
let ids = Arc::new(AtomicUsize::new(0));
let make = || {
    let ids = ids.clone();
    PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed(ps_seed)),
        Keys, store.clone(), HostPolicy, now as fn() -> i64,
        Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)))
            as BoxedTokenIds,
    )
};
let direct = make()?;
let federated = make()?.with_federation(adapter);
```

`MemoryStore::clone` shares its atomic state; a durable adapter must provide the
same sharing/linearization. A shared ID source prevents PS-issued Person/Auth
collisions. `HostPolicy::bind_person` in this example represents an already
host-authenticated account; there is no invented interaction endpoint.

The router reads the Resource token's **unverified** `aud` solely as a handler
selection hint. Only the configured AS audience selects the federated instance:

```rust
let audience = if request.method() == "POST" && request.uri().path() == "/token" {
    strict_json(request.body()).ok()
        .and_then(|v| v.get("resource_token").and_then(Value::as_str).map(str::to_owned))
        .and_then(|t| ResourceToken::parse(&t).ok())
        .map(|t| t.unverified_claims().aud.clone())
} else { None };
let pending = request.uri().path().starts_with("/token/pending/")
    && matches!(request.method().as_str(), "GET" | "POST" | "DELETE");
let response = if pending || audience.as_deref() == Some(AS) {
    federated.handle(request)
} else {
    direct.handle(request)
};
```

Both handlers still verify the Agent proof, challenge, presented token, target,
retained lineage and policy. `/person` and discovery use `direct`; malformed or
unknown audiences also reach its normal authenticated refusal (`aud` must equal
PS in direct mode). This is a single selection, never a retry through direct
issuance after an AS refusal. The adapter independently admits its AS before any
network access. Bound request collection before routing.

To enable deferred grants, configure `with_deferred` on the federated instance.
Route **GET, POST and DELETE `/token/pending/*` to that same instance**, including
queued clarification answers and cancellation. Pending requests have no original
Resource token for audience selection; sending them to the direct instance loses
access to the deferred custody. Keep the same external `signed_origin` and shared
PS issuance store described above, with a separate PS continuation store.

The executable/test verifies both grants, common person binding, exact shared
JWKS and both retained receipts. It also submits a foreign-signed AS-directed
routing hint and an unknown audience: both fail, without another AS call. In an
async HTTP service, run the selected federated `handle` in a blocking worker
because its adapter performs synchronous outbound I/O. Direct handling requires
no outbound AS call.

## Obtain credentials for a one-level sub-agent

Run the complete [parent/child example](crates/aauth-rust-resource/examples/subagent.rs):

```sh
cargo test --locked -p aauth-rust-resource --example subagent
cargo run --locked -p aauth-rust-resource --example subagent
```

It executes authenticated AP child enrollment, immediate PS authorization,
immediate AS federation, and AS Payment then Approval using native handlers.
Requests and responses are buffered and routed in process. There are no sockets,
TLS exchange, identity provider or payment provider. The fixture supplies an
already authenticated person, generated keys, fixed Unix time and explicit host
settlement/approval decisions. The `four-party` example separately demonstrates
certificate-verified TLS. The Rust excerpts below are exact source from the
compiled example; its imports, constants, `Trust` snapshot wrapper and `Result`
alias provide their surrounding host context.

**The parent must admit its own AP's `aauth-agent.json` and JWKS before calling
`Subagent::verify` to verify the parent and child tokens.** Trust configured only
on a Resource does not populate the parent's key resolver. The parent also needs
the admitted PS, Resource and AS role snapshots used by its credential checks.
This fixture obtains the AP's public documents from the native provider:

```rust
let trust = Trust::default();
let ap = AgentProvider::new(AP, "ap", SigningKey::generate())?;
trust.admit(AP, "aauth-agent.json", &ap.metadata()?, &ap.jwks()?)?;
```

A network host instead obtains those documents over admitted, certificate-verified
HTTPS, checks exact metadata issuer equality, and admits the JWKS destination.
Choose trusted issuer/role pairs before key lookup. Never auto-trust a token-named
AP or follow its URLs without host admission. The example shares the retained
public snapshot with the parent and with the AP route's identity gate; it does
not give the parent the AP's signing key.

The host defines the child-enrollment endpoint. `/subagents` below is an example
route, not a standardized AP bootstrap endpoint supplied by the library. It uses
`AgentIdentityResource::for_origin` to verify the parent's actual issuer token
and HTTP proof. Its explicit host policy allows the configured top-level parent
only. The signed JSON body must contain exactly `discriminator` and `jwk`, fit
within 2 KiB, and contain a public-only Ed25519 key distinct from the parent's.
The discriminator has a 32-byte ASCII syntax limit and this fixture approves
only the `worker` slot. The host constructs all child claims; caller-supplied
parent, issuer, lifetime or posture claims are not accepted or inherited:

```rust
fn json_response(status: u16, body: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
        .unwrap()
}
fn child_route(
    provider: &AgentProvider,
    keys: &dyn AgentKeyResolver,
    ids: &AtomicUsize,
    request: &Request<Vec<u8>>,
    now: i64,
) -> Response<Vec<u8>> {
    if request.method() != "POST"
        || request.uri().path() != "/subagents"
        || request.uri().query().is_some()
    {
        return json_response(404, json!({"error":"not_found"}));
    }
    // A network adapter must also bound collection before allocating this body.
    if request.body().len() > 2048 {
        return json_response(413, json!({"error":"enrollment_body_too_large"}));
    }
    let gate = AgentIdentityResource::for_origin(
        AP,
        keys,
        |parent: &VerifiedAgentToken, _: &Request<Vec<u8>>| {
            parent.claims().iss == AP
                && parent.claims().sub == PARENT
                && parent.claims().parent_agent.is_none()
        },
    )
    .expect("configured AP origin");
    let (parent, ()) = match gate.authorize(request, now).into_result() {
        Ok(verified) => verified,
        Err(refusal) => return *refusal,
    };
    let Ok(body) = strict_json(request.body()) else {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    };
    let Some(body) = body.as_object() else {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    };
    if request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        != Some("application/json")
        || body.len() != 2
        || !body.contains_key("discriminator")
        || !body.contains_key("jwk")
    {
        return json_response(400, json!({"error":"invalid_enrollment"}));
    }
    let Some(name) = body["discriminator"].as_str().filter(|s| {
        !s.is_empty()
            && s.len() <= 32
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
    }) else {
        return json_response(400, json!({"error":"invalid_discriminator"}));
    };
    // This fixture approves one child slot for this authenticated parent.
    if name != "worker" {
        return json_response(403, json!({"error":"enrollment_denied"}));
    }
    let Ok(key) = serde_json::from_value::<Jwk>(body["jwk"].clone()) else {
        return json_response(400, json!({"error":"invalid_child_key"}));
    };
    if key.validate().is_err() || key.thumbprint().ok() == parent.claims().cnf.jwk.thumbprint().ok()
    {
        return json_response(400, json!({"error":"invalid_child_key"}));
    }
    let (local, domain) = parent
        .claims()
        .sub
        .rsplit_once('@')
        .expect("verified Agent identifier");
    let claims = AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: format!("{local}+{name}@{domain}"),
        jti: format!("child-{}", ids.fetch_add(1, Ordering::SeqCst)),
        iat: now,
        exp: now.saturating_add(900),
        cnf: Confirmation { jwk: key },
        ps: parent.claims().ps.clone(),
        parent_agent: Some(parent.claims().sub.clone()),
        nbf: None,
        extra: Default::default(),
    };
    // The AP independently authenticates this exact parent using its own key.
    match provider.issue_subagent(&claims, parent.compact(), now) {
        Ok(compact) => json_response(200, json!({"agent_token":compact})),
        Err(_) => json_response(400, json!({"error":"invalid_child_enrollment"})),
    }
}
```

Unsigned or changed signed content fails native verification with 401. A child
caller fails the top-level enrollment policy with 403. Invalid body/key/name is
400; oversized buffered input is 413. These enrollment-body errors are host
route choices. `issue_subagent` independently authenticates the exact
`parent.compact()` with the AP's configured issuer/key, even if the route's key
resolver was misconfigured. The AP requires the same issuer, authoritative
`parent_agent`, one level and a distinct proof key. Naming validation does not
turn a `+` into authority. Child Agent-token lifetimes are independent from the
parent's; returned credentials are bounded by both.

A production host supplies account/enrollment authorization, child inventory,
quotas, revocation policy, unique issuance IDs and replay/idempotency controls.
The fixture counter and one-slot policy do not supply those lifecycle services.
Bound network collection before allocation and retain a configured gate rather
than constructing a new one for each request when that suits your host.

The parent admits the AP endpoint before building the URI and signing. It sends
the resulting request unchanged and uses the actual returned token. Here native
dispatch calls `child_route` once; replace only that dispatch with your admitted
transport, preserving URI, body, Content-Type and signature headers:

```rust
let mut enrollment_request = Request::post(format!("{AP}/subagents"))
    .header("content-type", "application/json")
    .body(serde_json::to_vec(&json!({
        "discriminator":"worker", "jwk":child_key.public_jwk(),
    }))?)?;
parent.sign(&mut enrollment_request, NOW)?;
let enrollment_response = child_route(&ap, &trust, &enrollment_ids, &enrollment_request, NOW);
let child_compact = response_token(&enrollment_response, "agent_token")?;
```

The child retains its own private proof key in a separate `Agent`. The parent's
verification uses the child token and public snapshots only. This response
extractor is also compiled example source; it accepts a token only from an
actual successful response:

```rust
fn response_token(response: &Response<Vec<u8>>, member: &str) -> Result<String> {
    if response.status() != 200 {
        return Err(format!(
            "expected native 200, received {}: {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
        .into());
    }
    let body: Value = serde_json::from_slice(response.body())?;
    Ok(body[member].as_str().ok_or("missing credential")?.into())
}
```

With `person_endpoint` from issuer-checked, host-admitted PS metadata, the parent
obtains and verifies the child's Person credential:

```rust
let admitted_child = Subagent::verify(parent.token(), &child_compact, &trust, NOW)?;
let request =
    admitted_child.person_request(&parent, &person_endpoint, RESOURCE, &trust, NOW)?;
let delivered_person = person_server.handle(&request);
let person_compact = response_token(&delivered_person, "person_token")?;
let verified_person =
    admitted_child.verify_person_delivery(&person_compact, RESOURCE, PS, &trust, NOW)?;
```

`person_server.handle` is explicit in-process dispatch. A network host sends the
helper's exact signed bytes through its admitted PS transport and uses that
actual response. Supply certificate verification, target routing, bounded
collection, deadlines and redirect policy. Admit the final endpoint, including
any configured listener port, **before signing**; do not rewrite it in `send`.
The helpers perform no discovery fetch, transport, sleep or retry.
`Agent::new` and `with_token` check local key binding and do not replace issuer
or context verification.

Pass the verified Person token to the child out of band. The child proves its
request at the Resource and returns the challenge. This compiled exchange checks
the actual Resource and presented credential, chooses direct or federated
verification, then builds a fully parent-signed Auth request:

```rust
let person_holder = child.with_token(person_compact.clone())?;
let challenge = resource_handler(
    &signed(&person_holder, &format!("{RESOURCE}/records"), None)?,
    "challenge",
);
let Some(Requirement::AuthToken { resource_token }) =
    Requirement::from_headers(challenge.headers())?
else {
    return Err("native Resource did not issue an Auth challenge".into());
};
assert_eq!(protected_calls.load(Ordering::SeqCst), 0);
let context = FederatedContext {
    resource: RESOURCE,
    person_server: PS,
    access_server: AS,
    presented_token: &person_compact,
};
let verified_challenge = if mode == Mode::Direct {
    admitted_child.verify_resource_challenge(
        &resource_token,
        RESOURCE,
        PS,
        &person_compact,
        &trust,
        NOW,
    )?
} else {
    admitted_child.verify_federated_resource_challenge(
        &resource_token,
        &context,
        &trust,
        NOW,
    )?
};
let first = person_server.handle(&admitted_child.auth_request(
    &parent,
    &token_endpoint,
    &verified_challenge,
    &person_compact,
    &trust,
    NOW,
    &aauth_rust_agent::ResourceTokenAttempts::new(),
)?);
```

The request preserves exact `subagent_token`, `resource_token` and
`presented_token` strings. PS and AS policy see the parent in `.agent` and the
verified child in `.subagent`; issued Person/Auth `cnf` belongs to the child.
A child's optional `ps` may be absent; when present, the owning PS must match.
The AS's existing parent Agent PS profile still applies.

For an immediate result, `terminal` is the actual `first` response. For 202,
retain the parent's original Agent for `PollSession`; the bounded polling code
in the example and the continuation sections below produces `terminal` from
`polls.accept` after a parent-signed PS GET. Parent GETs only read PS custody.
The PS host inspects `federation_pending`, confirms settlement or approval using
its own admitted host evidence, then performs one explicit
`advance_federation(..., FederationInput::Poll)` per allowed stage. AS Payment
stays between the AS and PS host; the parent sees PS Approval. The example changes
fixture state explicitly and never pays a bill. Production settlement needs
provider authentication and idempotent billing controls. Keep PS and AS stores
separate and respect Retry-After and finite deadlines; zero intervals are for
this controlled fixture only.

The parent then verifies the final Auth credential against the original challenge
and presented token, for either direct PS or AS delivery. Only the child loads
the grant and proves the protected Resource request:

```rust
let grant = response_token(&terminal, "auth_token")?;
let verified_auth = if mode == Mode::Direct {
    admitted_child.verify_auth_delivery(
        &grant,
        RESOURCE,
        &verified_challenge,
        &person_compact,
        &trust,
        NOW,
    )?
} else {
    admitted_child.verify_federated_auth_delivery(
        &grant,
        &verified_challenge,
        &context,
        &trust,
        NOW,
    )?
};
let authorized = resource_handler(
    &signed(
        &child.with_token(grant)?,
        &format!("{RESOURCE}/records"),
        None,
    )?,
    "authorized",
);
```

The example asserts one protected handler call per scene, refusal of child-signed
PS requests and child polls, exact forwarding, and one terminal PS delivery
followed by 410. This does not provide application-request replay protection.
Current helpers reauthenticate both Agent tokens and check expiry at each call.
Person/Auth expiry cannot exceed either Agent token; Auth also cannot exceed its
presented credential. A challenge must be current when exchanged but does not
shorten an issued grant's lifetime. Pending custody also expires with its
original challenge and credentials. Long-running host work must decide whether
to recheck before its eventual effect; admission does not freeze time.

Revoking the parent's local PS binding stops pending and later child
authorization. In this profile, the parent's next pending poll receives
`400 revoked_presented_token`, then 410 after terminal custody is consumed; new
Person requests are refused with `403 denied`. An already delivered Auth token
normally remains usable at the Resource until its signed expiry, unless a
separate Resource-side revocation channel withdraws it. Local PS binding
revocation does not revoke an AP Agent token. AP-token revocation, per-child
revocation, key lifecycle and live snapshot refresh remain host responsibilities.

This path is missionless Core with immediate direct/federated grants and bounded
AS approval/payment. Missions, R3, child chaining, general remote AP enrollment
and durable continuation recovery remain gaps. The small host-defined AP route
is a buffered enrollment example, not a remote provider integration. Memory
continuations have no restart recovery; issuance storage and continuation
durability are separate host concerns.

## Stop acting on a terminated mission

A Person Server answers a request that names an ended mission with `403` and
`error` `mission_terminated`. Pass each answer to a request that named a mission
to `agent.missions().observe(mission_s256, &response)`. It returns the
termination, with `termination_reason` when present: `expired` invites proposing
a new mission, `revoked` does not. From then on the mission is ended for every
Agent derived from this one (`with_token`, `with_additional_signature_components`),
and `post_audit` refuses it with `ChannelError::MissionTerminated`. Use
`missions().is_active(s256)` before your own mission work and
`missions().may_present(credential)` before presenting a mission-bound Person,
Auth or Resource token. `with_missions` shares one tracker across Agents you build
separately for the same agent. Nothing here contacts the Person Server.

## Read usage counters

A Person Server or Access Server reads a metered resource's counters at its
`usage_endpoint`. `person_server.usage_request(endpoint, &query)` and
`access_server.usage_request(endpoint, &query)` build the signed POST: the server
signs as itself under `jwks_uri`, with its own `issuer` as `id` and its metadata
document as `dwk`, covering `content-type` and `content-digest`. The
`UsageQuery` carries at most one scope key (`sub`, `tenant` or `mission`) and
optional `jkts`. An Access Server names the Person Server in `ps` whenever it
sends a scope key; a Person Server never does. Take the endpoint from the
resource's admitted metadata, apply egress admission, send the exact bytes, and
read the answer with `read_usage(&response, &query)`. It requires `200`, an `aud`
equal to the caller, and the scope key echoed unchanged. A resource that has no
figure for a scope or key omits it. Verify an optional response signature with
`aauth_rust_budgets::verify_usage_signature`, and poll no faster than your
decisions need.

## Prepare explicit Agent polls

`aauth_rust_agent::PollSession::new(endpoint, &response, now, deadline)` parses
an authenticated 202/402 response from a host-admitted HTTPS endpoint. It accepts
absolute or root-relative same-origin pending locations, rejects changes of
Location during the session, and bounds the host deadline to one hour. Missing
Retry-After uses five seconds; 429 increases the interval by five seconds.
The host supplies trusted Unix seconds, schedules work and sends the request
returned by `session.request(&agent, now)`. That request is a signed GET with no
original POST body. Calling early returns `PollError::TooEarly { at }`.
Add a small scheduling margin when converting that whole-second timestamp into
a sub-second timer; waking on a second boundary can otherwise arrive early and
trigger `429` backoff. Respect the finite session deadline when scheduling.
Host approval or a grant entering PS custody does not shorten the caller's
current `Retry-After`: `request` still returns `TooEarly` until its scheduled
time. The helper observes actual responses, not host-side completion signals.
Keep the caller's poll schedule separate from the host's AS advancement schedule.

Pass the actual response to `session.accept(response, now)`. `None` keeps the
session pending; `Some(response)` returns the terminal wire response and closes
the session. A terminal response can also be a refusal, including `410 gone`;
inspect its status before treating it as a grant. Verify a final Auth token with
the existing Agent context helpers before presenting it to a Resource. The
polling helper does not authenticate
response bytes or broaden issuer trust. Use a fresh admitted transport response
for each call; never follow redirects with credentials.

For a clarification, `session.answer(&agent, answer, now)` mutably prepares the
signed `action=clarification_response` POST. Send those exact bytes and give its
actual response to the next `accept`; discard the session if the prepared answer
is abandoned. This lets a subsequent identical question start a new round.
An unanswered question keeps its original absolute timeout across repeated polls.
A successful reply to an on-time answer may arrive after the old question timeout;
the overall session deadline still bounds accepting that reply. A 429/503 refusal
preserves the old question deadline for any answer retry. `session.cancel(&agent, now)` creates a signed DELETE; observe the
server's result before reporting cancellation. Interaction URLs and codes are
host inputs for directing a person; sanitize untrusted Markdown before display.
Payment details stay between the AS and the trusted PS host. The Agent sees
Approval when the AS requests Payment or Claims; it receives no payment hint.
`PendingResponse::payment_challenge()` returns `Ok(Some(PaymentChallenge))`
for the supported WWW-Authenticate Payment profile, `Ok(None)` for a non-payment
requirement, and an error for malformed or unsupported payment framing. The
challenge has string fields `id`, `method`, `amount` and `currency`; only `id` is
required, and the other fields are `Option<String>`. The host decides what the
values mean and whether the admitted AS/provider has confirmed settlement.
The parser accepts an empty or JSON payment body and never charges or pays.

The shared `aauth_rust_core::continuation::ContinuationStore` contract exposes
atomic insert/load/conditional replace or remove. AS and PS hosts must use
separate stores or namespaces. `MemoryContinuations::new(capacity)` is a bounded
process-memory fixture with a 1 MiB encoded row limit; share an Arc across role
recomposition. Process restart durability and expiry collection belong to a
host adapter. Revision values change across deletion/reinsertion so a stale
consumer cannot remove a replacement record.

The complete bounded deferred journey also runs with
`cargo run --locked -p aauth-rust-resource --example four-party -- --deferred`.
It uses certificate-verified TLS and actual native AS/PS state. The fixture host
confirms example settlement, obtains approval, advances once per stage, and the
Agent verifies a grant before one protected POST. No payment provider is called.


## Configure AS and PS continuations

The immediate constructors retain their existing behavior. For an AS, create
`aauth_rust_access_server::DeferredConfig::new(store)` and call
`access.with_deferred(config, callback)?`. The callback receives a
`DeferredContext` containing independently verified original authorization,
PS-provided identity claims and clarification responses. Return
`Ok(Some(aauth_rust_core::continuation::Requirement::Approval))` or another
supported requirement to wait. `Ok(None)` runs the ordinary AS grant policy;
it is still that policy's responsibility to approve scopes and lifetime.

For a PS, first configure its existing `Federation` adapter, then call
`people.with_deferred(aauth_rust_person_server::DeferredConfig::new(store))?`.
Use separate AS and PS stores or namespaces. Both configs expose `lifetime`
(default 300 seconds) and `retry_after` (default 5 seconds); zero interval is
useful only in controlled fixtures. Every pending URL ends in 128 random bits
from the operating system's secure source
(`aauth_rust_core::continuation::generate_pending_id`); the host ID source names
issued tokens only. An AS interaction requirement uses the code the AS drew for
that pending request, `DeferredContext::interaction_code`: 40 random bits from
`generate_interaction_code`. A policy that returns any other code gets `500`.

### Approval without payment

Use the same deferred constructors for an approval-only application. The AS
callback returns `Ok(Some(Requirement::Approval))` until host evidence permits
`Ok(None)`; the ordinary grant policy still decides whether to issue the grant.
Record the authenticated approval for this pending operation in state the AS
callback reads. In one process, that callback and the PS host's
`approval_complete` callback can read the same owned approval record. Separate
hosts need an explicitly admitted approval integration. Returning `true` from
the PS callback only permits its next AS poll; it does not transmit approval to
the AS or change the AS callback's decision.

| Actor | Next step |
| --- | --- |
| Agent | Submit the original exchange; read the PS's `202` and pending Location with `PollSession`. |
| PS host | Inspect `federation_pending`, obtain approval from its authenticated approver, and respect the remaining AS retry wait. |
| PS host | Call `advance_federation` when ready. If the AS issues a grant, the PS verifies and retains it for delivery. |
| Agent | Wait out its own current `Retry-After`, poll the same PS Location, and verify a terminal `200` with its original exchange context. |
| Resource host | Admit the signed request and apply its own effect/idempotency policy. PS delivery consumption does not count the Resource effect. |

This composes the host helper and explicit Agent polls; it is not a separate
executable command. The `four-party --deferred` command above also exercises
payment before approval, and the `deferred_host` example only checks compilation.

On an AS 202 or 402, the PS returns 202 with its own pending URL. Payment and
Claims map to Approval toward the Agent; the original AS requirement remains
available only to the trusted PS host. Agent GET only reads PS custody. The
host calls `people.federation_pending(reference)?` to inspect that AS requirement
and its current remaining retry wait. It settles a bill,
completes an interaction, supplies claims or waits for an external approver.
Then `people.advance_federation(reference, FederationInput::Poll)?` performs one
signed AS GET, or POSTs a queued Agent clarification answer. It never resends
the original token POST. Respect AS Retry-After: an early host call returns
`AdvanceError::NotReady`; the library does not sleep or retry. An initial requested
answer can be submitted promptly, but a 429/503 refusal delays all subsequent
answer retries as well as GETs. Each consecutive 429 adds five seconds to the
persisted interval. An AS 503 uses its numeric or HTTP-date Retry-After, with
five seconds when absent. Malformed or out-of-profile upstream retry values
are bad AS answers and return `502 as_unreachable`. Agent-facing Retry-After
also accounts for the remaining AS wait and the PS's configured minimum.

The following helper performs one bounded host step. It is the exact source of
[`deferred_host.rs`](crates/aauth-rust-person-server/examples/deferred_host.rs),
checked with
`cargo check --locked -p aauth-rust-person-server --example deferred_host`.
Pass an already configured federated/deferred PS and its PS pending reference.
The two callbacks must use real host evidence: settlement is confirmed by the
admitted provider/AS, and approval by the host's authenticated approver or
interaction state. Return `false` while waiting. Serialize work for each
reference and make settlement idempotent by admitted AS identity plus bill ID;
a repeated 402 must not charge twice. Bound callback I/O and runtime within the
host job's deadline; the helper does not impose timeouts on host callbacks.

```rust
use aauth_rust_core::{
    AgentKeyResolver,
    continuation::{PaymentChallenge, PendingResponse, Requirement},
};
use aauth_rust_person_server::{
    AdvanceError, FederationFailure, FederationInput, PersonServer, Policy, Store,
};
use http::StatusCode;
use std::{error::Error, time::Duration};

#[derive(Debug)]
pub enum HostStep {
    RetryAfter(Duration),
    NeedsClaims(Vec<String>),
    Terminal {
        status: StatusCode,
        diagnostic: Option<FederationFailure>,
    },
    Closed(AdvanceError),
}

// Run on a blocking worker. Serialize work for this reference, and make both
// callbacks idempotent: another AS response can repeat the same requirement.
pub fn host_step<K, S, P, C, I>(
    people: &PersonServer<K, S, P, C, I>,
    reference: &str,
    settle_payment: impl FnOnce(&PendingResponse, &PaymentChallenge) -> Result<bool, Box<dyn Error>>,
    approval_complete: impl FnOnce(&PendingResponse) -> Result<bool, Box<dyn Error>>,
) -> Result<HostStep, Box<dyn Error>>
where
    K: AgentKeyResolver,
    S: Store,
    P: Policy,
    C: Fn() -> i64,
    I: Fn() -> String,
{
    let pending = match people.federation_pending(reference) {
        Ok(pending) => pending,
        Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
            return Ok(HostStep::Closed(error));
        }
        Err(AdvanceError::NotReady) => return Ok(HostStep::RetryAfter(Duration::from_secs(1))),
        Err(error) => return Err(error.into()),
    };
    // Whole-second clocks can straddle a boundary; keep a scheduling margin.
    let retry = Duration::from_secs(pending.retry_after.saturating_add(1));
    let ready = match &pending.requirement {
        Requirement::Payment { .. } => {
            let payment = pending
                .payment_challenge()?
                .ok_or("AS payment requirement has no Payment challenge")?;
            // The host confirms settlement with its admitted provider/AS.
            // Key its billing cache by admitted AS identity plus payment.id.
            settle_payment(&pending, &payment)?
        }
        Requirement::Approval | Requirement::Interaction { .. } => {
            // The host checks its authenticated approver/interaction state.
            approval_complete(&pending)?
        }
        Requirement::Claims(names) => return Ok(HostStep::NeedsClaims(names.clone())),
        // Poll also sends an Agent clarification answer already queued at PS.
        Requirement::Clarification { .. } | Requirement::Waiting => true,
    };
    if !ready {
        return Ok(HostStep::RetryAfter(retry));
    }
    let response = match people.advance_federation(reference, FederationInput::Poll) {
        Ok(response) => response,
        Err(AdvanceError::NotReady) => return Ok(HostStep::RetryAfter(retry)),
        Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
            return Ok(HostStep::Closed(error));
        }
        Err(error) => return Err(error.into()),
    };
    let status = response.status();
    if [
        StatusCode::ACCEPTED,
        StatusCode::PAYMENT_REQUIRED,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&status)
    {
        // Read the persisted interval after 429/503 backoff changed it.
        let pending = match people.federation_pending(reference) {
            Ok(pending) => pending,
            Err(error @ (AdvanceError::Gone | AdvanceError::Expired)) => {
                return Ok(HostStep::Closed(error));
            }
            Err(AdvanceError::NotReady) => {
                return Ok(HostStep::RetryAfter(Duration::from_secs(1)));
            }
            Err(error) => return Err(error.into()),
        };
        return Ok(HostStep::RetryAfter(Duration::from_secs(
            pending.retry_after.saturating_add(1),
        )));
    }
    // Keep diagnostics before framework conversion. No token is logged here.
    // A terminal 200 is held at the PS pending URL for the Agent's next poll.
    Ok(HostStep::Terminal {
        status,
        diagnostic: response.extensions().get::<FederationFailure>().cloned(),
    })
}

fn main() {
    println!("host_step compiled; supply a configured PS and real host callbacks to use it");
}
```

The helper schedules no work itself and makes at most one signed AS request.
On `RetryAfter`, arrange another step after that delay, within the host job's
finite deadline. It rereads the persisted interval after 429/503 responses;
`NotReady` also requires a later step. `Closed` stops host advancement. Stop on
`Terminal` and inspect `diagnostic.access_server`, `status` and `reason` when a
diagnostic is present. Remote detail text is untrusted and may be private; apply
your logging policy. A terminal 200 is retained for Agent delivery, so keep
serving the PS pending URL and let the Agent verify the final Auth token. The
helper's `main` only confirms compilation; it does not compose a service or
contact a payment provider. The complete TLS example exercises that composition.
`HostStep::RetryAfter` can mean the approval callback is still false, an AS wait
has not elapsed, or a later response requested backoff. Its delay includes the
helper's one-second scheduling margin, even when the remaining AS wait is zero.
Schedule that returned delay once; the helper does not sleep. Use the host's own
approval state to describe what is waiting, rather than inferring it from a delay.
`federation_pending` also returns `NotReady` for ready or in-flight custody;
retry advice alone does not mean approval is missing. Keep serving Agent delivery.

`NeedsClaims(names)` deliberately returns control to the host. Obtain those
claims from a trusted source, then call `advance_federation` with
`FederationInput::Claims(map)` and handle its response/errors using the same
rules. A host-supplied clarification can use `FederationInput::Clarification`;
the helper's Poll automatically sends an answer already queued by the Agent.

Use `FederationInput::Claims(map)` to POST requested claims from a trusted source;
`sub` is forbidden because the presented token already identifies the person.
Use `FederationInput::Clarification(answer)` for a host/user answer. If the PS
relays a question to the Agent, its signed `clarification_response` POST queues
one answer without AS I/O; the host explicitly advances it. The queue
acknowledgement and subsequent waiting Agent polls show approval rather than the
answered question. The PS retains the AS question deadline independently until
advancement, and a later AS question starts a new round even with identical text. Interaction URL/code
lifecycle belongs to the host that serves that interaction. Only that host can
confirm completion; an Agent poll does not approve an interaction or a payment.

### Delivery and Resource replay

`advance_federation` returns the actual AS pending response or the PS's verified
terminal response. Inspect its `FederationFailure` extension for diagnostics
before framework conversion. A 200 here is available in retained PS custody;
the Agent still obtains its terminal result through the PS pending URL. The PS
verifies that grant again and confirms current bindings after final custody I/O
before delivery. Its remaining `expires_in` uses the final clock; expiry or
revocation during store publication/removal never releases a prepared token. One
conditional consumer receives it; later GETs return 410. While delivery owns its
claimed row, competing authenticated owner polls and DELETE return 429 without
consuming custody, even after expiry or a Resource-trust change. The delivery
owner still checks current release conditions. A final storage failure returns
500 and can leave `delivering` custody for host reconciliation; storage recovery
does not automatically retry delivery. Signed DELETE cancels ready custody
locally without AS I/O. Cancelling waiting custody sends one AS DELETE and
consumes local custody; transport failure reports failure even though local
cancellation closes the PS continuation. Cancellation during host advancement
returns 429 for a later retry.

After successful delivery, an otherwise authenticated read of the consumed PS
reference returns `410` with error `gone`. This closes that continuation; it does
not revoke or spend the delivered Auth token. Another signed Resource request
can still pass ordinary token validation and host policy. The Resource host
owns replay and idempotency decisions and must couple a one-effect operation
with its own effect storage; continuation custody does not provide that guarantee.

This missionless Core-scope profile supports top-level Agents and one-level
parent-mediated children. Deadlines are capped by all original credentials,
including both Agent tokens for a child and the Resource challenge. Long-wait refresh needs a later profile; submit a fresh original
request after expiry. A clarification `updated_request` replaces the pending
resource and presented tokens after the pair verifies and the new resource
token keeps the original `iss`, `ps`, `sub`, `agent_jkt`, `mission_s256`, and
`tenant`. AS and PS independently enforce five clarification rounds,
preserve unanswered question deadlines and advertise remaining timeout seconds. There is no durable AS/PS continuation adapter in this
release. Custom stores must preserve atomic revisions, bounded records and
role namespaces across restart, collect expiry and reconcile uncertain in-flight
transitions. No automatic recovery repeats a POST, settlement or grant delivery.
The ordinary PS issued-token store, including redb, remains a separate contract.

## Subscribe to and deliver AAuth Events

AAuth Events lets a Resource notify an Agent through the Agent's Agent
Provider (AP), which acts as its inbox. The token types are in
`aauth_rust_core::events`: `SubscribeToken` (`aa-subscribe+jwt`, AP-signed,
carrying `sub`, `aud`, `cnf`, `eid`, `jti` and optional `max_uses`) and
`EventToken` (`aa-event+jwt`, Resource-signed, carrying `aud`, `eid`, `jti` and
`body_s256` exactly when there is a body, and never `cnf`). The roles use them as
follows. No role performs network I/O; the host fetches, admits and sends.

### Agent Provider

`AgentProvider::with_event_endpoint("https://ap.example/events")` publishes
`event_endpoint` in `metadata()`. Only a provider with one can build an
`events::EventInbox`, so an AP that receives events through this library always
publishes its endpoint.

After the host decides an Agent may subscribe at a Resource, call
`provider.issue_subscribe_token(&store, &SubscribeRequest { agent_token,
resource, expires_at, max_uses, subscription_expires_at }, now)`. It
authenticates the Agent's current Agent token with this provider's own key and
copies its `sub` and `cnf.jwk`, so the subscribe token always names the Agent's
current key. It draws `eid` and `jti` from the system random source, refuses an
`expires_at` beyond the Agent token's `exp`, and retains the `Subscription` in
the store before returning the token. A store failure releases no token.
`expires_at` is how long the Resource may accept the token for registration;
`subscription_expires_at` is the AP's own end for the subscription, if any.

Route POSTs to the event endpoint to
`inbox.receive(&request, now).into_response()`. The inbox requires the
`self-jwt` scheme, a body signed with covered `Content-Digest` and
`Content-Type`, and an event token that verifies (`typ`, `dwk`
`aauth-resource.json`, no `cnf`, unexpired) with the same Resource key that
verifies the HTTP signature. `body_s256` must match the body. The subscription
for `eid` must exist and not have ended (`404` otherwise), the token's `iss` must
be its Resource (`403`), and its `aud` its Agent (`401` `invalid_jwt`, checked
before a use is counted). The store then atomically drops an `(iss, jti)` it
already holds, refuses a subscription that has accepted `max_uses` events
(`404`), or counts the event and records the exact token and body. Only then
does the inbox answer `202`, with `{"remaining_uses": n}` when the subscription
has `max_uses`. A store failure is `503` and nothing is recorded.

`keys` resolves Resource keys for `aauth-resource.json`. A `TrustedIssuerKeys`
snapshot serves Resources you configure. An AP that accepts events from
Resources it has never seen supplies its own resolver, which applies egress
admission (`admit_fetch`) before fetching their metadata and JWKS.

`EventStore` is the durability contract: each successful write is durable
before it returns, and `record` is one atomic step. Use
`DirectoryEventStore::open(directory)` in production. Each subscription is a
JSON file with its use count and the events it accepted, and each accepted
event is a file with its exact token and body bytes. Every write goes to a
temporary file that is synchronized and renamed, and the directory is then
synchronized, before the store reports success. Accepting an event writes the
event file and then the subscription file, whose rename is the commit point:
an event file no subscription lists was never accepted, and the Resource's
retry replaces it. A failed or uncertain write is `503`, never `202`. A torn
subscription file makes that subscription unavailable rather than guessing its
count. One store value owns its directory; do not open it from two processes.
This covers process exit and an interrupted write, not power loss on storage
that ignores `fsync`. Each accepted event rewrites its subscription's file, so
very long unlimited subscriptions grow that file, and accepted event files are
retained: this release has no compaction. `MemoryEventStore` is a volatile reference for
tests. Delivery to the Agent is your transport: read `store.pending(agent)`,
hand each `RecordedEvent`'s `event_token` and `body` bytes to the Agent
unchanged, and `acknowledge` it once delivered.

### Agent

Record what each subscription is for before presenting its token:
`EventSubscriptions::new(agent_identifier)` then
`subscriptions.remember(&subscribe_token, context)`, which returns the `eid`.
Sign the registration with `agent.sign_subscription(&mut request,
&subscribe_token, now)`: the subscribe token is the `Signature-Key` JWT in place
of the Agent token, and a token for another key is refused.

When the AP delivers an event, call
`subscriptions.receive(&event_token, &body, &resource_keys, now)`. It verifies
the token (`typ`, `dwk`, the Resource key, `exp`), requires `aud` to equal the
Agent identifier exactly, checks `body_s256` against the body, looks up the
`eid`, requires `iss` to be the Resource that subscription named, and refuses an
`(iss, jti)` already processed. Act only on an `Ok`; an expired token is an
error because its response window has closed. `verify_event` performs the first
three checks without local state. The processed set is in memory; keep it
durably if the Agent must not act twice across restarts.

### Resource

Configure `events::EventsResource::new(EventsConfig { issuer, signed_origin,
kid, signing_key, ticket_path, max_ticket_lifetime }, ap_keys, store)`. The
issuer is each subscribe token's required `aud` and each event token's `iss`.
Publish `jwks()` and name it as `jwks_uri` in the Resource's metadata: the AP
discovers the delivery key from `{iss}/.well-known/aauth-resource.json`. `ap_keys`
resolves Agent Provider keys for `aauth-agent.json`, as for Agent tokens.

`register(&request, now, policy)` handles a public subscription endpoint. The
subscribe token must verify with `typ` `aa-subscribe+jwt`, `dwk`
`aauth-agent.json` and an unexpired `exp`; its `aud` must be this issuer; its
`cnf.jwk` must verify the request signature; and its `eid` must be nonempty.
Each failure is `401` with `Signature-Error`. Policy then sees the verified
token and request and returns the context to keep (`403` on `Deny`). The store
keeps `{agent_provider, eid, agent, max_uses}`; a repeated `(iss, eid)` is `409`.

For a protected channel, issue a ticket from the authenticated interaction:
`issue_ticket(&holder, context, lifetime, now)`, where `holder` is the
`VerifiedPersonToken`, `VerifiedAuthToken` or `AuthAuthorized` the Resource
verified on that request. The ticket records the RFC 7638 thumbprint of its
`cnf.jwk`, lives at most `max_ticket_lifetime` seconds (at most an hour), and is
retained before its URL `{signed_origin}{ticket_path}{id}` is returned. Route
POSTs under `ticket_path` to `register_with_ticket`. It verifies the subscribe
token as above, then requires the ticket to be unused and unexpired and the
thumbprint of the token's `cnf.jwk` to equal the recorded one. The store
consumes the ticket in the same step that registers the subscription. Every
ticket failure is `403`. The binding is the key, not the `sub` the token names.

To deliver, `prepare_event(agent_provider, eid, payload, expires_at, now)` mints
the event token: the subscription's `eid` and Agent, a fresh `jti`, and
`body_s256` when there is an `EventPayload`. Fetch
`agent_provider_metadata_url(agent_provider)` after `admit_fetch`, then
`delivery_request(&event, &metadata, now)` builds the POST to its current
`event_endpoint`, signed under `self-jwt`; with a body the signature covers
`content-digest` and `content-type`. Admit the endpoint with
`admit_event_endpoint`, send it without following redirects, and pass the
response to `delivery_outcome`. A `remaining_uses` of `0` or a `404` removes the
subscription; the Agent must subscribe again. To retry, sign the same
`PreparedEvent` again: its `jti` lets the AP drop a duplicate.

Describe event channels with an AsyncAPI JSON document and publish it with
`with_asyncapi(document)`. It must declare
`components.securitySchemes.aauth_subscribe` as `subscribe_security_scheme()`
returns (`type: http`, `scheme: aauth-subscribe`), or it is refused.
`SubscriptionStore` has the same durability contract as `EventStore`;
`MemorySubscriptionStore` is the volatile reference. AsyncAPI payload validation
is not implemented.
