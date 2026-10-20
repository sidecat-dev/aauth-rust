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

Implement `Policy::bind_person` using host-authenticated evidence and the verified
Agent identity. Login hints and tenant parameters are signed Agent assertions,
not person authentication. Return `Person.id` as a stable internal identifier,
and `Person.subject` as a stable opaque identifier directed to the requested
Resource. Do not publish the internal identifier or reuse the public subject at
another Resource. Tenant is organization context and may change without changing
the person. One Agent issuer/subject tuple binds to one accountable person;
conflicting or revoked bindings cannot be overwritten by policy.

`Policy::authorize` receives verified Agent and Resource claims, the exact
retained presented issuance, requested scopes and signed parameters. Return a
nonempty subset of those scopes and a positive lifetime up to one hour. Intentional
denial returns 403; an unavailable policy/store returns 500. Invalid token
parameters return typed 400 errors; HTTP proof/credential failures return 401
Signature-Error. The PS checks lineage before policy, caps parent lifetimes,
commits retained state, resamples its trusted clock and only then releases tokens.
A Resource challenge must still be current at exchange; its five-minute lifetime
does not cap the issued Auth token, whose other parent bounds still apply.

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

`AuthDecision::into_result()` yields `(VerifiedAuthToken, admitted_context)` or a
boxed refusal response. Application policy sees the verified Auth token and
actual request only after audience, holder, expiry and configured scopes pass.
Return your own response after performing authorized work. Admission does not
freeze time: a long-running operation must decide whether to recheck expiry
before its eventual effect.

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

This profile implements immediate, missionless PS authorization. AS federation,
missions, R3, Budget semantics, sub-agent delegation, deferred consent/polling,
revocation transport and automatic step-up orchestration remain outside it.
The PS rejects unsupported parameters explicitly. Its discovery publishes only
implemented endpoints, with one active public key; it provides no key-overlap
lifecycle. Core token verification alone does not establish application consent,
account admission or exactly-once effects.
