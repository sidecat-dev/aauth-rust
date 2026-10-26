# Specification baseline

The Rust journey uses the editor sources below. These are the exact current
snapshot used by this implementation, not a claim about later published drafts.
The six AAuth sources are byte-identical at 28e8258 and 70d6737.

| Document | Commit | Source | SHA-256 |
| --- | --- | --- | --- |
| draft-hardt-aauth-bootstrap | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-aauth-bootstrap.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-bootstrap.md) | `40ca9d052e942a78ef01a827a23bd0149d34a58f626e750949f3ddcd2601b82c` |
| draft-hardt-aauth-budgets | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-aauth-budgets.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-budgets.md) | `f00d34c91576476cdb30b7aa1aa13a0bc9fc1d99fc43b4f0389ccb3e8bf2e150` |
| draft-hardt-aauth-events | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-aauth-events.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-events.md) | `462b2fa2fdb10791dd976a7566cd09f5e5d64686c8d6e2966cc2e0caf87acd12` |
| draft-hardt-aauth-r3 | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-aauth-r3.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-r3.md) | `39672880b054e380d39c9c997523b3320216bade2e348a8f79990f2d85e1f2aa` |
| draft-hardt-aauth-supervision | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-aauth-supervision.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-supervision.md) | `9fd44f899e06bf2a1e903459799cccdd8c6365b5eb5fa1efe2ed5b23b1a6d1a3` |
| draft-hardt-oauth-aauth-protocol | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [draft-hardt-oauth-aauth-protocol.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md) | `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0` |
| interop-demo-profile | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | [interop-demo-profile.md](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/interop-demo-profile.md) | `596c7d2c952d8ec6cdfd66a91c2d123705f3e4ed75fa581b4e3ac20404971545` |
| draft-hardt-httpbis-signature-key | `69f5ba2647be848feed043fb6d8b0790e43cd0b6` | [draft-hardt-httpbis-signature-key.md](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md) | `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d` |

Agent, Person, Resource and PS/AS Auth tokens execute, with person binding,
three-party authorization, an immediate direct downstream chain and immediate
four-party federation. The proof subset is Ed25519, ES256, ES384, RS256, and PS256 `hwk`, Ed25519 `jwt`, Ed25519 `jkt-s256+jwt`
self-issued delegation, plus explicit
`jwks_uri` service proofs. A `jkt-jwt` member is verified by recomputing
`urn:jkt:sha-256:` from the header `jwk` and comparing it to `iss`, then
verifying the assertion and the HTTP signature under `cnf.jwk`. `iat` uses
the same window as `created`. `exp` must be strictly after the verifier
clock. The bare `cache` flag requires `jti`. When the host opts in, the library
issues a sealed `Signature-Key-Cache` identifier. A `self-jwt` member is the same kind of proof with one
key: after the compact JWT parses, `typ` matches the caller's deployment
policy, `exp` is after the verifier clock, an optional `iat` uses the same
window as `created`, `iss` is an HTTPS origin kept
byte for byte, `dwk` is a discovery-document name, the header `kid` is
present, and `cnf` is absent, the metadata document's `issuer` must equal
`iss` or the resolver is not called. The host resolver is then asked for that
exact `iss`, `dwk`, and `kid`. That key verifies the JWT and then the HTTP
signature. A `cache` parameter is rejected and no cache identifier is issued.
The library does not fetch the issuer. A direct `jwks` member names an HTTPS
JWKS `url` and a `kid`. The URL is the signer identity and is passed to the
host resolver unchanged: host case, an explicit port, a trailing slash, and a
query are not rewritten. Byte-different URLs are different identities. The
library does not fetch the JWKS. An EC header key carries `kty`, `crv`,
`x`, `y`, and `alg` (`ES256` with `P-256`, or `ES384` with `P-384`). An RSA
header key carries `kty`, `n`, `e`, and an `alg` that names both padding and
hash (`RS256` or `PS256`). `n` and `e` are minimal unsigned integers, the modulus is 256 to 1024 bytes, and the exponent is odd and at least 3. A missing parameter or a curve that disagrees with
`alg` is rejected. An `x509` member names an HTTPS `x5u` and a 32-byte `x5t`.
The URL is kept as presented and is not fetched. The host passes the PEM
chain and the DER trust anchors. The first certificate is the end entity. The
chain must validate to one of those anchors at the verifier clock, and `x5t`
must be the SHA-256 of that certificate, before the HTTP signature is checked.
That certificate's key selects one algorithm: Ed25519, P-256 as ES256, or
P-384 as ES384. An RSA certificate is `unsupported_algorithm` because
`rsaEncryption` names neither padding nor hash. Revocation is host-owned.
A `jwt` or `jkt-jwt` member may carry a bare `cache` flag. On `jwt` the flag
requires a nonempty `jti` and a nonnegative `exp`. The host may then ask
`AssertionCache` for a `Signature-Key-Cache` value. The identifier is a
XChaCha20-Poly1305 seal under a verifier key: 192 random bits, the scheme,
issuer, optional subject, SHA-256 of the verified compact assertion, the
`jti`, both expiries, and the Ed25519 confirmation key. `expires` is the retention time
and is not later than the assertion `exp`. It is honored through that second.
After it, or after this process evicts the entry, resolution is `cache_miss`.
A held assertion whose `exp` is not after the verifier clock fails as
`expired_jwt` once the HTTP signature has verified. A bad HTTP signature is
`invalid_signature`, including when the identifier resolves. An assertion with
more than 86400 seconds left is not cached. `self-jwt` rejects `cache`. A
caller presents `cid` only as the exact string issued, and does not present
`cached` merely because `Accept-Signature-Scheme` lists it first. Direct agent
identity, the person server, and the access server do not accept `cached`.
Compact JWS remains Ed25519. When a request carries more than one signature,
the signer writes the complete Signature-Key dictionary before creating any
signature, and each signature covers that field. The verifier still checks
one selected label. A client that reads `Accept-Signature-Scheme` or
`Accept-Signature-Alg` keeps only tokens it recognizes, compared
case-sensitively, and does not sign when none remain. `Signature-Error`
contributes its `error` token; other members are ignored. On a non-success
response the Person Server takes that token and does not require a JSON body.
When the header is absent, a problem body still supplies `error`. A JSON
`detail` may be present. `clock_skew` still requires `Date`. `KeyCache` stores a JWKS document the host fetched. It does not open a connection and cannot retract that fetch. A `jwks_uri` entry is keyed by issuer and `dwk`. Freshness
comes from `s-maxage`, then `max-age`, otherwise 300 seconds, and is at most
86400 seconds. `no-store` and
`no-cache` do not leave a reusable body. Another fetch of that issuer and `dwk`, or of that URL,
waits 60 seconds, and the cache holds only the bound given at open. A
discovery fetch is admitted only for HTTPS, to one pinned globally routable
unicast address, with a response cap of at most 65536 bytes and a timeout of
at most 30 seconds. Those bounds are checked again at admission. Embedded
IPv4 in mapped, compatible, well-known NAT64 (`64:ff9b::/96`), 6to4, and Teredo
forms is classified as that IPv4 address. The local-use prefix `64:ff9b:1::/48`
is refused as a whole. Anything else needs an explicit allowance, as does a JWKS
host that differs from the metadata host. Redirects stay on that host, including a different port, and stop after three. A
parsed `jwks_uri` `id` is an origin name; an empty allowlist does not
authorize it. A pseudonym client admits each Ed25519 thumbprint
for one canonical HTTPS authority. The same host with port 443, any path, and
any query is that server. A different port is a different server. The same
server may rotate to a new key. `jkt-jwt` binds the enclave key, not the
ephemeral confirmation key. `sign_request` does not keep this table. A
`jwt` that carries both `iss` and `dwk` is verified from host-supplied
metadata and JWKS. The library builds `{iss}/.well-known/{dwk}` and does not
fetch it or the JWKS. `iss` is a bare HTTPS origin. `issuer` must equal
`iss`. The header `kid` selects the issuer key, that key's `alg` must equal
the header `alg`, and both the issuer key and `cnf.jwk` are Ed25519. When
either claim is absent, the host supplies the Ed25519 issuer key itself.
Direct
agent identity still accepts only `jwt`. A `keyid` parameter is accepted only when it equals
the `kid` carried by that Signature-Key member; the key still comes from
Signature-Key. Opt-in AS/PS continuations cover bounded claims, clarification, interaction,
approval and WWW-Authenticate payment with signed polling. An Agent also parses
a Resource `202` `requirement=auth-token` and polls it with a retained auth
token. A host that holds the invocation replays one stored result for that
auth token `jti` through `exp`. During a clarification, `updated_request`
replaces the pending resource token only after the new pair verifies, the
resource identity matches the original (`iss`, `ps`, `sub`, `agent_jkt`,
`mission_s256`, and `tenant`), and consent allows that replacement. A refusal
leaves the stored request unchanged and does not call the access server.
A resource interaction sends the browser to its `callback`, adding `error`
when the flow did not finish. `access_denied` polls as `denied`,
`user_abandoned` as `abandoned`, `interaction_expired` as `expired`, and both
`server_error` and `temporarily_unavailable` as `server_error`.
`person_server_redirect` and `receive_callback` are helpers; no Person Server
route calls them. Callback targets are HTTPS, so `http://localhost` and
`http://127.0.0.1` are refused. A callback that carries `error` does not
complete the pending request. A resource that must propagate a downstream
interaction returns its own `202`, with its own code and pending URL. The host
binds that poll to the opener it already verified. The stored result is
returned once, at or before `exp`, and a later poll is `410`. A different
caller receives an empty `404`. An `aauth-resource` link helper returns a
target only when it is a server identifier plus
`/.well-known/aauth-resource.json`. The library fetches nothing. The link is
not an `AAuth-Requirement`. Settlement and
interaction/code lifecycle are host-owned. The AS sends payment and claims
requirements to the PS; the PS host handles them while the Agent sees Approval.
There is no Agent payment hint or settlement API in this profile. Single terminal
delivery applies per continuation, and Auth tokens carry no Resource challenge
or continuation identifier for cross-exchange binding. Request replay protection
and operation idempotency remain host duties. A host may install an already
approved top-level mission and have the immediate PS consume it: exact blob
identity, active state, owner, person binding and expiry are checked in the same
store transaction as Person and Auth issuance. The decoder refuses an empty
description, a negative approval time, and an expiry that is not strictly later
than approval. Installing a record that is not active writes no person binding.
An empty administrative termination reason is refused before the record changes. The direct Resource can opt in to
carrying that signed digest. Opt-in revocation executes for a Person Server, an Access Server, and a Resource.
The caller signs as a server. The recipient keys `(iss, jti)` by the verified caller, ignores an `iss` body field, and keeps the first `exp`.
The ledger is process memory. Downstream calls are a host-supplied directory, not an HTTP client in this library.
A recipient with nothing downstream answers an empty `200` and never `202`. A Resource refuses a revoked person or auth token with `401` `revoked_jwt` and does not issue a resource token; a revoked auth token asks for a person token.
An agent helper remembers a resource token refused as `revoked_resource_token`. `Subagent::auth_request` consults that set and does not build another request for that same token. The host records the token-endpoint error before the next build. Another error does not ban the token.
Opt-in mission creation, update, completion, approval and owner audit execute.
The agent proposes with a signed `jwt` POST and receives `202` with `Location`,
`Retry-After`, and `Cache-Control: no-store`. Approval is a separate POST signed
as this Person Server; a missing or different signature does not approve.
The proposing agent polls that location once and receives `s256` and the base64url
mission bytes the server persists. A later poll is `410 gone`. A denied proposal's
first poll is `403 access_denied` and the next is `410 gone`. The approval POST
does not return those bytes. The first signed approval claims the proposal before
the audit write, so a second approval is `404 mission_not_found` and does not
write another audit. An update or completion POST requires `action`; a missing or
unrecognized action is `400 invalid_request`. Update requires `description` and
returns that update's digest without changing the mission digest. Completion
requires `summary` and terminates with reason `completed`. The owning agent can
read the exact mission bytes and the accepted updates. A different owner receives
the same `404`, body, and headers as a missing mission. A proposal poll uses the
authenticated agent's issuer and subject together with the proposal id, so a
missing proposal and someone else's proposal miss the same way. A signature
that does not verify is refused before that lookup. Proposals are process memory. MemoryStore and
redb persist the approved document. `mission_control_endpoint`, `person_tokens`
and `capabilities` are not produced. AS, child, upstream and federated mission
paths do not execute. Opt-in interaction, permission, and audit endpoints execute.
The agent signs each POST with `jwt`. `type` is required on interaction. `action`
is required on permission and audit, and audit also requires `mission_s256`.
A denied permission does not authorize the action. For a resource-hosted interaction,
the resource pending URL remains the completion signal after the Person Server relay
resolves. `interaction` and `payment` return `424 interaction_unavailable` because
this library has no user channel. A `question` is answered by the host. An interaction
code is compared after stripping hyphens and folding Crockford aliases and case.
Presenting the code correlates the session and does not itself approve or deny. After that code is consumed, one POST signed as this Person Server stores the decision, and a second decision is refused. `InteractionCompletion` and `PermissionDecision` are agent helpers; no library poller calls them.
The code is single-use. Three failed attempts make it terminally `invalid_code`.
A code whose pending interaction has expired is `408 expired`. The host supplies
the emitted code. The code table is process memory. Opt-in resource session
tokens execute. The resource binds an opaque `token68` value to one verified
agent subject and returns it in one `AAuth-Access` header. The agent keeps the
latest value and sends `Authorization: AAuth` on the next request. The signature
covers `authorization`. `AgentIdentityResource::admit_session` verifies that
same request before it can return the bound subject. An unverified presentation
does not reveal the subject. A later
`AAuth-Access` value replaces the previous token. Empty values, embedded
whitespace, control characters, and more than one credential are rejected.
Opt-in `authorization_endpoint` executes. The agent presents a person token.
The resource verifies it before reading `scope`. A request without a person
token is `requirement=person-token`. Missing `scope` is `invalid_request`.
A recognized scope returns a resource token. An unrecognized scope is
`invalid_scope`. A duplicate JSON member and a repeated scope token are
`invalid_request`.
A held invocation runs once for an auth token `jti`. A repeated presentation
of that token at the same pending id returns the stored result through the
token's `exp` and does not run the invocation again. The host passes only the
`jti` and `exp` of an auth token this resource already verified, including the
HTTP proof. The ledger accepts a `jti` of `[A-Za-z0-9_-]{1,128}`.
A Resource that asks for a
`login_hint` also names the Person Server, directed subject, account and tenant
it expects. A verified token whose Person Server, subject, account or tenant
differs is refused with `403` `access_denied` and no `Signature-Error` header.
The same subject at another server does not match. The hint is not that
subject. The directed subject is a required string; an empty subject authorizes no one.
Supervision and companion authorization vocabularies remain outside
this subset.
Full R3 compliance is postponed by vocabulary; general media/service vocabularies
can grow on demand in both implementations, one test at a time. See [CONFORMANCE.md](CONFORMANCE.md).

Underlying standards: RFC 7515 (compact JWS), RFC 7517 (JWK), RFC 7638
(thumbprints), RFC 8032/8037 (Ed25519), RFC 9421 (HTTP Message Signatures),
RFC 9651 (Structured Fields), RFC 9864 (fully specified `Ed25519`).

The HTTP profile requires `@method`, `@authority`, `@path`, `signature-key` and
`created`. This implementation additionally requires `@query` when present,
and `authorization` when present. The local buffered profile additionally
requires covered SHA-256 Content-Digest for nonempty content or a supplied digest,
plus Content-Type when present on nonempty content. Actual bytes are checked, with a
1 MiB limit. Core Covered Components mandates body digest/type at PS/AS and
revocation endpoints; ordinary Resource body requirements remain Resource policy.
This implementation chooses the safe buffered default without changing that
normative distinction. RFC 9530 section 2 defines the digest field.
Production server identifiers remain HTTPS scheme and lowercase DNS host only;
test TLS uses name-to-loopback routing without changing those identifiers.
