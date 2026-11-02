# Executing behavior

As of 2026-10-24. This is not complete AAuth or
HTTP Signature Keys conformance. No percentage of either draft is claimed.
The exact editor-source pins are in [SPECIFICATIONS.md](SPECIFICATIONS.md).

This Rust 10 platform follow-up branches from Rust 09 `91d61ea`, which adds
delivery-custody controls on the pushed Rust 08 candidate `4dbbcfe`,
itself based on merged Rust 07 sprint main `5c9c89e`. Rust 07 includes the Rust 05
Access Server and Rust 06 deferred profiles and passed independent review, an
application user test and the 185-assertion shared-wire smoke before merge. Rust
08 adds regression coverage and the host guide; Rust 09 preserves claimed PS
delivery custody against competing expiry/trust cleanup. Rust 10 adds only
compile-time platform coverage and scoped platform documentation. The combined
follow-up remains a candidate until its own review and merge. Earlier shared-wire results
remain attributed to their exact revisions.

Engineer evidence at the unchanged Rust 09 runtime `91d61ea`:
**303 integration tests and 5 backend unit tests
passed, 0 failed**, including
the direct-identity TLS test (**14 wire/TLS checks**) and a three-party TLS test
that executes Orders→Inventory authorization and POST effects. A four-party TLS
test executes PS service proof, AS grant/delivery and one POST effect, compares
forwarded compact bytes at the TLS receiver and asserts wire problem codes. Executable examples
run those same compositions. A wire check is not counted as a separate Rust test.
Four additional rustdoc tests execute an unsigned Resource challenge, the PS
and AS constructor/metadata examples and durable-store open/reopen. One ignored backend
test is a subprocess entry point, executed by its two parent recovery tests.
The buffered `subagent` example separately passes eight route/workflow tests and its
executable scenes; those tests are outside the workspace test total.

| Source area | Executing subset | Evidence |
| --- | --- | --- |
| RFC 8032/8037, RFC 7518, RFC 7638, RFC 5958 | Ed25519 signing by default; ES256 keys generated in memory; ES256, ES384, RS256 and PS256 signing from a named PKCS #8 key; any of those held by a caller's external signer, whose public JWK is validated and whose every signature is verified under it before use; export of an in-memory key as PKCS #8 DER, zeroized on drop and refused for an external signer; strict verification; public-only JWK; fully specified algorithm and key-shape checks, including an EC point on its curve; thumbprints for OKP, EC and RSA keys | `aauth-rust-jose/tests/jose.rs` (14 tests, including the RFC 8032 empty-message signature vector and RFC 8037, RFC 9449 and RFC 7638 thumbprint examples) |
| One-level sub-agents | Actual parent and child AP signatures, authoritative parent_agent, same provider, single depth and distinct proof keys; parent signs PS requests, owns consent/binding/polls, child holds Person/Auth and signs Resource requests; local and immediate/deferred AS grants; exact retained parent/child identity and parent revocation | Core `subagents.rs` (7), AP `subagents.rs` (4), Agent `subagents.rs` (8), PS/AS endpoint cases, memory/redb contracts, Resource `subagent_revocation.rs` (2) and buffered native `subagent` example (8 separate example tests) |
| Explicit Agent polling | Signed GET, clarification POST and cancellation DELETE preparation; required waits, 429 linear backoff, 503 retry interval, stable same-origin Location and terminal completion; a 202 `requirement=auth-token` is parsed and polled with a retained auth token; host dispatches requests and verifies final credentials. The Resource does not hold an invocation or replay a result | `aauth-rust-agent/tests/polling.rs` (12 tests) |
| PS deferred federation | PS-owned signed Agent GET/clarification POST/DELETE, explicit signed AS advancement, exact original-token retention, independent grant verification and atomic delivery; payment/claims stay host-side; revocation/expiry/concurrency refuse | `aauth-rust-person-server/tests/authorization.rs` (67 tests, including 33 deferred cases), deferred TLS journey |
| AS deferred authorization | Explicit policy for 202 claims/clarification/interaction/approval or 402 payment, independently authenticated PS polls, exact retained tokens, bounded claims/chat, atomic single-consumer result, cancellation/expiry and rechecked issuer trust; native PS continuation verified separately | `aauth-rust-access-server/tests/endpoint.rs` (34 tests, including child approval/payment, trust/expiry fences and omitted presented_token) |
| Deferred wire and state primitives | Bounded 202 claims/clarification/interaction/approval/auth-token and 402 payment parsing, same-origin pending URLs, host-owned settlement details, atomic revision transitions and one-consumer removal; separate AS/PS role custody. An auth-token requirement from an Access Server is not a federation continuation | `aauth-rust-core/tests/continuation.rs` (14 tests), `payment.rs` (10 tests) |
| RFC 7515 | Compact JWS signed and verified with Ed25519 or ES256, the header `alg` naming the signing key's own algorithm (ES384, RS256 and PS256 are `unsupported_algorithm`); exact signed segments, no unsupported critical headers or unencoded payload profile; duplicate JSON members refused | Same JOSE tests |
| Signature-Key | `hwk` for Ed25519, ES256, ES384, RS256, and PS256 (each required parameter is present; RSA `alg` selects PKCS#1 v1.5 or PSS with SHA-256), `jwt` (bare `cache` requires `jti` and `exp`), Ed25519 or ES256 `jkt-s256+jwt` (thumbprint `iss`, `cnf.jwk` request key, bare `cache` requires `jti`; a host that opts in receives a sealed cache identifier), Ed25519 or ES256 `self-jwt` (host resolves exact `iss`, `dwk`, and header `kid` only after the JWT parses; `cnf` and `cache` are rejected; no cache identifier is issued; the same key verifies the JWT and the HTTP signature), direct `jwks` (exact `url` and `kid`; the URL is not canonicalized; a signature that fails under the resolved key asks the resolver once for a fresher one), `x509` (HTTPS `x5u` is not fetched or rewritten; `x5t` is the SHA-256 of the first certificate's DER; the host supplies the PEM chain, trust anchors, and CRLs; each certificate needs a current CRL from its issuer, so an empty CRL list is refused; chain validation, including revocation, runs before the signature; the end-entity key selects Ed25519, ES256, or ES384; an RSA certificate is `unsupported_algorithm`), `cached` (`cid` is presented unchanged; a local index or a ChaCha20-Poly1305 seal resolves it; the HTTP signature is then checked with the sealed Ed25519 or ES256 confirmation key; unknown, evicted, and unopenable identifiers are `cache_miss`; a held assertion past `exp` is `expired_jwt`; `expires` is not later than the assertion `exp` and is honored through that second; an assertion with more than 86400 seconds left is not cached; a client does not present `cached` until an identifier was issued), explicit `jwks_uri`, selected-label correlation, required key coverage, unknown unselected scheme ignored, defined unsupported-scheme/algorithm errors, `keyid` accepted only when it names that same member. A scheme that names no algorithm until its key is resolved (`jwks_uri`, `jwks`, `jwt`, `jkt-jwt`, `self-jwt`, `cached`) checks the signature length against the resolved key, so a resolved key of a type the verifier does not implement, such as `AKP`, is `unsupported_algorithm`, not `invalid_signature`. Multiple signatures write the complete Signature-Key dictionary before any signature is created, and each signature covers `signature-key`. A client drops unrecognized `Accept-Signature-Scheme` and `Accept-Signature-Alg` tokens and reads the `error` member of `Signature-Error` and, for `invalid_input`, its `required_input` list (`parse_signature_error`). A verifier can require components beyond the profile (`prepare_with_components`); a signature without them is `invalid_input`. A JWKS cache the host fills expires by `Cache-Control`, refuses a refetch of the same issuer and `dwk`, or the same URL, inside sixty seconds, caps freshness at 86400 seconds, and holds a caller-chosen number of targets. Before a discovery fetch, the host admits an HTTPS URL, one globally routable unicast address after embedded IPv4 is decoded, refusing the local-use NAT64 prefix `64:ff9b:1::/48` as a whole, a finite size and timeout rechecked at admission, and a same-host redirect. A parsed `jwks_uri` origin is not an authorization. A pseudonym key's Ed25519 or ES256 thumbprint is admitted for one canonical HTTPS authority. A `jwt` with both `iss` and `dwk` is checked against host-supplied metadata and JWKS and is not fetched: `iss` is a bare origin, `issuer` must equal `iss`, and the header `kid` selects an Ed25519 or ES256 key whose `alg` equals the header `alg`. `cnf.jwk` is Ed25519 or ES256. Compact JWS and the `jwt`, `jkt-jwt`, `self-jwt`, `jwks`, `jwks_uri` and `cached` schemes take Ed25519 and ES256 keys, and every AAuth role refuses another with `unsupported_algorithm` and `Accept-Signature-Alg: Ed25519, ES256`. A signing key whose external signer fails leaves the request or response without a `Signature` (`SigningFailed`). Direct agent identity still accepts only `jwt` | `aauth-rust-signature-key/tests/proofs.rs` (50 tests), TLS journey |
| RFC 9421 / AAuth Signing | Buffered requests covering method, authority, path, Signature-Key; query and Authorization coverage when present; exact ±60-second `created` window; canonical field values (outer OWS trimmed, repeated lines combined) | Proof tests, independently stated signature-base fixture |
| Agent token / Common Verification | `aa-agent+jwt`, an `Ed25519` or `ES256` issuer key and `cnf.jwk` (`ES384`, `RS256` and `PS256` are `unsupported_algorithm`), named issuer key, expected `dwk`, required claims, exact identifiers including local length, case and `+` placement (a top-level local part has none; a sub-agent's has one, with non-empty parts on both sides), `exp` without leeway, `nbf`, public confirmation key, optional PS syntax | `aauth-rust-core/tests/agent_tokens.rs` (18 tests) |
| Person, Resource and Auth tokens | Role-specific typ/dwk, required and forbidden claims, Ed25519 or ES256 public confirmation keys, minting under the issuer key's own `alg`, Ed25519 or ES256, exact signed bytes, Person/Auth one-hour ceiling and expiry/nbf; `aud` read as a string or a one-element array and minted as a string; Core verification does not grant application access | `aauth-rust-core/tests/role_tokens.rs` (11 tests) |
| AP metadata and JWKS | Exact issuer binding; HTTPS JWKS location with terminal invalid_key for unusable metadata; reject foreign issuer with invalid_key separately from rotation; select only named kid, tolerate unselected unsupported keys; host-retained snapshot | Core tests; AP discovery over TLS |
| Direct Agent identity | Unsigned request challenge; token plus proof before policy; `hwk`, `cached`, `jwks`, `jkt-jwt`, `self-jwt`, and `x509` receive `unsupported_scheme` and no `Signature-Key-Cache` is emitted; wrong key refusal; exact endpoint or explicit origin binding before policy; denial after valid authentication; Date from verifier time on clock_skew. An `AAuth-Capabilities` header is ignored, including unknown tokens, and its absence assumes no capability. ES256 provider and agent keys, and keys held by an external signer, issue and verify like Ed25519 ones; a signer that fails issues no token and signs no request | `aauth-rust-resource/tests/identity.rs` (34 tests), `response_mapping.rs` (2 tests), TLS journey |
| Resource metadata | Explicit published issuer separate from signed authority/port, agent-token access and 60-second window; no fictitious JWKS/authorization endpoints; invalid publication settings return a local configuration error | Resource and axum metadata tests |
| Framework adapter | Origin-form URI reconstruction from configured HTTPS origin, typed policy context, custom success response, wrong-origin proof refusal and bounded actual-body handling; canonical metadata publication with a nondefault signed port | `aauth-rust-resource/tests/axum_service.rs` (5 tests), executable axum example |
| Local composition | Fresh random AP/Agent keys; certificate-verified loopback TLS; AP metadata/JWKS retrieval; the agent reads the Resource's metadata; Resource outcomes | `aauth-rust-resource/tests/loopback_tls.rs` (1 test, 15 checks) |
| Opt-in discovery and revocation delivery | Admitted HTTPS fetches and refusals; trusted-issuer key discovery with cache, floor and refetch; one refetch after a failed signature; trusted direct `jwks` URLs and `self-jwt` issuers; a Person Server cascade delivered to a Resource and through an Access Server, and a deferred answer polled | `aauth-rust-discovery/tests/discovery.rs` (2 tests), `tests/signers.rs` (2 tests), `tests/cascade.rs` (2 tests) |
| Person binding / PS token endpoints | Agent proof and covered JSON before policy; case-insensitive JSON media type without rewriting covered bytes; stable directed identities; issuer-scoped atomic records and binding; exact presented lineage; distinct invalid, expired, and revoked presented-token errors; scope narrowing; expiry and binding rechecked after policy/storage; no release before commit; repeatable valid exchanges with fresh retained Auth issuances. Metadata publishes exactly `issuer`, `jwks_uri`, `person_token_endpoint`, and `auth_token_endpoint`. `platform` must be one of the five pinned registry values. `device` is at most 64 characters and has no control characters. `capabilities` is a unique nonempty string array; unknown tokens do not change issuance. `justification` reaches host policy and is not a scope input. An ES256 agent receives ES256-signed Person and Auth tokens from an ES256 Person Server | `aauth-rust-person-server/tests/endpoints.rs` (5 tests), `authorization.rs` (34 non-deferred tests, plus the mixed-grants composition test), `store.rs` (7 tests for logical/persistence contracts, detection fixtures and shared serialization/validation) |
| Durable PS store adapter | Same logical contract as MemoryStore; actual close/reopen, issuer-qualified records, exact retry/conflict ordering, sticky revocation; schema/row errors; reconstructed direct/chained PS flows | `aauth-rust-person-server-redb/tests/backend.rs` (10 tests), `service_restart.rs` (2 tests), crate rustdoc |
| Page corruption / bounded records | Exact data-byte checksum failure and 28 page-prefix bit flips/zeroings never escape open as a panic or bad record; 1 MiB accepted, one-byte overflow and 64 MiB refused without table writes; empty binding refused on read/commit/revoke | `aauth-rust-person-server-redb/tests/corruption.rs` (2 tests), backend tests |
| Backend transaction recovery | Acknowledged commit survives process exit without Drop; staged uncommitted real transaction stays invisible; injected native FileBackend write error preserves prior state and exposes no partial indexes | `aauth-rust-person-server-redb/src/failure_tests.rs` (3 parent/unit tests; 1 ignored child entry invoked by parents) |
| Durable file creation / record shape | Parent directory synchronized after file/schema initialization; sync failure refuses open; bare filenames use current directory. Both stores reject malformed Agent identities, parent ties and Person/Auth lineage without leaking state; durable decoder refuses malformed rows | `aauth-rust-person-server-redb/src/open_tests.rs` (2 Unix tests), shared store contract/validation and backend row tests; Linux syscall witness |
| Resource PS authorization / Agent response verification | Person is identity, never authorization; signed Resource challenge; intended PS/audience/key/presented-token ties; Auth route scopes before typed policy; `authorize_for` checks the Person Server (`iss` on Person, `ps` on Auth) together with `sub`, `account` and `tenant`; a verified mismatch is `403` `access_denied` with no `Signature-Error`, and `login_hint` or an empty subject is not authorization. `sub` is a required string; Agent verifies challenge and delivery context; specific wrong-audience diagnostics with pinned invalid_jwt wire code; named captured policy types | `aauth-rust-resource/tests/ps_authorization.rs` |
| Requirement extraction | RFC 9651 dictionary and combined field lines; immediate Agent/Person/Auth requirements; exact decoded resource-token; ignore extensions; refuse malformed or unsupported requirements; omit credentials from Debug. `reason=budget-exhausted` and `reason=insufficient-budget` stay parameters. `requirement=budget-exhausted` is unsatisfiable | `aauth-rust-agent/tests/requirements.rs` (7 tests), used by the three-party TLS scene |
| Opt-in budgets | Budget object, narrowing, resource offer, PS and AS issuance, per-token reserve/commit/release, refusal without draw-down, consumption replacement, usage response. The host's `default_bound` is the maximum cost. `AAuth-Max-Cost` may only lower it, and a client figure of zero is not a free admission. A delivered budget on a retained continuation is checked against the parameter the person server sent. A mismatch is `502` `as_unreachable` and is not recorded. A budget offer is not retained when the access server answers `202` or `402`: the response is `500` `server_error`, no continuation is written, and the account book does not take the grant. Go `3f7fc54b8ea1e310148c922b1d09e64bd6e24739` refuses that continuation the same way after consent and the access-server call. The ledger key is `(iss, jti)`. A later grant that disagrees with the token already opened for that pair is `500` and carries no `AAuth-Budget`. A person server narrows a later grant so outstanding allocations for that subject at that resource stay within its cap. `IssuerPolicy::omit_above` omits the four-party parameter when the offer amount is above that limit. Three-party issuance still narrows and counts the grant. A usage response sends `Cache-Control: no-store`. A decimals mismatch against cached units is `400` `invalid_budget` and is not rescaled. An access-server parameter below the cap is issued at that amount. Subagent person and auth requests declare `budget` in `capabilities` and send `AAuth-Capabilities: budget`. A host-supplied `justification` is copied onto the auth request. A step-up offers the declared scale and carries `budget_consumed` only when that scale matches the locked grant. `authorize_reserved` reserves without committing. `authorize_observed` does not meter. `into_response` on either is `500` and does not commit. An insufficient refusal can omit `required`. `IssuerPolicy::until` ends the issued auth token at that Unix second. The cap counts outstanding allocations. Default servers still reject `budget`. No metadata fetch. A consent description is plain text from `description_text` (HTML-escaped, not rendered as Markdown), kept separate from the formatted amount. The draft's sanitize-before-rendering rule is met by that plain text. Not the whole budgets draft | `aauth-rust-budgets/tests/profile.rs` (16), access-server `budgets.rs` (5), person-server `budgets.rs` (7), resource `budgets.rs` (11) |
| Immediate AS federation | Admitted PS jwks_uri proof plus independent Agent/Resource/presented verification before AS policy; context/scope/parent bounds; a Person Server's `scope` (a nonempty subset of the Resource token's) and `exp` (after the request) narrow the grant and any wait, anything else in them is `400 invalid_request`; PS consent, exact forwarding, returned-grant verification/retention and AS Auth step-up; no direct-mode fallback under collocation | AS endpoint base cases (9, including omitted presented_token and the narrowing), PS authorization tests, Resource federation/role test and `four_party_tls.rs` (2 tests: immediate and deferred, including exact forwarded bytes and problem codes) |
| Federated retained namespace | AS issuer/JTI identifies the credential; explicit PS namespace owns binding/directed identity; exact presented ancestry, conflicts/revocation and reopen | Updated public storetest and persistence contract, MemoryStore and RedbStore |
| Call chaining / original person | Exact upstream ties in Person, Auth and Auth step-up; three-party and four-party chaining, with the Person Server passing `upstream_token` to its Access Server and retaining the chained receipt; missions carried down three- and four-party chains; original binding revocation and hop-by-hop chain revocation; intermediary self-issued identity; separate directed subjects; no intermediary binding; default-denied chain hooks, including `Policy::consent_upstream` | PS authorization tests; `aauth-rust-resource/tests/three_party_tls.rs` (2 application/TLS tests, including identical-POST replay) |
| Supervision | Supervision server role (metadata, JWKS, connect, mission, decision and event endpoints, signed terminal decisions, idempotence by `sdi`, event deduplication, standing `once`/`mission`/`always` reach) and the Person Server's consulting side (`with_supervision`): one decision point, so a routed agent's acts are never decided by host policy; `allow` narrowed to the answer's scope and `exp`, `deny` refused, ask, deferral, clarification or an unavailable SS held for the person; in-order event outbox, journal replay to a new SS, `unknown_sub` and `unknown_mission` recovery, and a stored decision record verifiable with public keys. A four-party `allow` that narrows is sent to the Access Server as `scope` and `exp`, which this library's Access Server applies, and is enforced on the token delivered, which is reported once released, also after the Access Server deferred. An R3 request is an `auth_token` act. `revocation.received` for agent and resource tokens, `interaction.requested` for relays and questions, and `terminated` for every mission end the PS finds, once. Response signatures with `;req` components in Signature-Key. A supervised agent's resource-initiated interaction is decided by the SS before the person is sent to the Resource and issued within the allow at the Resource's callback | PS `tests/supervision.rs` (18), SS `tests/server.rs` (7), Signature-Key `tests/responses.rs` (2), `supervised-agents` example |

Snapshot ownership and absence of network fetching are architecture properties
checked by source inspection of `aauth-rust-core/src/discovery.rs`; they are not
additional protocol test results. The example's listener/thread cleanup follows
its owned Drop implementation, also checked by inspection.

The 15 checks are AP metadata, AP JWKS, the Resource metadata the agent
reads before calling, unsigned challenge, accepted identity,
accepted pseudonymous `hwk` proof, `hwk` identity scheme rejection, tampered signature,
expired token, uncovered Signature-Key, future `created`, future `iat`, wrong
confirmation key, policy denial without signature diagnostics, and untrusted TLS
certificate refusal. The proof endpoint is example infrastructure; it does not
turn an `hwk` key into an AAuth identity.

## Immediate Access Server federation

The optional `aauth-rust-access-server` role executes immediate top-level and
one-level parent-mediated, missionless Core-scope grants. It verifies a PS `jwks_uri` HTTP proof, Agent,
Resource and actual presented Person/Auth credentials before resource policy;
checks lineage/key/target/role, scope narrowing and parent lifetimes; and publishes
AS metadata/JWKS. `aauth-rust-access-server/tests/endpoint.rs` pins refusals before
policy, typed policy outcomes, time resampling, listener/issuer separation and
invalid service identities reported as invalid_key before policy.
PS federation and the four-party TLS composition execute in the same checkout.
The PS verifies AS role/issuer, recipient/key/person, tenant/account, scope and
parent expiry before storing/releasing the exact credential. Well-formed terminal
AS problems, including 401, relay their status/error in the PS's own problem body;
AS Signature-Error/detail remain host-only FederationFailure response extensions.
Terminal clock_skew at 400 or 401 preserves AS Date. Endpoint/transport/malformed,
unverifiable grants and unsupported continuations remain as_unreachable. No shared four-party harness result or full
cross-implementation equivalence is claimed by these native tests.

**R3-FULL-COMPLIANCE:** unclaimed. The current Core endpoint profile does not
advertise or negotiate R3 authorization. Unsupported R3 claims fail closed in
that profile rather than conferring scope authority.

`PsAuthorizationResource::with_r3` supports opt-in immediate, unmetered class
R3 on the direct Person-Server path. The host selects definitions, maps requests
to operations and provides an immutable document store; exact document bytes
and entitlement are committed before token release. Buffered admission verifies
request proof, token identity and document-bound grants before application
effects. At `f763511`, 97 Resource CODE CHECKS passed, including 11 R3 controls,
plus workspace compile, lint and docs. [Sprint qualification evidence](https://gitlab.com/sidecat-dev/sprint-aauth-20261024/sprint/-/tree/main/cycles/wc-05/r3-resource-role/)
records the actual Go Agent/PS → Rust Resource workflow with matching issuer
and signed origin: authorization, signed document fetch, narrowed grant,
Resource process restart, signed POST, exact-body receipt and refusals. A
separate actual signed HTTP control used explicit endpoints at a different
host/nondefault port, fetched the advertised URI verbatim and reused its grant.
Qualification used host HTTP/disk adapters and volatile Go PS custody;
production host/store integration remains application work. The direct per-call
subset is described below. Budgets, missions, AS federation and deferred Auth
delivery remain unsupported R3 compositions. `/authorize` refuses account-bearing bodies;
host-account challenge composition remains unqualified. Full R3 conformance
is unclaimed.

The Rust Agent and Person Server now support the same opt-in immediate,
unmetered direct class flow. The Agent signs `r3_operations` and verifies the
returned Resource/PS identity, holder, lineage, reference, scope and lifetime.
The PS fetches the literal document URI with its own signed role proof, verifies
exact bytes and account, applies explicit host consent, and commits the audit
and issuance records before release. R3 revocation is rechecked after callbacks
and after child registration; the non-R3 Core callback/revocation gap remains a
separate follow-up.

At `d79be7db`, 267 CODE CHECKS passed, including blocked-consent/audit withdrawal,
revocation precedence, cascade, omitted Core scope, strict Resource scope and
Observed grant controls; build, workspace compile, lint and docs also passed.
[Sprint qualification evidence](https://gitlab.com/sidecat-dev/sprint-aauth-20261024/sprint/-/tree/main/cycles/wc-05/r3-agent-ps/)
records actual TLS Rust Agent → Rust PS → Rust Resource with distinct issuer
and signed origin, Go Agent → Rust PS/Resource with matching origin, and
Go Agent/PS → Rust Resource. They exercise literal signed fetch, a narrowed
grant, exact-body application receipts and refusals. This does not claim Rust
Agent → Go PS equivalence. Host transport, egress, consent, definition/request
mapping and durable storage remain application responsibilities; cascades need
a complete retained-token scan. The example PS stores/audit are volatile.
R3 compositions with budgets, missions, sub-agents, chaining and AS authorization
remain refused or unfinished; full R3 conformance remains unclaimed.

Direct, unmetered Person-Server per-call proposals now have executed `401` retry
and `202` held-invocation paths. With `with_r3_per_call`, a class token operation
listed in `r3_per_call` is challenged for one concrete call. The exact proposal
and lineage are committed to the host `R3CallStore` before challenge release;
the signed document endpoint serves it to the entitled PS. Explicit
`R3Policy::authorize_proposal` consent (default deny) issues one operation bounded
by the class token lifetime. Completion verifies stored bytes, lineage, holder
and parameters before claim. The signed pending poll is authenticated as sent;
host policy receives the verified held operation and body with the current
per-call token. A denied policy leaves that proposal unconsumed. R3 revocation
is checked after policy and on both sides of the host claim callback. Revocation
after binding suppresses release without rolling back the claim or redispatching.

At runtime source `9cc0c391f2301f7e04b62b9c28697e6ca00ed62e`, 114 focused CODE
CHECKS passed (Resource 25, Agent 8, PS 81), with no failures or ignored cases.
The two new [TLS admission controls](crates/aauth-rust-resource/tests/r3_per_call_admission.rs)
first failed against unchanged `746b79da` production using control source
`9eaa13b4`: both a denied held DELETE and revocation completed during blocked
policy incorrectly returned `200`, performed an effect and consumed the claim.
The repair returned `403` and `401 revoked_jwt`, respectively, with zero effects
and no consumed claim. The same denied proposal then completed once when its
original operation was allowed, and exact-token replay did not repeat the effect.

The normal release `r3-per-call` and `r3-three-party` executables from `9cc0c391`
both passed actual TLS journeys on 2026-10-27. Their respective SHA-256 identities
were `b9d01764bdf23ec968db2ead7851984a584c2e32bf2e0396ee2f5214cb937883`
and `464db16cccb75ec82ce901706217f8d3a944d135989a8e8eed727f2d8ab7af39`.
Per-call execution observed one read, two intended deletes across retry and held
paths, three audit records, retained-result replay, and parameter, holder and
foreign-token refusals. The existing class journey retained exact-body receipts
and its previous refusals. Separately, tests-only source `c5c09b88` passed all
three admission controls, including the two repeated controls. Its added signed
revocation during a blocked claim callback returned `401`; the bound claim stayed
byte-for-byte unchanged, had no result, and retry returned `401` with zero effects.
Production sources were unchanged from `9cc0c391`; those release binaries were
not rebuilt or relabeled as `c5c09b88`.

This is a bounded direct-R3 qualification, not a full suite or full conformance
claim. Resource recomposition from files occurred within one process; no actual
OS restart or generic durable `R3CallStore` adapter/crash contract was qualified.
PS store/audit custody in the example is volatile. Mixed-language per-call flows,
recorded-approval reuse after `expired_presented_token`, and composition with
budgets, missions, AS, sub-agents or chaining remain unqualified or unsupported. The digest-parameter
source path has no separate actual journey in this batch.

The result-release increment was executed at source `71b09d5a`: six actual
HTTP admission scenarios and five Core revocation controls passed, followed by
strict Clippy across Resource, Person Server and R3 targets. These are focused
results, not full conformance. The existing `r3-per-call` executable also ran at
`e8354bb7`, observing one read, two deletes and three audit records; the later
formatting and Core-control changes are separately identified.

For side-effect-free queries, set `R3PerCallConfig::hold` and supply its optional
`release` callback. Return `R3Release` only when running the query changes nothing
outside its result; audited, billed, metered or third-party operations require
execution consent instead. The callback supplies the held response, structural
`result` and consent `display`. The PS routes this proposal exclusively through
`R3Policy::authorize_release`, which refuses by default. Execution approval does
not imply disclosure approval. See the `records.query` implementation in
[the per-call example](crates/aauth-rust-resource/examples/r3_per_call/mod.rs).

The HTTP scenarios observed one computation before approval, disclosure denial,
wrong-proposal and substituted-call refusals, and identical approved replay
without recomputation. Signed revocation during policy refuses before claim;
revocation during claim preserves the consumed claim while withholding the
result. The plain-Core control likewise refuses a token revoked during host
policy, refuses its replay before another policy call, and admits a fresh token.
The release profile is202-only and unmetered. The host must enforce the callback's
side-effect-free contract.

The Resource accepts R3 and budgets together, in either order. `/authorize`
with `r3_operations` and a `budget` object issues one class Resource token
carrying that narrowed offer. `r3_and_budgets_issue_a_combined_resource_token`
pins the token and admits one protected call under an Auth token that carries
the same grant. A `budget` object without budgets enabled is `invalid_budget`.
The Person Server accepts `with_budgets` and `with_r3` in either order.
`budgets_before_r3_still_exchange_and_admit` enables budgets first, then
exchanges and admits the combined grant.
`later_class_grant_is_narrowed_to_the_remaining_cap` signs 500 under a cap
of 800, then signs the next offer for that subject and resource as 300.
`class_grant_signs_zero_when_the_cap_is_spent` signs 500 under a cap of 500.
The next offer signs as 0. The Resource answers `budget-exhausted` and does
not run the tool. `class_cap_is_free_again_after_the_grant_expires` signs
500 for 50 seconds. At that expiry the same offer signs as 500 again. The
reservation is the Person Server account book, not an operating-system
restart. `failed_r3_audit_does_not_reserve_the_budget_cap` withholds the
Auth token when the R3 audit commit fails. The account book stays empty,
and the next offer still signs 500 under a cap of 800. Host3
`aauth-wc07-completion-audit01` passed that refusal at `a9cd876`.
`reserved_class_call_settles_below_the_hold` reserves the admitted maximum
on a class call, then commits 200 of that hold. The field shows `cost=200`
and `remaining=300`. A later call for 200 is admitted. A call for the full
bound is `insufficient-budget` and does not run the tool. Host3
`aauth-wc07-completion-settle01` passed that settlement at `a9351fa`.
`concurrent_class_calls_spend_the_grant_once` admits one of two simultaneous
class calls against one grant. The other is `budget-exhausted` and does not
run the tool. Host3 `aauth-wc07-completion-race01` passed that race at
`9ae8de8`. `dropping_a_class_hold_releases_the_grant` drops that hold
without a commit. The same grant is then admitted in full: `cost=500` and
`remaining=0`. Host3 `aauth-wc07-completion-drop01` passed that release at
`f150618`. `denied_class_consent_writes_no_audit_and_reserves_nothing`
answers `403 access_denied`. No audit row is written and the account book
stays empty. The next offer still signs 500 under a cap of 800. Host3
`aauth-wc07-completion-deny01` passed that refusal at `3b6883b`.
`class_grant_outside_the_document_writes_no_audit_and_reserves_nothing`
answers `500 server_error` when consent names operations the fetched
document does not contain. No audit row is written and the account book
stays empty. The next offer still signs 500 under a cap of 800. Host3
`aauth-wc07-completion-outside01` passed that refusal at `6fa4997`.
`core_budget_with_r3_enabled_skips_the_class_path_and_a_failed_commit_reserves_nothing`
issues a core budget token while class R3 is enabled. That exchange does not
call class consent. A failed issuance commit withholds the token and leaves
the account book empty. The retry signs 500 and carries no R3 reference.
The next class offer signs 300 under a cap of 800. Host3
`aauth-wc07-completion-core01` passed that composition at `183d921`.
`denied_class_call_releases_the_budget_hold` refuses the protected class
call and does not run the tool. The hold is released. The same grant is
then admitted in full: `cost=500` and `remaining=0`. Host3
`aauth-wc07-completion-calldeny01` passed that release at `6f64216`.
`revocation_during_a_class_call_does_not_draw_down_the_grant` revokes the
Auth token while the protected call is in host policy. The decision is
revoked. The hold is released, so the full grant can still be reserved. Host3
`aauth-wc07-completion-revokeduring01` passed that fence at `73f0ea2`.
`failed_document_commit_withholds_the_budgeted_class_token` answers `500
server_error` when the class document store fails. No resource token is
released, the store stays empty, and the account book stays empty. The next
offer still signs 500. Host3 `aauth-wc07-completion-docfail01` passed that
withholding at `f27ce72`.
`class_audit_survives_when_issuance_commit_fails` writes the class audit
and then the issuance store fails. The Auth token is withheld and the
account book stays empty. The next offer still signs 500, and a second
audit row is written. Host3 `aauth-wc07-completion-issuance01` passed that
split at `7d03878`.
`revocation_after_issuance_withholds_the_class_token_without_reserving`
revokes the resource token after the class audit is written. The exchange
is `400 revoked_resource_token`. The account book stays empty, and the next
offer still signs 500. Host3 `aauth-wc07-completion-after01` passed that
withholding at `c84884a`.
`class_grant_that_expires_before_release_reserves_nothing` moves the clock
past the resource token after the class audit is written. The exchange is
`400 expired_resource_token`. The account book stays empty, and the next
offer still signs 500. Host3 `aauth-wc07-completion-expire01` passed that
expiry at `710ec56`.
`well_formed_budget_consumption_is_not_resolved_and_reserves_nothing` refuses
a class token whose consumption record names the presented token. The
exchange is `400 invalid_resource_token`. A record whose `jti` does not
match is `400 invalid_budget`. No audit row is written and the account book
stays empty. The next offer still signs 500. Retained-grant resolution is
still unspecified. Host3 `aauth-wc07-completion-consumed01` passed that
refusal at `e49947d`.
`failed_proposal_commit_withholds_the_challenge` answers `500` when the
proposal store fails. No challenge token is released and the call does not
run. The next challenge is released and the store keeps that record. Host3
`aauth-wc07-completion-proposal01` passed that withholding at `ab5545b`.
`a_per_call_executes_once_and_the_replay_returns_the_retained_result`
approves one proposal, retains the response `ran`, and the second
presentation returns that response. The store is process memory. Host3
`aauth-wc07-completion-replay01` passed that replay at `7ae1c32`. A different Auth token for that same proposal is
forbidden and does not receive the retained response. The original token
still replays it. Host3 `aauth-wc07-completion-other01` passed that
distinction at `6007318`. A completion that does not retain its result
answers `500` on the next presentation. Host3 `aauth-wc07-completion-unfinished01`
passed that unfinished call at `22eeed4`.
`a_held_per_call_is_accepted_and_completes_only_at_its_pending_url`
answers `202` and stores the held call. The same approval on the mapped
route is forbidden. Completion at the pending URL retains the response,
and the next presentation there returns it. Host3
`aauth-wc07-completion-hold01` passed that hold at `cbbd53d`.
`release_gating_runs_once_before_approval_and_replays_the_held_response`
runs the call while issuing the `202`. Approval releases the stored
response and does not run the call again. The next presentation returns
that response. Host3 `aauth-wc07-completion-release01` passed that
release at `367f2f6`.
`re_requested_held_release_reuses_the_bytes_and_retires_the_prior` approves
one release-gated call and does not complete it. After that proposal token
has expired, and while `release_until` is still ahead, the same class token
computes again and does not retire the first record. A new class token,
with a different `jti`, reuses the first held bytes and retires that record.
The original per-call token is forbidden at its pending URL. The successor
returns the first bytes. The same-token challenge still returns its own
bytes. The store is process memory. Host3
`aauth-wc07-completion-rerequest01` passed that re-request at `b4303d0`.
Receipt START `2026-10-29T20:35:11.200055+00:00`, log mtime
`2026-10-29T20:35:12.567456178Z`, exit 0: 1 passed, 0 failed, 35 filtered.
`class_budget_grant_stops_at_period_end` is host policy: the decision asks
for 600 seconds and the Auth token stops at `period_end`. Host3
`aauth-wc07-completion-federated01` passed
`federated_class_and_proposal_keep_original_tokens_and_reject_changed_authority`
at `4949605`. A class document with federation enabled is fetched and
consented, then the exact tokens are relayed. The returned Auth token names
that document. A changed subject, reference, or issuer is `502
as_unreachable` and no Auth token is released. A proposal is presented with
the person token, consented with proposal consent, and relayed the same way.
Core consent is not used. The returned Auth token matches those proposal
bytes. Declined proposal consent is `403` and does not call the access
server. A token for a different proposal is refused. Host3
`aauth-wc07-completion-federated02` passed the same qualification at
`e60dbd5`, including deferred custody. An access-server `202` for the class
document and `402` for the proposal are `500 server_error`. Consent and the
access-server call still happen. The continuation store is not written, and
the response has no Auth token. A changed tenant, account, or confirmation
key, a granted operation other than the proposal, a per-call member on that
token, and an Auth token with no R3 claims are `502 as_unreachable`. A
fetched document whose bytes do not match the reference is `400
invalid_resource_token` after the fetch and before consent. A document fetch
that answers `401`, or a fetch transport failure, is `500 server_error` and
does not consent. Host3 `aauth-wc07-completion-federated03` passed that
qualification at `b2d9f1f`. A
deferred continuation that carries a budget offer is not stored. When the
access server answers `202` or `402` and the resource token carries a budget
offer, the person server returns `500` `server_error`. Consent and the
access-server call still happen. The continuation store is not written, the
account book does not take the grant, and the response has no Auth token.
Go `3f7fc54b8ea1e310148c922b1d09e64bd6e24739` refuses that continuation the
same way. A continuation that was already stored still checks a later
delivery against the amount sent. A mismatch is `502` `as_unreachable` and
is not recorded. A missionless Core grant with no budget offer still defers.
A class Resource token may carry a budget offer: the PS verifies
it with the combined R3 budget verifier, narrows the offer, and signs that
grant on the Auth token. A well-formed `budget_consumed` on that
Resource token is `invalid_resource_token`: Go does not resolve it against
a retained grant. A malformed record is `invalid_budget`.
`per_call_with_a_budget_offer_is_refused` leaves one operation per call while
the class token carries a budget offer. The exchange is `invalid_resource_token`
and no Auth token is issued.
`proposal_with_a_budget_offer_is_refused_before_approval` fetches that proposal.
Without a budget the Person Server records one approval. The same artifact
with a budget offer is `invalid_resource_token` and does not record another.
`r3_only_class_token_is_unchanged_when_budgets_are_enabled` issues a class
token with no budget. The Auth token has no budget claim, and the Resource
admits the call. `combined_budget_auth_expires_and_a_later_grant_revokes`
presents that Auth token at its `exp` and receives `expired_jwt` with no
second effect. A later Auth token for the same class is admitted, and a
Person Server revocation of its `jti` is `revoked_jwt` before another effect.
The revocation ledger is process memory. That run is not an operating-system
restart.

The example file store writes each proposal record, then synchronizes the
directory on Unix. Class documents in that store synchronize the directory
the same way. `reopen_reads_the_same_held_release_from_the_directory` drops
the proposal store and opens another on the same directory; the held bytes
are still there. `reopen_reads_the_same_class_document_from_the_directory`
does that for the class document. Those two drops are the same process.
`reopen_after_process_exit_reads_held_release_and_class_document` starts a
second process. That process writes the held release and the class document,
synchronizes the directory, and exits. The parent opens the same directory
and reads both records. The child pid is not the parent pid. This is a
process exit. It is not power loss, not a crash during the write, and not a
generic `R3CallStore` adapter. The budget ledger remains process memory and
is not in that directory. Mission context and an access server added to
class R3 stay refused: `per_call_and_unsupported_compositions_are_refused_explicitly`
rejects both at configuration, and mission context added afterwards is `500`
with no resource token. Host3 `aauth-wc07-completion-recovery01` ran both
in one unit at `86b466e`. Receipt START `2026-10-29T21:19:21.976993+00:00`,
log mtime `2026-10-29T21:19:29.356935+00:00`. The reopen filter passed 3,
ignored the worker entry, and failed 0. The composition refusal passed 1
and failed 0. `systemctl show` reported `Result=success`.

A later library change allows class and per-call R3 on a federated Resource.
`new_federated(...).with_r3(...)` keeps the access server. The Resource token
`aud` is that server. The retained class document names `aauth-access.json`.
The Person Server still fetches with `aauth-person.json`. An access-server
Auth token (`aauth-access.json`) admits a class operation and one per-call
completion; the same token then replays. A Person-Server Auth token on that
Resource is refused. Direct R3 still records `aauth-person.json`. A mission
composition is still `InvalidR3Profile`, and a mission added afterwards is
still `500`. The test is
`federated_access_server_serves_and_admits_class_and_per_call_r3`. Host3
`aauth-wc07-completion-fedr301` ran that test at
`d127366037486a700ec9ab0b8802425f0f48b2d7` (tree
`8ee20ca97f842201ae87e269a6fc0fb9d4e9b1c4`). It passed 1 and failed 0, with
12 filtered. `per_call_and_unsupported_compositions_are_refused_explicitly`
passed 1 and failed 0, with 12 filtered. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Receipt START
`2026-10-30T01:20:19.111840811+00:00`, log mtime
`2026-10-30T01:20:34.563439467Z`. systemd-run invocation
`409cf4842f204830a5c592308ee126ad`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. This
commit records that receipt and does not change behavior. It does not change
the DirectR3 interop pin or retained-grant `budget_consumed`. The Agent
still requires `aauth-person.json` on a delivered Auth token. This is not
the Go four-party HTTP exchange, not a separate product-QA pass, and not
power loss.

A later Agent change accepts the grant Go's access server issues. The signed
`dwk` selects the issuer role. `aauth-person.json` still requires `iss == ps`.
`aauth-access.json` is an Access Server. In both cases `iss` is the Resource
token's `aud`, and that audience is no longer required to be the Person
Server. A per-call grant uses the class token's `dwk`, including when the
Person Server and Access Server identifiers are the same. The tests are
`access_server_class_grant_uses_the_signed_access_document`,
`direct_person_server_grant_still_verifies`,
`access_server_per_call_grant_uses_the_class_document`, and
`shared_identifier_keeps_the_class_tokens_access_document`. Host3
`aauth-wc07-completion-agentdlv01` ran that file at
`b571a068d7d92d40adac1447116874f50ff886bb` (tree
`03844aeb3dcf97b548639a46c1e8c70867145c90`). Four tests passed and none
failed. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Receipt START
`2026-10-30T01:55:01.369101645+00:00`, log mtime
`2026-10-30T01:55:25.050481331Z`. systemd-run invocation
`350646b4ff4f4df9aa9cc260c41c147e`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. This
commit records that receipt and does not change behavior. It does not change
the DirectR3 interop pin or retained-grant `budget_consumed`. This is not
the Go federated HTTP exchange, not a separate product-QA pass, and not
power loss.

One separate Go HTTP exchange now verifies an access-server class grant and
one proposal beside the DirectR3 pin. Behavior
`34b7b9640b0f58925a9161974f25f605eec29ffa` (tree
`c8ca1a3d2e82a5ebcddc082f5d228d20458d2aef`) adds Go
`resource.NewFederatedAuthorization`, an `accessserver` `R3Config`, and
`personserver.NewFederatedAuthorization` on hosts that do not replace the
DirectR3 servers. The class document grants only `records.delete`. The
proposal is the 401 from `POST /records/r-1`. The Rust Agent verifies both
grants: `dwk` is `aauth-access.json` and `iss` is that Access Server. Person
status is 200, class exchange is 200, and the class grant verifies. The
proposal challenge is 401, the proposal exchange is 200, and the per-call
grant verifies. The Person Server records one class consent and one proposal
consent. The Access Server records one class authorization, one proposal
authorization, and two issuances. Retry Claim and Retain stay unresolved, so
this exchange does not finish the protected call. Commit
`7f1e2dc3b9fc14833213da8d3680d9751550e0b8` (tree
`cf212af050dc33e6bd0504d088d6b37e60067bdd`) imports `strings`. Host3 at the
parent stopped in `go run` before any exchange. Host3
`aauth-wc07-completion-fedhttp02` ran at that import fix.
`r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The example's transcript
check required the counts above. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Reads stayed 2 and both
deletes stayed `"r-1"`. Receipt START
`2026-10-30T02:35:13.010942722+00:00`, log mtime
`2026-10-30T02:35:25.147777167Z`. systemd-run invocation
`fcadd014ff4c4f9482d1a529cf4e3e91`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDHTTP_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. This is not a completed protected per-call,
not a separate product-QA pass, and not power loss.

The same federated proposal now completes once and replays that auth token.
Behavior `7defa9a573e59321fcb352d2bc19c288426d050e` (tree
`cc190d0624c918fc8a551ff81d2140e1d4b54546`) claims the prepared retry, runs
the protected handler, and retains that response. Host3
`aauth-wc07-completion-fedcall01` at that source returned 400
`invalid_request`. The example transport sent `Connection: close`, which Go
will not retain. Invocation `30981be59d8941f9bee16e2e4ac4743c`. That unit is
not a pass. Commit `cf3c81abc4c958aaf5d9db91c3dcad4302c31df4` (tree
`158e8a4bc7af7b7ff45c3ace34db76d696cb30bb`) sends the completion and the
replay without connection close. The 401 challenge still uses the existing
transport. Host3 `aauth-wc07-completion-fedcall02` ran at that source.
`r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. Completion status is
200, replay status is 200, the replay body matches, and the protected
handler ran once. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Reads stayed 2 and both
deletes stayed `"r-1"`. Receipt START
`2026-10-30T03:08:43.820844829+00:00`, log mtime
`2026-10-30T03:08:55.614566569Z`. systemd-run invocation
`34849f1178534f94b152c02eba2b9b2f`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDCALL_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. This is not a separate product-QA pass and
not power loss.

POST /records/held-1 on that federated resource now returns 202 and one poll
runs the protected handler. Behavior
`841376a93ce79347f400fefd4b5d07f0b1a6efdc` (tree
`dde0616b607ca2c284d4a4db9ae7801b20049bd4`) keeps `POST /records/r-1` as the
401 completion. The held path is the only request selected for
`HeldInvocations`. Budget stays unset. The initial POST omits connection
close because Go snapshots that challenge. The poll is a signed GET of the
pending URL and also omits connection close. Host3
`aauth-wc07-completion-fedheld01` ran at that source. `r3-per-call-interop`
against Go `3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The held
challenge is 202, the poll is 200, the replay is 200, the replay body
matches, and the held protected handler ran once. The r-1 completion stayed
200, its replay stayed 200, and its protected handler still ran once. The
transcript check required two proposal consents, two proposal authorizations,
and three issuances. Class consent and class authorization stayed one.
`query-runs=2` and `proposal-err=invalid_resource_token` stay visible. Reads
stayed 2 and both deletes stayed `"r-1"`. Receipt START
`2026-10-30T03:34:08.931098592+00:00`, log mtime
`2026-10-30T03:34:22.314289833Z`. systemd-run invocation
`1f614cc373594a9db776759da60e8b98`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDHELD_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. This is not a separate product-QA pass and
not power loss.

The agent now refuses an immediate poll of that held 202. Behavior
`fd30916fe64ae28206725c004a72adc32054e03e` (tree
`08d01b56f5e2d06a3959689fc4a7b7d11482a305`) parses the pending response and
keeps the GET until `Retry-After` of 5 seconds has elapsed. The same auth
token then runs the protected handler once. A second GET of that pending URL
replays the retained body. The finished poll session does not send another
poll. `POST /records/r-1` stays the 401 completion. Budget stays unset.
Host3 `aauth-wc07-completion-fedwait01` ran at that source.
`r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The held challenge is
202, the immediate poll is refused, the wait is 5, the poll is 200, the
replay is 200, and the replay body matches. The held protected handler ran
once. The r-1 completion stayed 200 with one protected run. `query-runs=2`
and `proposal-err=invalid_resource_token` stay visible. Reads stayed 2 and
both deletes stayed `"r-1"`. Receipt START
`2026-10-30T03:46:39.964492728+00:00`, log mtime
`2026-10-30T03:46:52.760416762Z`. systemd-run invocation
`7c94b0fed3d04cbbb4579b0ee51b4182`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDWAIT_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. This is not a separate product-QA pass and
not power loss.

A POST of that held pending URL now returns 405, and a different pending id
returns 410. Commit `07a29c19ac98850ce7f300c8a1505f8a649358af` (tree
`1cd9f643b711086f1def7611ab346b976be6cb4b`) added those checks. Host3
`aauth-wc07-completion-fedreject01` at that source did not compile: rustc
E0502, because the pending-id borrow outlived `PollSession::accept`.
Invocation `285c0b872c0c496792a5d6fa2fd8f0d0`. START
`2026-10-30T03:57:42.902167282+00:00`. The log recorded `CARGO_RC 101` and no
`FEDREJECT_DONE`. That unit is not a pass. Commit
`4b9a4c7625052d7f99e68da481b27538b65ab9eb` (tree
`0a614be684c0cd83bb8d30447f70b89009c976b4`) owns the pending id before accept.
The POST is `405` `method_not_allowed` with `Allow: GET`. The GET of
`not-this-held-call` is `410` `gone`. The same auth token then replays the
retained body. The protected handler still ran once. `POST /records/r-1`
stays the 401 completion. Budget stays unset. Host3
`aauth-wc07-completion-fedreject02` ran at that source.
`r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The held challenge is
202, the immediate poll is refused, the wait is 5, the poll is 200, the
replay is 200, and the replay body matches. The method is 405
`method_not_allowed`, and the unknown pending id is 410 `gone`. The held
protected handler ran once. The r-1 completion stayed 200 with one protected
run. `query-runs=2` and `proposal-err=invalid_resource_token` stay visible.
Reads stayed 2 and both deletes stayed `"r-1"`. The example required
`Allow: GET`. The printed line does not show that header. Receipt START
`2026-10-30T03:58:55.826651876+00:00`, log mtime
`2026-10-30T03:59:08.711850436Z`. systemd-run invocation
`5a19bca5696247f6b352b1c6304f159f`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDREJECT02_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. It does not record a different-token replay.
This is not a separate product-QA pass and not power loss.

A second compact form of that held auth token now returns 403. Commit
`1e4c188ff1b017dd36cb93b1ede6cc15ed4adac3` (tree
`c7924ac3382357890bc787c537a97763c4289ffd`) re-signs the same auth-token
payload with example key `fed-as-2` and sends a GET of the completed pending
URL. The status is `403` `access_denied`. The original token then replays the
retained body. The protected handler still ran once. `POST /records/r-1`
stays the 401 completion. Budget stays unset. Host3
`aauth-wc07-completion-fedmismatch01` ran at that source.
`r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The held challenge is
202, the immediate poll is refused, the wait is 5, the poll is 200, the
replay is 200, and the replay body matches. The method is 405
`method_not_allowed`, and the unknown pending id is 410 `gone`. The different
compact token is 403 `access_denied`. The held protected handler ran once.
The r-1 completion stayed 200 with one protected run. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Reads stayed 2 and both
deletes stayed `"r-1"`. The example required the original token to replay
after the 403. The printed line does not show that follow-up. Receipt START
`2026-10-30T04:13:22.942879710+00:00`, log mtime
`2026-10-30T04:13:35.922429178Z`. systemd-run invocation
`03d2325e0a0d422ab54a71b57bc107a0`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDMISMATCH01_DONE`. This commit records that
receipt and does not change behavior. It does not change the DirectR3 interop
pin or retained-grant `budget_consumed`. This is not a separate product-QA
pass and not power loss.

A five-second auth token for `expire-1` now returns 401 at its exp. Commit
`fa5f08c446df7d38aab48d6b8a556a7739bafbc6` (tree
`ef086893c751f6632b1603e18ae6160b2205fd6b`) issued that `records.delete`
proposal for five seconds and presented it with a signature created at exp.
Host3 `aauth-wc07-completion-fedexpire01` at that source returned 200
`{"deleted":true}`. Invocation `0b6a13da67b143398af8fe3778695024`. START
`2026-10-30T04:39:26.497417235+00:00`, log mtime
`2026-10-30T04:39:39.685698081Z`. The log recorded `CARGO_RC 1` and no
`FEDEXPIRE01_DONE`. Go sets signature `VerifiedAt` from the server clock, so
the signature created time did not expire the token. That unit is not a pass.
Commit `278f59faff5580467ef774a8f17178d44832b3e1` (tree
`e60632bd0c4923194adbbd9b21d38c53ac88a9ee`) moves the federated server clock
to that exp after issuance and signs the completion at the same instant. The
status is `401` `invalid_token`. The problem type is
`urn:ietf:params:sig-error:expired_jwt`. The `Signature-Error` header is
`error=expired_jwt`. The JSON `error` field stays `invalid_token`. The
protected handler did not run. `POST /records/r-1` stays the 401 completion.
Only `POST /records/held-1` is held. Budget stays unset. The DirectR3 clock
stays at InitialNow. Host3 `aauth-wc07-completion-fedexpire02` ran at that
source. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. The held challenge is
202, the immediate poll is refused, the wait is 5, the poll is 200, the
replay is 200, and the replay body matches. The method is 405
`method_not_allowed`, and the unknown pending id is 410 `gone`. The different
compact token is 403 `access_denied`. The expired call is 401
`invalid_token` with signature error `error=expired_jwt`, and its protected
handler ran zero times. The held protected handler ran once. The r-1
completion stayed 200 with one protected run. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. Reads stayed 2 and both
deletes stayed `"r-1"`. The transcript check required three proposal
consents, three proposal authorizations, and four issuances. Class consent
and class authorization stayed one. Receipt START
`2026-10-30T04:45:07.658500613+00:00`, log mtime
`2026-10-30T04:45:21.019017701Z`. systemd-run invocation
`42fbfb6d97744efea1d666b2c0f2c9f2`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `FEDEXPIRE02_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin or
retained-grant `budget_consumed`. This is not a separate product-QA pass and
not power loss. The clock advance is not a wall-clock sleep.

A Person token on a budgeted mapped R3 route now returns 401. Behavior commit
`f12b2168e3880f37b77e5ff39c6efd32e92e4423` (tree
`13260e4337599f9a4d1b49488bdddd7f061771c7`) drops the Core `budget` extra
before the reactive class mint. A proactive `/authorize` body that carries a
budget object still mints a budget resource token. A non-GET of
`/r3/pending/{id}` returns 405 `method_not_allowed` with `Allow: GET`. A
pending id that is not stored returns 410 `gone`. A different per-call token
on a stored invocation stays 403 `access_denied`, and the original token
still replays. `verify_r3_resource_token` and class delivery require a
Person-Server parent, so an access-server auth token is not that parent. A
per-call token must be issued by the class token's issuer.
`verify_r3_proposal_challenge` still requires the proposal audience to be
that issuer. Host3 `aauth-wc07-completion-qadefect01` at that source passed
`qa_d1_budgeted_mapped_person_challenge_is_unauthorized` and
`qa_d2_held_pending_post_is_method_not_allowed_and_unknown_id_is_gone` 2/0
with 13 filtered, then
`person_challenge_on_a_mapped_route_issues_a_retained_class_document` 1/0
with 14 filtered, `r3_and_budgets_issue_a_combined_resource_token` 1/0 with
14 filtered, and
`federated_access_server_serves_and_admits_class_and_per_call_r3` 1/0 with
14 filtered. `r3_delivery` passed 5/0, including
`qa_d3_person_parent_and_class_issuer`. This unit did not run
`r3-per-call-interop`. `query-runs=2` and `proposal-err=invalid_resource_token`
stay as previously recorded. Retained-grant `budget_consumed` stays
unresolved. Receipt START `2026-10-30T05:15:10.637795155+00:00`, log mtime
`2026-10-30T05:15:19.879434881Z`. systemd-run invocation
`b077d368c17641068111c6e6f7103477`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `QADEFECT01_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin.
This is not a separate product-QA pass and not power loss.

A second poll of a held invocation stays 202 while its grant is unretained.
Behavior commit `635b8d80b0e14bb3c2c36df4b97a63a918924a9c` (tree
`7057a7a8889a54a444da958950575b151a90371b`) keeps that proposal URI while the
host still holds the cloned execution grant. The poll is 202. `Location` is
`https://resource.example:8443/r3/pending/challenge-live`. `Retry-After` is
`1`. `Cache-Control` is `no-store`. The body is `{"status":"pending"}`. The
response has no `AAuth-Requirement`. Retaining the result then replays
`held-once`. Dropping that grant without a retained result returns 500
`server_error`. The first retained result still replays. A second
presentation of an unretained `/op/refuse` completion stays `InternalError`.
`HeldInvocations::poll` of the same `jti`, while the handler is still inside
`execute`, returns `Unfinished` and runs that handler once. A later poll
replays the finished body. Host3 `aauth-wc07-completion-heldlive01` at that
source passed `held_poll_while_the_grant_is_unretained_stays_pending` 1/0
with 15 filtered,
`qa_d2_held_pending_post_is_method_not_allowed_and_unknown_id_is_gone` 1/0
with 15 filtered, `a_poll_during_execution_does_not_run_again` 1/0 with 1
filtered, `repeated_auth_token_replays_the_held_result` 1/0 with 1 filtered,
and
`a_per_call_executes_once_and_the_replay_returns_the_retained_result` 1/0
with 41 filtered. This unit did not run `r3-per-call-interop`. It did not
rerun directory reopen or interrupted retain. `query-runs=2` and
`proposal-err=invalid_resource_token` stay as previously recorded.
Retained-grant `budget_consumed` stays unresolved. Receipt START
`2026-10-30T05:39:16.650882627+00:00`, log mtime
`2026-10-30T05:39:31.493956Z`. systemd-run invocation
`e8b0f53b660a4c3db27a74abf57ccb7c`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `HELDLIVE01_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin.
This is not a separate product-QA pass and not power loss.

A second presentation of a `401` completion stays `503` while its grant is
unretained. Behavior commit `24b48dd397a3c69dcd3ab1ae2326e4c900e231ba` (tree
`5b0e927878eb66d1a17585d3b4fc83b0d5bb16be`) keeps that proposal URI while the
host still holds the cloned execution grant. The response is `503`
`temporarily_unavailable` with `Retry-After: 1`. It has no `Location` and no
`AAuth-Requirement`. Retaining the result then replays `ran-once`. Dropping
that grant without a retained result returns `500` `server_error`. The first
retained result still replays. A held poll whose grant is still held stays
`202`. Host3 `aauth-wc07-completion-retrylive01` at that source passed
`a_retry_while_the_grant_is_unretained_is_unavailable` 1/0 with 16 filtered,
`held_poll_while_the_grant_is_unretained_stays_pending` 1/0 with 16 filtered,
and
`a_per_call_executes_once_and_the_replay_returns_the_retained_result` 1/0
with 41 filtered. This unit did not run `r3-per-call-interop`. It did not
rerun directory reopen or interrupted retain. `query-runs=2` and
`proposal-err=invalid_resource_token` stay as previously recorded.
Retained-grant `budget_consumed` stays unresolved. Receipt START
`2026-10-30T06:05:02.130016325+00:00`, log mtime
`2026-10-30T06:05:16.317087Z`. systemd-run invocation
`f2a1501a4a5e45958fad82558899e1d3`. After collect, `systemctl show` reported
`Result=success`, `ExecMainStatus=0`, and an empty `InvocationID`. The log
recorded `CARGO_RC 0` and `RETRYLIVE01_DONE`. This commit records that receipt
and does not change behavior. It does not change the DirectR3 interop pin.
This is not a separate product-QA pass and not power loss.

A per-call application `202` is retained only as a same-origin pending
response. Behavior commits `cda51b0277f0b5258d96ce4566229117137c07f8` and
`db8af2137bbfd6a3951a26f31d961bdf0cce8caf` keep the `202` with its `Location`,
`Retry-After` and `Cache-Control` when it has exactly one `Location` on the
Resource origin (absolute, or a path that starts with one `/`), exactly one
nonnegative decimal `Retry-After` that fits a nanosecond duration,
`Cache-Control` containing `no-store`, exactly one `application/json`
`Content-Type`, and a JSON object whose `status` is a non-empty string with no
duplicate or case-variant member. These are the conditions of aauth-go
`validateApplicationPendingResponse` at `3f7fc54`; both refuse a fragment. Rust
also refuses a network-path (`//host`) reference, even to its own host, and a
bare relative, query-only, `*` or bare-host reference; aauth-go resolves
relative references against the Resource origin. Any other `202` is retained as
`500` `server_error`; that refusal is what each later presentation replays, and
the call does not run again. A release-gated call's computed response is kept
under the same rule before approval releases it. `DirectoryCallStore` and the
example file stores keep the pending headers across reopen. A `no-store` split
across `Cache-Control` lines is kept, as in aauth-go, but `aauth-rust-agent`
`PollSession` accepts only one `Cache-Control` line and refuses that replay.
`an_application_202_is_kept_only_as_a_same_origin_pending_response`,
`an_application_202_replays_with_its_pending_headers_or_as_server_error`,
`a_released_application_202_replays_with_its_pending_headers_or_as_server_error`
and `a_retained_pending_result_reopens_with_its_headers` pin this.

Host3 `aauth-claude-header05` at `457c23a3a1b301791b488b9e94368cbdf904e207`
(tree `18a9a00990968cc134829351470bd7b05d7c84df`; `db8af21` differs only by
rustfmt of `tests/r3_class.rs`) ran the GitLab linux job's steps except the
cross-target checks: build, consumer bootstrap, docs, publish dry run,
`cargo test --no-fail-fast` (702 passed, 0 failed, 9 ignored in 78 targets),
every CI example run, `r3-per-call-interop` tests and the `r3-per-call` run.
Receipt START `2026-10-30T07:41:55.483579755+00:00`, END
`2026-10-30T07:45:15.351054390+00:00`, `Result=success`, `ExecMainStatus=0`.
Strict all-targets Clippy still refuses findings that were already on main in
the `r3-per-call` example and `r3_standard_definitions` tests; library and
binary targets pass it. The earlier batch at `fb2d290`
(`aauth-claude-header03`) passed the same steps with 701 workspace tests.
`fb2d290` also formats the workspace, clears three Clippy findings, and
corrects `invalid_r3_requests_release_no_token_and_retain_nothing`, which has
expected `invalid_request` since `cb658a8` made that request `invalid_budget`
and failed at `0c86939`. Independent consumer QA of the earlier candidate
`0d62470` found the release-gated and `*`/bare-host gaps that `db8af21`
closes. These are engineering checks, not product QA, and not power loss.

An approved mission composes with direct class R3. Behavior commit
`b32b6b03bfcfb46174c4e6ace85b8c789a209fed` (tree
`43ac440afb3649a5e2dbc10faff3ca69bf013377`) lets a Resource with
`with_mission_context` and `with_r3` issue a class document for a mission-bound
Person token. `R3DocumentRecord` and `DirectoryDocumentStore` keep its
`mission_s256`. Admission requires the Auth token's `mission_s256` to equal the
document's: a missionless token, another mission, or a mission-bound token on a
missionless document is `403` and does not reach host policy. The Person Server
grants under an active mission it holds. R3 policy sees the mission. The
grant ends no later than the mission's `expires_at`, the Auth token names
`mission_s256`, and after the R3 audit record the issuance commits through
`MissionStore::commit_mission_token` against the unchanged active mission. A
terminated mission issues no further token. As in aauth-go's direct R3
profile, missions do not compose with per-call proposals: the Resource refuses
`with_r3_per_call` with mission context as `InvalidR3Profile`, a proposal under
a mission is `invalid_resource_token`, and a class decision that leaves
operations per call under a mission is `500`. Missions with an access server,
sub-agents and call chaining stay refused. The Agent refuses a mission-bound R3
Resource token that outlives its Person token.
`a_mission_class_document_admits_only_an_auth_token_for_that_mission`,
`a_mission_class_grant_names_the_mission_and_ends_with_it` (Agent, Resource and
Person Server in process, with a 300-second mission against a 600-second
decision), `a_mission_resource_token_never_outlives_its_person_token`, and the
updated `per_call_and_unsupported_compositions_are_refused_explicitly` pin this.
Host3 `aauth-claude-missions01` at that commit passed rustfmt, library and
binary Clippy with `-D warnings`, `cargo test --locked --no-fail-fast` with two
harness threads (705 passed, 0 failed, 9 ignored in 78 targets) and the
`r3-per-call-interop` tests. Receipt START
`2026-10-30T11:34:14.247067716+00:00`, END
`2026-10-30T11:37:26.652223103+00:00`, `Result=success`, `ExecMainStatus=0`.
These are engineering checks, not product QA.

Independent consumer QA of that candidate, over HTTPS with live aauth-go,
found one defect. The Resource gave every Resource token a fixed 300-second
lifetime, including mission-bound ones. With less than five minutes left on
the Person token, the Agent then refused the Resource's own challenge.
Commit `d778d45265684a6b523f6ba6f5db1047ea3ae278` (tree
`e207cf45a321a0e953b9a6cebb76a65764830003`) ends a mission-bound Resource token
no later than the token presented with it, as aauth-go does. This covers the
reactive challenge, the proactive R3 grant and the budget step-up. Missionless
tokens keep 300 seconds. `a_mission_resource_token_ends_with_the_person_token`
pins a two-minute mission on both R3 paths. Host3 `aauth-claude-missions03` at
that commit passed rustfmt, library and binary Clippy with `-D warnings`,
`cargo test --locked --no-fail-fast` with two harness threads (706 passed,
0 failed, 9 ignored in 78 targets) and the `r3-per-call-interop` tests. Receipt
START `2026-10-30T13:45:55.864099778+00:00`, END
`2026-10-30T13:53:08.853082365+00:00`, `Result=success`, `ExecMainStatus=0`.

A required-row batch closes 18 MUST-level rows. A 2026-10-30 grading of
`v0.1.0-alpha.9` against the pinned drafts found 8 of them failing and 10 with
code but no test. Commits `5b223d5` through
`d1d3a369c4cfd59d6f37a9870f35fd3d7be03b67` (tree
`87cdc28dc12d9a7cead8289048ef4603e3e10385`) make these changes.

Agent:

- A `401` from the R3 authorization endpoint takes its error code from
  `Signature-Error`, never from the body.
- `Agent::with_additional_signature_components` covers a Resource's
  `additional_signature_components` on every request the Agent signs,
  including R3 authorization requests and polls. Signing refuses when a
  listed component cannot be covered. Verifiers accept any covered lowercase
  header field, and the required coverage is unchanged.
- A runtime `401` or `202` requirement outranks a published operation
  annotation.

Resource:

- `PsAuthorizationConfig::scope_descriptions` is required. The constructor
  refuses a missing, blank or extra description, and metadata always
  publishes the descriptions. A per-call challenge whose class token names an
  undescribed scope is `403`.
- A release proposal opens its `detail` with an `## Action` section stating
  that the operation has already run and that approval releases its result.
- The release hook is never asked to run an operation that its definition
  annotates `budget: true`.
- `Vocabulary::new` refuses a non-standard URI in the `urn:aauth:vocabulary:`
  namespace.
- New tests assert three things: a person token is continuity, not identity
  proofing; a gRPC operation entry without `method` is refused; and
  annotations change no enforcement decision.

Servers:

- Interaction codes carry 40 bits, and pending URL ids carry 128 bits, from
  the operating system's secure random source. This covers the Person Server,
  the Access Server, chained interactions and R3 held calls. The host's token
  id source no longer names a pending URL. `HeldInvocations::open` draws and
  returns its own id.
- The R3 audit entry is now part of the issuance record, so one store commit
  writes both or neither. This supersedes the earlier
  `class_audit_survives_when_issuance_commit_fails` record above; that test is
  now `failed_issuance_commit_writes_no_class_audit`.
- Direct Person Server issuance reads back the audit entry's fields and
  refuses an R3 document whose digest differs.
- The Access Server verifies a passed-through `upstream_token` before policy,
  and the issued token ends no later than it. Four-party call chaining, added
  later the same day, now passes a chained request on to the Access Server.

Host3 `aauth-claude-rows01` at `d1d3a36` passed rustfmt, library and binary
Clippy with `-D warnings`, `cargo test --locked --no-fail-fast` with two harness
threads (739 passed, 0 failed, 9 ignored in 83 targets) and the
`r3-per-call-interop` tests. Each of the 18 rows names a test that passed in
that run. Receipt START `2026-10-30T16:12:00.121592342+00:00`, END
`2026-10-30T16:18:05.873342882+00:00`, `Result=success`, `ExecMainStatus=0`.

AAuth Events is implemented against all 22 MUST-level rows of the pinned
Events draft. Commits `6b641d6` through
`91da08b88e58b35e50b9975e306d1bb1ae1fb5d4` (tree
`25e669f7ed0d510461e46068dcbec8d680c2cfef`) add the following.

- Core: the subscribe and event tokens. Event tokens are `aa-event+jwt`
  self-jwt from the Resource. They carry the subscription's `eid`, carry
  `body_s256` exactly when the delivery has a body, and never carry `cnf`.
- Agent Provider:
  - It publishes an HTTPS `event_endpoint` and issues subscribe tokens
    after storing the subscription.
  - It validates a delivery in the draft's order. It checks `aud`, and
    routes by `eid` to the right Resource and Agent, before spending a
    `max_uses` use.
  - It answers `202` with `remaining_uses` only after the inbox store
    reports the write.
  - `DirectoryEventStore` is a durable, file-backed inbox. Every write is
    fsynced and renamed before it reports success, an uncertain write is
    `503` and counts nothing, and a torn subscription file is refused.
    Accepted events and the `max_uses` count survive a reopen and a process
    exit. It is one process per directory, with no compaction.
- Agent:
  - It signs registrations with the subscribe token.
  - It verifies `typ`, `dwk`, the Resource signature, `aud` and `exp`,
    and checks the delivered body against `body_s256`.
  - It maps `eid` to its own context and ignores a repeated event.
- Resource:
  - It verifies subscribe tokens before registering.
  - It registers public subscriptions, and protected ones through tickets.
    A ticket is single-use, short-lived and bound to the JWK Thumbprint of
    the key that established it.
  - It mints event tokens and signs deliveries, covering `content-digest`
    and `content-type` when there is a body.
  - `EventsResource::with_asyncapi` refuses an AsyncAPI JSON document that
    lacks the `aauth_subscribe` security scheme. A document a host serves
    by other means is not checked.

AP-to-Agent transport is the host's, as the draft leaves it. The AP hands the
host's store the exact verified bytes, and the Agent verifies them. The draft
orders the use count before the `aud` check; this library checks `aud`
first, so a misaddressed delivery spends nothing. Host3 `aauth-claude-events01`
at `91da08b` passed:

- rustfmt;
- library and binary Clippy with `-D warnings`;
- `cargo test --locked --no-fail-fast` with two harness threads (778 passed,
  0 failed, 10 ignored in 88 targets);
- the `r3-per-call-interop` tests.

Each of the 22 rows names a test that passed in that run. Receipt START
`2026-10-30T17:31:45.479144566+00:00`, END
`2026-10-30T17:37:45.638537676+00:00`, `Result=success`, `ExecMainStatus=0`.

Changes on 2026-10-30, after a review of the MUST-level rows against the
pinned drafts:

- A request missing `Signature-Key` is `invalid_signature`.
- Interaction codes are emitted in upper case; the Resource accepts a code in
  any case with the `I`, `L` and `O` aliases folded.
- `read_call_outcome` decides from the `error` member, not the HTTP status.
- Revocation pending URLs answer `410` once their final response has been
  returned, at the Person Server and the Access Server.
- Whenever `Signature-Error` is sent, the problem `type` is
  `urn:ietf:params:sig-error:<code>`.
- A mission's `expires_at` is checked at the permission, audit and interaction
  endpoints and on mission update, completion and read.
- `x509` verification checks revocation against CRLs the host supplies.
  `verify_x509` takes the CRLs, and an empty list is refused.
- Every response to a budgeted Auth token carries `AAuth-Budget`, including
  refusals at the R3 gate and after host policy, revoked tokens, and `405` and
  `410` at R3 pending URLs.
- `/person` accepts an upstream Auth token issued by the Person Server's own
  Access Server.

Four-party call chaining, added later on 2026-10-30, closes both: see below.

Features added on 2026-10-30:

- Every role can publish `name`, `description`, `logo_uri`, `logo_dark_uri`,
  `documentation_uri`, `tos_uri` and `policy_uri`. Each URL must be `https`,
  and key discovery refuses metadata whose display URL is not.
- `AAuth-Capabilities` is read and written. An absent or unreadable header
  declares nothing. `ChainedInteraction::open` takes the caller's capabilities
  and does not raise an interaction the caller did not declare.
- `AgentIdentityResource::with_further_schemes` accepts schemes beside `jwt`
  and lists them all on refusal; those requests return
  `Decision::OtherScheme` for the host to verify.
- An `Agent` tracks missions its Person Server reported terminated.
  `post_audit` refuses them, and `may_present` tells the host whether a
  mission-bound token may be used.
- `Store::replace_binding` establishes a new agent-person binding after
  revocation. Bindings and token records carry a generation, so earlier
  credentials stay revoked.
- `usage_request` and `read_usage` let the Person Server and Access Server
  query a Resource's usage endpoint and check the answer was produced for the
  caller.
- `R3Definitions` groups a Resource's internal definitions. A request spanning
  several gets one document with a merged display.
- Resource-initiated interaction, three-party: a Resource puts its own flow in
  the challenge with `authorize_with_interaction`. The Person Server, with
  `with_resource_interaction`, then checks the code, validates the Resource
  URL through the host's egress check, and redirects with a per-flow callback.
  A callback that carries an error ends the request with the mapped polling
  error.

Consent through a supervision server came on 2026-10-31; see below.

Added later on 2026-10-30:

- Four-party call chaining. A federated Person Server passes `upstream_token`
  to its Access Server with the intermediary's agent token, refuses an Auth
  token that would outlive the upstream token, and retains the Access Server's
  token with the same upstream link; step-up and deferred chained requests work,
  and an Access Server interaction reaches the intermediary unchanged. An
  upstream Auth token issued by this Person Server or its Access Server is
  accepted at `/person` and `/token`. Hosts opt in with
  `Policy::consent_upstream`, which defaults to deny.
- In three-party chains the mission travels down the chain, caps the downstream
  tokens' expiry, and a terminated mission refuses the chain with
  `403 mission_terminated`. Four-party missions came on 2026-10-31; see below.
- Revocation: revoking a person token revokes the person tokens issued from it
  hop by hop, and step-up tokens enter the ledger. Revoking an agent token
  revokes each of the agent's person tokens the same way, calling each Access
  Server once per person token and naming the person token. A waiting request
  whose upstream token or resource token is revoked ends with the polling error
  `403 revoked`; a new request naming a revoked token still gets
  `revoked_upstream_token` or `revoked_resource_token`.
  An Access Server told that a person token is revoked revokes every Auth
  token issued from it, including step-ups at any depth, at its Resource and
  in its own ledger, so none is accepted again as a presented token.
- Signature-Key signing: `SigningKey::from_pkcs8_der` signs with ES256, ES384,
  RS256 and PS256 keys as well as Ed25519, and an `hwk` member carries the key
  in the draft's order. `KeyMaterial::Jwt { jwt, cache }` may carry the bare
  `cache` flag, which needs `jti` and `exp`. `x509` chains and CRLs may be
  signed by RSA issuers. API changes: `KeyMaterial::Jwt` is a struct variant,
  and `SigningKey::sign` returns `Vec<u8>`.

Added on 2026-10-31:

- Four-party missions, chained or not. A federated Person Server consents with
  the mission, loads it again just before contacting the Access Server, and
  refuses an Auth token for another mission or one that outlives the mission.
  The receipt is retained through `MissionStore::commit_mission_token`, which
  now takes federated receipts. A mission that ends while the Access Server
  decides, or while a request waits, ends the request with
  `403 mission_terminated`. The Access Server copies `mission_s256` into the
  Auth token, and a federated Resource with `with_mission_context` carries the
  mission in its challenge. Missions with sub-agents or per-call proposals stay
  refused.
- Metered release of a held R3 result. With `with_release_metering`, a Resource
  offers the release's `R3Release::cost` as a `budget` on the per-call
  proposal's Resource token, a three-party Person Server narrows it onto the
  per-call Auth token, and the Resource draws the cost down once when it
  releases the result; a replay is not charged again. A per-call token whose
  budget is too small gets `403` with `AAuth-Budget`, and the result stays
  held. The drafts do not say whether a per-call token may carry `budget`; this
  is the library's reading. A federated Person Server relays a proposal that
  offers a budget with its ceiling and releases the Access Server's per-call
  token only when its `budget` narrows that ceiling (`502 as_unreachable`
  otherwise), as aauth-go `0e2447b` does (INTERPRETATIONS.md). This library's
  Access Server has no R3, so the four-party grant comes from another Access
  Server. API change: `R3Release` gains `cost`.
- Supervision (`draft-hardt-aauth-supervision`). The new crate
  `aauth-rust-supervision-server` is the supervision server role, and
  `PersonServer::with_supervision` is the Person Server's side. For an agent
  routed to a supervision server, every act the Person Server decides goes to
  that server, and host policy is not called. Covered acts: person tokens
  (direct, sub-agent, chained), auth tokens (three-party, sub-agent, chained,
  four-party), permission, mission proposal, update and completion. An `allow`
  issues, narrowed to the answer's scope and `exp`; a `deny` refuses; an ask, a
  deferral, a clarification or an unavailable server holds the act for the
  person at a pending URL. Reports are delivered in order, a new supervision
  server receives the agent's journal before its first act, and a stored
  decision verifies later against the server's public keys. Signature-Key gains
  response signatures with `;req` components. Not covered then: R3 and
  resource-initiated interaction for a supervised agent were refused; a
  four-party `allow` that narrows scope or `exp` was refused because the Access
  Server takes no narrowing; `auth_token.issued` after an Access Server
  deferral, `revocation.received` for resource tokens, `interaction.requested`,
  and mission terminations other than completion were not reported. All but
  resource-initiated interaction came on 2026-11-01, and resource-initiated
  interaction in alpha.21; see below. The draft
  choices the library made are in INTERPRETATIONS.md and USE-IN-YOUR-SERVICE.md.
- Fixes from the aauth-conformance suite (main `332f645`). A completion at the
  mission endpoint ends issuance under the mission; a resolved key of a type the
  verifier does not implement is `unsupported_algorithm`; an agent identifier
  with a misplaced `+` is refused; Person, Resource and Auth tokens accept a
  one-element `aud` array; a federated Person Server relays a budgeted per-call
  proposal. The R3 document endpoint's `unsupported_scheme` refusal names
  `jwks_uri`, the one scheme it accepts. Shared token error messages no longer
  say "Agent token" when another token failed; the wire codes are unchanged.
  API change: `validate_agent_identifier` and every token parse refuse
  `aauth:+x@…`, `aauth:x+@…` and `aauth:a+b+c@…`. The readings are in
  INTERPRETATIONS.md.

Added on 2026-11-01:

- Interaction relay. With `with_interaction_relay`, the Person Server relays
  an agent's `interaction` or `payment` (`url` and `code` required) to the
  person through the host's `RelayChannel`, keeps it before answering `202`
  at `/interaction/relay/{id}`, and answers the agent's poll once: `200`
  `{"status":"interacting"}` after `relay_engaged`, or
  `{"status":"pending"}` after `relay_finished` or at the end of the wait,
  which the agent's `max_wait` can shorten. A host with no channel answers
  `424 interaction_unavailable`, as before. The wire is aauth-go's. API
  change: `Agent::post_interaction` takes the `url` and `code`.
- Supervision leftovers. A four-party `allow` that narrows scope or `exp` is
  sent to the Access Server with `scope` (only when narrower) and `exp`
  members, and this library's Access Server issues within them; a token
  wider than the allowance, from an Access Server that ignored them, is
  refused with `403 access_denied`, or `403 denied` at a poll, as aauth-go
  does (`a_person_servers_narrowing_bounds_the_grant`,
  `a_four_party_request_is_put_to_the_supervisor_before_the_access_server`). `auth_token.issued` is reported when a four-party token is released,
  also after the Access Server deferred, under the act's `sdi`, and for R3
  tokens. An R3 request from a supervised agent is an `auth_token` act: an
  `allow` grants every operation of the class document, or the proposed call,
  and `R3Policy` is not called; a held act carries the fetched document for
  the person (`SupervisionHold::r3_document`). A Resource's revocation of a
  resource token that was in a supervised request is reported as
  `revocation.received` with `token_type` `resource_token`. A relay or a
  question is reported as `interaction.requested`. A mission's end is
  reported `terminated` once, with its reason, the first time the Person
  Server finds it ended, whether it expired, was terminated by the host, or
  was completed. Resource-initiated interaction for a supervised agent is
  still refused. API change: `SupervisionHold` gains `r3_document`.
- alpha.18 leftovers. An `unsupported_scheme` refusal names the scheme the
  endpoint accepts: `jwks_uri` at the Person Server's revocation, mission
  approval and interaction decision endpoints, which named `jwt`, and at the
  Resource's revocation and usage endpoints, which named none. The usage
  endpoint answers every signature failure with `Signature-Error`, as any
  signed request is answered, in place of `invalid_signature`, `invalid_key`
  or `untrusted_issuer` in the body. The Supervision Server answers a trusted
  Person Server key of a type it does not implement with
  `unsupported_algorithm` and `Accept-Signature-Alg`, and a failed issuer
  check with `issuer_missing` or `issuer_mismatch`, where it answered
  `invalid_key`; the Resource's revocation endpoint now sends
  `Accept-Signature-Alg` with `unsupported_algorithm` too. A federated Person
  Server relays a class document that offers a budget with its ceiling and
  releases the Access Server's class token only when its `budget` narrows
  that ceiling (`502 as_unreachable` for a missing, extra, wider or
  re-denominated one), as aauth-go's Person Server checks
  (`tests/federated_r3.rs`). The Agent's R3 helpers accept a Resource token
  that offers a budget and check the grant's `budget` against the offer, on
  the class and the per-call path (`tests/r3_delivery.rs`). The Agent takes
  what a Resource requires it to sign from the Resource's metadata document,
  after the issuer check (`Agent::with_resource_metadata`), or from an
  `invalid_input` refusal (`Agent::with_required_input`)
  (`tests/signature_components.rs`); the `direct-identity` example's agent
  reads the Resource's metadata that way before calling. API changes: the two
  `Agent` methods and `SignatureComponentsError` are new;
  `verify_r3_resource_token`, `verify_r3_proposal_challenge`,
  `verify_r3_auth_delivery` and `verify_r3_per_call_delivery` accept budgets
  where they refused them. The readings are in INTERPRETATIONS.md.
- ES256 agent keys and tokens, external signers and key export. Compact JWS
  signs and verifies ES256 as well as Ed25519, so Agent, Person, Resource,
  Auth, subscribe and event tokens may be minted with an ES256 issuer key and
  may carry an ES256 `cnf.jwk`; `jwt`, `jwks_uri`, `jwks` and `self-jwt` keys
  and response signatures take ES256; every role's `Accept-Signature-Alg` is
  `Ed25519, ES256`. Ed25519 stays the default. `SigningKey::generate_es256`
  makes an ES256 key. `SigningKey::external` signs with a caller's
  `ExternalSigner` (keystore, HSM, secure enclave or remote service) wherever
  a `SigningKey` signs, validating its public JWK and verifying each of its
  signatures before use. `SigningKey::export_pkcs8_der` writes an in-memory
  key as PKCS #8 DER for `from_pkcs8_der`, zeroized on drop and refused for an
  external signer. `Jwk::validate` refuses an EC point off its curve. API
  changes: `SigningKey::sign` returns `Result<Vec<u8>, Error>`; `Jws::sign`
  requires the header `alg` to name the key's algorithm; the JOSE `Error`
  gains `Signer` and `NotExportable`, `TokenError` gains `SigningFailed`
  (`server_error`), the Signature-Key `Error` gains `SigningFailed`, and the
  budgets `Error` gains `Signing`; `role_signature_alg_header()` is
  `Ed25519, ES256`.
- Discovery and revocation delivery, opt-in in the new `aauth-rust-discovery`
  crate, the only crate that opens connections. `DiscoveryClient` fetches
  through the Signature-Key egress admission (`https` only, every resolved
  address globally routable unicast and pinned, same-host redirects, at most
  65536 bytes and ten seconds by default, no proxy from the environment).
  `KeyResolver` resolves (`iss`, `dwk`, `kid`) for host-trusted issuers by
  metadata, `issuer` check and `jwks_uri`, cached by the `KeyCache` rules,
  with an unknown-`kid` refetch after the one-minute floor and the last set
  kept for 24 hours after a failed refresh. `RevocationClient` discovers each
  recipient's `revocation_endpoint`, signs the revocation as the sender under
  `jwks_uri`, and maps the answer to the cascade outcomes, polling a `202`
  with a signed GET. Evidence: `aauth-rust-discovery/tests/discovery.rs` (2
  tests: discovery, cache and refetch over TLS; `http`, loopback without the
  opt-in, cross-host redirect, oversized body and issuer mismatch refused),
  `tests/cascade.rs` (2 tests: a Person Server's person-token revocation
  reaching the Resource and, through the Access Server, the Resource again,
  every key found by discovery; a `202` polled to `200`, and no endpoint
  read as unsupported). API change: `RevocationDirectory::revoke` takes a
  `RevocationSender` and a `RevocationTarget`, which names the recipient's
  role document. `KeyCache` gains `refresh` and `record_failure`, and egress
  admission gains `admit_target` and the `DiscoveryFetch::Endpoint` target.
  The readings are in INTERPRETATIONS.md.

Added on 2026-11-02 (alpha.20):

- Mission expiry. The person's approval at the native mission endpoint may
  carry `expires_at`, an RFC 3339 time after the approval, and the mission
  blob carries it as sent. Past it the mission is terminated (`expired`):
  Person and Auth tokens under it expire no later, `/person` and the mission
  endpoint answer `403 mission_terminated`, and an update is refused. A
  malformed or past `expires_at`, or one on a denial, is `400
  invalid_request` and leaves the proposal pending
  (`tests/mission_endpoint.rs`, `an_approval_may_set_the_missions_expiry`).
- Required components. `parse_signature_error` reads the `required_input`
  list of an `invalid_input` refusal, and the Agent's `with_required_input`
  uses it. `PreparedRequest::prepare_with_components` requires components a
  server lists beyond the profile; `required_components_with` is the list a
  refusal names. `AgentIdentityResource` and `PsAuthorizationResource` gain
  `with_additional_signature_components`, published in their metadata as
  `additional_signature_components` and required on every agent request
  (`tests/identity.rs`, `tests/ps_authorization.rs`, `tests/proofs.rs`).
- ES256 under `jkt-jwt` and `cached`. The enclave key and the delegated
  `cnf.jwk` of a `jkt-jwt` may each be Ed25519 or ES256, the assertion cache
  seals the whole confirmation key, and `ServerKeyBinding` admits ES256
  pseudonym keys (`tests/proofs.rs`,
  `jkt_jwt_takes_es256_enclave_and_confirmation_keys_and_caches_them`).
- One refresh after a failed signature. When a token signature or a
  `jwks_uri` request or response signature fails under the resolved key, the
  verifier asks `AgentKeyResolver::refreshed_key` once and retries with a
  fresher key (`verify_with_refresh`); `JwksResolver` and `IssuerKeyResolver`
  do the same for `jwks` and `self-jwt`. The discovery `KeyResolver` refetches
  under the once-a-minute floor (core `tests/agent_tokens.rs`, discovery
  `tests/signers.rs`).
- Direct `jwks` and `self-jwt` on the discovery client. `KeyResolver`
  resolves a direct `jwks` URL the host trusts (`trust_jwks`,
  `trust_jwks_when`) through the client's admission, cached by URL, and
  `KeyResolver::verify_self_jwt` verifies a `self-jwt` request from a trusted
  issuer's metadata and keys. An untrusted signer is never fetched and is
  `invalid_key` (`tests/signers.rs`).
- Advertised schemes. Every Resource endpoint's `unsupported_scheme` refusal
  names the schemes that endpoint accepts, with no default; the R3 document
  endpoint names `jwks_uri` only, as since alpha.18 (`tests/r3_class.rs`).
- API changes: `AgentKeyResolver`, `JwksResolver` and `IssuerKeyResolver`
  gain `refreshed_key` (default: no fresher key); the Resource's
  `SignatureFailure::Input` holds `String`s; `ConfigurationError` and
  `PsConfigurationError` gain `InvalidComponent`; `DiscoveryError` gains
  `UntrustedJwks` and `signature_error`. New: `parse_signature_error`,
  `SignatureErrorField`, `required_components_with`, `is_coverable_component`,
  `PreparedRequest::prepare_with_components`, `verify_with_refresh`, and
  `KeyResolver::{trust_jwks, trust_jwks_when, trusts_jwks, refresh,
  resolve_jwks, verify_self_jwt}`. A cache identifier issued by an earlier
  release is `cache_miss`. The readings are in INTERPRETATIONS.md.

Added on 2026-11-02 (alpha.21):

- Resource-initiated interaction under supervision. A supervised agent's
  `/token` request whose resource token carries `interaction` is put to its
  supervision server first, as every auth token act is (Supervision, line 79:
  the PS makes no supervision decision of its own). A deny is `403
  access_denied` and the person is never sent anywhere. An allow, or the
  person's allow after an ask, runs Core's steps unchanged (Protocol, lines
  986-997): this server's interaction URL, the interstitial, the Resource's
  flow and the callback. The callback issues the Auth token within the allow
  (`scope`, `exp`) with no consent of the host's, and `auth_token.issued` is
  reported under the decision's `sdi`. A held act's pending URL relays the
  flow once allowed: its polls answer as `/token/interaction/{id}` does, and
  a `DELETE` there ends the flow. API change: `ResourceInteractionCallback`
  gains `Completed`, and `PendingResourceInteraction` gains `supervised`
  (`tests/supervision.rs`,
  `a_supervised_resource_interaction_is_decided_first_and_issued_within_the_allow`,
  `a_held_resource_interaction_is_relayed_at_the_one_pending_url`).

Added on 2026-11-02, after alpha.21 (not released):

- Person identity access. `PersonIdentityResource` serves on a verified
  Person token alone (Protocol, Person Identity Access). A request with no
  verified Person token, unsigned or signed with an Agent or Auth token, is
  `401` with `AAuth-Requirement: requirement=person-token` and no parameters
  (Person Token Required, line 615). A Person token for another Resource is
  `invalid_jwt` with the audience detail. `Authorized` takes the verified
  token type as a second parameter, which defaults to the Agent token. The
  conformance suite's `core.person-token-required` clause grades it.
- A direct agent's Person token. `Agent::person_request` signs the Person
  token request with the Agent token, and `Agent::verify_person_delivery`
  checks the token the PS returns (Person Token Endpoint). The conformance
  suite's `agent.person-flow` clause grades the retry that presents it.
- `Jwk::rfc7638_thumbprint` computes the RFC 7638 thumbprint of a key
  without `alg`, such as the RFC 8037 example key. `Jwk::thumbprint` still
  refuses such a key. The suite's `vector.jwk-thumbprint.no-alg` clause
  grades it.

`Ledger::open_directory` writes the Resource budget meter to a host directory.
Each successful `open`, `reserve`, `commit`, `release`, `complete_held`, and
`prune_keys` publishes `ledger.json` only after the new bytes are synchronized.
The previous complete file is kept as `ledger.json.prev`. A partial
`ledger.json.tmp` is not the spend. A second process that opens the directory
continues that spend. `reopen_after_process_exit_keeps_the_spent_grant` is
that process exit: the child spends the grant and exits, and the parent reads
`budget-exhausted`. `interrupted_write_keeps_the_last_complete_grant` stops
before the rename and also truncates the current file. Reopen reads the last
complete snapshot and does not apply the torn spend.
`durable_budget_ledger_reopens_spent_after_process_exit` admits one call
through the Resource. A second process opens that directory and cannot reserve
another unit. A new Resource given the reopened meter and the same class
documents answers `budget-exhausted` and does not run the tool.
`interrupted_replace_keeps_the_previous_claim_bytes` stops a claim replace
before the rename, then recovers the previous complete claim after the current
file is truncated. This is not power loss. A ledger that was not opened on a
directory is still process memory. Host3 `aauth-wc07-completion-ledger01`
ran that batch in one unit at `6bf78dca91c57f74396308cfea5320a9525ce07a`.
Receipt START `2026-10-29T21:45:04.454951949+00:00`, log mtime
`2026-10-29T21:45:41.231686+00:00`. The durable budget tests passed 2,
ignored the worker entry, and failed 0. The interrupted claim replace
passed 1 and failed 0. The Resource reopen passed 1, ignored the worker
entry, and failed 0. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. `systemctl show`
reported `Result=success` and `ExecMainStatus=0`.

`DirectoryCallStore` is a public `R3CallStore`. Each proposal and each claim
is written to its own file, synchronized, and renamed into place. The
previous complete file is kept beside a replacement. A torn current file is
not a new claim: a valid previous file is the record, and a torn file with
no previous file is unavailable. `reopen_after_process_exit_does_not_execute_again`
starts a second process. That process commits one proposal, claims it, and
exits. The parent opens the same directory. The next claim is `Unfinished`,
not `Execute`. The child pid is not the parent pid.
`interrupted_claim_write_is_not_adopted` stops the first claim before the
rename. The claim file is absent, and the retry may `Execute`.
`interrupted_retain_keeps_the_unfinished_claim` stops the result write
before the rename. The bound claim stays unfinished, and a later retain
under the same fence stores the result. `torn_claim_keeps_the_bound_claim`
retains one result, then truncates the current claim file. Reopen reads the
previous complete claim. That claim is `Unfinished`, not a second
`Execute`, and the torn bytes are not the retained result. This is a
process exit and an interrupted write. It is not power loss. The example
`FileCalls` store stays private to the example.
`directory_call_store_replays_the_product_after_process_exit` runs this
store through the Resource. The first process issues one per-call
approval, executes the call once, and retains the body. A second process
opens the same directory, presents the same Auth token, and receives
`Replayed` with that body. The child pid is not the parent pid. This is
a process exit. It is not power loss.

Host3 `aauth-wc07-completion-product01` ran that product replay in one
unit at `a7fe681d1d0d088595de293a2a9d55b1ef6b91b5`. Receipt START
`2026-10-29T22:40:32.541308313+00:00`, log mtime
`2026-10-29T22:40:46.797966968+00:00`. The resource test binary was
rebuilt. `directory_call_store_replays_the_product_after_process_exit`
passed 1 and failed 0, with 39 filtered. The directory call store passed
4, ignored the worker entry, and failed 0. `r3-per-call-interop` against
Go `3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2`
and `proposal-err=invalid_resource_token` stay visible. systemd-run
reported invocation `adc137b154ce43c8b21e607839370ab4`. After the unit
was collected, `systemctl show` reported `Result=success` and
`ExecMainStatus=0`, and `InvocationID` was empty.

`DirectoryDocumentStore` is the public class-document custody. `commit`
writes the whole record to a temporary file, synchronizes it, and renames
it. An exact repeat is accepted. A different record at the same URI is
`Conflict` and leaves the stored bytes unchanged. An interrupted write
returns before the rename, leaves the final name absent, and a retry can
commit. A torn current file is `Unavailable`, not a missing document and
not a recovered previous document. Documents are create-only. There is no
previous file. `reopen_after_process_exit_loads_the_same_document` commits
in the parent and loads that subject and body in the child. The child pid
is not the parent pid.
`directory_document_store_admits_the_class_after_process_exit` runs this
store through the Resource. The first process issues one class approval
and admits `/op/permit`. A second process opens the same directory,
presents the same Auth token, and is admitted again. The child pid is not
the parent pid. This is a process exit. It is not power loss. The example
`FileDocuments` store stays private to the example.

Host3 `aauth-wc07-completion-document01` ran that class admission in one
unit at `2d55b0cd531778b9013921c4cadd553321e1f6cb`. Receipt START
`2026-10-29T22:54:06.378681479+00:00`, log mtime
`2026-10-29T22:54:26.393846723+00:00`. The resource library was rebuilt.
`directory_document_store_admits_the_class_after_process_exit` passed 1
and failed 0, with 41 filtered. The directory document store passed 4,
ignored the worker entry, and failed 0. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. systemd-run reported
invocation `2a11a83491dd42c7876129e6f173e99f`. After the unit was
collected, `systemctl show` reported `Result=success` and
`ExecMainStatus=0`, and `InvocationID` was empty.

`r3-per-call-interop` pins `query-runs=2` and
`proposal-err=invalid_resource_token`. The second query run is the
release-retry challenge while the prior proposal token is still live.
Draft `70d67375` has no invocation id and no result digest, so that pin
stays. It is separate from
`fresh_bytes_can_be_released_under_a_still_live_recorded_approval`.
The proposal status is Go `DirectR3Config` at
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739`: direct R3 supports class
documents only, and a proposal resource token is `400`
`invalid_resource_token`. That refusal is not the unspecified
`budget_consumed` retained-grant resolution. A well-formed
`budget_consumed` on a class Resource token remains
`invalid_resource_token` and is not applied.

Host3 `aauth-wc07-completion-align01` ran that batch in one unit at
`f552df6a62de3cdb12efd4fd9af958c4f5413083`. Receipt START
`2026-10-29T22:15:54.303157140+00:00`, log mtime
`2026-10-29T22:16:21.762515300+00:00`. The budgeted deferred tests passed
2 and failed 0. The directory call store passed 4, ignored the worker
entry, and failed 0. `r3-per-call-interop` against Go
`3f7fc54b8ea1e310148c922b1d09e64bd6e24739` exited 0. `query-runs=2` and
`proposal-err=invalid_resource_token` stay visible. systemd-run reported
invocation `d7d988646e1b47d7b992be6d340f83f6`. After the unit was
collected, `systemctl show` reported `Result=success` and
`ExecMainStatus=0`, and `InvocationID` was empty.

`fresh_resource_spends_the_same_grant_again` spends the grant, then the same
Resource answers `budget-exhausted`. A second Resource on the same class
documents, with a new ledger, admits that still-live token again. That is
not an operating-system restart. `with_budget_ledger` accepts a ledger the
host already holds. `shared_budget_ledger_continues_after_recomposition`
spends the grant, then another Resource given that same ledger answers
`budget-exhausted` and does not run the tool. Host3
`aauth-wc07-completion-shared01` passed that recomposition at `3246e68`.
The ledger remains process memory. Sharing it is not an operating-system
restart.

`R3PerCallConfig::held_result_lifetime` is host policy, in seconds. It is not
extended when a refreshed class token re-requests the call, and it is not a
draft promise. The resource reuses the held bytes only while `release_until`
is still ahead, the prior proposal token has expired, and the new class token
has a different `jti`. A still-live challenge is not retired by a same-token
duplicate or by another call under that token. After `release_until`, a
matching call may run again. Draft `70d67375` has no invocation id and does
not carry a digest of the result, so a Person Server recorded approval that
is still live can release those new bytes when the proposal document is
unchanged. `fresh_bytes_can_be_released_under_a_still_live_recorded_approval`
keeps that visible. It is not a stronger consent binding.

The separate [R3 library](crates/aauth-rust-r3/README.md) now includes seven
operation codecs, artifact/proposal validation, signed claims, bounded artifact
fetching, and definition adapters for MCP, OpenAPI, AsyncAPI, gRPC descriptor
sets, WSDL 1.1, and OData CSDL 4.0. GraphQL introspection still supplies no
operation identity. gRPC does not compile `.proto` text or dial reflection.
OData metadata does not prove HTTP methods. Resource and Person Server R3
paths already accept any registered snapshot; they do not grow a second
vocabulary switch. A source test builds each new snapshot with that parser,
asks the Resource to authorize both derived operations, and has the Person
Server grant one of them. The Resource then admits that operation and refuses
the other. The same permit and refusal also cross a loopback TLS HTTP/1.1
client and server for each parser. Actual library consumers and Go/Rust
exchanges have exercised the earlier MCP, OpenAPI, and AsyncAPI paths. The
gRPC descriptor, self-contained WSDL 1.1, and OData CSDL 4.0 adapters
and their Resource/Person Server snapshot integration passed the Linux
workspace checks and loopback TLS permit/refusal journeys at `918cc366`.
This evidence covers the tested definition profiles; complete schema coverage
and cross-platform qualification are not claimed. This does not
qualify role endpoints, discovery, consent, or the normative R3 table.
Application-specific formats remain application-owned.

## One-level parent-mediated sub-agents

`AgentProvider::issue_subagent` verifies the actual parent token using the AP's
configured signing key before issuing a child. `core::verify_subagent` verifies
both actual tokens and the authoritative `parent_agent` relationship. A `+` in an
Agent identifier grants no authority. This profile requires one child naming
segment and a distinct child proof key. Parent and child AP-token lifetimes are
independent; every issued Person/Auth credential and pending deadline is bounded
by both. The child's optional `ps` may be absent; when present it must match the
owning PS. The authenticated parent's PS binding remains mandatory.

PS and AS policy contexts keep `.agent` as the parent and expose the independently
verified child as `.subagent`. Parent proofs authorize the PS exchange; child
proofs are refused there with the existing `401 invalid_jwt` role error. Person
and Auth `cnf` belong to the child. `agent::Subagent` lets the parent prepare signed
requests and verify child-bound deliveries without holding the child's private
key. The Resource admits the child's protected request with the resulting Auth.
The buffered example executes direct PS, immediate AS and AS Payment→Approval
flows through actual native handlers; it does not demonstrate child TLS or a real
identity/payment provider.

`TokenRecord.agent` is the credential holder; optional `parent_agent` retains the
verified parent and `principal` names its binding. First-child Person issuance
atomically creates only that parent binding. Memory/redb logical and reopen
contracts preserve the parent field, holder, exact presented lineage and sticky
parent revocation. Old serialized records default the new field to `None`.
Custom adapters must preserve it and pass the expanded contracts before child use.
Revoking the parent binding blocks new child credentials and pending delivery.
Already delivered credentials retain their signed expiry until a host enables
revocation. Opt-in revocation is TOKEN-REVOCATION below. It does not emit
`revoked_subagent_token`, and this section does not claim a separate per-child
revocation result.
The two `Resource/tests/subagent_revocation.rs` tests present actual delivered
PS/AS Auth credentials with signed child requests after parent revocation: the
Resource still accepts at 1249 and refuses with `401 expired_jwt` at 1250, before
policy. The next parent-mediated PS exchange returns `400 revoked_presented_token`;
new Person issuance returns `403 denied`.

PS custody belongs to the exact retained parent's identity and key; a child or
another poller gets `403 wrong_poller`. Exact parent/child compact bytes survive
role recomposition and are reverified before advancement and terminal release.
The final resolver trust/credential recheck precedes the final host binding read.
After that storage callback, the PS samples its clock and performs pure expiry
checks and remaining-lifetime calculation without another resolver callback.
A trust change during the final binding read is not rechecked in that release;
this ordering is not an atomic trust/store snapshot. Parent-only
cancellation, concurrent single delivery and child/parent expiry are exercised.
The existing pending-reference existence and signed-poll replay limits below
also apply to child flows. Nonterminal PS pending publication may cross expiry
or a trust change during its storage callback; a later poll/advance rechecks it
and withholds credentials. Hosts still own durable continuation recovery.

Four separate `PS/tests/support/release_fences.rs` tests advance time during the
final binding read, after resolver revalidation, and fail when their respective
final guard is removed. Person, local Auth and immediate AS Auth each refuse with
`400 expired_subagent_token`. Deferred delivery refuses with `408 expired`, then
`410` on the next poll: its retained deadline is at or before the original child
expiry. That final deadline guard covers child expiry too; a later child-specific
check at the same timestamp would be redundant. The deferred test keeps every
credential valid beyond the pending deadline so no other expiry can mask its
removed guard. Earlier resolver-delay tests cover a different callback window.

This subset excludes grandchildren, child-signed PS endpoints, child/upstream
chaining, mission/R3 delegation and remote AP enrollment. It does not establish
a general delegation lifecycle or automatic sub-agent process supervision.

## Limits and choices

- Direct Agent identity and immediate missionless PS/AS authorization execute.
  Local AP sub-agent issuance and parent-mediated child credentials also execute.
  Enrollment and recursive delegation do not execute.
  Opt-in resource session tokens do execute. The ledger is process memory.
  A presented token is refused unless the verified agent signature covers
  `authorization` and the opaque value is bound to that agent.
  Opt-in `authorization_endpoint` does execute. It verifies a person token
  before reading `scope` and returns a resource token for a recognized scope.
  Held invocation retention does execute. The first poll of an auth token `jti`
  runs the invocation once. A repeated poll at the same pending id returns that
  result through the token's `exp` and does not run it again.
  A resource interaction redirect does execute. The resource sends the browser
  to `callback` when the flow ends, with `error` when it did not finish.
  `access_denied` polls as `denied`, `user_abandoned` as `abandoned`,
  `interaction_expired` as `expired`, and both `server_error` and
  `temporarily_unavailable` as `server_error`. `person_server_redirect` and
  `receive_callback` are helpers; no Person Server route calls them. Callback
  targets must be HTTPS. `http://localhost` and `http://127.0.0.1` are refused.
  A callback that carries `error` does not complete the pending request.
  Interaction chaining does execute. A resource that receives a downstream
  interaction `202` returns its own pending URL and its own interaction code.
  The host binds the poll to the opener it already verified. That caller receives
  the stored result once, at or before `exp`. A later poll is `410`. A different
  caller receives an empty `404` and not the result.
  `aauth-resource` link helpers return a target only when it is a server
  identifier followed by `/.well-known/aauth-resource.json`, and the metadata
  `issuer` is that identifier. The library fetches nothing. The link is not an
  `AAuth-Requirement`.
  Opt-in mission creation, update, completion, authenticated approval and owner audit do execute.
  Opt-in interaction, permission, and audit posts do execute. Interaction and payment relays reach the person only through a host `RelayChannel` (`with_interaction_relay`), and are otherwise `424 interaction_unavailable`. Presented interaction codes are correlated, not consent.
  Opt-in revocation does execute. The ledger is process memory, and downstream
  calls go through a `RevocationDirectory`; `RevocationClient` in the opt-in
  `aauth-rust-discovery` crate is one over HTTPS.
  Separately host-approved top-level immediate PS mission consumption is
  available through the optional same-store boundary described below. A direct
  Resource stays missionless unless `with_mission_context` is set. Other
  unsupported PS parameters are refused explicitly.
- R3 behavior is limited to the opt-in subsets above; the default Core profile
  does not negotiate it. Events is implemented as recorded above.
  Bootstrap behavior is absent. Supervision is recorded under "Added on
  2026-10-31".
  Pinning a document does not imply implementing it. Opt-in budgets are the
  separate row above.
- Header web keys sign and verify Ed25519, ES256, ES384, RS256, and PS256. RSA `n` and `e` are minimal unsigned integers, the modulus is 256 to 1024 bytes, and the exponent is odd and at least 3. Compact JWS
  and the `jwt`, `jkt-jwt`, `self-jwt`, `jwks`, `jwks_uri`, and `cached`
  schemes take Ed25519 and ES256. ES512, Ed448, and other RSA hashes are
  `unsupported_algorithm`. `ExternalSigner` is the hook for a key held outside
  the process; adapters for particular keystores, HSMs or services are the
  host's. A Resource built `with_further_schemes` still names `Ed25519, ES256`
  in `Accept-Signature-Alg`, although its host may verify an `hwk` or `x509`
  further scheme with ES384, RS256 or PS256.
  `cached` executes in this crate when the host opts in. The identifier is a
  XChaCha20-Poly1305 seal of the scheme, issuer, optional subject, SHA-256 of
  the verified compact assertion, the `jti`, the assertion `exp`, the retention
  time, and the Ed25519 confirmation key, plus 192 random bits. It does not
  contain the `jti` in the clear. A local index records what this process has
  not evicted; a peer that holds the same key opens the seal without that
  index. Opening the seal is not authentication: the HTTP signature is checked
  next. An unknown, evicted, tampered, or unopenable identifier is `cache_miss`.
  The identifier is honored through its `expires` second and is a miss after
  that. An assertion still held at `exp` fails as `expired_jwt`. `expires` is
  not later than the assertion `exp`. An assertion with more than 86400 seconds
  remaining is not cached, and there is no separate revocation list. A full
  index, or a confirmation key that already has its per-key allotment, also
  issues nothing. `self-jwt` still rejects `cache`. Direct agent identity, the
  person server, and the access server do not accept `cached` and emit no
  `Signature-Key-Cache`. A client helper skips `cached` until an identifier
  was issued, including when `cached` is listed first, and presents that
  identifier unchanged.
  `x509` executes in this crate: the host supplies the PEM chain, the trust
  anchors, and the CRLs, and this library does not fetch `x5u` or a revocation
  source. The first certificate is the end entity. Its chain, including a
  current CRL from each certificate's issuer, must validate before `x5t` is
  accepted. An empty CRL list is refused. The end-entity key selects Ed25519,
  P-256 as ES256, or P-384 as ES384. An RSA end-entity certificate is
  `unsupported_algorithm` because its key identifier names neither padding nor
  hash. Issuers in the chain and CRL signers may use Ed25519, P-256, P-384, or
  RSA from 2048 to 8192 bits with PKCS #1 v1.5 or PSS over SHA-256, SHA-384 or
  SHA-512.
  Direct `jwks` executes in this crate: the host supplies the key for the exact
  `url` and `kid`, and this library does not fetch or rewrite that URL.
  `self-jwt` executes in this crate: the host supplies the metadata bytes and
  the issuer key, the library requires metadata `issuer` to equal `iss`, and
  this library does not fetch `{iss}/.well-known/{dwk}` or issue a cache identifier.
  `sign_requests` writes every Signature-Key member before it creates any
  signature, and each signature covers `signature-key`. A verifier still
  selects one label; unselected members are ignored. The Resource, person
  server, and access server still verify the configured `sig` label only.
  A client helper ignores unrecognized tokens in `Accept-Signature-Scheme`
  and `Accept-Signature-Alg`, skips `cached` until an identifier was issued,
  and takes the `Signature-Error` code from the `error` member alone. The
  response body is not an input to that read. On a non-success Access Server
  response, the Person Server uses that header when it is present and does
  not require a JSON body; a problem `error` applies only when the header is
  absent, and `clock_skew` still requires `Date`.
  `KeyCache` records a JWKS document the host already fetched. It does not
  open a connection, and `store` cannot retract that fetch. A `jwks_uri`
  entry is keyed by issuer and `dwk`. `s-maxage` wins over `max-age`. A quoted
  delta is accepted. `Age` is subtracted after the 86400-second cap. `Expires`
  is an IMF-fixdate used when `Cache-Control` sets no lifetime: `Expires` minus
  `Date`, or minus `now` when `Date` is absent. A
  missing lifetime uses 300 seconds, and freshness is at most 86400 seconds.
  `no-store` and `no-cache` record the fetch without making the body reusable.
  The same issuer and `dwk`, or the same URL, cannot be fetched again for 60
  seconds. The entry bound is chosen at open, and a zero bound is refused.
  Egress admission does not fetch. It requires HTTPS, pins one resolved
  address, and refuses a connected peer that differs from the pin.
  `admit_target` checks the URL alone, before name resolution. The opt-in
  `aauth-rust-discovery` client applies these checks to every connection it
  opens. Only a
  globally routable unicast address is admitted. IPv4-mapped, IPv4-compatible,
  well-known NAT64 (`64:ff9b::/96`), 6to4, and Teredo forms are decoded before
  that check. The local-use prefix `64:ff9b:1::/48` is refused as a whole.
  Other addresses are refused unless the caller allows them. Zero or unbounded size and timeout
  are `invalid_input` at admission. A redirect to another host is refused.
  Three redirects are admitted, including a different port on the same host,
  and a fourth is `invalid_input`. A
  `jwks_uri` on a different host than its metadata document is refused unless
  the caller allows it.
  The response cap is at most 65536 bytes and the timeout is at most 30
  seconds. A parsed `id` is an origin name. It is authorized only when that
  exact string is on a list the host supplies.
  `ServerKeyBinding` admits an Ed25519 or ES256 thumbprint for one canonical
  HTTPS authority. Host case, the path, the query, and port 443 do not make
  another server. Any other port does. The same server may use a second key.
  A key of another algorithm is refused. `sign_request` does not consult
  this binding. For `jkt-jwt` the caller passes the enclave key.
  `verify_discovered_jwt` does not fetch. The host supplies the bytes from
  `{iss}/.well-known/{dwk}` and from `jwks_uri`. `iss` is a bare HTTPS origin.
  The metadata `issuer` must equal the `iss` claim byte for byte. The header
  `kid` selects one JWKS key. That key and `cnf.jwk` are Ed25519 or ES256,
  the key `alg` equals the header `alg`, and the key must verify the assertion
  before `cnf.jwk` is returned. An assertion missing `iss` or `dwk` is
  verified with an Ed25519 or ES256 key the host already holds, and the
  discovery documents are not read.
  Combined field lines and
  repeated dictionary/parameter names use RFC 9651 last-wins parsing. An identical
  repeated Signature-Input member preserves its signature base; changing the
  selected last member requires a new valid proof.
- The local buffered profile computes and verifies SHA-256 Content-Digest for
  nonempty content or a supplied digest, covering Content-Type when present on nonempty content. The hard limit is 1 MiB, checked at signing and verification. Tests pin a
  known digest, changed/removed body, altered type, malformed/missing digest,
  missing coverage and the inclusive limit. This Resource default is additional
  policy, not a claim that Core mandates it for every ordinary Resource API.
  Only a single unparameterized sha-256 digest member is supported. Streaming
  content/trailers, component parameters, general field canonicalization, nonce
  replay storage and complete negotiation are absent. A `keyid` parameter is
  accepted only when it equals the `kid` already carried by the selected
  Signature-Key member (the JWT header `kid`, the direct `jwks` `kid`, or the `jwks_uri` `kid`). The
  verifier still takes the key from Signature-Key. `hwk` has no `kid`, so
  `keyid` on `hwk` is refused, as is a mismatch or a non-string `keyid`; the
  wire code remains `invalid_signature`. The alg signature parameter is ignored. Hosts must bound collection and pass
  actual content before decompression, never an empty placeholder for unread data.
  Identical proof bytes can be accepted repeatedly inside the window; no replay
  cache or application idempotency store is supplied. The Resource fixes label
  sig, a 60-second window and jwt scheme.
- Local signing/verifier clocks and AP-issued iat/exp use the supported range
  0..=8589934591 Unix seconds (through 2242), not contemporary milliseconds.
  This is a local profile bound, not a general NumericDate rule.
- **EMPTY-CONTENT-TYPE:** Content-Type on empty content is outside the conditional
  proof, including when a digest was supplied. A host assigning meaning to that
  field on an empty call must reject that form or use a different explicit
  profile. Ordinary empty requests retain their previous proof behavior.
- **ORIGIN-INPUT:** `for_origin` parses request-origin configuration and accepts
  a root slash. Published server identifiers use strict validation without a
  trailing slash; `metadata_for` never normalizes an invalid identifier.
- **BUFFER-LIMIT-WIRE:** buffered content over 1 MiB returns `invalid_request`,
  distinct from missing coverage (`invalid_input`) and a bad proof/digest
  (`invalid_signature`). The byte ceiling is documented, not negotiated in
  discovery. Hosts should bound collection first; the axum adapter returns 413.
  Covered empty field values follow RFC 9421; signing does not validate media
  type semantics, which remain the receiving application's responsibility.
- **AP-KEY-ROLLOVER:** AP JWKS publication contains exactly one active key.
  Retained old keys, overlap timing and automatic retirement are not implemented.
  The resolver accepts supplied multi-key JWKS and selects by kid; tests prove
  old/new verification during overlap and old-key refusal after removal. This
  resolver behavior is not an AP rotation lifecycle.
- **PS-STATE-PROFILE:** PS exchanges and chains require the exact retained
  Person/Auth issuance, not just a valid signed JWT. This is a local retained-state
  policy; it does not claim Core common JWT verification requires a database.
  The PS retains compact hashes and lineage without publishing internal person
  IDs. `MemoryStore` is volatile. The separate redb adapter supplies immediate-
  durable transactions and tested process recovery, retaining records indefinitely.
  Host adapters run `storetest` for atomic conflicts, concurrency, revocation and
  exact records, plus its separate consuming reopen contract. Neither generic
  contract establishes every backend's durability. `retain_until` is a removal
  minimum, not implemented cleanup; backups, capacity and supported lifecycle
  remain host duties.
  Against Core [Person Token Endpoint retention](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint),
  the retained data exceeds the required jti/aud/exp record: kind, directed
  subject, internal person/Agent identity, tenant, holder thumbprint, compact
  hash and presented/upstream ties. `retain_until` is exp plus the configured
  Resource lifetime bound plus 3660 seconds. This longer local retention and
  exact-record verification requirement are not the draft's minimum revocation
  record or a requirement on interoperating JWT verifiers.
- **PS-DIRECT-PROFILE:** Immediate PS-issued Auth only, with Core scope strings,
  explicit direct/upstream host policy and Resource-directed identity. PS JSON
  requires covered Content-Type and Content-Digest. PS issuance caps Person/Auth
  at one hour and all required parent expiries; Resource challenges default to
  five minutes. Direct construction is PS-only; explicit federation is separate.
  No deferred consent/polling, interaction chaining,
  mission or Budget semantics are inferred from an upstream token.
- **RESOURCE-SCOPE-PROFILE:** One PS/AS authorization Resource value admits one
  nonempty fixed scope profile across its origin; its host router admits paths.
  Scope-free profiles and automatic step-up negotiation are absent. The PS does
  verify an authentic Auth token used as `presented_token` for a later grant.
  AS/PS policy may issue a proper scope subset, but this Resource helper then
  refuses 403 if that subset lacks any configured scope. Host must align its AS
  policy and per-operation Resource profiles; partial grants do not trigger
  automatic step-up negotiation.
- **AGENT-REQUIREMENT-PROFILE:** Agent parses immediate Agent/Person/Auth
  requirements with a 64 KiB combined-field limit. Other values remain
  explicit unsupported errors in that immediate parser. The separate
  `PollSession` helper parses complete 202/402 responses and prepares signed GET,
  clarification POST and DELETE without transport or sleeps. A 202
  `requirement=auth-token` with a nonempty `resource-token` is one of those
  responses; the poll presents a retained auth token whose confirmation key
  matches the Agent. The Resource does not hold the invocation or retain a
  result. It enforces finite
  deadlines and Retry-After/backoff. Final credentials still require verification.
  AS/PS continuation requires explicit with_deferred configuration and separate
  stores; the immediate parser remains distinct from full response parsing.
- PS, AS and signing-Resource helpers also publish one active key. Their multi-key
  overlap/retirement lifecycle is absent, as with AP-KEY-ROLLOVER. Metadata
  advertises only implemented endpoints; branding extensions belong to the host.
- The AP follows the Agent-token 24-hour lifetime SHOULD as an issuance limit.
  Core/Resource verification does not impose that recommendation as a hard
  ceiling on other issuers. Hosts can enforce a stricter lifetime in policy.
- The Resource applies the optional future-`iat` refusal at its 60-second proof
  window. Core token verification alone does not treat `iat` as validity.
  The Resource tests pin acceptance at `iat = now + 60` and refusal at `now + 61`.
  Query coverage is an additional local requirement when a query is present.
- Hosts must supply trusted issuer resolution, DNS/redirect egress admission,
  JWKS cache lifetime, once-per-minute fetch floor and refresh policy. The local
  journeys fetch configured role snapshots and reuse them; they are not open
  Internet discovery/cache clients. Host person authentication and consent policy
  are application responsibilities, not established by a valid Agent proof.
- The real TLS journey demonstrates one immediate downstream hop, not arbitrary
  deployment topology or a general multi-hop interoperability claim. PS release
  checks do not cover time elapsed between later Resource admission and an
  application's eventual effect. Replay, idempotency and rate/capacity policy
  remain host responsibilities.
- These cases do not establish full cross-implementation compatibility or a
  general security audit. Review findings are conformance evidence only when
  executed by cited tests. Cross-check draft findings in other implementations
  before filing with editors.

## Federation clause limits

| Named limit | Pinned Core clause | Behavior and boundary |
| --- | --- | --- |
| **AS-IMMEDIATE-PROFILE** | [AS Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#as-token-endpoint) | Immediate top-level and one-level parent-mediated missionless Core-scope grants. An optional verified subagent_token binds the grant to the child; policy still receives the parent. A mission-bound grant copies the presented token's `mission_s256`. A chained request's `upstream_token` is verified and bounds the grant. Unsupported companion claims fail closed. |
| **AS-DEFERRED-PROFILE** | [AS Response](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#as-response) | AS opt-in claims/clarification/interaction/approval and WWW-Authenticate payment continuations execute with authenticated PS polls. Opt-in PS stores its own continuation, exposes actual AS details to the trusted host and signs one explicit advancement; Agent GET never polls the AS. Default immediate PS still rejects continuation with 502 as_unreachable. Settlement, billing cache and interaction UI/code consumption belong to host policy. |
| **AS-HOST-TRANSPORT** | [PS-AS Federation](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-as-federation), [Auth Token Delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-token-delivery) | Host admits AS discovery and verifies metadata issuer, bounded HTTPS/certificates, DNS/egress/deadlines/no credential redirects. PS validates endpoint syntax, signed exact body and complete returned grant. The example executes genuine admitted TLS. `DiscoveryClient::fetch_metadata` and `send` in `aauth-rust-discovery` are an admitted Internet transport for the adapter; `aauth-rust-discovery/tests/cascade.rs` federates through them. |
| **AS-AGENT-PS-PROFILE** | [Agent Token](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#agent-token), [PS-to-AS Token Request](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-to-as-token-request) | AS requires the authenticated parent/top-level Agent token's optional ps claim to be present and equal the signing PS; absent/different ps is 400 invalid_agent_token before policy. A child's optional ps may be absent but, when present, must equal that PS. This is a tighter shared Go/Rust profile, not a general claim that ps is mandatory in every Agent token. |
| **AS-RETAINED-PROFILE** | [Auth Token Delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-token-delivery) | PS retains every delivered AS Auth in its local exact-lineage policy before release. Optional TokenRecord.person_server preserves PS namespace separately from AS token identity. Older local JSON records remain unchanged; custom adapters must pass the extended contract before federation use. AS retains explicit pending state. With revocation enabled it also keeps an in-memory list of issued auth tokens so a person-token revocation can name them. That list is not an audit log, not a replay cache, and not durable. |

## Deferred profile boundaries

Both roles require separate explicit continuation stores. Pending deadlines are
capped by the original parent Agent, optional child Agent, presented and Resource expiry; long-wait request
refresh/decision reuse is not implemented. A clarification `updated_request` replaces the pending resource token only after the new pair verifies, the resource identity matches the original, and consent allows the replacement. Denied consent leaves the stored request unchanged and does not call the access server.
The supported chat action is `clarification_response`, bounded to five rounds,
plus signed cancellation. AS and PS each retain their own round counter and
absolute question deadline; repeating an unanswered question never restarts it,
and the wire timeout reports remaining seconds. The PS acknowledges a queued
answer with approval while awaiting host advancement, so an identical question
in a subsequent round remains distinguishable. AS 429 intervals accumulate five
seconds per refusal. A queued answer or manual answer cannot bypass a 429/503
retry deadline. Terminal grant checks run after final custody writes/removals,
including current trust, PS binding, pending expiry and remaining token lifetime;
`expires_in` uses that final clock. Claims never request or accept `sub`. Only the
WWW-Authenticate payment profile with empty/JSON body executes; settlement,
per-AS billing caches, user authentication and interaction/code consumption
belong to host policy. No provider or browser UI is supplied.

`MemoryContinuations` is a bounded process fixture, not a durable adapter. Shared
Arc custody survives role recomposition. Hosts implement crash durability,
expired-row collection and reconciliation of uncertain `busy`, `advancing` or
`delivering` transitions; no hidden retry reclaims such a transition. A failed
conditional write never releases an Auth token. PS verified Auth rows already
committed remain retained when subsequent delivery fails, as on the direct path.
Host diagnostics for an AS advancement are returned by `advance_federation`;
local consent refusal before AS discovery/transport attaches
`FederationFailureReason::ConsentRefused(PolicyError)` with no AS status.
The Agent retains the ordinary refusal status/error.
Response extensions are not serialized into the stored Agent wire response.
Missions, recursive delegation, child/upstream chaining, upstream AS authorization,
R3 and companion continuation remain named gaps. Native tests and the real-TLS journey do not imply a shared
deferred harness result; shared measurements are recorded separately.

Authenticated callers that do not own a pending reference receive
`403 wrong_poller`, independently of a real policy/user `403 denied`.
This profile retains `410 gone` for both unknown and consumed references;
it does not distinguish those two histories. An authenticated non-owner can
still distinguish a live reference (`403 wrong_poller`) from an unknown or
consumed one (`410 gone`). This reveals continuation existence to a caller who
has or guesses the pending URL, as in Go. Foreign callers never consume custody. When AS cancellation wins a race, an in-flight response is withheld
with `410 gone`. A PS DELETE during host advancement returns `429 slow_down`;
retry cancellation after that transition. Actual storage failures remain local
`500 server_error`.
After fresh Agent authentication and exact owner matching, a PS poll or DELETE
that finds `delivering` custody returns `429 slow_down` without expiry/trust
cleanup or changing its revision. The delivery owner alone removes its claimed
row and then rechecks release conditions. Deterministic tests pause after the
successful delivery claim, expire the pending deadline or withdraw Resource
trust, and prove that competing GET/DELETE requests retain custody while the
owner returns `408 expired` or `400 invalid_resource_token` without a credential.
Normal contention delivers the exact terminal token once; a genuine final
removal error remains local `500 server_error`, retaining uncertain `delivering`
custody for host reconciliation. These checks do not make resolver, clock and
store operations atomic or provide crash recovery.

Agent-facing PS Retry-After derives from the larger of the PS minimum and the
remaining AS wait. Early polling reports the remaining wait; contention with no
completion estimate uses one second. The host's `federation_pending` view also
reports remaining AS wait and refuses expired/nonwaiting custody. AS 429
backoff adds five seconds while honoring a longer advertised minimum. AS 503
accepts delta seconds or HTTP-date (missing means five seconds); malformed,
duplicate or over-one-hour retry values are `502 as_unreachable` with a host
malformed-answer diagnostic. The Agent helper honors a longer numeric 429
Retry-After; its direct 503 helper accepts delta seconds. Neither helper sleeps.

Interaction URLs reject queries and fragments. Codes require at least eight
Crockford Base32 symbols, with optional hyphens. A code is emitted in upper
case; a received code may be in either case, and redemption also folds `I` and
`L` to `1` and `O` to `0`. This checks
format and length; unpredictability, single use and redemption remain host
responsibilities. `PendingResponse::payment_challenge` parses the Payment
challenge into bill id and optional opaque method/amount/currency fields,
rejecting missing/ambiguous ids and malformed syntax without changing the raw
header or settling a payment.

**AS-GRANT-EQUIVALENCE:** Auth carries neither a Resource challenge identifier
nor a continuation identifier. A previously retained, byte-identical grant can
be accepted by another exchange with the same Person token and otherwise
matching verified context. Reusing its issuer/JTI with a different presented
Person parent conflicts with the retained receipt and returns
`502 as_unreachable` / `InvalidGrant`, rather than a local storage error.
A fresh-JTI equivalent grant has no cryptographic exchange tie either. This is
not a grant replay cache: single terminal delivery applies to each continuation,
and hosts own operation replay protection and application idempotency. Native
`cross_exchange_grant_reuse_is_bounded_by_the_exact_presented_parent` pins both
same-token acceptance and different-token refusal; actual storage unavailability
still returns 500.

**PENDING-PROOF-REPLAY:** There is no signed-request replay cache for pending
URLs. A captured signed Agent GET replayed within the 60-second proof window
can consume the single terminal delivery; the legitimate Agent then gets
`410 gone`. The delivered Auth is still bound to the Agent key, so the captured
request alone does not provide that key. Native
`a_captured_signed_poll_can_take_one_delivery_inside_its_proof_window` pins this
limit. Host transport/logging and replay controls remain necessary.

## Person Server clause limits

These are limits of the implemented profile or duties assigned to its host,
not claims that the cited clauses are fully implemented.

| Named limit | Pinned Core clause | Behavior and boundary |
| --- | --- | --- |
| **PS-PRESENTED-ERRORS** | [Resource Token Verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-verification) | A missing/different retained issuance or recipient Agent is invalid_presented_token. Genuine Resource-versus-presented jti/sub/tenant/PS mismatches remain invalid_resource_token. |
| **PS-IMMEDIATE-DENIAL** | [Polling Error Codes](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#polling-error-codes) | Immediate host PolicyError::Denied retains 403 access_denied. Deferred AS policy denial is 403 denied, relayed by the PS on its pending URL. Expired pending state returns 408 expired; consumed/cancelled state returns 410 gone. A revoked binding on new Person issuance separately returns 403 denied; presented/upstream revocation uses its specific 400 code. |
| **PS-BINDING-REVOCATION** | [Agent Person Binding](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#agent-person-binding), [token errors](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#token-endpoint-error-codes) | Binding revocation blocks new Person issuance with 403 denied, direct exchanges of outstanding Person/Auth with 400 revoked_presented_token, and chains with revoked_upstream_token, including policy/commit races. Binding revocation is separate from token revocation: an Agent Provider revocation of one agent token does not set the binding's revoked flag. |
| **TOKEN-REVOCATION** | [Token Revocation](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#token-revocation) | Opt-in via `with_revocation`. The endpoint is advertised only then. The caller signs as a server; `iss` is the verified signature identity, never a body field. State is `(iss, jti)` in process memory and the first `exp` wins. A revocation POST covers `content-digest` and `content-type`. Empty `200` has no `Content-Type`. A party with nothing downstream, including every Resource and a PS or AS receiving a resource-token revocation, answers immediately and never `202`, including when `Prefer: wait=0` is set. A deferred cascade is `202` with `Retry-After`, `Cache-Control: no-store`, and no `AAuth-Requirement`. The same caller polls with a signed GET, and a poll after the final response is `410 gone`; another caller and an unknown id both receive the same empty `404`. `429 rate_limited` carries `Retry-After`. An Agent Provider revocation is an empty `200`, denies that agent token with `401` `Signature-Error: error=revoked_jwt`, and leaves the binding in place. A revoked person or auth token at a Resource is `401` `error=revoked_jwt` and does not produce a resource token; a revoked auth token also carries `AAuth-Requirement: requirement=person-token`. A revoked resource or presented token is refused before policy, including when the signature is valid and the token is also expired. Downstream delivery is `RevocationDirectory`, told the sender and the recipient's role document. The role crates do not open a connection, fetch JWKS, or persist the ledger; `RevocationClient` in `aauth-rust-discovery` delivers over HTTPS. |
| **PS-SCOPE-ONLY** | [Resource Token Structure](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-structure), [Scopes](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#scopes) | The PS requires a nonempty Core scope string. Missing/empty scope and companion authority claims are refused; a companion claim cannot replace scope in this profile. Every Resource configuration describes each scope its tokens can carry: `scope_descriptions` is required and always published, and a per-call challenge whose class token names an undescribed scope is `403`. PS identity-claim expansion is not implemented. |
| **PS-MISSION-INPUT** | [Person Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint), [Resource Token Verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-verification) | Top-level immediate PS mission consumption is opt-in through Store::missions on the SAME atomic store. MemoryStore supports separately host-approved Active records and refuses a non-active install before writing a binding; unsupported stores (including redb) refuse. The decoder refuses an empty description, a negative approval time, and an expiry that is not strictly after approval. MemoryStore refuses an empty administrative termination reason before any write. Person/Auth issuance checks owner, PS, exact digest, person binding, active state and expiry before/after host work, atomically at retention, and before release. A direct Resource stays missionless unless with_mission_context is set; that opt-in copies the Person digest into the challenge and admits a PS Auth digest to host policy, which must compare it. The challenge may outlive the Person credential. Federated (four-party) and upstream mission paths are supported, chained or not; child mission paths remain unsupported. Mission creation, update, completion, approval and owner audit are opt-in on PS-MISSION-ENDPOINT and are not this issuance record. |
| **PS-MISSION-ENDPOINT** | [Mission Creation](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#mission-creation), [Mission Approval](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#mission-approval), [Mission Update](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#mission-update), [Mission Completion](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#mission-completion), [PS Approval Endpoint Authentication](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-approval-endpoint-auth) | Opt-in `with_missions`. Metadata advertises `mission_endpoint` only then. POST `{mission_endpoint}` requires a signed agent `jwt` and a nonempty `description`; other members are ignored. The proposal is process-local. That POST is `202` with `Location` `{mission_endpoint}/proposal/{id}`, `Retry-After`, and `Cache-Control: no-store`. The proposing agent polls that URL with a signed GET. A pending proposal returns the same `202`. POST `{mission_endpoint}/proposal/{id}/approval` with `decision` `approve` or `deny` must be signed as this Person Server (`jwks_uri`, `aauth-person.json`, this kid). Any other caller, including the proposing agent, is refused and the proposal stays pending. The approval POST records the decision and does not return `s256` or `mission`. The agent's next poll returns `s256` and `mission` once, the unpadded base64url of the exact JSON persisted, and a later poll is `410 gone`. A denied proposal's first poll is `403 access_denied` and a later poll is `410 gone`. A second approval is `404 mission_not_found` and does not write another audit. A token with `parent_agent` is `401 invalid_jwt` and does not create or change a proposal. That JSON contains `agent`, `approved_at` (UTC RFC3339) and `description`. POST `{mission_endpoint}/{s256}` requires `action`. A missing or unrecognized action is `400 invalid_request`. `action=update` requires `description` and appends a new digest without changing the mission digest. `action=completion` requires `summary` and terminates with reason `completed`. Each accepted update is persisted as the update object `{"action":"update","description":...}`, a completion summary as `{"action":"completion","summary":...}`, and the returned or listed `s256` is the digest of those persisted bytes. A missing mission and a different owner both produce the same `404 mission_not_found`, including the same body and header set, on GET and POST. A proposal poll uses one key of agent issuer, subject, and proposal id, so a missing id and another agent's id miss the same way. A signature that does not verify is `401` before either lookup, whether or not that id is stored. Approval reads a proposal id only after this server's signature verifies. A terminated mission returns `403 mission_terminated`. GET `{mission_endpoint}/{s256}` by the owner returns those same `mission` bytes plus accepted updates. MemoryStore and redb persist that audit. redb creates `aauth_ps_missions` and still does not implement issuance `MissionStore`. At most 64 updates are accepted. Each persisted update or summary JSON value is at most 32 KiB. Description and summary text longer than 16384 bytes is `invalid_request`. `person_tokens`, `capabilities` and `mission_control_endpoint` are absent. The library always requires the approval signature; it cannot see a loopback interface, so it does not implement the draft's local-deployment exemption. |
| **RESOURCE-HELD** | [Deferred Delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#deferred-auth-token) | `HeldInvocations` is process memory. `open` draws a 128-bit pending id from the operating system's secure random source and returns it. The host then polls it with an auth token `jti` and that token's `exp`. The first poll at or before `exp` runs the invocation once and stores the status, content type, and body. A later poll with the same `jti` at that pending id returns those bytes through `exp` and does not run the invocation again. A different `jti`, or the same `jti` at another pending id, does not receive the result and does not run the invocation. After `exp`, the stored result is not returned and the invocation still does not run. `authorize` still answers with the stateless `401` challenge. The host chooses this ledger when it holds the invocation. The host verifies the request with `authorize_observed` or `authorize_reserved` and passes that token's `jti` and `exp`. `authorize` on the same request would commit the admitted maximum as well. When budgets are on, the completing call is metered once with `budget_complete_held`. `into_response` on a hold or an observed admission is `500` `server_error` and does not commit. `jti` must match `[A-Za-z0-9_-]{1,128}`.
| **RESOURCE-AUTHORIZE** | [Authorization Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#authorization-endpoint-request) | Opt-in `with_authorization_endpoint`. Metadata advertises `{issuer}/authorize` only then. `POST /authorize` on the signed origin requires a person token in `Signature-Key`. No proof, and a verified agent token, are `401` `requirement=person-token`. A person token that fails verification is `401` with `Signature-Error`. `scope` is required after that verification. A missing or empty `scope` is `400 invalid_request`. An unrecognized scope is `400 invalid_scope`. A duplicate JSON member and a repeated scope token are `400 invalid_request`. A recognized scope returns `200` `{"resource_token"}` whose `ps`, `sub`, `presented_jti`, and `scope` come from the verified person token and the request. An auth token is refused as the wrong token type and does not take the place of the person token. An optional `account` member is ignored. |
| **RESOURCE-SESSION** | [AAuth-Access Response Header](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#aauth-access) | The host binds one `token68` value to one agent subject in a process-memory `SessionLedger`. A response carries that value in one `AAuth-Access` header. The agent retains the latest value and sets `Authorization: AAuth` before signing, so the signature covers `authorization`. `admit_session` verifies that request before admission. A presentation that does not verify is `SessionAdmit::Standalone` and does not return the bound subject. A token bound to another subject, or a token replaced by a later issue, is `Unbound`. Empty values, embedded whitespace, control characters, and more than one credential are rejected and do not replace a retained token. There is no separate refresh request. |
| **PS-GOVERNANCE** | [Interaction Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#interaction-endpoint), [Permission Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#permission-endpoint), [Audit Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#audit-endpoint), [Interaction Code Format](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#interaction-code-format) | Opt-in `with_governance`. Metadata advertises `interaction_endpoint`, `permission_endpoint`, and `audit_endpoint` only then. Each agent POST is a signed `jwt`. Interaction requires `type`. Missing or unknown `type` is `400 invalid_request`. `interaction` and `payment` are relayed through a host `RelayChannel` with `with_interaction_relay`: they need an HTTPS `url` without query or fragment and an interaction `code`, are kept before `202` with `Location: {signed_origin}/interaction/relay/{id}`, and a signed agent GET there answers `202` while waiting, then once `200` `{"status":"interacting"}` or `{"status":"pending"}`, then `410 invalid_code`; another agent's poll is `410 invalid_code`. Without it, or when the channel has none, they are `424 interaction_unavailable`. `question` returns the host answer. Permission requires `action` and returns `granted` or `denied`. Audit requires `mission_s256` and `action`, requires an active stored mission, and returns empty `201`. A missing mission is `404 mission_not_found`. A terminated mission is `403 mission_terminated`. Agent helpers, not a library poller, keep the resource pending URL as the completion signal after a Person Server relay resolves (`InteractionCompletion`) and refuse to proceed on `permission=denied` (`PermissionDecision::may_proceed`). The host supplies an emittable interaction code. Redemption strips hyphens, ignores case, and folds `I`/`L` to `1` and `O` to `0`. A match returns `correlated: true` and does not record a decision. A second presentation is `410 invalid_code`. Three mismatches make later attempts, including the right code, `410 invalid_code`. At or after the pending expiry the presentation is `408 expired`. The decision POST must be signed as this Person Server. An unsigned decision does not act. A signed decision is stored only after that code has been redeemed, a second decision is refused, and `recorded_interaction_decision` returns the stored decision. Codes are process memory. The code routes have no `202`. |
| **PS-RESOURCE-LIFETIME** | [Resource Token Structure](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-structure) | The PS hard-refuses a current Resource token whose lifetime exceeds max_resource_lifetime (default 300 seconds, configurable 1..3600). This is local policy above the five-minute SHOULD, not a draft MUST or an Auth expiry cap. |
| **CHAIN-PS-ROUTING** | [Call Chaining](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#call-chaining) | The host routes using verified upstream Person iss or Auth ps, never the intermediary Agent's ps. The PS verifies that the upstream names itself. There is no automatic Agent HTTP router; the one-PS example deliberately gives the intermediary a different ps and still reaches the upstream PS. |
| **CHAIN-SERVED-REQUEST** | [Call Chaining](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#call-chaining) | The intermediary may use only a token from a request it served. A Person-token request answered with an Auth challenge does not qualify. The PS accepts valid Person upstream evidence but cannot observe a remote handler's served state; host code must enforce this before starting the chain. No synthetic served bit is claimed. |
| **INTERMEDIARY-DISCOVERY** | [Intermediary Agent Identity](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#intermediary-agent-identity) | The library verifies Agent iss equals upstream aud and resolves keys through aauth-agent.json. Host discovery must obtain that intermediary's own-origin Agent metadata with the same issuer as Resource metadata, rather than an unrelated AP. Resolver injection alone does not establish network provenance. The TLS example executes both role documents and a merged JWKS. |
| **DIRECTED-SUB-POLICY** | [Directed Identifiers Across a Chain](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#directed-sub-chaining) | Host policy supplies stable downstream-directed subjects. The PS refuses copying the immediate upstream subject (403 access_denied through typed policy denial); the store enforces stable per-person/resource mappings and per-resource uniqueness. It does not derive HMAC subjects or enforce global inequality across every Resource. Pairwise derivation and prevention of nonadjacent reuse remain host duties. |
| **PS-HOST-METADATA** | [Person Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint) | First-use Resource metadata fetching/presentation and the distinct-resource-per-Agent rate-limit SHOULDs are host duties. The library has neither an outbound fetcher nor that limiter. Sanitize Agent-asserted justification before rendering; there is no library renderer. |
| **PS-ACCOUNT-PROFILE** | [Account Binding](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#account-binding) | PS copies account from a verified Resource challenge. `authorize` emits no account. `authorize_for` may put one account in the challenge and then requires that same account on the Auth token. There is no explicit authorization endpoint or account selector. No application account linking, identity proofing or complete account-flow test claim is made. |
| **PS-REISSUE** | [Auth Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-token-endpoint) | The draft does not make a Resource token single-use. Repeating an identical valid exchange reruns policy and can release another independently retained Auth token with a fresh jti and the same parent bounds. This is not operation idempotency or exactly-once delivery. |
| **ISSUANCE-RELEASE** | [Person Token Endpoint retention](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint) | A committed record can remain after a final expiry/revocation check refuses to release its credential. If the newly issued token expires during the post-commit release window while its inputs remain valid, both immediate direct and federated PS paths return 500 server_error, release no token and retain the committed row. Deferred custody additionally caps its deadline by the retained Auth expiry and returns 408 expired if that deadline elapses before delivery. There is no rollback/delete API; host cleanup follows retain_until. Other parent-expiry/revocation failures keep their typed parameter errors. authorization.rs pins both post-commit modes and absence of AS Auth rows after unverified delivery. |

The TLS application uses a fixed operation and demo admission policy. It does
not establish general caller-body forwarding, a downstream account database or
arbitrary router admission. Native PS tests separately isolate parent lifetime
bounds; the TLS expiry ordering alone is not proof of which cap was decisive.

## Durable storage evidence and limits

The Go comparator is `personserver/storetest/issued_auth_token.go` at sprint
`d914b4f`, with `storetest/doc.go`'s explicit separation of logical contracts
from application restart/transaction/failure tests. This is a comparison of
that issued-token contract, not a claim to implement Go's mission, deferred-
consent, audit, revocation-delivery or other store interfaces.

| Go issued-token guarantee | Rust evidence |
| --- | --- |
| Issuer/JTI namespace, complete retained round-trip and exact retry | `storetest::check_store_contract`, including populated Auth/presented/upstream ties and owned snapshots |
| Each retained field conflicts independently, original preserved after every refusal | Auth scalar and nested issuer/JTI/digest/option-presence mutations; invalid conflicting expiry also pins conflict-before-validation precedence |
| Concurrent same-JTI winner and identical retry linearization | 32 calls start at a barrier; every identical winner succeeds and each differing loser is Conflict |
| Backend persistence is separate from logical conformance | `check_persistence_contract` consumes the only handle twice; concrete adapter recovery and reconstructed PS tests listed above |

Rust also checks its stricter atomic Agent-person binding and stable directed
identity profile, both private indexes after refused commits, and losing token
absence in an eight-caller first-binding race. The optional same-store MissionStore boundary now supports separately approved
missions in MemoryStore. The ordinary issued-token store contract does not certify
that extension; redb does not implement it. No Go mission-lifecycle-store parity is claimed.
The shared shape validator checks identifier syntax and nonempty references/
digests, requires a presented parent for Auth and forbids one for Person. It
does not authenticate parent credentials or verify digest contents. Existing-
record comparison still precedes validation, so a differing malformed retry is
Conflict and cannot rewrite retained state.

**DURABLE-STORE-PROFILE:** one redb 4.4 database owner per file, shared by clones;
five typed schema tables, keyed operations, immediate durability. Schema 1 only;
foreign/incompatible schema is refused without adoption, malformed/miskeyed rows
return Unavailable rather than absent identity. Opening scans engine page
integrity and schema; it does not decode every record or verify its ancestry.
No encryption, migrations, garbage collection, distributed ownership, live-backup
API, database-independent durability proof or other concrete backend is supplied.
Records remain indefinitely, even past retain_until. The host preserves separate
signing keys/unique token IDs and controls filesystem/backups/capacity.

**DURABLE-STORE-GROWTH:** no adapter-enforced bound on total file size or record
count. There is no quota/reclamation mechanism. Hosts provision capacity for all
issuances and stop admission before exhaustion; a filesystem quota only stops
writes. Deleting/rotating the file is not a supported retention/identity-preserving
bound. Go's permission to remove records after ExpiresAt is not implemented;
Rust's later retain_until floor and indefinite retention remain distinct.

**DURABLE-STORE-RECORD-SIZE:** a local 1 MiB encoded UTF-8 JSON limit per retained
record, including escaping, exposed as MAX_RECORD_BYTES. Fresh oversized commits
are InvalidRecord before writes; oversized stored JSON is Unavailable. Encoding
stops at the cap. Exact existing-record comparison precedes shape/size checks,
preserving Conflict on differing retries. This bounds neither caller allocations
nor record count/file size, and is not the shared Store/Go contract or HTTP body
limit. Tests pin 64 MiB refusal without table changes, the exact accepted edge,
one-byte overflow, existing-row conflict precedence and oversized stored rows.

**DURABLE-STORE-CORRUPTION:** every open runs redb check_integrity before schema
access and guards engine open, integrity and metadata parsing against unwinding
panics. Detected page corruption, a reported repair or a caught panic refuses
open with store_unavailable. redb may modify a file while repairing it, even if
the adapter refuses it; preserve a closed copy before diagnosis and restore a
verified closed backup before resuming. Startup cost grows with retained pages.
The tests mutate exact serialized data and 28 page prefixes (single bit/512 zero
bytes); each mutation is refused or leaves the exact retained record intact.
Unused space need not fail integrity checks. Checksums do not authenticate
coherently rewritten rows, and do not protect against external modification
after open. panic=abort, allocation aborts and process signals are not contained.

**DURABLE-STORE-PLATFORM:** this optional adapter requires Unix and a filesystem
supporting directory synchronization. Every open synchronizes the parent after
file/schema initialization, before returning; failure is a typed local
store_unavailable. The host must durably provision the private parent directory.
There is an unacknowledged window after the schema commit and before parent
sync: the initialized file may exist without a durable directory entry; no
usable store has been returned. An open error does not promise no file changes.
Linux syscall evidence checks file-before-directory synchronization; relative-
filename and injected directory-sync refusal tests execute. Non-Unix open is
refused before creating a database. This candidate configures Linux x86_64 CI
and cross-target library checks for ARM64 Linux and Windows MSVC. The configured
Windows check typechecks the redb test target, including its non-Unix refusal
control; that control is not executed on Windows. ARM64, macOS and Windows runtime/storage
qualification is not claimed for this head.
Other protocol crates and custom Store implementations do not depend on this
adapter's platform restriction.

**DURABLE-STORE-IO:** logical refusal leaves all state unchanged. Operational
I/O failure can make a whole transaction's outcome uncertain; PS commit errors
never release a token. The FileBackend test injects one write error and verifies
prior state/recovery and absent partial indexes for that failure. A failed redb
commit latches the live database against further writes on every clone. Hosts
must stop issuance/revocation, drop every owner/handler clone, reopen the same
file and reconstruct the PS. Reads on surviving handles are not the oracle for
the failed commit's durable outcome. No automatic live recovery is supplied.
The fault test pins same-clone write/revoke refusal, last-clone locking and
successful writes/revocation after reopen. Logical refusals do not latch it. Process exit
without destructors is tested; physical power loss and all late-I/O failure
positions are not simulated. There is no claim that every Unavailable means
nothing was committed, or that database durability prevents HTTP request replay.

## Build evidence

Native engineer baseline: Linux x86_64, Rust 1.99.1, source `91d61ea`.
`cargo test --locked`, the optimized TLS example, formatting and clippy with
warnings denied pass there. This follow-up preserves those runtime and test
bytes; its own CI checks the exact submitted head.

[CI](.gitlab-ci.yml) uses the `sprint-gen6` Docker runner, pinned Rust 1.99.1 and
two Cargo build jobs. The Linux x86_64 job retains all workspace checks/examples
and the optimized Linux demo binary for 14 days as a build artifact, not a
published release. It additionally installs target standard libraries in its
container and runs these compile-only checks:

| Target | Configured check | Limit |
| --- | --- | --- |
| ARM64 Linux (`aarch64-unknown-linux-gnu`) | All workspace libraries | Typechecking, no foreign application linking or execution |
| Windows MSVC (`x86_64-pc-windows-msvc`) | All workspace libraries and redb tests | Non-Unix refusal test compiled, not executed; adapter remains unsupported at open |

The cross-target commands use `cargo check` and do not build the Resource TLS
development targets. They require the host toolchain and target Rust standard
libraries; no target C compiler or runtime is exercised. Linux runtime results
and foreign-target metadata checks are distinct evidence. No macOS build/run or
ARM64/Windows native test result is claimed, and older platform/shared-wire
receipts remain tied to their original revisions. To verify packaging without
uploading crates, run `cargo publish --workspace --dry-run --locked` with an
unused `CARGO_TARGET_DIR` for repeated checks of unchanged alpha versions.

## Host-approved mission consumption evidence and limits

Selected source: Core70d6737 Mission Approval/Identifier, Person Token Endpoint/
Structure, Resource Token Verification, Auth Token Structure/Verification, Mission
Management/Status Errors and Scopes (see SPECIFICATIONS.md). Core's ApprovedMission
keeps exact decoded bytes and canonical s256/base64url, ignores additive/legacy
content for authority, and parses RFC3339 timestamps. It refuses an empty
description, a negative approval time, and an expiry that is not strictly after
approval. `install_approved_mission` refuses a record that is not Active and
writes no person binding for that call. PS tests in `tests/missions.rs`
exercise real public Person/Auth requests, private person ownership, expiry caps,
substitution/stripping, host grant broadening and policy/commit races. Resource
tests exercise the opt-in challenge copy and the host comparison of the Auth
digest. The default Resource still refuses a mission before policy. Executed
results belong to exact retained run receipts, not merely these source files.

`MemoryStore::install_approved_mission` supplies already-approved host state and
an independently authenticated private person binding. It is not mission creation,
a PS login interface or proof that a human approved the text. The reference store
is volatile; custom mission stores must compare and commit under the same atomic
boundary and invalidate approvals on binding replacement. Termination is permanent
and expiry is materialized. A completion accepted at the mission endpoint ends
issuance under the mission in the same store step: `/person` and `/token` naming
it answer `403 mission_terminated` with `termination_reason` `completed`
(`tests/missions.rs`). `terminate_mission` records its reason in the endpoint's
audit row as well. Already issued Resource Auth admission has no automatic
mission-state/revocation channel; the host must supply current enforcement where
needed. No blanket cascade is added. An opted-in Resource sees the authenticated
digest and Core scopes, not private mission text. The default Resource refuses
the digest before policy. A generic frozen-revision handler is
application policy, not an invented protocol proposal claim.

This slice does not add AS, child/chained/federated missions, deferred mission
approval, mission proposal/review UI, permission endpoints, R3 or full latest
conformance. Existing missionless shared results retain their original suite
identity; a new mission suite is separately attributable. See INTERPRETATIONS.md.
