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
| RFC 8032/8037, RFC 7638 | Ed25519 signing and strict verification; public-only OKP JWK; fully specified algorithm and key-shape checks; thumbprint | `aauth-rust-jose/tests/jose.rs` (9 tests, including RFC 8032 empty-message signature vector) |
| One-level sub-agents | Actual parent and child AP signatures, authoritative parent_agent, same provider, single depth and distinct proof keys; parent signs PS requests, owns consent/binding/polls, child holds Person/Auth and signs Resource requests; local and immediate/deferred AS grants; exact retained parent/child identity and parent revocation | Core `subagents.rs` (7), AP `subagents.rs` (4), Agent `subagents.rs` (8), PS/AS endpoint cases, memory/redb contracts, Resource `subagent_revocation.rs` (2) and buffered native `subagent` example (8 separate example tests) |
| Explicit Agent polling | Signed GET, clarification POST and cancellation DELETE preparation; required waits, 429 linear backoff, 503 retry interval, stable same-origin Location and terminal completion; host dispatches requests and verifies final credentials | `aauth-rust-agent/tests/polling.rs` (10 tests) |
| PS deferred federation | PS-owned signed Agent GET/clarification POST/DELETE, explicit signed AS advancement, exact original-token retention, independent grant verification and atomic delivery; payment/claims stay host-side; revocation/expiry/concurrency refuse | `aauth-rust-person-server/tests/authorization.rs` (66 tests, including 33 deferred cases), deferred TLS journey |
| AS deferred authorization | Explicit policy for 202 claims/clarification/interaction/approval or 402 payment, independently authenticated PS polls, exact retained tokens, bounded claims/chat, atomic single-consumer result, cancellation/expiry and rechecked issuer trust; native PS continuation verified separately | `aauth-rust-access-server/tests/endpoint.rs` (34 tests, including child approval/payment, trust/expiry fences and omitted presented_token) |
| Deferred wire and state primitives | Bounded 202 claims/clarification/interaction/approval and 402 payment parsing, same-origin pending URLs, host-owned settlement details, atomic revision transitions and one-consumer removal; separate AS/PS role custody | `aauth-rust-core/tests/continuation.rs` (14 tests), `payment.rs` (10 tests) |
| RFC 7515 | Compact JWS, exact signed segments, no unsupported critical headers or unencoded payload profile; duplicate JSON members refused | Same JOSE tests |
| Signature-Key | `hwk`, `jwt`, explicit `jwks_uri`, selected-label correlation, required key coverage, unknown unselected scheme ignored, defined unsupported-scheme/algorithm errors | `aauth-rust-signature-key/tests/proofs.rs` (28 tests), TLS journey |
| RFC 9421 / AAuth Signing | Buffered requests covering method, authority, path, Signature-Key; query and Authorization coverage when present; exact ±60-second `created` window; canonical field values (outer OWS trimmed, repeated lines combined) | Proof tests, independently stated signature-base fixture |
| Agent token / Common Verification | `aa-agent+jwt`, `Ed25519`, named issuer key, expected `dwk`, required claims, exact identifiers, `exp` without leeway, `nbf`, public confirmation key, optional PS syntax | `aauth-rust-core/tests/agent_tokens.rs` (17 tests) |
| Person, Resource and Auth tokens | Role-specific typ/dwk, required and forbidden claims, public confirmation keys, exact signed bytes, Person/Auth one-hour ceiling and expiry/nbf; Core verification does not grant application access | `aauth-rust-core/tests/role_tokens.rs` (10 tests) |
| AP metadata and JWKS | Exact issuer binding; HTTPS JWKS location with terminal invalid_key for unusable metadata; reject foreign issuer with invalid_key separately from rotation; select only named kid, tolerate unselected unsupported keys; host-retained snapshot | Core tests; AP discovery over TLS |
| Direct Agent identity | Unsigned request challenge; token plus proof before policy; `hwk` receives defined scheme rejection; wrong key refusal; exact endpoint or explicit origin binding before policy; denial after valid authentication; Date from verifier time on clock_skew | `aauth-rust-resource/tests/identity.rs` (30 tests), `response_mapping.rs` (2 tests), TLS journey |
| Resource metadata | Explicit published issuer separate from signed authority/port, agent-token access and 60-second window; no fictitious JWKS/authorization endpoints; invalid publication settings return a local configuration error | Resource and axum metadata tests |
| Framework adapter | Origin-form URI reconstruction from configured HTTPS origin, typed policy context, custom success response, wrong-origin proof refusal and bounded actual-body handling; canonical metadata publication with a nondefault signed port | `aauth-rust-resource/tests/axum_service.rs` (5 tests), executable axum example |
| Local composition | Fresh random AP/Agent keys; certificate-verified loopback TLS; AP metadata/JWKS retrieval; Resource outcomes | `aauth-rust-resource/tests/loopback_tls.rs` (1 test, 14 checks) |
| Person binding / PS token endpoints | Agent proof and covered JSON before policy; case-insensitive JSON media type without rewriting covered bytes; stable directed identities; issuer-scoped atomic records and binding; exact presented lineage; distinct invalid/revoked presented-token errors; scope narrowing; expiry and binding rechecked after policy/storage; no release before commit; repeatable valid exchanges with fresh retained Auth issuances | `aauth-rust-person-server/tests/endpoints.rs` (2 tests), `authorization.rs` (33 non-deferred tests, plus the mixed-grants composition test), `store.rs` (6 tests for logical/persistence contracts, detection fixtures and shared serialization/validation) |
| Durable PS store adapter | Same logical contract as MemoryStore; actual close/reopen, issuer-qualified records, exact retry/conflict ordering, sticky revocation; schema/row errors; reconstructed direct/chained PS flows | `aauth-rust-person-server-redb/tests/backend.rs` (10 tests), `service_restart.rs` (2 tests), crate rustdoc |
| Page corruption / bounded records | Exact data-byte checksum failure and 28 page-prefix bit flips/zeroings never escape open as a panic or bad record; 1 MiB accepted, one-byte overflow and 64 MiB refused without table writes; empty binding refused on read/commit/revoke | `aauth-rust-person-server-redb/tests/corruption.rs` (2 tests), backend tests |
| Backend transaction recovery | Acknowledged commit survives process exit without Drop; staged uncommitted real transaction stays invisible; injected native FileBackend write error preserves prior state and exposes no partial indexes | `aauth-rust-person-server-redb/src/failure_tests.rs` (3 parent/unit tests; 1 ignored child entry invoked by parents) |
| Durable file creation / record shape | Parent directory synchronized after file/schema initialization; sync failure refuses open; bare filenames use current directory. Both stores reject malformed Agent identities, parent ties and Person/Auth lineage without leaking state; durable decoder refuses malformed rows | `aauth-rust-person-server-redb/src/open_tests.rs` (2 Unix tests), shared store contract/validation and backend row tests; Linux syscall witness |
| Resource PS authorization / Agent response verification | Person is identity, never authorization; signed Resource challenge; intended PS/audience/key/presented-token ties; Auth route scopes before typed policy; `authorize_for` checks the Person Server (`iss` on Person, `ps` on Auth) together with `sub`, `account` and `tenant`; a verified mismatch is `403` `access_denied` with no `Signature-Error`, and `login_hint` or a missing subject is not authorization; Agent verifies challenge and delivery context; specific wrong-audience diagnostics with pinned invalid_jwt wire code; named captured policy types | `aauth-rust-resource/tests/ps_authorization.rs` |
| Requirement extraction | RFC 9651 dictionary and combined field lines; immediate Agent/Person/Auth requirements; exact decoded resource-token; ignore extensions; refuse malformed or unsupported requirements; omit credentials from Debug | `aauth-rust-agent/tests/requirements.rs` (6 tests), used by the three-party TLS scene |
| Immediate AS federation | Admitted PS jwks_uri proof plus independent Agent/Resource/presented verification before AS policy; context/scope/parent bounds; PS consent, exact forwarding, returned-grant verification/retention and AS Auth step-up; no direct-mode fallback under collocation | AS endpoint base cases (7, including omitted presented_token), PS authorization tests, Resource federation/role test and `four_party_tls.rs` (2 tests: immediate and deferred, including exact forwarded bytes and problem codes) |
| Federated retained namespace | AS issuer/JTI identifies the credential; explicit PS namespace owns binding/directed identity; exact presented ancestry, conflicts/revocation and reopen | Updated public storetest and persistence contract, MemoryStore and RedbStore |
| Immediate call chaining / original person | Exact upstream ties in Person, Auth and Auth step-up; original binding revocation; intermediary self-issued identity; separate directed subjects; no intermediary binding; default-denied chain hooks | PS authorization tests; `aauth-rust-resource/tests/three_party_tls.rs` (2 application/TLS tests, including identical-POST replay) |

Snapshot ownership and absence of network fetching are architecture properties
checked by source inspection of `aauth-rust-core/src/discovery.rs`; they are not
additional protocol test results. The example's listener/thread cleanup follows
its owned Drop implementation, also checked by inspection.

The 14 checks are AP metadata, AP JWKS, unsigned challenge, accepted identity,
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

**R3-FULL-COMPLIANCE:** postponed by vocabulary. The current Rust Core-scope
profile has no R3 authorization vocabulary. General-purpose media/service
vocabularies may be defined in R3 and implemented in both Go and Rust on demand,
one test at a time; full compliance remains unclaimed. Application-specific
formats belong to the application. Unsupported R3 claims fail closed in this
profile rather than conferring scope authority.

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
Already delivered credentials retain their signed expiry; AP-token revocation
transport, per-child token revocation, cascades and automatic Resource revocation
are absent. No `revoked_subagent_token` result is claimed without such a source.
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
  Session tokens, enrollment, revocation transport/cascades, recursive delegation,
  mission creation/management and permission/interaction/audit endpoints do not execute.
  Separately host-approved top-level immediate PS mission consumption is
  available through the optional same-store boundary described below. A direct
  Resource stays missionless unless `with_mission_context` is set. Other
  unsupported PS parameters are refused explicitly.
- No R3, Events, Budgets, Bootstrap or Supervision behavior. Pinning a document
  does not imply implementing it.
- Ed25519 only. Other algorithms, private/HSM signer adapters and remaining
  Signature-Key schemes are absent. Verifiers select the configured `sig` label;
  this is not general multiple-signature policy. Combined field lines and
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
  replay storage, keyid and complete negotiation are absent. keyid is refused;
  the alg signature parameter is ignored. Hosts must bound collection and pass
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
  clarification POST and DELETE without transport or sleeps. It enforces finite
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
| **AS-IMMEDIATE-PROFILE** | [AS Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#as-token-endpoint) | Immediate top-level and one-level parent-mediated missionless Core-scope grants. An optional verified subagent_token binds the grant to the child; policy still receives the parent. Upstream parameters, missions and unsupported companion claims fail closed. PS-issued three-party chaining remains available in direct mode; AS call chaining is absent. |
| **AS-DEFERRED-PROFILE** | [AS Response](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#as-response) | AS opt-in claims/clarification/interaction/approval and WWW-Authenticate payment continuations execute with authenticated PS polls. Opt-in PS stores its own continuation, exposes actual AS details to the trusted host and signs one explicit advancement; Agent GET never polls the AS. Default immediate PS still rejects continuation with 502 as_unreachable. Settlement, billing cache and interaction UI/code consumption belong to host policy. |
| **AS-HOST-TRANSPORT** | [PS-AS Federation](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-as-federation), [Auth Token Delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-token-delivery) | Host admits AS discovery and verifies metadata issuer, bounded HTTPS/certificates, DNS/egress/deadlines/no credential redirects. PS validates endpoint syntax, signed exact body and complete returned grant. The example executes genuine admitted TLS; no general Internet transport is supplied. |
| **AS-AGENT-PS-PROFILE** | [Agent Token](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#agent-token), [PS-to-AS Token Request](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#ps-to-as-token-request) | AS requires the authenticated parent/top-level Agent token's optional ps claim to be present and equal the signing PS; absent/different ps is 400 invalid_agent_token before policy. A child's optional ps may be absent but, when present, must equal that PS. This is a tighter shared Go/Rust profile, not a general claim that ps is mandatory in every Agent token. |
| **AS-RETAINED-PROFILE** | [Auth Token Delivery](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#auth-token-delivery) | PS retains every delivered AS Auth in its local exact-lineage policy before release. Optional TokenRecord.person_server preserves PS namespace separately from AS token identity. Older local JSON records remain unchanged; custom adapters must pass the extended contract before federation use. AS retains only explicit pending state in this profile, with no issued-JWT audit/revocation or replay cache. |

## Deferred profile boundaries

Both roles require separate explicit continuation stores. Pending deadlines are
capped by the original parent Agent, optional child Agent, presented and Resource expiry; long-wait request
refresh/decision reuse and clarification `updated_request` are not implemented.
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
case-insensitive Crockford Base32 symbols, with optional hyphens. This checks
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
| **PS-BINDING-REVOCATION** | [Agent Person Binding](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#agent-person-binding), [token errors](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#token-endpoint-error-codes) | Binding revocation blocks new Person issuance with 403 denied, direct exchanges of outstanding Person/Auth with 400 revoked_presented_token, and chains with revoked_upstream_token, including policy/commit races. There is no individual token/Agent-token revocation set, cascade or Resource revocation delivery; an already issued Auth token still verifies at a Resource until expiry unless the host adds that state. |
| **PS-SCOPE-ONLY** | [Resource Token Structure](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-structure), [Scopes](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#scopes) | The PS requires a nonempty Core scope string. Missing/empty scope and companion authority claims are refused; a companion claim cannot replace scope in this profile. Resource hosts can opt into exact configured scope descriptions with with_scope_descriptions; PS identity-claim expansion is not implemented. |
| **PS-MISSION-INPUT** | [Person Token Endpoint](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#person-token-endpoint), [Resource Token Verification](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#resource-token-verification) | Top-level immediate PS mission consumption is opt-in through Store::missions on the SAME atomic store. MemoryStore supports separately host-approved Active records and refuses a non-active install before writing a binding; unsupported stores (including redb) refuse. The decoder refuses an empty description, a negative approval time, and an expiry that is not strictly after approval. Person/Auth issuance checks owner, PS, exact digest, person binding, active state and expiry before/after host work, atomically at retention, and before release. A direct Resource stays missionless unless with_mission_context is set; that opt-in copies the Person digest into the challenge and admits a PS Auth digest to host policy, which must compare it. The challenge may outlive the Person credential. AS/federated, child/upstream mission paths and mission creation/management endpoints remain unsupported. |
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
and expiry is materialized. Already issued Resource Auth admission has no automatic
mission-state/revocation channel; the host must supply current enforcement where
needed. No blanket cascade is added. An opted-in Resource sees the authenticated
digest and Core scopes, not private mission text. The default Resource refuses
the digest before policy. A generic frozen-revision handler is
application policy, not an invented protocol proposal claim.

This slice does not add AS, child/chained/federated missions, deferred mission
approval, mission proposal/review UI, permission endpoints, R3 or full latest
conformance. Existing missionless shared results retain their original suite
identity; a new mission suite is separately attributable. See INTERPRETATIONS.md.
