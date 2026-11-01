# Selected mission interpretations

Source: Core70d67375deb0bb002af7da0711fc58f6e8926e7e, as recorded in
SPECIFICATIONS.md. These choices concern the bounded immediate PS/Resource path.

- ISO8601 mission timestamps use the RFC3339 profile, including offsets and
  fractions. Integer JWT expiry uses the floor of the mission timestamp, so a
  fractional expiry cannot extend authority; the reference store treats that
  conservative integer boundary as terminated. Exact timestamp bytes are retained.
- The approving PS is authenticated beside s256, never from legacy approver
  content. Unknown members preserve their original bytes and confer no authority.
  Duplicate JSON members at any depth are rejected as ambiguous input.
- A host-approved record includes a PS-private authenticated person ID as well
  as the full AP/Agent identity. Mission text, text assent or a token supplied
  by an unauthenticated host caller cannot establish Person approval. Installation
  is host administration; Policy still chooses the directed identity and grant.
- An unknown or wrong-owner reference at the Person token endpoint returns
  invalid_request; the selected endpoint error table supplies no distinct code
  there. The mission endpoint returns the same `404` `mission_not_found`, body,
  and header set when the mission is absent and when it belongs to a different
  authenticated agent. A proposal poll and a mission read or update each look
  up one owner-qualified key, so those two misses are the same path. The draft
  does not define a cycle bound; this profile treats that single lookup as the
  timing equivalence. A request whose signature does not verify is refused
  before that lookup, whether or not the path names a stored mission. Approval
  reads a proposal id only after this Person Server's signature verifies.
  Owned terminal missions return mission_terminated with mission_status
  terminated and an opaque termination_reason. The reason never permits
  reactivation. An empty reason is refused before the record changes; the draft
  does not define the empty string.
- A completion the mission endpoint accepts ends issuance under that mission.
  The draft has one mission state: Mission Completion (line 1505) terminates
  the mission with reason `completed`, Mission Management (line 1514) and
  Mission Status Errors (line 1550) refuse a terminated mission at every PS
  endpoint, and Person Token Endpoint (line 810) and Resource Token
  Verification step 4 (line 768) require it to be active. This library keeps
  the endpoint's audit row and the issuance `MissionRecord` apart, so a
  termination recorded in the audit row is read as a termination of the
  issuance record in the same atomic step, and `/person` and `/token` answer
  `403 mission_terminated` with `termination_reason` `completed`. The other
  way round, `MemoryStore::terminate_mission` writes its reason into the
  audit row, so the mission endpoint answers `mission_terminated` too; it
  refuses a reason longer than the audit row's 256 bytes before any write.
- Store::missions is optional and closed by default; mission checks and issuance
  retention must be atomic in the same store. Expiry/termination/revocation during
  policy or commit withholds credentials even if an internal issuance row was
  already retained. No rollback claim is made after an uncertain commit. Stores
  supporting administrative binding replacement must invalidate old approvals.
- A Resource challenge is not a grant and may outlive a Person credential/mission.
  Issuance/redemption still require current inputs. Person/Auth expiry remains
  bounded by the mission and verified parent credentials. Resource host policy
  owns operation/revision/payload enforcement and any current revocation channel.

AS, children, chaining, human review, creation and deferred mission control are
not implemented by this profile. This is no full R3/latest-edition qualification.

# Selected budget interpretations

Source: `draft-hardt-aauth-budgets` at `70d67375deb0bb002af7da0711fc58f6e8926e7e`.
These choices are what the opt-in profile executes. They are not a claim that
the draft required each spelling.

- The draft does not name a request header for the caller's maximum cost.
  Buffered admission reads one bare Structured Field integer from
  `AAuth-Max-Cost`. The host's `default_bound` is the maximum. The client
  header may only lower it. A higher client figure does not raise the bound.
  A client figure of zero does not admit the host's work. When the header is
  absent, the metered cost is `default_bound`. A malformed header is a
  refusal of the call: the grant is not drawn down, and `AAuth-Budget` still
  reports the untouched remainder.
- `"$5.00"` does not specify rounding or a currency symbol. USD amounts render
  with a leading `$` and two digits, half-up from the signed scale. The amount
  string and the description stay separate values. There is no wire field for
  "visually distinct." The draft says the unit description is Markdown and
  that an implementation must sanitize it before rendering. This profile does
  not render Markdown. `description_text` produces plain text: it HTML-escapes
  `&`, `<`, `>`, `"`, and `'`, removes control characters and bidi formatting
  characters, collapses whitespace, and caps the normalized text at
  `DESCRIPTION_TEXT_LIMIT` (1024) scalar values, ending a longer description
  with `…`. It does not decode character references or rewrite links.
- A usage response that mixes units reports the first declared unit. It does
  not convert. A counter that would exceed 15 digits is omitted. When
  `all_time` would exceed that limit, or is zero, the `usage` object is
  omitted. An unrecognized scope key also omits `usage`, so those two cases
  are not distinguished on the wire. A caller who has not appeared on an
  accepted token is the same `200` with `usage` omitted, not `403`. A caller
  who has appeared still does not receive another caller's `tenant`,
  `mission_s256`, or key thumbprint.
- A JSON number that is not an integer in the i64 range, including `1.0`, is
  malformed. It is not rounded.
- Duplicate `budget_units` names are rejected at configuration. An empty unit
  cache accepts the scale signed on the token. A step-up offer uses the scale
  declared now. `budget_consumed` is included only when the locked grant uses
  that unit and those decimals. Metering of an already issued token stays on
  the signed scale.
- Authorization-endpoint decimals mismatch is not in the error table. This
  profile returns `400` `invalid_budget` and does not rescale. The same code
  is used for an unknown unit, a malformed budget object, and an access-server
  parameter that does not narrow the resource offer.
- When the agent omits `budget`, the resource offers `min(max, default_offer)`
  of the first declared unit. The draft does not say which offer that is.
- An auth token that carries `budget` while budgets are off is still rejected
  as an unsupported companion claim. Opt-in is per server.
- The usage response is signed in this crate. Signature-Key's `sign_request`
  covers a request. The response coverage is `@status`, `content-type`,
  `content-digest`, `@authority;req`, and `@path;req`. The response also
  sends `Cache-Control: no-store`. That field is outside the signature base.
  A parser still accepts an unsigned usage body. The resource's `usage`
  method always signs.
- `IssuerPolicy::omit_above` omits the four-party PS-to-AS parameter when the
  resource offer amount is above that limit. It does not apply to three-party
  issuance: the person server still narrows the offer and counts the grant.
  Omitting the claim there would leave this library's resource serving the
  token unmetered, and the ceiling would not count it. An offer equal to the
  limit is still narrowed to the cap. The standing ceiling is separate: a
  later grant is narrowed by outstanding allocations for that subject at that
  resource. `clear_outstanding_budgets` is a hidden conformance hook. It drops
  every live allocation for every subject. Tokens already issued stay valid,
  and the next grant sees the full cap. The conformance adapter calls it when
  a scenario starts, so one process does not carry the ceiling across
  scenarios. It is not an HTTP route.
- A federated Person Server relays a per-call proposal that offers a budget,
  as aauth-go does ("A per-call token's budget meters the release of a held
  result" in its INTERPRETATIONS.md, main `0e2447b`). R3 Approving Release
  Rather Than Execution (lines 688-723) and Budgets Resource Token, PS-to-AS
  Token Request and Auth Token Extensions (lines 425-452, 542-572, 574-608)
  do not say whether a per-call proposal's Resource token or its per-call
  Auth token may carry `budget`; both libraries read that they may. Go's nine
  steps, as this library takes them: (1) the Agent presents the proposal's
  Resource token with the class Auth token it called with, and `budget` in
  `capabilities`; (2) the PS verifies the Resource token's R3 reference and
  `budget`, checks the offer against its declared units (`invalid_budget`
  otherwise), fetches the proposal and asks `R3Policy::authorize_proposal`,
  which sees the offer on the verified Resource token; (3) the ceiling is the
  offer narrowed by `IssuerPolicy` (cap and outstanding grants), or nothing
  above `omit_above`; (4) the PS-to-AS request carries `budget` with the
  ceiling, and omits it when there is none; (5, 6) the Access Server checks
  the offer, grants within the ceiling and signs the per-call token with
  `budget`, which this library's Access Server does not do, since it has no
  R3; (7) the PS verifies the per-call token with the budget profile when it
  sent a ceiling and without it when it did not, and refuses a missing,
  extra, wider or re-denominated `budget` with `502 as_unreachable`;
  (8) an Access Server `202` or `402` is refused with `500 server_error` and
  nothing is written when deferred custody is enabled, and is `502
  as_unreachable` without it, as for any deferred answer the PS cannot hold;
  (9) the Agent's R3 helpers leave the budget check to the host
  (`verify_budget_resource_token`, `verify_budget_per_call_auth_token`). Where
  Go keeps no allocation ledger across tokens, this PS counts the relayed
  grant against its cap, as for every federated budget; that is not on the
  wire. A three-party Person Server still grants the release budget itself.
- This library is not an intermediary, so it does not implement a rule about
  rewriting `AAuth-Budget` in transit. The RateLimit and TPX passages cited
  with normative keywords sit in non-normative prior art and are not executed.

# Selected token, identifier and signature interpretations

Source: protocol and `draft-hardt-httpbis-signature-key` at the pins in
SPECIFICATIONS.md.

- **`aud` as an array.** Resource Token Structure (line 742), Person Token
  Structure (line 867) and Auth Token Structure (line 1778) give `aud` one
  URL, and Common JWT Verification (line 2313) verifies per RFC 7519, whose
  `aud` may be an array. Person, Resource and Auth tokens are read with `aud`
  as a string or a one-element array, which other implementations write; an
  empty array or one with two or more members is `invalid_jwt`. Tokens this
  library mints carry the string.
- **`+` in an agent identifier.** Agent Identifiers (lines 488-490): a
  top-level local part has no `+`, and a sub-agent's is its parent's local
  part, `+` and a non-empty discriminator. Sub-Agents (line 1915) allows one
  level, so a parent local part never holds `+`. `validate_agent_identifier`
  therefore refuses a local part that starts or ends with `+` or holds more
  than one. It checks syntax only: which parent a sub-agent has comes from
  `parent_agent`, never from the identifier (line 490).
- **A key whose type the verifier does not implement.** Signature-Key
  Algorithm Determination (lines 225-233) and protocol Verification (Server)
  step 6 (line 2249) make it `unsupported_algorithm`. Under `jwks_uri`,
  `jwks`, `jwt`, `jkt-jwt`, `self-jwt` and `cached` the algorithm is known only
  once the key is resolved, so `PreparedRequest` and `PreparedResponse` no
  longer refuse a signature whose length is not 64 bytes before then; `verify`
  checks the length against the resolved key. An ML-DSA-44 signature under a `jwks_uri` member that
  selects an `AKP` key is `unsupported_algorithm`, not `invalid_signature`.
- **`Accept-Signature-Scheme` per endpoint.** Verification (Server) step 4
  (line 2247) names "the schemes the server accepts"; Signature-Key Scheme
  Rejection (line 2266) says the header states what the server accepts from
  any caller. The R3 document endpoint accepts only `jwks_uri` (R3 Document
  Access Restriction, line 729), so its `unsupported_scheme` refusal names
  `jwks_uri`, not the Resource's `jwt`.

# Selected supervision interpretations

Choices `draft-hardt-aauth-supervision` leaves open, as the supervision server
and the Person Server in this workspace make them.

1. **Connect answers.** `200 {"status":"connected"}`; `disconnect` → `200 {"status":"disconnected"}`. The PS accepts any `200` body.
2. **Connect pending.** `202`, `AAuth-Requirement: requirement=interaction; url="<interaction_url>"; code="XXXX-XXXX"`, `Location: {origin}/connect/pending/{id}`, `Retry-After: 5`, `Cache-Control: no-store`, body `{"status":"pending"}`. Poll (signed GET by the same PS): the same `202`, then `200 {"status":"connected"}`; a refusal `403 denied`; past its lifetime `408 expired`; unknown or consumed `410 invalid_code`; another PS `404 unknown_pending`.
3. **Connect request.** `{"action":"connect","id":"c-<128-bit b64url>","iat","sub","tenant"?}` with `Prefer: wait=30`, no `Accept-Signature`.
4. **Deferred decision.** `202` with no `AAuth-Requirement`, body `{"sdi","status":"pending"}`, `Location: {origin}/pending/{id}`, `Retry-After: 5`, `Cache-Control: no-store`. The PS also accepts `requirement=approval`.
5. **Clarification.** `202`, `AAuth-Requirement: requirement=clarification`, `Retry-After: 0`, body `{"sdi","status":"pending","decision":"clarify","clarification","timeout"?,"options"?}`.
6. **Clarification reply.** The PS POSTs `{"action":"clarification_response","clarification_response":"..."}`, or for an auth token act `{"action":"updated_request","resource_token","presented_token","justification"?}`, to the SS pending URL. The SS answers that POST with its current state: the decision (`200`, signed for that POST) or `202`. `DELETE` → `200 {"status":"cancelled"}`.
7. **What a signed decision covers.** `@status`, `content-type`, `content-digest`, then each component the PS lists in `Accept-Signature` that the SS can produce, in the PS's order: `@method;req`, `@authority;req`, `@path;req`, `@query;req` (only with a query), `content-digest;req` and `content-type;req` (only when present), `signature-key`. Without `Accept-Signature`: the draft's six for a POST, five (no `content-digest;req`) for a GET. Label `sig`; `Signature-Input` carries `created` and `keyid`. `signature-key` is not covered by default, as in the draft example.
8. **What the PS asks for and checks.** `Accept-Signature: sig=("@status" "content-type" "content-digest" "content-digest";req "@authority";req "@path";req)` on supervision POSTs; `sig=("@status" "content-type" "content-digest" "@authority";req "@path";req)` on polls. It requires the three MUST components and verifies every covered `;req` against its own request. `Signature-Key` must use `jwks_uri`, with `id` equal to the issuer of the SS it called and `dwk` `aauth-supervisor.json`. It refuses a `created` more than 60 s ahead and has no lower bound.
9. **Repeats under one `sdi`.** Decided at once: the exact stored bytes, original signature included. Decided after a deferral: the decision signed afresh for the repeated request. Still pending: `202` with the same `Location`. The same `sdi` for a different act or agent is `invalid_request`.
10. **Errors.** `application/problem+json` `{"type":"about:blank","title","status","error"}`; `rate_limited` always carries `Retry-After` (default 5). A request whose signature fails is `401` with `Signature-Error: error=<code>`. A PS the key resolver does not trust is `403 unsupported_iss`; a trusted PS without a connection for the `sub` is `404 unknown_sub`.
11. **Pending lifetime.** An undecided pending URL at the SS answers `unknown_pending` after `pending_lifetime` (default 3600 s), not `408 expired`.
12. **Identifiers.** `sdi` = `d-` + 22 base64url chars (128 bits). Event and report `id` = `e-` + 22. Connect `id` = `c-` + 22.
13. **Mission reports.** `approved`: `{"action":"approved","id","sdi":<proposal sdi when the SS allowed it>,"iat","sub","agent","s256","mission"}`, no `mission_s256`. `terminated`: `{"action":"terminated","id","sdi"?,"iat","sub","agent","reason"}`, no `mission_s256`. The SS's `approved` check of `s256` against `mission` is enforced (`invalid_request` on mismatch). It also checks `agent` against the blob.
14. **Act bodies.** The agent's request body, every member, plus `act` (decision endpoint) and `agent_token` (all acts but update and completion), plus the envelope. The SS checks that `agent_token`'s `sub` equals `agent`.
15. **`auth_token.issued`** carries `scope` only when the token has one; `issuer` is the PS or the AS. A four-party token is reported when the PS releases it to the agent, including after the AS deferred, under the act's `sdi`.
16. **`revocation.received`** `token_type` is `agent_token`, `iss` the agent provider, or `resource_token`, `iss` the resource. Neither carries `sdi` or `mission_s256`. A resource token is reported to the SS deciding for the agent whose supervised auth token request carried it, once; a resource token the PS never put to an SS is reported to none, since the PS cannot tell whose it is.
17. **Tokens issued with no SS** (agent not routed) get a PS-minted `sdi` in their `*.issued` reports. Those reports are kept for replay to an SS the agent is routed to later.
18. **`decision.resolved`.** `recommendation` is echoed from the `ask`, and omitted with `supervisor: unavailable`. `proposed` is sent only for an allowed proposal: the terms the mission was minted from. `abandoned` is sent when an act the person was asked about expires or the agent cancels it, including an act that went to the person because the SS was unavailable.
19. **Denials to the agent.** Permission: `200 {"permission":"denied","reason"?}`. Mission request: `403 {"error":"access_denied","reason"?}` on the request, `403 denied` (with `reason`) on a poll. Token request: `403 access_denied` on the request, `403 denied` on a poll, never a reason.
20. **Held acts at the PS.** `Location: {signed_origin}/pending/{id}`. `requirement=approval` (`Retry-After: 5`) while the SS or the person decides; `requirement=clarification` (`Retry-After: 0`) relaying the SS's question, `timeout` and `options` verbatim. The terminal answer is what the original request would have returned. Past its lifetime: `408 expired`. After the terminal answer: `410 gone`. Another agent: `403 wrong_poller`.
21. **A proposal allowed at once** is answered `200 {"s256","mission"}` directly by the `POST /mission`. The blob members are `agent`, `approved_at`, `description`, and `approved_tools`, `approved_resources` and `expires_at` when the SS set them, in sorted key order.
22. **An `allow` that does not fit.** A `scope` outside the requested scopes, an `exp` already past, or a proposal `allow` without `description` is a malformed answer: the SS is unavailable for the act and the person is asked.
23. **Reach at the SS.** `mission` and `always` are kept per (PS, sub, agent, kind). The default kind is `"<act> <resource>"`: a person token's `resource`, or the forwarded resource token's `iss`. A permission's kind is `"permission <action>"`; any other act's is its name. Reach applies to person token, auth token, permission and update acts, not to proposals or completions. The latest matching answer wins. A mission-scoped answer ends with the mission's `terminated` report. Custom `apply` values go to `Policy::observe`.
24. **`unknown_mission` on events.** It applies to every event naming a `mission_s256`. A `terminated` report for a mission the SS never held is `201`.
25. **`rate_limited`.** The PS holds the act and sends it again after `Retry-After` when the host advances it. A wait past the act's deadline makes the SS unavailable for the act.
26. **Connection recovery.** `unsupported_iss` makes the PS forget the connection. `unknown_sub` reconnects once and `unknown_mission` replays once, then the request is sent again under the same `sdi` or `id`.
27. **Event delivery.** Any 2xx counts as delivered. `invalid_request` drops the event, since retrying will not help. Any other failure stops that pair's queue until the next attempt.
28. **A mission's end** is reported once, when the PS finds it, as aauth-go does: `terminated` with the reason the PS holds (`completed`, `expired`, or the host's, such as `revoked`) the first time a request, a poll or the mission endpoint finds the mission ended. After an allowed completion it carries the completion's `sdi`. A host termination is reported when the mission is next found; the PS has no other signal.
29. **A four-party narrowing** is enforced when the token is delivered, as aauth-go does. The PS-to-AS request has no scope or `exp` member, so the PS sends its usual request and refuses an AS token whose `scope` is outside the allowed `scope` or whose `exp` is after the allowed `exp`: `403 access_denied` on the request, `403 denied` on a poll (choice 19). The AS has issued it; the PS does not retain or release it.
30. **R3 under supervision.** An R3 auth token request is an `auth_token` act (Decision Endpoint): the forwarded `resource_token` carries `r3_uri` and `r3_s256` among "any budget or other requirement the resource attached". The SS cannot fetch the document (R3 Document Access Restriction admits only the AS in `aud` and the PS in `ps`), and the supervision draft has no member to carry it, so the SS decides on the request as the agent sent it; a held act gives the host the exact bytes the PS fetched (`SupervisionHold::r3_document`) to show the person `display`. The `allow` has no member that narrows operations, and the PS "proceeds with the act" without a decision of its own, so in three-party access it issues `r3_granted` with every operation of the class document and no `r3_per_call`, with the Core `scope` and `exp` narrowed as the answer says; a per-call proposal's `allow` issues the per-call token for the proposed call. In four-party access the AS sets the operations and choice 29 applies. Host `R3Policy` is not called, and a recorded per-call approval (R3 Per-Call Flow) is not applied: with an SS "the PS never answers from its own record", so a resubmitted proposal is a new act.
31. **Interaction relay** wire, as aauth-go records it: `type` `interaction` or `payment` with `url` (HTTPS, no query or fragment) and `code` required, `description`, `max_wait` and `mission_s256` optional, `question` refused. The PS keeps the relay before answering `202` with `Location: {signed_origin}/interaction/relay/{id}`, `Retry-After`, `Cache-Control: no-store`, body `{"status":"pending"}` and no `AAuth-Requirement`. A signed agent GET answers `202` while it waits, then once `200 {"status":"interacting"}` after the person engaged, or `200 {"status":"pending"}` when the PS can do no more or the wait (capped by `max_wait`) ended, then `410 invalid_code`; another agent's poll is `410 invalid_code`. A relay naming a mission that has ended answers `403 mission_terminated`. No channel is `424 interaction_unavailable`.
32. **`interaction.requested`** is sent once the PS has taken an `interaction` or `payment` relay or a `question` to the person: `type`, `url` when there is one, `mission_s256` when the request names a mission, no `code`. A relay with no channel is not reported.

Where the draft's text pulls two ways, this library reads it as follows.

1. **Idempotence vs. a decision reached at a pending URL.** "The same signed response" cannot verify against a repeated POST when the decision's `;req` components bind it to the poll GET. The library signs the decision afresh for the repeated request (choice 9).
2. **`Signature-Key` on a response** depends on signature-key issue 43 (the draft's Editor's Note). The draft example does not cover `signature-key`, so a stored record's `id` and `dwk` are bound only through the key they resolve to.
3. **Retry vs. unavailable.** Delivery says the PS retries a request "until it does" receive a terminal response; Unavailable Supervisor says the PS puts the act to the person and later reports `decision.resolved` with `supervisor: unavailable`. The library retries events and reports, and does not resend a supervision request once its act has gone to the person.
4. **Polling until the agent's request would expire.** At that point "the PS treats the SS as unavailable for this decision", but the request has expired and nothing is left to put to the person. The library ends the act (`408`). It reports nothing unless the person had been asked, and then reports `abandoned`.
5. **`token_type` values** for `revocation.received` are not defined (choice 16).
6. **Replay of "log entries … each as the event or report it would have been".** Accepted updates and permission decisions have no event. The library replays what was reported: the binding, approvals, mission-scoped events and outstanding token issuances.
7. **Answering a clarification reply.** "The SS then answers with a decision, or with a further clarification": The library answers the reply POST itself (choice 6).
8. **Routing a chained request.** The envelope `agent` is the agent that presented its token, so for a chained request it is the intermediary. The library routes on `(person, requesting agent)`; the person comes from the upstream record.
9. **"Endpoint URLs MUST be … on the issuer's origin or one the SS controls".** A PS cannot check control. The library's PS checks HTTPS only and leaves the origin to the host's egress admission. The library's SS publishes same-origin endpoints.
10. **`unsupported_iss` vs. `unknown_sub`.** The draft does not say how an SS tells them apart. The library: an untrusted PS (key resolver) is `unsupported_iss`; a trusted PS without the connection is `unknown_sub` (choice 10).
11. **An agent with no person yet.** Routing is per person, so a permission or mission request from an agent not yet bound to a person cannot be routed. The library lets host policy decide it.
12. **Mission approval and `approved_resources`.** The SS `allow` names the resources "the PS is to issue person tokens for at approval". The library's mission endpoint returns no `person_tokens` today (see CONFORMANCE.md).

# Selected discovery and revocation delivery interpretations

Source: Signature-Key, `JWKS URI Discovery`, `Caching and Performance` and
`Scheme-Specific Risks`; AAuth Core, `Metadata Documents`, `Keying Material`,
`JWKS Discovery and Caching` and `Token Revocation`, as recorded in
SPECIFICATIONS.md. These choices concern the opt-in `aauth-rust-discovery`
crate.

1. **Redirects.** Egress admission says "at minimum, do not follow redirects
   to a different host". A discovery GET follows a redirect only on the same
   host, at most three (`MAX_DISCOVERY_REDIRECTS`), each `https` and each
   resolved address admitted again. A signed request (a revocation POST or
   poll, a federation request) follows none: the signature covers its path,
   and its body goes only where it was admitted; a `3xx` answer is
   `revocation_unavailable`.
2. **Every resolved address.** A host resolves once. Every address it
   resolves to must be admitted, or the fetch is refused before connecting;
   the client then connects to the first admitted address that accepts, and
   refuses a peer other than that address. An IPv4 address carried in an IPv6
   form is judged as that IPv4 address, as the admission does.
3. **Relaxing admission** is a builder call (`allow_restricted_addresses`,
   `limits`, `resolver`, `transport`), never a default. Only `https` is ever
   fetched; a custom transport receives the admitted address and must connect
   only to it.
4. **Discovery is not trust.** `KeyResolver` answers `UntrustedIssuer` before
   any fetch unless the host named the issuer and its role document. A fetch
   failure is `invalid_key` at the verifier; the metadata checks keep
   `issuer_missing` and `issuer_mismatch`, and a missing `kid` is
   `unknown_key`.
5. **Freshness** comes from the JWKS response, by the `KeyCache` rules
   (`s-maxage`, `max-age`, `Expires`, `Age`; five minutes without them; at
   most 24 hours). The metadata document is fetched again each time the JWKS
   is. A cache header the cache cannot read, such as `Expires: 0`, makes that
   response usable for the lookup that fetched it and not reused. `no-store`
   and `no-cache` are not reused either, even after a failed refresh; for the
   next minute that issuer's keys are unavailable.
6. **The once-a-minute floor** counts every fetch of an issuer and role,
   failed ones included. An unknown `kid` in a fresh set fetches the set again
   only once the minute has passed; inside it the answer is `unknown_key`.
   Concurrent lookups of one issuer and role wait for one fetch.
7. **A failed refresh** answers from the last reusable set fetched less than
   24 hours earlier, never past that bound.
8. **Recipient role documents.** The role names each recipient's metadata
   document from its own records: a Resource is `aauth-resource.json` and an
   Access Server `aauth-access.json`; a Resource sends a resource-token
   revocation to `aauth-person.json` three-party, and to `aauth-access.json`
   for the `aud` plus `aauth-person.json` for the `ps` four-party.
9. **No `revocation_endpoint`** in a metadata document that passed the issuer
   check is `revocation_unsupported`. Metadata that cannot be fetched or fails
   the issuer check is `revocation_unavailable`.
10. **Covered components.** A revocation covers `content-type` and
    `content-digest` and, at a Resource, its `additional_signature_components`.
    A listed header the request does not carry is `revocation_unavailable`.
11. **`Prefer: wait`** is sent with the client timeout less two seconds, so a
    recipient that honors it answers `202` before the caller gives up.
12. **`202`.** Its single `Location` must be `https` on the same host and port
    as the revocation endpoint; it may be an absolute path. The next delivery
    of that revocation polls it with a signed GET with no body. A `202` from
    the poll that names another `Location` is `revocation_unavailable`. A poll
    answered `404` or `410` posts the revocation again; a poll that cannot
    connect is `revocation_unavailable` and keeps the pending URL.
13. **`429 rate_limited`** is not one of the two terminal failures, so it is
    reported deferred, and the next delivery posts again.
14. **Answer size.** A revocation answer is bounded like a discovery
    document, 65536 bytes; a larger one is `revocation_unavailable`.
