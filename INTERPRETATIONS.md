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
  string and the sanitized description stay separate values. There is no wire
  field for "visually distinct."
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
- This library is not an intermediary, so it does not implement a rule about
  rewriting `AAuth-Budget` in transit. The RateLimit and TPX passages cited
  with normative keywords sit in non-normative prior art and are not executed.
