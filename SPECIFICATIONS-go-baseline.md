# Specification baseline

This repository implements a bounded part of the current AAuth editor source.
The exact commits below define the text used for implementation and review.
Rendered Internet-Draft publications may be older than these editor revisions.

SHA-256 values below are over the raw editor-source bytes at the named commit.
All seven files match the retained local source mirror used for review.

## Exact source manifest

| Document | Repository commit | Editor source | SHA-256 |
| --- | --- | --- | --- |
| AAuth Protocol | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-oauth-aauth-protocol.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md) | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` |
| AAuth Rich Resource Requests (R3) | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-r3.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-r3.md) | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` |
| AAuth Events | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-events.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-events.md) | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` |
| AAuth Bootstrap Guidance | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-bootstrap.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-bootstrap.md) | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` |
| AAuth Budgets | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-budgets.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-budgets.md) | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` |
| AAuth Interoperability Demo Profile | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`interop-demo-profile.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/interop-demo-profile.md) | `ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195` |
| HTTP Signature Keys | [Signature-Key `0ff751b`](https://github.com/dickhardt/signature-key/commit/0ff751b571e7fe51336bcc1e526954a202317cc0) | [`draft-hardt-httpbis-signature-key.md`](https://github.com/dickhardt/signature-key/blob/0ff751b571e7fe51336bcc1e526954a202317cc0/draft-hardt-httpbis-signature-key.md) | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` |

## Targeted additional source: Signature-Key `clock_skew`

This is one targeted source, not a repin. The manifest above and the rest of
the library remain at their stated revisions. Only the signature `created`
classification in `signaturekey.PrepareRequest` and the `Signature-Error:
error=clock_skew` answer for a header JWT `iat` follow this text.

- Document: HTTP Signature Keys, editor source `draft-hardt-httpbis-signature-key.md`.
- Repository commit: [Signature-Key `69f5ba2`](https://github.com/dickhardt/signature-key/commit/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
- Section: the `### clock_skew` heading at line 1104; the section is lines 1104-1114.
- SHA-256 of the whole file at that commit: `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

The JWT `iat` rule itself follows the Protocol -11 overlay below.

## Targeted additional source: Signature-Key `revoked_jwt`

This is one targeted source, not a repin. Only the `revoked_jwt` code and its
use for a withdrawn JWT carried in `Signature-Key` follow this text:
`signaturekey.ErrorRevokedJWT`, returned by a Resource or Person Server only
where its own revocation store gives it notice.

- Document: HTTP Signature Keys, editor source `draft-hardt-httpbis-signature-key.md`.
- Repository commit: [Signature-Key `69f5ba2`](https://github.com/dickhardt/signature-key/commit/69f5ba2647be848feed043fb6d8b0790e43cd0b6).
- Section: the `### revoked_jwt` heading at line 1092; the section is lines 1092-1102. The registry row is line 1462.
- SHA-256 of the whole file at that commit: `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

## Targeted additional source: Protocol -11 presenting a revoked token

This is one targeted source, not a repin. Only the first bullet of the section
follows this text: a revoked Agent or Auth token carried in `Signature-Key` is
`401` with `Signature-Error: error=revoked_jwt`, and a Resource refusing a
revoked Auth token also sends `AAuth-Requirement: requirement=person-token`
and never `requirement=auth-token`. A token carried as a request parameter
(`revoked_<parameter>_token`, the pending-request `revoked` state) is not
adopted, and no global parameter-token remapping, cascade or recovery is added.

- Document: AAuth Protocol -11, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `28e8258`](https://github.com/dickhardt/AAuth/commit/28e8258f8153a2a51a709c53ebc9618f941564e4).
- Section: the `### Presenting a Revoked Token` heading at line 2760; the section is lines 2760-2767.
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

## Targeted additional source: Protocol -11 agent identifier local part

This is one targeted source, not a repin. The manifest above and the rest of
the library, including every other Protocol clause, remain at their stated
revisions. Only the `local` part grammar and exact-comparison rule in
`ValidateAgentIdentifier` and `ValidateAgentRelationship` follow this text.

- Document: AAuth Protocol -11, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `28e8258`](https://github.com/dickhardt/AAuth/commit/28e8258f8153a2a51a709c53ebc9618f941564e4).
- Section: the `## Agent Identifiers` heading at line 486; the section is lines 486-507. Document History line 3213 records the change (issue #164).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The `local` part accepts `A-Za-z`, digits, `-`, `_`, `+` and `.`, and agent
identifiers compare exactly without case folding. The overlay is a list, not a
table row, because the baseline manifest check requires exactly one table row
per source file.

## Targeted additional source: Protocol -11 revocation request

This is one targeted source, not a repin. The manifest above and every other
Protocol clause remain at their stated revisions. Only the revocation request
and its `403 unsupported_iss` mapping follow this text: the `{jti, exp}` body,
the issuer taken only from the verified signature, mandatory `content-type`
and `content-digest` coverage, `(iss, jti)` state recorded whether or not the
token was seen, and the Errors table entries already adopted in
`INTERPRETATIONS.md`. The `429` `rate_limited` response is adopted for client
feedback only: the AP and PS revocation clients return additive
`aauth.RateLimitedError` with the recipient's `Retry-After`; recipient entry or
rate enforcement is not implemented. Cascade and polling of a `202` are not
adopted (`revoked_jwt` is adopted by the overlays above). The `200` Body rule is adopted for the AP and PS
clients only (`aauth.ReadRevocationResponse`): no body is a recorded revocation;
a present body that is not `application/json`, one JSON object with an optional
array `downstream`, is `aauth.ErrRevocationUnavailable`. A valid `downstream`
report is validated and not returned.

- Document: AAuth Protocol -11, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `28e8258`](https://github.com/dickhardt/AAuth/commit/28e8258f8153a2a51a709c53ebc9618f941564e4).
- Section: the `## Token Revocation` heading at line 2666, `### Revocation Request` (lines 2670-2700) and the Errors table in `### Revocation Response` (lines 2701-2746).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

## Targeted additional source: Protocol -11 JWT `iat` and `clock_skew`

This is one targeted source, not a repin. The manifest above and every other
Protocol clause remain at their stated revisions. Only the JWT `iat` rule and
its `clock_skew` answers follow this text. General token verification no longer
refuses a future `iat`; `exp` and `nbf` checks are unchanged and no universal
JWT leeway is added. A verifier that has a prepared signed request refuses a
JWT whose `iat` is later than the request's captured time plus its effective
signature window (`signaturekey.PreparedRequest.CheckIssuedAt`, 60 seconds by
default). The token in the `Signature-Key` header is answered `401` with
`Signature-Error: error=clock_skew`; a token carried as a request parameter
(the Resource, upstream and sub-agent tokens at the PS and AS token endpoints)
is answered `400` with body error `clock_skew` and no `Signature-Error`. A
verifier with no request, such as a response-token consumer, applies no
future-`iat` refusal. The Events subscribe-token and event-token checks are
unchanged; both still refuse a future `iat`.

- Document: AAuth Protocol -11, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `28e8258`](https://github.com/dickhardt/AAuth/commit/28e8258f8153a2a51a709c53ebc9618f941564e4).
- Section: the `### Common JWT Verification` heading at line 2311 (lines 2311-2322) and the `clock_skew` row at line 2597 of `### Token Endpoint Error Codes`.
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

The overlay is a list, not a table row, because the baseline manifest check
requires exactly one table row per source file.

[AAuth Explorer at `e6d7913`](https://github.com/aauth-dev/explorer/commit/e6d79137cda1a6a650d4394a37095393e1cc62ba)
is a non-normative diagnostic implementation, not an editor source. It is
tracked by Git commit rather than inserted into the source manifest.

## Targeted additional source: Protocol -11 call-chain expiry

This is one targeted source, not a repin. The manifest above and every other
Protocol clause remain at their stated revisions. Only these rules follow this
text, and only on the supported call-chain path: one immediate, missionless,
accountless hop whose `upstream_token` is an auth token issued by the same
Person Server.

- A person token issued with `upstream_token` does not outlive it: the
  `upstream_token` part of the `exp` rule in `### Person Token Structure`.
- An auth token issued on a request carrying `upstream_token` does not outlive
  it: the `upstream_token` sentence of the `exp` rule in
  `### Auth Token Structure`, and "Downstream access does not outlive it" in
  `### Call Chaining`.

- Document: AAuth Protocol -11, editor source `draft-hardt-oauth-aauth-protocol.md`.
- Repository commit: [AAuth `28e8258`](https://github.com/dickhardt/AAuth/commit/28e8258f8153a2a51a709c53ebc9618f941564e4).
- Section: `### Person Token Structure` at line 856 (the `exp` rule at line 863), `### Auth Token Structure` at line 1768 (the `exp` rule at line 1775), and `### Call Chaining` at line 1846 (the paragraph at line 1850).
- SHA-256 of the whole file at that commit: `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0`.

Not adopted by this entry: `expired_upstream_token`, so an upstream token that
fails only `exp` still returns `invalid_upstream_token`; person tokens as
upstream tokens; mission- or account-bound upstream tokens; AS-issued upstream
tokens and federated downstream issuance; and repeated hops or cascade. This
overlay does not claim full call chaining.

## Native R3 vocabulary baselines

R3 names seven external description formats without citing exact revisions.
The table below fixes the sources used by this implementation. These are
adapter baselines, not additional AAuth normative sources, and each row states
the narrower representation this repository actually parses.

| Vocabulary | Reviewed baseline | Current parser boundary |
| --- | --- | --- |
| MCP | [MCP 2025-11-25, commit `38c84e9`](https://github.com/modelcontextprotocol/specification/tree/38c84e9f93ad191d9eb26d92b945d17bd0efcaf3/docs/specification/2025-11-25/server) | Exact JSON-encoded `tools/list` result objects with cursor continuity and required object-rooted Tool `inputSchema`; JSON-RPC transport remains outside the parser |
| OpenAPI | [OpenAPI 3.0.4](https://spec.openapis.org/oas/v3.0.4.html) and [3.1.1](https://spec.openapis.org/oas/v3.1.1.html) | Self-contained JSON or YAML Paths operations with `operationId`; callbacks, webhooks, and external reference acquisition are outside the profile |
| gRPC | [`google.golang.org/protobuf` v1.36.10](https://github.com/protocolbuffers/protobuf-go/tree/v1.36.10) | Complete binary `google.protobuf.FileDescriptorSet`; reflection and `.proto` acquisition or compilation are outside the parser |
| GraphQL | [GraphQL September 2025](https://spec.graphql.org/September2025/) | JSON response framing through object-valued `data.__schema`, followed by the typed R3 operation-identity refusal; no full introspection validator |
| AsyncAPI | [AsyncAPI JSON Schemas v6.11.1, commit `e609fc2`](https://github.com/asyncapi/spec-json-schemas/tree/e609fc2341007395d75df5756fc6fccf662c2087) | Focused self-contained 3.0.0/3.1.0 JSON operation-to-root-channel profile; no YAML conversion or general document validator |
| WSDL | [WSDL 1.1, W3C Note 15 March 2001](https://www.w3.org/TR/2001/NOTE-wsdl-20010315) | Self-contained service, binding, port-type, and message linkage needed to derive unique operations; no XML Schema or arbitrary extension validation |
| OData | [OData CSDL XML 4.01](https://docs.oasis-open.org/odata/odata-csdl-xml/v4.01/odata-csdl-xml-v4.01.html) | Self-contained Edmx 4.0 entity-container and bound-operation identity subset; method and AAuth annotation authority remain refused |

## Verify the protocol map against source bytes

[PROTOCOL.md](PROTOCOL.md) is backed by a machine-readable map of all 612
normalized Markdown headings and 1,200 uppercase normative or field-presence
occurrences in these seven files. Given a directory containing the exact
editor-source files above, verify every digest, line count, heading coordinate,
title, non-overlapping range, exact-line digest, strength, dependency, and the
owner and proof seam supplied by each occurrence's heading with:

```sh
go run ./internal/specmodel/cmd/verify -source-dir /path/to/editor-sources
```

The ordinary Go suite also verifies that each file, commit, and digest remains
bound in one row of this manifest and that the model uses controlled
classification, ownership, state-role, and proof-seam vocabularies.

## Implementation relationship

### AAuth Core

Core has executing direct-identity, session, three-party, four-party,
deferred-delivery, and bounded revocation paths. It is not complete. The
source-area table in [CONFORMANCE.md](CONFORMANCE.md) is the supported-behavior
summary; it names evidence and exclusions for each path rather than inferring
support from exported types.

Core requires fully specified JOSE algorithm identifiers and requires support
for `Ed25519`. This implementation uses `Ed25519`; it does not accept the
polymorphic `EdDSA` identifier as an equivalent spelling.

### HTTP Signature Keys

The current role paths use `jwt`, `jwks_uri`, `hwk`, and the Ed25519
`jkt-s256+jwt` subset of `jkt-jwt`, plus a bounded set of shared
message-signature behavior. Other schemes, complete negotiation, and generic
replay enforcement remain explicit gaps in [CONFORMANCE.md](CONFORMANCE.md).

### Companion specifications and interoperability

R3, Events, Bootstrap, Budgets, and the interoperability profile are pinned as
first-class inputs even where behavior is absent. This repository now has one
executing two-key repository profile; its application-selected endpoints and
JSON remain implementation choices because the source is informational.
[CONFORMANCE.md](CONFORMANCE.md) separates reusable Core primitives from an
executing companion-spec path, and [ARCHITECTURE.md](ARCHITECTURE.md) assigns
new behavior without moving companion semantics into the Core package.

See [INTERPRETATIONS.md](INTERPRETATIONS.md) for active implementation
choices and [SPEC-FEEDBACK.md](SPEC-FEEDBACK.md) for questions to raise with the
editors.
