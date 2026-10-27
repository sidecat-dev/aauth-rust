# Rich Resource Requests library

`aauth-rust-r3` provides the data and verification layer for describing which
operations an authorization permits. A service can register an operation
vocabulary, parse a document or per-call proposal, check a grant against that
document, and compare the proposed parameters with the actual call.

The crate includes operation codecs for MCP, OpenAPI, AsyncAPI, GraphQL, WSDL,
OData and gRPC. Authoritative definition adapters currently cover MCP tools,
OpenAPI JSON and AsyncAPI. GraphQL introspection alone is refused because it
does not identify an executable operation. WSDL, OData and gRPC definition
adapters remain unfinished; the JSON Schema adapter lacks RE2 pattern validation.

Resource/Auth token helpers verify signed R3 claims and exact artifact digests.
The artifact fetcher requires the host to supply its trusted HTTPS transport
and egress policy. It checks PS/AS signing identity and bounded response bytes;
it does not discover an endpoint or make a consent decision.

Proposals support an optional object-valued `result`. Optional display/detail,
excerpt and media type preserve absent and present-empty values separately.
Hosts must retain the original bytes used by a signed reference: parsing and
serializing an equivalent JSON value does not preserve arbitrary whitespace,
member order or its digest. Release-gating policy and required human-readable
explanations remain host responsibilities.

Built Rust and Go consumers have exchanged artifacts and signed references;
the retained execution records distinguish each exact source and input set.
The foundation batch also exercised large objects, quoted media parameters,
malformed input, changed-byte and wrong-key refusals. These library workflows
do not establish an integrated Resource/PS/AS R3 exchange. Endpoint wiring,
discovery, entitlements, account binding, consent, caching and audit remain
unfinished. See the repository's [conformance profile](../../CONFORMANCE.md).

The optional-field constructors/accessors use `Option<&str>`, and
`ProposalOptions` includes `result`. Consumers of earlier development commits
must migrate those calls. No published crate compatibility is claimed.
