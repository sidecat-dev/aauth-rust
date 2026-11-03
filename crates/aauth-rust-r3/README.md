# Rich Resource Requests library

`aauth-rust-r3` provides the data and verification layer for describing which
operations an authorization permits. A service can register an operation
vocabulary, parse a document or per-call proposal, check a grant against that
document, and compare the proposed parameters with the actual call.

The crate includes operation codecs for MCP, OpenAPI, AsyncAPI, GraphQL, WSDL,
OData and gRPC. Definition parsers cover MCP tools, OpenAPI JSON, AsyncAPI,
gRPC `FileDescriptorSet`, self-contained WSDL 1.1, and OData CSDL 4.0.
GraphQL introspection is refused because it does not identify an executable
operation. gRPC refuses hosted `.proto` text and live reflection. OData
metadata does not prove HTTP methods. The JSON Schema adapter lacks RE2
pattern validation.

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

This crate alone does not run an R3 exchange. The Resource, Person Server and
Access Server crates wire it into their roles; the [R3 guide](../../docs/features/r3.md)
shows how to turn it on, and its
[Limits](../../docs/features/r3.md#limits) say what is not implemented.
