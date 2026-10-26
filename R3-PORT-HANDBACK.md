# R3 port hand-back

Branch `wc-05-rust-r3` starts at `704effbf898e768839de82277334a716379a931e`. Commit `51fe3838b9f0e9702f455eaefd47d400745384f7` adds documents, direct grants, and per-call proposals to `aauth-rust-r3`. Grammar and set algebra from `3c373a55d6f265844c18743268fcf5b7b9aca1c2` stay in the crate. No row is `pass`.

## What is in the batch

The crate parses an R3 document and an R3 proposal, proves a direct grant is a subset of one document, and proves a direct set and a per-call set are disjoint subsets of that document. A reference binds an absolute HTTPS URI to the unpadded base64url SHA-256 of the exact caller bytes. Account parity compares presence and value, including a present empty string. The crate does not fetch a definition, decide policy, execute a call, or issue a token.

A document requires `vocabulary` and a non-empty `operations` array. `account` is optional. A present `display` requires a non-blank `summary`; `implications`, `data_accessed`, and `irreversible` are optional. A grant requires `vocabulary` and an `operations` array, and the array may be empty. A proposal requires `vocabulary`, exactly one operation, and a `parameters` object. A parameter is inline JSON or a digest descriptor (`s256`, optional `excerpt`, optional `media_type`). Numbers compare by normalized spelling, not floating point. The tests use a named `{name}` codec. They do not import a standard vocabulary and they do not use MCP `tool` members.

Still later: the seven standard vocabularies, hints, token minting and verification, fetch, and the resource and person-server wiring.

## Rows

| id | result | test |
| --- | --- | --- |
| R3-L00156-O01-MAY | reaches, not run | `vocabulary_accepts_a_namespaced_third_party_annotation_encoding` registers `https://example.test/vocabulary/custom-annotation` and refuses an unnamespaced annotation encoding. The integration journey that publishes a private codec is not in this batch. |
| R3-L00471-O01-REQUIRED | reaches, not run | `document_validation_and_strict_json` rejects a document with no `operations` member and a document whose `operations` array is empty. `document_parse_referenced_binds_exact_bytes` rejects that empty document even when the digest matches. |
| R3-L00477-O01-RECOMMENDED | reaches, not run | `document_validation_and_strict_json` round-trips `display.summary`. The wording of the summary is not judged. |
| R3-L00479-O01-REQUIRED | reaches, not run | The same test rejects `display:{}`, `summary:""`, and a summary that is only spaces. `Display::new` rejects a blank summary. |
| R3-L00480-O01-OPTIONAL | reaches, not run | The same test round-trips `implications`. |
| R3-L00481-O01-OPTIONAL | reaches, not run | The same test round-trips `data_accessed`. |
| R3-L00482-O01-OPTIONAL | reaches, not run | The same test round-trips `irreversible`. |
| R3-L00616-O01-REQUIRED | reaches, not run | `grant_parse_accepts_empty_and_subset_and_rejects_adversarial_input` rejects a grant object that has no `vocabulary` member. |
| R3-L00617-O01-REQUIRED | reaches, not run | The same test accepts `"operations":[]`, round-trips that empty grant, and rejects a grant that omits `operations`. |
| R3-L00643-O01-REQUIRED | reaches, not run | `proposal_rejects_ambiguous_or_invalid_shapes` rejects a proposal with no `operations` member, an empty `operations` array, and two operations. |
| R3-L00645-O01-REQUIRED | reaches, not run | The same test rejects a proposal with no `parameters` member and a proposal whose `parameters` value is an array. |
| R3-L00645-O02-MAY | reaches, not run | `proposal_json_round_trip_and_copy_safety` puts `body` in a digest object and leaves `to` inline. |
| R3-L00647-O01-REQUIRED | reaches, not run | That round trip keeps `s256` equal to the digest of the original bytes. The shape test rejects a short `s256`. |
| R3-L00648-O01-OPTIONAL | reaches, not run | The round trip keeps excerpt `Hi Mom, are you free…`. An excerpt of 4097 characters is accepted. |
| R3-L00649-O01-OPTIONAL | reaches, not run | The round trip keeps `media_type` `text/plain`. |
| R3-L00655-O01-RECOMMENDED | reaches, not run | The round trip keeps `display.summary` and parses it back. The `## Action` heading convention is not treated as a requirement. |
| R3-L00655-O02-MAY | reaches, not run | The same round trip keeps `detail` as `## Action\nSend an email`. |

These library checks are in the batch. The rows also need a later object, so they are not marked reached:

| id | what this batch checks | what is still missing |
| --- | --- | --- |
| R3-L00413-O01-REQUIRED | An empty request set is refused before the codec runs. | The authorization request object. |
| R3-L00469-O01-REQUIRED | A document vocabulary must be one registered codec. | A check against advertised `r3_vocabularies`. |
| R3-L00469-O02-MUST | An unknown vocabulary is refused and nothing is published by this crate. | Metadata publication. |
| R3-L00473-O01-OPTIONAL | `validate_document_account` requires the same presence and the same value. | Binding that check to an authorization endpoint. |
| R3-L00488-O01-MUST | The digest is the exact caller bytes. Different spacing is a different digest. | A resource that serializes once and serves those bytes. |
| R3-L00488-O02-SHOULD | A parsed document does not retain its source bytes. | Serving the stored bytes instead of marshaling again. |
| R3-L00502-O01-REQUIRED | `Reference::new` requires an absolute HTTPS URI. | The `r3_uri` token claim. |
| R3-L00503-O01-REQUIRED | `Reference::new` requires a canonical 32-byte unpadded base64url digest. | The `r3_s256` token claim. |
| R3-L00547-O01-MUST | `parse_referenced_document` rejects bytes that do not match the digest. | The Person Server path that stops before consent. |
| R3-L00572-O01-OPTIONAL | `Authorization::new` proves the per-call set is a subset and is disjoint from the direct set. | The `r3_per_call` token member. |
| R3-L00617-O02-MAY | `Grant::new` rejects a grant that is not a subset of the document. | An issuer that narrows a grant at issuance. |
| R3-L00677-O01-MUST | `Parameters::matches` accepts structurally equal JSON and exact digest bytes, and rejects a changed value or a changed byte. | Returning 401 or 202 and holding the call. |
| R3-L00740-O01-MUST | Referenced document and proposal parsers check the digest before they parse. | The fetch party. |

`vocabulary_uri_rejects_a_fragment_and_a_non_absolute_form` still checks only the URI grammar used by R3-L00144-O02-MUST. Metadata publication is not in this batch, so that row is not reached.

Rows that stay `fail` are R3-L00435-O01-MUST, R3-L00698-O01-MUST, R3-L00723-O01-MUST, and R3-L00748-O01-MUST. R3-L00152-O01-MUST stays `n/a`. Rows that stay `not offered` are R3-L00417-O01-MAY, R3-L00433-O01-MAY, R3-L00438-O01-MAY, R3-L00440-O01-MAY, R3-L00475-O01-SHOULD, R3-L00546-O01-MAY, R3-L00651-O01-OPTIONAL, and R3-L00721-O01-MAY. This hand-back does not copy `go_status`.

## Droplet

One run, for this batch:

```
cargo test -p aauth-rust-r3 --locked --lib
```

That command covers the thirteen `vocabulary_` tests from the grammar batch and these tests:

- `document_validation_and_strict_json`
- `document_digest_uses_exact_caller_owned_bytes`
- `document_returned_operation_copies`
- `document_parse_referenced_binds_exact_bytes`
- `document_rejects_raw_invalid_utf8`
- `document_account_parity`
- `reference_validation`
- `reference_rejects_context_free_json`
- `grant_must_be_document_subset`
- `grant_parse_accepts_empty_and_subset_and_rejects_adversarial_input`
- `grant_unmarshal_requires_document_context`
- `authorization_requires_disjoint_subsets`
- `proposal_json_round_trip_and_copy_safety`
- `proposal_parameter_matching_uses_structural_json_and_exact_digest_bytes`
- `proposal_rejects_ambiguous_or_invalid_shapes`
- `proposal_account_parity_and_referenced_digest`
- `numbers_match_without_floating_point`

While preparing the commit, this window ran that command, `cargo fmt -p aauth-rust-r3 -- --check`, `cargo clippy -p aauth-rust-r3 --all-targets --locked -- -D warnings`, and `RUSTDOCFLAGS="-D warnings" cargo doc -p aauth-rust-r3 --no-deps --locked`. The local test run reported 30 passed. Those runs are not the droplet log. A `reaches, not run` row stays short of `pass` until that log exists.

## Go edges not copied

Errors are `Result`. There is no `context.Context`, no `net/http`, and no panic on a bad document, grant, or proposal. JSON numbers stay the sender's spelling. `arbitrary_precision` stays off, and equality does not use floating point. Parameter object keys are sorted. Operation bytes stay the codec's canonical bytes. A present empty account is kept; an absent account is omitted. A parser that takes bytes rejects raw invalid UTF-8. There is no invalid-UTF-8 `String` API. `&`, `<`, and `>` are not HTML-escaped. `Document`, `Grant`, `Proposal`, and `Reference` refuse context-free JSON, and a failed deserialize leaves a populated value in place.

## Left untracked

`BRIEF.md`, `GO-R3-TABLE.md`, and `obligations-r3.json` are not in the batch commit.
