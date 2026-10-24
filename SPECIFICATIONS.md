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
four-party federation. The proof subset is Ed25519 `hwk`/`jwt` plus explicit
`jwks_uri` service proofs. A `keyid` parameter is accepted only when it equals
the `kid` carried by that Signature-Key member; the key still comes from
Signature-Key. Opt-in AS/PS continuations cover bounded claims, clarification, interaction,
approval and WWW-Authenticate payment with signed polling. An Agent also parses
a Resource `202` `requirement=auth-token` and polls it with a retained auth
token. The Resource does not hold that invocation. Settlement and
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
carrying that signed digest. Mission creation, update, completion and control
endpoints do not execute. AS, child, upstream and federated mission paths do not
execute. A Resource that asks for a
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
