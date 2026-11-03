# Specification baseline

This implementation follows the editor sources below, at these exact commits.
They are not a claim about later published drafts. What the crates do with each
draft, and what they leave out, is in [CONFORMANCE.md](CONFORMANCE.md); the
choices made where a draft leaves room are in [INTERPRETATIONS.md](INTERPRETATIONS.md).

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

Underlying standards: RFC 7515 (compact JWS), RFC 7517 (JWK), RFC 7518
(ES256), RFC 7638 (thumbprints), RFC 8032/8037 (Ed25519), RFC 5958 (PKCS #8
keys), RFC 9421 (HTTP Message Signatures),
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
