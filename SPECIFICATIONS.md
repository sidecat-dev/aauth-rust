# Specification baseline

The Rust journey uses the editor sources below. These are the exact current
snapshot supplied for this cycle, not a claim about later published drafts.
The six AAuth sources are byte-identical at 28e8258 and 70d6737.

The Go baseline and all its targeted overlay pins/digests are preserved verbatim
in [SPECIFICATIONS-go-baseline.md](SPECIFICATIONS-go-baseline.md). That file is
comparison material, not the Rust behavior ledger. Its Go package/status links
describe the sibling repository. No Go behavior is implied here.

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

Only Agent tokens, identifiers, the direct Agent-identity Resource path and the
Ed25519 `hwk`/`jwt` proof subset execute. Supervision and the other pinned
companions are future inputs. See [CONFORMANCE.md](CONFORMANCE.md).

Underlying standards: RFC 7515 (compact JWS), RFC 7517 (JWK), RFC 7638
(thumbprints), RFC 8032/8037 (Ed25519), RFC 9421 (HTTP Message Signatures),
RFC 9651 (Structured Fields), RFC 9864 (fully specified `Ed25519`).

The HTTP profile requires `@method`, `@authority`, `@path`, `signature-key` and
`created`. This implementation additionally requires `@query` when present,
and `authorization` when present. The first journey is bodyless: signed
body-bearing requests are refused until Content-Digest verification exists.
Production server identifiers remain HTTPS scheme and lowercase DNS host only;
test TLS uses name-to-loopback routing without changing those identifiers.

## Matching Go baseline manifest

The following original pins and digests are retained for direct comparison.
They do not replace the explicit current-source Rust behavior pin above. The
complete original overlay list is retained in SPECIFICATIONS-go-baseline.md.

| Document | Repository commit | Editor source | SHA-256 |
| --- | --- | --- | --- |
| AAuth Protocol | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-oauth-aauth-protocol.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-oauth-aauth-protocol.md) | `c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19` |
| AAuth Rich Resource Requests (R3) | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-r3.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-r3.md) | `dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760` |
| AAuth Events | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-events.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-events.md) | `6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0` |
| AAuth Bootstrap Guidance | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-bootstrap.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-bootstrap.md) | `ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872` |
| AAuth Budgets | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`draft-hardt-aauth-budgets.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/draft-hardt-aauth-budgets.md) | `7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d` |
| AAuth Interoperability Demo Profile | [AAuth `a99d353`](https://github.com/dickhardt/AAuth/commit/a99d353cf18aee81d0c5445bac070164fb3b8bc5) | [`interop-demo-profile.md`](https://github.com/dickhardt/AAuth/blob/a99d353cf18aee81d0c5445bac070164fb3b8bc5/interop-demo-profile.md) | `ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195` |
| HTTP Signature Keys | [Signature-Key `0ff751b`](https://github.com/dickhardt/signature-key/commit/0ff751b571e7fe51336bcc1e526954a202317cc0) | [`draft-hardt-httpbis-signature-key.md`](https://github.com/dickhardt/signature-key/blob/0ff751b571e7fe51336bcc1e526954a202317cc0/draft-hardt-httpbis-signature-key.md) | `335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb` |
