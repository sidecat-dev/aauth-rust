# Sanitizer hand-back

`sanitize_markdown` is gone. Consent descriptions are plain text from `description_text`. Cargo was not run in this window. `rustfmt` 1.99.1 `--check` is clean on the edited Rust files. A Python copy of the normalizer matched the equality assertions and the recheck inputs below.

## What changed

`description_text` (`crates/aauth-rust-budgets/src/value.rs:601`) walks scalar values only. It does not slice bytes, decode character references, or parse Markdown. It cannot panic on the multi-byte, lone-surrogate-spelling, or 8192-character inputs from RECHECK.md section A.

Order:

1. Collapse Unicode whitespace, including control whitespace, to a single space. Drop leading and trailing space.
2. Drop other control characters (`char::is_control`) and bidi formatting characters.
3. Cap the normalized text at `DESCRIPTION_TEXT_LIMIT` (`value.rs:577`), which is 1024 scalar values. A longer string is cut to that length and ends with `…` (U+2026) inside the bound.
4. HTML-escape `&` `<` `>` `"` `'` as `&amp;` `&lt;` `&gt;` `&quot;` `&#39;`.

The bound is applied before escaping, so the returned string can be longer than 1024. The draft states no length; 1024 is this profile's cap.

Bidi characters removed (`value.rs:583`): U+061C, U+200E, U+200F, U+202A–U+202E (embeddings, PDF, and both overrides), and U+2066–U+2069 (isolates). That is wider than the two override characters. Embeddings, marks, and isolates spoof a consent line the same way.

`consent_figure` (`value.rs:653`) puts `human_amount` and `description_text` in separate fields. `UnitDeclaration::description` (`value.rs:169`) still returns the published string. Normalization happens at render time, not in `budget_units` JSON.

`PersonServer::budget_consent` (`crates/aauth-rust-person-server/src/server.rs:279`) is unchanged in behavior other than calling the new normalizer. Its doc says the description is already-escaped plain text: insert it as escaped text, do not render Markdown, and do not escape it again.

Deleted from `value.rs`: `sanitize_markdown` and `decode_until_stable`, `strip_tags_and_controls`, `decode_entities`, `decode_entity`, `neutralize_disallowed_schemes`, `scheme_allowed`, `allow_list_links`, `consume_inline_link`, `skip_title_and_close`, `rewrite_reference_definitions`, `reference_destination`. No alias remains. The export is `description_text` and `DESCRIPTION_TEXT_LIMIT` (`crates/aauth-rust-budgets/src/lib.rs:34`).

Docs: `SPECIFICATIONS.md` (person-server consent sentence in the budgets paragraph), `CONFORMANCE.md` (opt-in budgets row), `INTERPRETATIONS.md:58`. All three now say the description is plain text and name the draft's sanitize-before-rendering sentence. `CONFORMANCE.md` test counts in that row were already stale (profile.rs was 18 tests, the row said 16; person-server `budgets.rs` was 9 tests, the row said 7). They were not renumbered. This window adds one profile test and one person-server test.

## Tests

Budgets, `crates/aauth-rust-budgets/tests/profile.rs`:

- `consent_keeps_the_amount_apart_from_the_plain_description` (`:169`). `$5.00` is separate from the description and is not inside it. `https`, `http`, and `mailto` stay literal text, with no `href` and no `<`. `ftp:` stays as text. Tags, quotes, controls, bidi, an autolink, and a reference definition are escaped or kept as text. A string of exactly 1024 characters is unchanged. One more character ends with `…` and drops the extra character.
- `description_text_escapes_recheck_inputs_without_a_link` (`:231`). For every sample, the escaped string and a decode of `&amp;`, `&quot;`, and `&#39;` contain no `<` and no `>`. The escaped string is not an HTML `javascript:` link (`<a`, `href="javascript:`, `href='javascript:`, or `href=javascript:`). An 8192-character run of `a` and of `é` is truncated to 1024 and ends with `…`.

Samples in `recheck_descriptions` (`profile.rs`, and the same list in the person-server test): both entity forms (`&#92;:` and `&#x5c;&#x3a;`), the backslash forms (`javascript\:`, `JaVaScRiPt\:`, `data\:`, `vbscript\:`, and the `fetch` form), both nested entity forms plus nine layers of `java`/`script:`, the multi-byte backslash inputs (`[x](\é)`, `[x](a\éb)`, `[x](&#92;&#233;)`), `<script>`, autolinks (`<javascript:alert(1)>`, `<https://example.test>`), a reference definition, the three old allow-list gaps (`file:`, the escaped-quote early return, `ms\-msdt:`), lone-surrogate spellings (`&#xD800;`, `&#xDFFF;`, `&#55296;`, and 1024 copies of `&#xD800;`), an `<a href="javascript:…">` input, and 8192 `<` characters.

Person server, `crates/aauth-rust-person-server/tests/budgets.rs`:

- `person_server_narrows_amount_without_changing_unit_or_decimals` (`:130`) still shows `$5.00` apart from the description. The description is exactly `pay &lt;b&gt;now&lt;/b&gt; [x](javascript:alert(1))`.
- `consent_renders_recheck_descriptions_as_plain_text` (`:231`) runs the same inputs through `budget_consent`. The amount stays `$5.00` and is not the description. The description has no raw `<` or `>`, the same partial decode has no `<` or `>`, and the escaped text is not a `javascript:` link. `https` and `mailto` are returned unchanged, as text.

## Rows

The sprint table is not in this checkout. The commit message names the tests.

- `BUDGET-L00385-O02` (draft line 385, sanitize before rendering): `description_text_escapes_recheck_inputs_without_a_link` and `consent_keeps_the_amount_apart_from_the_plain_description`.
- `BUDGET-L00538-O01` (draft line 538, human amount distinct from the sanitized description): those two profile tests, plus `person_server_narrows_amount_without_changing_unit_or_decimals` and `consent_renders_recheck_descriptions_as_plain_text`.

## Choices

Angle brackets are escaped, not deleted. `description_text("<script>")` is `&lt;script&gt;`. The escaped string contains no `<`. Decoding `&amp;`, `&quot;`, and `&#39;` still contains no `<`, which is what the tests assert. A full HTML decode restores the resource's brackets as text. That is the text a person reads when the escaped string is inserted into HTML. Deleting brackets would make a full decode contain no `<`, and would not be HTML-escaping. Escape was chosen because the assignment requires it.

`javascript:` can remain as letters. `[x](javascript\:alert(1))` is returned unchanged, as text. It is not a link unless a host renders Markdown. The host doc forbids that.

U+200B, U+FEFF, and other non-control, non-bidi format characters are kept. The assignment names control characters and bidi overrides only.

No new dependencies. `BRIEF.md` and `RECHECK.md` are untracked window notes and are not part of the commit.

## Unsettled

Nothing left open. The length 1024 and the choice to escape brackets rather than delete them are recorded above so they can be changed without another reading of the diff.
