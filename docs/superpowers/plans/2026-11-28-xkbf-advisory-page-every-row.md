# Plan: the advisory page parser reads every row and every range (ai-tools-alerts#xkbf)

Spec: `docs/superpowers/specs/2026-11-28-xkbf-advisory-page-every-row-design.md`.
One chunk; about 250 changed lines without the fixture.

## Chunk: parser

Files:

- `aitools_alerts/poster/rules.py`, the section "the vendor's page, read by the poster"
- `tests/poster/pages.py`, `advisory_page`
- `tests/poster/test_rules.py`, after `test_read_advisory_takes_nothing_from_the_description_or_an_unknown_shape`
- `tests/fixtures/poster/advisory-page-rows.html` (new), `tests/fixtures/poster/README.md`
- `CHANGELOG.md`, the unreleased section

Steps:

- [x] 1. Reproduce: run `rules.read_advisory` on the live page of
  GHSA-v2gx-m79c-pvxj. One block, `>= 2.0.0, <= 2.16.0`, no patch: the notice's
  values.
- [x] 2. `rules._package_rows(text)`: split the page (scripts, styles and SVG
  removed, as `_lines` does) into tags and text. Track `div` depth. A `div` with
  class `Bow-row` opens a row; inside a row a `div` with class `float-left` opens
  a column; each closes where its `div` closes. Collect each column's text nodes.
  Stop at the first text node "Description". Return `None` when a row or column
  opens inside a column, or when text lies outside a column after the first row.
- [x] 3. `rules._blocks(text)`: three columns a row; labels required in the first
  row and optional later; a row without a label takes the label above; no label
  among the values; ranges and patched versions pair by place; an empty column
  gives `None` for each block of the row; unequal non-zero counts refuse the
  page. Returns a tuple of `Block`, or `None`.
- [x] 4. `rules.read_advisory` calls `_blocks` in place of the label loop. Nothing
  else in it changes. `rules.evidence` does not change.
- [x] 5. `pages.advisory_page` renders GitHub's shape: a `Box-body`, one row per
  package with GitHub's classes, labels in the first row only, one element per
  range and per patched version. Consecutive `blocks` with one name and registry
  share a row when each states a range; otherwise each is its own row.
- [x] 6. The fixture: the title, header, package box, description and sidebar of
  the live page, with scripts, styles, SVG, images and the author link removed.
  Describe it in the fixtures README.
- [x] 7. Tests (spec, "New tests"): the fixture's three blocks and the evidence
  for `@modelcontextprotocol/inspector`; a product in an unlabelled later row;
  pairing by place, one range unpatched, an empty column; nine refused shapes,
  each also `unparsed` through `evidence`; rows written in a description.
- [x] 8. CHANGELOG entry under the unreleased heading.
- [ ] 9. Comment on ai-tools-alerts#z3fs: what the release session must know.
- [x] 10. After the reviews (the spec has the rules as they stand): the box is the
  `div` the first row opens in and holds nothing but rows, from its start; a row
  opens directly in it and before it closes. An entry is one `div` directly in a
  column, kept when empty, so pairing by place survives an empty element. Labels
  are read in the first row only. Each row's registry is its own. The heading
  counts only outside a row. A test for each, and the mutation list grown to
  fourteen.

Verification:

- `python3 -m pytest -q tests/poster/test_rules.py` (the parser and evidence tests)
- `scripts/test-gate.sh` (the public scan, then the whole suite) on the commit
- Mutation checks, each must fail a test: take only the first entry of a column;
  drop the "text outside a column" refusal; drop the unequal-count refusal; read
  rows after the "Description" heading.

Acceptance:

- The fixture gives three blocks; evidence for the inspector gives fix `2.17.0`
  and range `UNEXPRESSED`.
- Every test that built a page through `advisory_page` passes unchanged.
- The gate passes.

Rollback: revert the commit. Nothing is stored in a new form; the poster reads
pages again each run.

Not in this plan: the re-read of catalog notices (ai-tools-alerts#n2yj), the
terminal disposition of a page that never parses (ai-tools-alerts#psb5), any
release or install (ai-tools-alerts#z3fs).
