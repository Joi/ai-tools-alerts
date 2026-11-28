# The advisory page parser reads every row and every range (ai-tools-alerts#xkbf)

## Problem

The catalog notice for GHSA-v2gx-m79c-pvxj (MCP Inspector) says
`affected ">=2.0.0,<=2.16.0"`, `fixed null`, no action. The repository advisory
states two ranges for `@modelcontextprotocol/inspector` (`>= 2.0.0, <= 2.16.0`
fixed in 2.17.0; `<= 1.0.6` fixed in 1.0.7) and one for
`@modelcontextprotocol/inspector-server`. A member on 1.0.x is not matched, and a
member on 2.x is told no fix exists.

The page as GitHub serves it on 2026-11-28, run through `rules.read_advisory` at
main `4def27d`, gives exactly the notice's values. The parser is the cause:

1. GitHub renders one package once, with every range as its own element under
   one "Affected versions" label and every patched version under one "Patched
   versions" label. The parser takes the first text node after "Affected
   versions" and expects the "Patched versions" label next. It meets the second
   range instead, so it keeps one range and no patch.
2. GitHub prints the three labels in the first row only. A later package row has
   no label, and the parser finds a block only at a "Package" or "Software"
   label. A product named only in a later row is never matched ("vendor page
   names another package").

The test helper `tests/poster/pages.py` repeats the labels for every block,
which is not GitHub's shape, so no test saw either.

Whether the advisory already stated the 1.x range when the poster read it cannot
be read from the page (GitHub shows no edit history to the public). It does not
change the finding: the parser gives the published values from the complete
page.

## Success criteria

- `rules.read_advisory` on a page in the shape of GHSA-v2gx-m79c-pvxj gives three
  blocks: inspector `>= 2.0.0, <= 2.16.0` / `2.17.0`, inspector `<= 1.0.6` /
  `1.0.7`, inspector-server `<= 1.0.6` / `1.0.7`.
- `rules.evidence` for a product whose package has two ranges gives the highest
  patched version as the fix and `UNEXPRESSED` as the range (the existing rule
  for several blocks, dmmf), never the first range alone and never "no fix".
- A product named only in an unlabelled later row is matched.
- The one-row fixture `tests/fixtures/poster/advisory-page.html` reads as before.
- Text in a description still cannot stand in for a field.
- A page whose package box has a shape the parser does not know is not read
  (`None`, which `evidence` reports as `unparsed` and main defers and counts),
  never read in part.
- `scripts/test-gate.sh` passes.

## Approach

`read_advisory` reads the package box by GitHub's own row and column elements,
in place of label-and-next-text-node:

- The page is split into tags and text once. Reading stops at the first text
  node that is exactly "Description", as now.
- A `div` whose class list has `Bow-row` (GitHub's spelling) starts a row. Inside
  a row, a `div` whose class list has `float-left` starts a column. Text nodes
  are collected per column, normalised as `_lines` does.
- A row must have exactly three columns: package, affected, patched.
  - Column 1: an optional "Package" or "Software" label, then the name, then the
    registry in parentheses. A row without a label takes the label of the
    nearest labelled row above. The first row must carry a label.
  - Column 2: an optional "Affected versions" label, then one text node per
    range. Column 3: an optional "Patched versions" label, then one per patched
    version. The first row must carry both labels.
- Ranges and patched versions pair by position. Equal counts: one block per
  pair. One side empty: one block per entry of the other side, the empty side
  `None` (an empty field renders no text node; this is today's reading of a row
  with no range or no patch). Both sides empty: one block with neither. Unequal
  non-zero counts: the page is not read.
- The box is rows of columns and nothing else: from the first row to the
  "Description" heading, a text node outside a column makes the page unread, and
  so does a row or column opening inside a column. A package row GitHub lays out
  some other way is then never left out while the rest reads as the whole.
- Any row that breaks these rules makes the whole page unread. No rows at all
  makes it unread, as "no blocks" does now.

Everything else in `read_advisory` (the GHSA id, the sidebar CVE ID, severity,
title, description, the whole-page check) is unchanged. `evidence` is unchanged:
with several blocks for the product it already gives the highest patched version
and `UNEXPRESSED` for the range, and "no fix" only when one of the blocks states
none.

Class names are attribute text only GitHub writes: the title, package names and
versions are escaped text, and the description comes after the cut and has its
class attributes removed by GitHub's sanitiser.

Tests: `tests/poster/pages.py` renders GitHub's shape (labels in the first row
only, rows and columns with GitHub's classes, one element per range). Its
`blocks` argument keeps its meaning: consecutive entries with one name and
registry render as one row with several ranges when each of them states a range,
and otherwise each entry is its own row (an entry with no range renders an empty
element, which in a shared row could not be paired). A second fixture,
`tests/fixtures/poster/advisory-page-rows.html`, is the labelled part of the
live GHSA-v2gx-m79c-pvxj page with scripts, images and the author link removed,
as the first fixture was made.

New tests in `tests/poster/test_rules.py`:

- the new fixture reads as the three exact blocks, and `evidence` for a product
  scoped to the two-range package gives the fix 2.17.0 and `UNEXPRESSED`;
- a product named only in an unlabelled later row is matched, with its own range
  and fix;
- one range without a patch among several ("None" at its place) gives no fix;
- each refused shape makes the page unread and `evidence` report `unparsed`:
  unequal counts, a row of two columns, a first row without a label, a label
  among the values, a later row laid out without the row class, a column inside
  a column;
- row and column markup written in a description changes nothing.

## What a member sees after this

For a package with several ranges the block carries the highest fix and no
range, and the post says to see the source for the range. A member on a patched
release of an older branch (inspector 1.0.7) is matched and told to upgrade to
2.17.0. That is wider than the advisory and is the safe direction; expressing a
union of ranges needs a schema change and is not in this issue.

A fix now read where none was read before can raise a level (the clauses that
need a fix), which is the rule working on the vendor's own statement.

## Alternatives considered

- Keep text nodes and guess the row boundary from the "(" after a name: a range
  and a patched version in an unlabelled row cannot be told apart. Rejected.
- Read the advisory API instead of the page: `api.github.com/advisories/<id>`
  answers 404 for this advisory (not in the global database yet), which is the
  common state of a fresh repository advisory. Rejected.
- Fall back to the label reading when no row element is found: that is the
  reading that produced the wrong notice. Rejected; an unknown shape defers and
  is counted, with no person needed, and the count shows in the run summary.

## The other questions in the issue

- Question 3, a catalog notice is never read again: confirmed in the code. Once
  a notice is listed in a digest its ids go to `digested` and the candidate is
  dropped on sight (`Run` "once is enough"); the catalog inventory keeps the
  first block. So the published Inspector notice stays wrong after this fix, and
  an advisory its vendor edits later is never corrected. That is a second
  deliverable (a bounded re-read of catalog entries, new state, its own tests)
  and is filed as its own issue, per the split rule.
- Question 4, the title: intended. A block's title is the template
  `<product>: <kind> (<id>)` (0dvh); the source's own title is upstream text and
  is kept out of the signed block. Alert posts carry it on a body line; a
  catalog post is the block alone (q03f). No change.

## Blast radius and rollback

One function in `aitools_alerts/poster/rules.py`, the test page helper, one new
fixture. Poster only: no reader, schema or wire change. If GitHub's markup lacks
the row classes on some page, that advisory defers each run and shows in the
"advisory page not parsed, deferred" count; nothing wrong is published. Rollback
is a revert of the commit. The poster runs from an installed release, so the fix
reaches the service with the next release (noted on ai-tools-alerts#z3fs).

## A page that never parses

`Run.admit` defers an unparsed page every run with no end; that is the rule on
main (`test_a_failed_fetch_or_an_unparsed_page_defers_and_never_drops`) and this
change keeps it. It does make the path more likely: a page whose box is laid out
another way was read in part before and is deferred now. Deferred is the better
of the two, and neither waits for a person in the sense of blocking a run, but a
markup change at GitHub would hold every new repository advisory with only a
count to show for it. The terminal disposition (post as a notice without
fields, drop with a digest line, or a digest line on a burst) is a design
decision about `admit`, not about the parser, and is ai-tools-alerts#psb5.

## Open questions

None that block. Whether GitHub ever renders unequal counts of ranges and
patched versions in one row is unknown; the parser refuses that page.
