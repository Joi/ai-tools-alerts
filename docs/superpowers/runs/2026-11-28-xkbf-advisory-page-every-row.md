# Run: xkbf-advisory-page-every-row
Instruction: Read TASK-ai-tools-alerts#xkbf.md in this worktree root, then run `kata show ai-tools-alerts#xkbf` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: code-review:parser
Rung: medium (start-floor medium: dispatch floor; evaluator constraint-lens, BR1 REV1 NOV1 INT0 FC1 = 4, no hard trigger)
Lens: "the service runs with no human in the loop. Nothing you build may wait for a person to act." (carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-xkbf-advisory-page-every-row-design.md   Plan: docs/superpowers/plans/2026-11-28-xkbf-advisory-page-every-row.md
Agency project: — (no mcp__agency__* tools in this session; built directly)
Kata: ai-tools-alerts#xkbf
Limits: wall clock 5 hours; one independent pass per artifact, one delta when a BLOCKER fix changed behaviour; completion check: `rules.read_advisory` on the page shape of GHSA-v2gx-m79c-pvxj gives three blocks, and `rules.evidence` gives a fix of 2.17.0.
Last reviewed: spec 7bc81dc (snapshot)

## Scorecards
Pass 1 [spec]: 1B/3S/1C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 7bc81dc, REASON=-)
  - B a later package row laid out without the row class is left out and the rest read as the whole: text outside a column after the first row refuses the page (fixed, tests)
  - S an unknown shape defers with no end: rebutted for this issue. It is the rule on main (`test_a_failed_fetch_or_an_unparsed_page_defers_and_never_drops`) and a decision about `Run.admit`, not the parser; filed as ai-tools-alerts#psb5 and stated in the spec
  - S the helper's grouping against entries with no range: consecutive entries share a row only when each states a range (fixed in the spec; the helper was built so)
  - S the tests were not named: listed in the spec and written (fixed)
  - C the snapshot's commit message: rebutted, a dangling review snapshot, never on the branch
  passes: 1 · elapsed: ~8 min
Pass 1 [plan]: 1B/1S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6.1-sol high, at 38c118e, REASON=-; run beside the code review)
  - B a package row laid out another way before the first row is left out: the box is the div the first row opens in and must hold no text before it; rows open directly in it and before it closes (fixed, tests)
  - S an unknown shape defers with no end: rebutted as on the spec pass (ai-tools-alerts#psb5, raised to priority 1)
Pass 1 [code:parser]: 3B/3S/5C/0R · fixed -/- · velocity = (—→11, escalation no)   (Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6.1-sol high, whole branch origin/main...38c118e, REASON=-)
  - B (S1, S2) a value that is the word "Description" ended the box and hid the rows after it: the heading counts only outside a row (fixed, tests)
  - B (S2) empty elements dropped, so a range took the next range's patch: an entry is one element, kept when empty (fixed, tests)
  - B (S1, S2) under a "Software" first row a later row's registry was dropped, so `pip:x` matched the bare name: each row's registry is its own (fixed, test)
  - S (S1) a label's words in a later row were taken as a label: labels are read in the first row only (fixed, tests)
  - S (S1, S2) an unknown shape defers with no end: rebutted, ai-tools-alerts#psb5
  - S (S1) the box was not bounded before its first row (the plan's B; fixed)
  - C (S1) a line break inside an element made two entries (fixed with the entry change, test); `>` inside an attribute value (rebutted: only GitHub writes attributes, and `_lines` reads tags the same way); two refused-shape tests on one line (cases added; fourteen mutations each caught); plan checkbox (fixed)
  passes: 1 · BLOCKER fixes changed behaviour: one delta (fresheyes --since 38c118e --rebuttals) follows

## Chunks
- [ ] parser — every row and every range of the package box; test page helper in GitHub's shape; fixture

## Notes
- 2026-11-28: the live page of GHSA-v2gx-m79c-pvxj, run through `rules.read_advisory` at 4def27d, gives exactly the notice's values (one block, `>= 2.0.0, <= 2.16.0`, no patch). Cause: one "Affected versions" label over two ranges, one "Patched versions" label over two versions, and a second package row with no labels.
- Split: the re-read of catalog notices is ai-tools-alerts#n2yj; the end state of a page that never parses is ai-tools-alerts#psb5.
- The plan was written while the spec's review ran and is reviewed beside the code, on the commit: the spec's findings changed one parser rule and the test list, both in the plan as written.
- Mutation checks, each caught by a test: first entry of a column only; text outside a column allowed; unequal counts allowed; rows read after the heading; first-row label optional; a label among the values; a column inside a column; two columns allowed.
- Main merged before the review (fast-forward to aff940b, the v0.4.0 pin).
