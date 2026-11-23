# Run: tyje-bot-patch-never-narrows
Instruction: ai-tools-alerts#tyje (brief TASK-ai-tools-alerts#tyje.md, /do-it, starting rung floored at medium): a relay-bot patch must not silence its own alert. Today `pull._apply_patch` with role relay-bot refuses a level lowering and an expiry but accepts a patch that narrows `products`, lowers `fixed`, empties `actions` or replaces `sources`. Build the reader rule the design review names (ai-tools-alerts#h29n, finding D1), with tests for each field, and keep released readers' behaviour documented. Stay inside this finding.
Stage: code-review:chunk 1
Rung: medium (dispatch floor medium; start-floor evaluator not run: its rubric file is outside the paths the seat rules let this session read; no hard trigger in this piece: no secret, key or credential handling and no deploy path in the diff)
Lens: "Readers at v0.1.6 and earlier are on member machines. This change must not alter the wire format, and it must never make the reader show less than it shows today for a patch a curator signed."
Spec: docs/superpowers/specs/2026-11-24-tyje-bot-patch-never-narrows-design.md   Plan: docs/superpowers/plans/2026-11-24-tyje-bot-patch-never-narrows.md
Agency project: — (no agency tools in this session; built directly)
Kata: ai-tools-alerts#tyje (related ai-tools-alerts#h29n; review ai-tools-alerts#3mhj)
Review shape: one independent pass per artifact (fresheyes, gpt-6-astra high: the issue is a security finding), one delta only when a BLOCKER fix changes behaviour. Wall clock: 4 hours from 2026-11-23T20:10Z. Completion check: scripts/test-gate.sh passes and the pull request merges.

Last reviewed: spec b380d0498007bb8ab203611a82930b74e667c682
Last reviewed: plan 5b7d8e421e3c6520228a04dcfb9075c7883d7f91

## Scorecards
Pass 1 [spec]: 1B/2S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6-astra high, snapshot b380d049, REASON=-)
  spec passes: 1 · fixed 1 (B): range cover alone let `fixed` fall inside a range `affected` already bounds (`<2.0` with fixed 3.0 → 2.0), which changes the upgrade the plan shows; `fixed` is now judged apart from the range, null the highest, with plan-level tests.
  rebutted 2 (S): (a) a curator's partial amendment after a held bot narrowing reads against the wide state, where a released reader carries the narrowed one: on purpose. The curator signed the fields the patch names; reading it against the narrowed state would let any later curator amendment put a forged narrowing into force. Stated in the spec, with a regression test of the designed behaviour. The lens line above is sharpened accordingly: a curator's patch applies exactly as signed, each field it names, whole. (b) the snapshot's commit message: a dangling review snapshot, never landed.
Pass 1 [plan]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6-astra high, snapshot 5b7d8e42, REASON=-)
  plan passes: 1 · fixed 3, all test gaps: the grid test goes through check.match with readable, unreadable and missing installed versions (versions.check alone cannot see a name match's actions); each list starts with two entries and loses one, with and without an addition in the same field; an upgrade action going from no version to one is held, asserted on the stored action.

## Chunks
- [x] chunk 1: the range comparison (versions.py), the reader rule (pull.py), tests, docs

## Notes
- Prior work: `kata search "narrow products fixed bot patch"` finds only ai-tools-alerts#h29n, whose comments carry the design review (finding D1 and rule 6 of the revised design). No dead end on record. capability-search not run: it is in a private repository the brief puts out of scope, and this piece builds no tool.
- The poster takes a thread's previous state from its own ledger (`poster/main.py`, `schema.validate(entry.advisory)`), not from the reader, so a narrowing the reader holds back is not sent again on the next run.
