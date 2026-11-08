# Run: mention-inline-code
Instruction: ai-tools-alerts#k5tr — start at medium. Task: exactly the kata issue body (TASK-ai-tools-alerts#k5tr.md): every rendered text wraps a whitespace-preceded @token in inline code; a source title cannot supply a backtick pairing with ours; /@user/ URLs untouched; aitools-alert block unchanged; tests as listed; acceptance fixture shaped like the 2026-11-08 digest. Under 120 changed lines. Repoman-lane ending.
Stage: code-review:compose-inline
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; dispatch floor medium too)
Lens: "aitools-alert block unchanged"; "a source title cannot supply a backtick pairing with ours"; "/@user/ URLs untouched"; "under 120 changed lines"
Spec: docs/superpowers/specs/2026-11-09-mention-inline-code-design.md   Plan: docs/superpowers/plans/2026-11-09-mention-inline-code.md
Agency project: —
Kata: ai-tools-alerts#k5tr
Last reviewed: —
Pre-handoff review: —

## Scorecards
Pass 1 [spec]: 0B/2S/1C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol, snap 161ce40, run 20261109-055057-d7f09f)
  S1 saved digest stays wedged after install — rebutted: live item hand-repaired 20:50Z per issue body; wedging is #8acj; spec now says so.
  S2 snapshot commit message — rebutted: review snapshots are dangling objects, never landed; landed commits get descriptive messages.
  C1 _inline not idempotent — fixed: claim removed, spec says it runs once per body.
spec: passes 1
Pass 1 [plan]: 0B/2S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6.1-sol, snap b227348, run 20261109-055430-d1f6b4)
  S1 no repoman row, gate cannot run; poster-only verification — fixed: repo is not repoman-managed (no marker, no row); verification is `python3 -m pytest tests -q`.
  S2 reply paths untested — fixed: scoped-product-name test over root, reply en/ja and block; mutation-checked.
plan: passes 1

## Chunks
- [ ] compose-inline — `_inline` in compose.py, applied to every body; tests

## Notes
- kata search "mention backtick inline code": only k5tr itself; prior work r7hr (fe140a9..a33feb8) added the source-title line and `candidates._title`'s run collapse.
- Ending: the brief says repoman lane, but the repo has no `.repoman-managed` marker and no registry row (checked cell-fleet origin/main repos.tsv). r7hr landed by fast-forward of main with a close; this run does the same (decided: comment on k5tr). roborev is not enrolled for this repo, so no post-push check; the whole-branch fresheyes pass is the independent look before landing.
- Code was drafted while the spec review ran (before plan approval); the plan review's findings were applied to it after. Spec edits from the spec review were applied with an asserting python replace, not the Edit tool; noted per the artifact-edit guardrail.
- Agency: project 01a1bcee-3e21-73bb-b2f9-ca7f17ba6a22, task 01a1bcef-d860-7f1e-b582-4b2f9f4bc212 (assign → execute → evaluator → submitted, score 90).
- The buzz-upstream checkout named in the brief is not on the build machine; the relay rule is taken from the issue body.
