# Run: 53fy-widened-fixed-flagged
Instruction: Read TASK-ai-tools-alerts#53fy.md in this worktree root, then run `kata show ai-tools-alerts#53fy` and follow the brief and the dispatch rules pasted after this sentence. (The brief file is empty; the issue text is the brief: a relay-bot widening of `fixed` past the advisory is flagged and gives no upgrade version. Dispatch: /do-it, starting rung floored at medium.)
Stage: verifying (the gate on the merged head, then the pull request and its merge; the merge commit and the close are on the issue)
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; no hard trigger; the dispatch brief floors it at medium too)
Lens (every review pass carries all three): "It still matches and still interrupts: the alert is not narrowed"; "with the fetch failing nothing changes"; "a released reader is unaffected (`tests/test_wire_compat.py`)"
Spec: docs/superpowers/specs/2026-11-27-53fy-widened-fixed-flagged-design.md   Plan: docs/superpowers/plans/2026-11-27-53fy-widened-fixed-flagged.md
Agency project: —
Kata: ai-tools-alerts#53fy
Last reviewed: spec 1c5baf5bd57d487ff8ab7a62ef1568e4e046c1d2
Last reviewed: plan 37768c33c5594c6c6074411cb8579e5bfe58ec76
Last reviewed: code (whole branch) f28bcd218b780a8beaa681f7fc7d3ef336bbb33b (the tree of commit 5561320); delta to 4ac0fd231728cf2f7844943a68d93d95b7cfd02a
Unreviewed after the delta: e696180 (the delta's one finding, the spec only), 6814ce5 (merge of main: `__all__` in verify.py and the changelog's Unreleased section conflicted, nothing else), the run-record commit

Limits: wall clock 4 hours from 2026-11-27T12:10Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the four acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.

Ending: the repository has no `.repoman-managed` marker, so the unmanaged landing applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges, the issue closed on the merge commit.

## Scorecards
Pass 1 [spec]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high, run 20261127-211252-b122bf; passes: 1)
- B1 first notification is the only one and names the raised version: fixed (a correction, sent once, remembered in seen.json).
- B2 translations carry the version: fixed (a flagged match uses no translation).
- S1 a read whose cache cannot be written is lost to the flag: fixed (the command's own results are threaded through).
- S2 the snapshot commit's message is vague: rebutted. It is a dangling review snapshot (`git commit-tree`), on no branch, never pushed.
- Rung stays medium: no BLOCKER or SUBSTANTIVE finding survives the pass. The BLOCKER fixes changed the spec; medium runs no delta, the plan review reads the plan built on them.
Pass 1 [plan]: 3B/0S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, run 20261127-211916-1be14a; passes: 1)
- B1 fresh results bypass the too-old guard: fixed (`_flag` uses them only where `_results` is not None).
- B2 two flagged products: a correction right after a notification that said no version: fixed (an accepted notification records the key of every flagged match of the entry; the correction line claims nothing about an earlier notice).
- B3 a flagged and an unflagged match share one translation: fixed (no translation for any match of an entry with a flagged match).
- Rung stays medium: nothing survives the pass. No delta at medium; the code review reads the code built on the amended plan.
Pass 1 [code:reader]: 1B/1S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (Stage 2: fresheyes gpt-6.1-sol high, run 20261127-215852-606d68, snapshot f28bcd2; passes: 1)
- B1 the English title can name the contradicted version: fixed (the id stands for the title of an entry with a flagged match, in check, plan, the notification and the correction).
- S1 the skill and snippet tell the agent to report the raw action before plan, and do not document the key: fixed (the key and the rule, before the first report, in all three copies; pinned in tests/test_templates.py).
- Stage 1 (same-model subagent) did not finish: the seat's usage limit ended it. Not rerun: the independent pass is the one the rung requires, and the delta below reads the fixes.
- The BLOCKER fix changes behaviour: one delta pass (fresheyes --since 5561320, no rebuttals file: every finding was fixed). Cause named for the climb to heavy's delta: do-it's own rule for a behaviour-changing BLOCKER fix, no hard trigger.
- Gate at the reviewed tree (before the fixes): scripts/test-gate.sh, public scan clean, 3395 passed.
Pass 2 [code:reader]: 0B/1S/0C/0R · fixed 2/2 prior · velocity ↓ (2→1, escalation no)   (delta: fresheyes gpt-6.1-sol high --since 5561320, run 20261128-020348-ccb2b2; passes: 2)
- S the spec gave two rules for the title of a flagged alert: fixed in e696180 (the spec only). No further pass.

## Chunks
- [x] reader: the flag, the plan without a version, the lines, tests, docs (5561320, 4ac0fd2, e696180; review clean after one pass and one delta)

## Notes
- Directive nfwc8d (the brief arrived as a comment after the run began; acknowledged on the issue): landing by pull request merged with the no-reply author address, main merged before the final gate and before the merge, no rollout, nothing read outside the worktree from then on. The review tool runs from outside the worktree; nothing else was read there after the directive.
- Size: 234 changed lines of code, about 560 of tests, the rest documents and this record (1,101 in all). Not split: the flag, the plan without a version and the correction change nothing a member sees alone, and the spec and plan reviews had been spent on the whole (as ai-tools-alerts#swfe decided).
- The brief's order "merge main before your review": the whole-branch review ran before the directive arrived, on the branch as cut from dd4d195. Main (kk2q, nx25) was merged after the delta; the merge touched two conflict hunks named above.
- Agency project 01a21cf7-77d2-788d-80f3-bd95b9d84383, three tasks (core, CLI, compat and documents), executed in this session.
- Existing tests changed (4), each because `test_verify_cli.bot()` posts `fixed` 99.0.0 and `test_verify.ghsa()` stated 9.9.9, so a whole read now flags it; each now serves an advisory that states 99.0.0 (`ghsa(fixed="99.0.0")`, a new parameter) and asserts what it asserted before: `test_never_supported_cli.py::test_support_lost_yesterday_keeps_the_level_and_is_flagged_only_past_48_hours` (through `supported_then_withdrawn`), `test_unverified_cli.py::test_a_third_unverified_critical_from_one_key_is_listed_and_does_not_interrupt`, `test_unverified_cli.py::test_a_copy_of_a_post_confirmed_earlier_is_not_confirmed_with_it`, `test_verify_cli.py::test_published_below_the_source_is_flagged`.
- Found in execution: a withdrawn advisory still lists ranges and would have flagged; `fixed_stated` now needs the product supported at some level (spec amended).
- Plan item not built as a test: a `may apply` match with a flagged `fixed` (such a match has no version or no range to compare; `_corrections` excludes it by reason).
- Skip-temptation: the spec's criteria list was reordered once with a script, not the Edit tool; it applied cleanly. Later artifact edits use Edit.
- Stray process: a `fresheyes.sh --help` probe started a review (the script has no help flag); its process group was stopped at once, no result used.
- The brief file `TASK-ai-tools-alerts#53fy.md` is empty (0 bytes); the issue body carries the build and the acceptance.
- Prior work read: ai-tools-alerts#swfe (spec, close-out, decision 2 names this follow-up), ai-tools-alerts#0z4e (the level's half), ai-tools-alerts#tyje (the join), ai-tools-alerts#2mgd (scope product identity).
