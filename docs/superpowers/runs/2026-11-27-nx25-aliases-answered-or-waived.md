# Run: nx25-aliases-answered-or-waived
Instruction: Read TASK-ai-tools-alerts#nx25.md in this worktree root, then run `kata show ai-tools-alerts#nx25` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: done
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT0 FC1 = 4; the dispatch floors it at medium too)
Lens: "Nothing you build may wait for a person to act."; "lowerings unchanged" (a lowering keeps today's rule whole; a first id that answers 404 is a failed read, as today); "Stay inside this issue."; "No host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record."
Last reviewed: spec deee8fdc575b6d9748fa1d0932302152f6f14ee1
Last reviewed: plan ae0e972b5bbfe2ba84938d4ad5559cc291c49589
Last reviewed: code 98910880c410bf8456b0f10fb0cb4f87261e0155 (whole branch, `git diff origin/main...9891088`; main dd4d195, not moved)
Spec: docs/superpowers/specs/2026-11-27-nx25-aliases-answered-or-waived-design.md   Plan: docs/superpowers/plans/2026-11-27-nx25-aliases-answered-or-waived.md
Agency project: — (no Agency tools in this session and its server does not answer; the three tasks are built in this session)
Kata: ai-tools-alerts#nx25
Limits: wall clock 5 hours from 2026-11-26T20:27Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — passes: 1 · elapsed: 12 min. Fixed 6/7 in the spec text (its Review section): only a refused answer is waived; a tied alias stays tied through a 404; a place a run for refreshing an answer; `asked` in the result key; the first eight aliases count; every tied alias read in one run. Rebutted: the message of the review snapshot commit, a dangling object that is never pushed. No delta pass: this rung has none, and the plan and code reviews read the revised rule.
Pass 1 [plan]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
plan — passes: 1 · elapsed: 9 min. Fixed 4/4 (the plan's Review section): the first-eight selection in the result key; the `MAX_PAIRS` test in tests/test_verify_narrowing.py; a test that a waived alias never makes a result whole; a test of `TooLarge` for a chunked body.
Pass 1 [code:whole-branch]: 2B/5S/4C/0R · fixed -/- · velocity = (—→11, escalation no)
code — Stage 2 (fresheyes, gpt-6.1-sol, 9891088): 2 blockers (replies replayed by a signer-set date reorder the aliases; a failed refresh of an answered alias left a contradiction standing), 2 substantive (the lowering test's two orders were one; the plan's "green after each step"), 1 cosmetic (module docstring). Stage 1 (same-model subagent): the same two as substantive, plus a refused answer kept through later failures; cosmetic: test gaps, a tied alias read for another thread in the same run, a deadline that an editable advisory can restart. Fixed: both blockers (`counted`, kept per first id; `tried` holds what the last request met), the sticky refused answer, the lowering test, the plan sentence, the docstring, the same-run tied alias, tests for 408, pruning, a refusal under the lowering rule. Rebutted: "test through signed-event replay" (the selection no longer reads the replay order; the test puts aliases in front at the level the selection is made); the restartable deadline (bounded by the eight that count, in the spec's open questions); the remaining test gaps (a 304 with no ETag sent and clocks set back are covered by the existing `304 unasked` failure case and by `_due`'s tests, the budget cutting only the refresh read changes no result).
Rung: climbs medium → heavy (cause: two BLOCKERs after the medium pass whose fixes change behaviour); the one delta pass runs `--since 9891088` with the rebuttals.
Pass 2 [code:whole-branch]: 2B/0S/0C/0R · fixed 2/2 prior · velocity ↓ (11→2, escalation no)
code — delta (fresheyes, gpt-6.1-sol, `--since 9891088`, reviewed head 48d339c): 2 findings, both fixed in the next commit with a regression test each, no further pass (ruling 41e2). (1) A record kept from an earlier read made the end-of-run pruning drop `since` every run, so an alias that was readable and is refused from then on held the thread for good; the pruning now uses the reads' own rule (`_alias_state`). This overturned the rebuttal that a restartable deadline is bounded at eight days: taken. (2) `whole` was true when a listed alias that does not count for the first id was not read; it now needs a record for every alias the state lists.
Gate: `scripts/test-gate.sh` in a clone of the branch alone, on 9891088: 1 failed (tests/test_never_supported_cli.py: a run whose budget cut an alias read stored a judged result under a new time), 3389 passed. Fixed with the delta's findings: a read the budget did not make leaves the read incomplete. The scan in the shared clone lists hits on other sessions' refs only: none of the 66 hit objects is reachable from this branch.
Gate on 5e2eb10, same clone method: 3405 passed, 1 skipped, public scan clean.
After the reviewed head 48d339c: 5e2eb10 (the delta's two findings and the gate's one, with tests; read by no review), then this record.

## Chunks
- [x] verify: alias memory, the reads of a run, the deadline, the lowering's own key; tests
- [x] docs: CHANGELOG, README

## Notes
- Skip temptations: none. The code was drafted while the spec review ran and was reworked after each review; Agency was not available, so the tasks were built in this session.
- Watchdog: four fresheyes runs, each FRESHEYES_DONE REASON=-; no stall. One review was started by mistake with `--help` as its scope and stopped at once.
- Wall clock: the seat's usage limit stopped the run for about 15 hours after the plan review was launched; work time was inside the 5 hours.
- Spec and plan were edited by script with exact-match checks in places, not only with the edit tool.
- Size: 8 files, about 1,000 changed lines with the spec, plan and this record; code and tests about 560. Not split (decided comment on the issue).
- Prior work read: issues nx25, 2mgd (spec, plan, run record, close-out), h29n (design review D1 to D14); `kata search "alias first id incomplete unread 404"` is the issue's own search (2mgd, fv4g, tavj).
