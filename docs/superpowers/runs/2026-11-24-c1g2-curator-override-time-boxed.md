# Run: c1g2-curator-override-time-boxed
Instruction: Read TASK-ai-tools-alerts#c1g2.md in this worktree root, then run `kata show ai-tools-alerts#c1g2` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: code-review:all
Rung: medium (start-floor medium: constraint-lens, BR2 REV1 NOV1 INT2 FC1 = 7; no hard trigger; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act." / "No rollout." / no host, home-path or personal-email text in any commit, PR text or run record.
Spec: docs/superpowers/specs/2026-11-24-c1g2-curator-override-time-boxed-design.md   Plan: docs/superpowers/plans/2026-11-24-c1g2-curator-override-time-boxed.md
Agency project: — (no agency tools in this session; the plan is executed in-session)
Kata: ai-tools-alerts#c1g2
Limits: wall clock 5 hours from 2026-11-24T13:02Z; one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the three acceptance tests of the issue pass in `scripts/test-gate.sh`.
Last reviewed: spec 299ea8430f0c6d98cd45faacdc1a749eff206f9e
Last reviewed: plan 08fa4605ed5b56e1c66e67c1ae7632da90b32e9a

## Scorecards
Pass 1 [spec]: 3B/3S/0C/1R · fixed -/- · velocity = (—→7, escalation no)
passes: 1 · elapsed: 12 min

Spec pass 1 findings and what was done (reviewer: fresheyes, gpt-6.1-sol, high):
- BLOCKER: a relay-bot reply that clears `fixed` makes the source read `high` for a KEV critical and confirms the lowering the same key then signs. Fixed: the check is asked about `pull.widest`, which keeps the first fixed version the thread stated (`Thread.held_fixed`); test `test_clearing_the_fixed_version_does_not_make_the_source_confirm_a_lowering`.
- BLOCKER: fields that give `notice` would confirm lowering a `high` that rests on a reading. Fixed: `verify.lowering` confirms only `match`, and never below the ruleset's `reading_cap`; test `test_fields_that_give_notice_do_not_confirm_a_lowering_below_what_a_reading_may_hold`.
- BLOCKER: a confirming result was cached for good. Fixed: `verify.run(recheck=)` reads an asked state again daily, a result older than 48 hours confirms nothing, a failed read is `unread` at once; test `test_a_confirmation_is_read_again_every_day_and_does_not_outlive_two`.
- SUBSTANTIVE: a retraction asked at `none` read as `match` from a source's silence. Fixed in `verify.judge`, and a retraction is never confirmed (below `reading_cap`); test `test_a_retraction_is_contradicted_by_support_and_never_confirmed`.
- SUBSTANTIVE: `run` notified before the source was read and did not look again. Fixed: `cmd_run` builds the matches again after the source check when a lowering was asked about; the first acceptance test asserts the notification and exit 2 in the same run.
- SUBSTANTIVE: the compatibility test did not exercise the change. Fixed: a new case in `tests/test_wire_compat.py` states the exception; `spec/wire.md` names it.
- Not taken (restatement): the message of the review snapshot commit. That commit is a dangling object made for the reviewer and lands nowhere.

Pass 1 [plan]: 1B/4S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
passes: 1 · elapsed: 9 min

Plan pass 1 findings and what was done (same reviewer):
- BLOCKER: when the request budget cut a refresh short, `verify.run` kept the old result with a new time, so an old confirmation read as fresh and could stand in for a contradiction just found. Fixed: a rechecked state is stored `unread` there; test `test_a_refresh_the_budget_cut_short_does_not_pass_for_a_fresh_confirmation`.
- SUBSTANTIVE: the plan did not say a curator block's level sets or clears `offered`. The code did; the plan now says so, with two tests.
- SUBSTANTIVE: no stated path for the settings and the kept threads to `_matches` and `_source_check`. The plan now names `a.settings`, `a.raw`, `a.asked`.
- SUBSTANTIVE: `recheck=` not wired from the CLI in the plan. The plan now says so; test `test_a_confirmed_lowering_is_read_again_a_day_later_through_the_cli`.
- SUBSTANTIVE: refusal lost between `Thread` and the JSON. `Entry.refused` carries it; asserted for both JSON commands.

## Chunks
- [x] reader: hold, lapse, widest state, published lowering (aitools_alerts/pull.py)
- [x] member check applies to a lowering (aitools_alerts/verify.py, aitools_alerts/cli.py)
- [x] curator command: renew, standing state, hold note (aitools_alerts/curator.py); exporter and poster read the standing state
- [x] docs: README, docs/design.md, spec/wire.md, CHANGELOG.md

## Notes
- The repo has no repoman marker: the ending is a pull request this session merges (TASK brief), not a repoman handoff.
- Seat rule: nothing outside the worktree is read. The review tools are run, not read.
- Order: the code was written while the spec and plan reviews ran, to stay inside the wall-clock limit. Each review's findings were applied to the code as well as to the document.
- Skip-temptation, resolved: the start-floor evaluator was run although the brief already set the floor.
- Tooling slip: asking the review script for its usage text started a review of nothing; it was stopped within a minute (its own process group only). No finding came of it.
- The spec and plan were first amended with a checked replace script (it fails when the text to replace is not found exactly once), not the edit tool the skill names. Later edits of the run documents use the edit tool.
- Replay detail changed from the first draft after a test showed it: only a curator's own reply lapses a hold during replay. With any reply doing so, a stored relay-bot event dated years ahead undid every curator correction of its thread.
