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

Pass 1 [code:all]: 2B/7S/3C/0R · fixed -/- · velocity = (—→12, escalation no)
passes: 1 · elapsed: 17 min (Stage 1, a same-model subagent, and Stage 2, fresheyes on the whole branch at 6e7f36a92e601d2e0cd024758d16adbd253ac97d, in parallel)

Code pass 1, Stage 2 (fresheyes, gpt-6.1-sol, high), all fixed:
- BLOCKER: a product entry in another spelling replaced the original in the widest state and left the check with a name it cannot judge. Fixed: `Thread.held_products`, added to `pull.widest`; tests `test_a_product_put_in_another_spelling_is_still_asked_about_by_its_first_name`, `test_respelling_the_product_does_not_take_a_curator_lowering_past_the_source`.
- BLOCKER: the history (fixed versions, aliases) was taken only from the widest state, so a fix a curator supplied was not in it. Fixed: `_Hold.note` records every state shown; tests `test_a_fix_and_an_alias_a_curator_supplied_are_part_of_what_is_asked`, `test_a_fix_a_curator_supplied_keeps_the_source_at_critical_for_a_later_bot_lowering`.
- SUBSTANTIVE: alias history cost the square of the aliases. Fixed with a set; `test_a_flood_of_aliases_is_kept_once_each`.
- SUBSTANTIVE: a damaged ruleset stopped `notify`. Fixed: no cache or ruleset is loaded unless a lowering is published, and a failure settles nothing; `test_a_damaged_ruleset_stops_no_alert_and_settles_no_lowering`.
- SUBSTANTIVE: `run` listed the alerts as they were before the source check. Fixed: it lists them again when they changed; asserted in the first acceptance test.
- SUBSTANTIVE: `verify` summarised the alerts as they were before the check. Fixed, with a line for the asked states; `test_verify_counts_the_alert_a_refused_retraction_brought_back`.
- SUBSTANTIVE: `renew` failed when a held list had grown past 50. Fixed; `test_renew_of_a_hold_on_a_thread_whose_list_has_grown_past_what_one_event_carries`.

Code pass 1, Stage 1 (same model; it also ran origin/main's replay against this one on 450 random threads and found no difference where no curator and no lowering is involved):
- SUBSTANTIVE: a curator raise sent with an expiry was lost after the hold. Fixed; `test_a_curator_raise_sent_with_an_expiry_outlasts_the_hold_and_the_expiry_does_not`.
- SUBSTANTIVE: a failed or cut-short re-read erased a contradiction. Fixed (`verify._settled`); asserted in the two re-read tests.
- COSMETIC, fixed: `plan` printed refusal lines of other advisories; the second pass of `run` ran with `verify = "off"`.
- COSMETIC, left: the hold note also prints under `--dry-run` (it says when the hold would end); a hold the checkpoint has already lapsed is still asked about (one request, no effect on what is shown).

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
