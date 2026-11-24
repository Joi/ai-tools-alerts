# Run: 3qyq-advisory-readers
Instruction: ai-tools-alerts#3qyq (starting rung floored at medium): the poster reads GHSA and OSV from the fixed endpoints; the reversible withdrawn state; the claim tag on sent events (findings D4 and D13 of the design review on ai-tools-alerts#h29n)
Stage: code-review:readers
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch brief floors it at medium too)
Lens: "A 404 is never a withdrawal"; "a 404 and a 429 from the advisory endpoint each lower nothing"; "a withdrawn unreviewed advisory lowers nothing"; "an advisory whose severity toggles hourly produces at most three replies in a week"; "no human in the loop; nothing you build may wait for a person to act"
Last reviewed: spec 048e451637a8eb8d39dfc8a4d1f6f29503dd222e
Last reviewed: plan dad276eac0b326a9e403c3b7a9d3c93b0a286fba
Last reviewed: code a7cda1e39597b085d6f7370b43baf05950307b77 (the whole branch, `git diff origin/main...`, after the merge of main at v0.2.0)
Review tier: gpt-6-astra at high (the issue calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-25-3qyq-advisory-readers-design.md   Plan: docs/superpowers/plans/2026-11-25-3qyq-advisory-readers.md
Agency project: — (this session has no Agency tools; see Notes)
Kata: ai-tools-alerts#3qyq
Limits: wall clock 5 hours from the 2026-11-24T20:51Z dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Split: this issue keeps build items 1 to 3 (the readers and the recompute). ai-tools-alerts#y484 takes the `withdrawn` state (item 4), ai-tools-alerts#hh5s the claim tag (item 5).

## Scorecards
Pass 1 [spec]: 6B/2S/0C/0R · fixed -/- · velocity = (—→8, escalation no)
spec passes: 1 · reviewer gpt-6-astra (fresheyes run 20261125-055822-7306cb) · six BLOCKERs and one SUBSTANTIVE fixed in the spec, one SUBSTANTIVE rebutted; nothing survives, so the rung stays medium

Spec findings and what was done:
1. BLOCKER, a withdrawn malware advisory published again could not return to critical: `held` inferred `stop_using` only from a thread standing at the level. Fixed: `support` returns the current tied read's `stop_using` and `held` passes it on (criterion 3a).
2. BLOCKER, admission and `ledger.merge` bypassed the alias rule: a fix group's other member lent its reading. Fixed: `Run.one` keeps only readings `sources.tied` accepts for the candidate's first id (criterion 3c).
3. BLOCKER, a KEV listing that changed no level never marked the thread exploited. Fixed: `Run._judge` marks it when a copy lists it (criterion 3d).
4. BLOCKER, a notice held while the API failed had no path back. Fixed: the candidate is admitted again each run for seven days (criterion 3b).
5. BLOCKER, admission could spend the whole budget and failing waits could starve the rest. Fixed: three lanes of ten requests and twenty seconds, each rotated by the hour (criterion 3e).
6. SUBSTANTIVE, the OSV reader had no path in. Fixed: the ids a first GHSA read names are read, as the member does (criterion 3f).
7. BLOCKER, the breaker's share test would fail with GHSA threads judged. Fixed: the share is of the threads read whole this run; criterion 9 names the tests that change.
8. SUBSTANTIVE, the snapshot commit's message. Rebutted: a dangling commit made for the reviewer by `git commit-tree`; it is on no branch and never lands.

Pass 1 [plan]: 7B/2S/0C/0R · fixed -/- · velocity = (—→9, escalation no)
plan passes: 1 · reviewer gpt-6-astra (fresheyes run 20261125-060607-9c8ff0) · all nine fixed, in the plan's "Amendments" section, the spec and the code; nothing survives, so the rung stays medium

Plan findings and what was done:
1. BLOCKER, a candidate's readings were filtered by its own id, so a group member sighted alone could raise the thread it was posted under. Fixed: filtered by the thread's published id.
2. BLOCKER, a CVE beside an advisory first id bypassed the tie rule. Fixed: it counts only when the first id's response names it.
3. BLOCKER, `ids |= extra` with a list. Fixed: `ids | set(named)`.
4. BLOCKER, `support`'s fifth value broke two ny5g unit tests. Fixed: their helper takes the first four; the spec's criterion 9 says so.
5. BLOCKER, the failed-read test named hour 46. Fixed: hour 27.
6. BLOCKER, Task 3's tests needed Task 4. Fixed: order changed.
7. BLOCKER, the list of existing tests that change was short. Fixed: the test environment's advisory API answers by default; criterion 9 names every test rewritten.
8. SUBSTANTIVE, the retry had no bound when the `waiting` map is full. Fixed: no first sight on record, no retry.
9. SUBSTANTIVE, the failure matrix and the OSV test were thin. Fixed: both bodies added, each answer run with and without a wait; the OSV test asserts a level only OSV supports.

Pass 1 [code:readers]: 4B/4S/2C/0R · fixed -/- · velocity = (—→10, escalation no)
code passes: 1 · the whole branch at a7cda1e39597b085d6f7370b43baf05950307b77 · Stage 2 gpt-6-astra (fresheyes run 20261125-063720-3aaa76): 4 BLOCKER, 1 SUBSTANTIVE · Stage 1 a same-model reviewer, which ran its probes against an extract of that commit: 2 BLOCKER (both among Stage 2's), 4 SUBSTANTIVE (one among Stage 2's), 2 COSMETIC · every finding fixed, none rebutted; the rung stays medium

Code findings and what was done:
1. BLOCKER (both reviewers), a KEV-governed thread with no CVE judged reached the catalog version comparison with none and raised `TypeError`, stopping every run until KEV returned; a CVE the advisory stopped naming also let an outage add time. Fixed: such a thread is not known without a complete copy, with a once-listed CVE no longer judged, or with no CVE judged.
2. BLOCKER (both), the KEV listing was remembered only in the recompute file, so losing the file dropped the KEV-absence rules. Fixed: `Run.recompute` marks the ledger; the state keeps the CVEs.
3. BLOCKER (Stage 2), a fix group's level could come from another member's KEV listing while its first id's source said less. Fixed: `ledger.merge` puts the member with the strongest evidence first.
4. BLOCKER (Stage 2; SUBSTANTIVE in Stage 1), ids past the three a member reads were read and counted, so a fourth could raise. Fixed: `sources.chosen` is the member's selection; nothing else is read or counted.
5. SUBSTANTIVE (Stage 2), a published stop_using kept a critical after the advisory stated a patched version. Fixed: inferred only when a source was not read whole.
6. SUBSTANTIVE (Stage 1), a lane's 20 seconds ran from its first request, so slow vendor pages ended admission's reads. Fixed: only time inside the lane's requests counts.
7. SUBSTANTIVE (Stage 1), the rotation test passed with a fixed order. Fixed: it asserts all fourteen threads are asked in fourteen hours, ten a run.
8. SUBSTANTIVE (Stage 1), no test showed `_judge` uses the wait lane. Fixed: `test_threads_with_a_wait_are_read_in_a_lane_of_their_own`.
9. COSMETIC (Stage 1), the breaker test of this file passes with `judged` for `known`. Left: ny5g's own test fails under that change, as Stage 1 found.
10. COSMETIC (Stage 1), `observe`'s docstring. Fixed.

Pass 2 [code:readers]: 3B/0S/0C/0R · fixed 8/8 prior · velocity ↓ (10→3, escalation no)
code passes: 2 (the whole branch, then the one delta `--since a7cda1e39597b085d6f7370b43baf05950307b77` at da8f7153ee97295f82a48b10036e5acf5fd1d556, fresheyes run 20261125-065553-5c5b41, gpt-6-astra; it gave three findings as "major" with no class, taken as BLOCKERs) · all three fixed in the next commit, which no reviewer has read; no further pass, as the review cycle rules

Code findings, pass 2 (the delta), and what was done:
1. A fix group now led by its loudest member was judged old by that member's date alone. Fixed: the group's age is its newest member's (`Run.plan_new`); `test_a_fix_group_is_as_new_as_its_newest_member`.
2. A KEV listing first seen in the last judging of a run (a thread that run posted) was not marked in the ledger. Fixed: the ledger is marked after that judging; `test_a_kev_listing_first_seen_on_a_thread_this_run_posted_reaches_the_ledger`.
3. The group's order counted readings the tie rule then rejects, so a member could win the first place and lose its level. Fixed: members are ranked by their tied readings; `test_a_reading_the_first_id_does_not_tie_wins_no_place_in_a_fix_group`.

## Chunks
- [ ] readers: `poster/sources.py`, `recompute.support` and `judge`, `rules.readings_for`, `main.Run`

## Notes
- The delta's first launch printed `FRESHEYES_STALLED … REASON=LOG_WAIT`: a caller error (scope text given with `--since`, which fresheyes refuses before it starts), not a stall. Relaunched without the text; not counted as a retry.
- One spec edit and several code edits were made with a script that asserts each replaced text occurs exactly once, not with the Edit tool. The skill asks for Edit on run artifacts; the later artifact edits use it.
- Main moved twice during the run: the v0.2.0 release (merged before the whole-branch review) and ai-tools-alerts#tavj (merged after the delta; one conflict, in the changelog). tavj changed which aliases a member reads beside a CVE first id when there are more than three; `sources.chosen` now counts none in that case. That change and the three delta fixes are the code no reviewer has read.
- Agency: the skill's Step 3 names Agency tools; this session has none, as the ny5g run found. The plan's tasks are executed here and reviewed at the chunk boundary.
- Prior work read: ai-tools-alerts#ny5g and every note on it (tyje, t8jr, s6mt, r0ra, fv4g, 9kgk), the notes on 3qyq (ny5g as built, yw7r). `kata search "GHSA OSV advisory API reading withdrawn state poster"`: 3qyq, ny5g, fv4g, h29n.
