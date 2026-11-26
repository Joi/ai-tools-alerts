# Run: swfe-narrowing-checked-like-lowering
Instruction: ai-tools-alerts#swfe (starting rung floored at medium; repoman-lane ending). Brief: `TASK-ai-tools-alerts#swfe.md`: a relay-bot narrowing of products, range or fixed version is checked by the member like a lowering (revised design rule 6).
Stage: code-review:whole-branch
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; no hard trigger; the dispatch brief floors it at medium too)
Lens (every review pass carries both): "a released reader still shows the wider entry (tests/test_wire_compat.py)"; "the service runs with no human in the loop; nothing built may wait for a person to act"
Spec: docs/superpowers/specs/2026-11-26-swfe-narrowing-checked-like-lowering-design.md   Plan: docs/superpowers/plans/2026-11-26-swfe-narrowing-checked-like-lowering.md
Agency project: —
Kata: ai-tools-alerts#swfe
Last reviewed: spec 77cb1c0446bf7f9f587345e196a152829d982076
Last reviewed: plan 2795f02baa457b4d0b69de4a166783e657200526
Last reviewed: code (whole branch) f418801675898c32e7c5a37d762e28d919a1f43f

Limits: wall clock 5 hours from 2026-11-26T01:49Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the four acceptance cases pass in `scripts/test-gate.sh`.

Ending: the repository has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges, the issue closed on the merge commit.

## Scorecards
Pass 1 [spec]: 4B/3S/1C/0R · fixed -/- · velocity = (—→8, escalation no)
spec: passes 1 · reviewed 77cb1c0 (fresheyes, gpt-6.1-sol, high; REASON=-). All eight taken in the spec: the ecosystem binding; every new entry must state a pair; a readable range survives an unreadable one; the refusal is remembered by content and outlives the offer; a refusal stops only its own list; a flooded thread still takes an offer; `run` shows a changed product list; the false `min_cli` sentence removed. None survives, so the rung stays medium.
Pass 1 [plan]: 0B/7S/1C/0R · fixed -/- · velocity = (—→8, escalation no)
plan: passes 1 · reviewed 2795f02 (fresheyes, gpt-6.1-sol, high; REASON=-). All eight taken, in the plan and the code: a kept level contradiction no longer renews a confirmation (`_entry`, `whole` false); a cut-short run keeps the ranges it read; the two existing tests the change amends are named; `run` compares the same three fields on both sides; the refusal line comes from the marked entries and prints with the check off; `MAX_PAIRS` defined as the true maximum, nothing cut; a test that the same list's refusal ends by `run` alone; the README's contrary sentences. None survives, so the rung stays medium.
Pass 1 [code:whole-branch]: 2B/3S/2C/0R · fixed -/- · velocity = (—→7, escalation no)
code: passes 1 · reviewed f418801 (Stage 2 fresheyes, gpt-6.1-sol, high, REASON=-: 1 BLOCKER, 2 SUBSTANTIVE; Stage 1 same-model subagent in parallel: 1 BLOCKER, 2 SUBSTANTIVE, 2 cosmetic, one of its SUBSTANTIVE the same defect as Stage 2's BLOCKER). All taken:
- BLOCKER (Stage 2; Stage 1 finding 2): `narrow_key` kept order and duplicates, and a respelled list had another key. Now the key of the entry set, and a mark on the thread: no other list of a marked thread waits until fresh whole reads do not contradict it.
- BLOCKER (Stage 1, run end to end): the list was compared with `pull.widest`, which fills in a `fixed` the signer can plant, so a contradicted list read as unchanged and applied at once. Now compared with what the thread shows, per case-folded name.
- SUBSTANTIVE (Stage 2): under the lock the record was pruned against the threads read before it. Now rebuilt from the refreshed state.
- SUBSTANTIVE (Stage 2): the check captured before the lock could apply a list the refreshed record refuses. Now the command goes on with the refreshed threads, checkpoint and check.
- SUBSTANTIVE (Stage 1): `test_a_retracted_thread_takes_no_narrowing` proved nothing of its name. Rewritten.
- Cosmetic (Stage 1): two test names said more than the tests prove. Renamed.
The BLOCKER fixes change behaviour, so the rung climbs medium to heavy (the review cycle's one delta): `fresheyes --since f418801`, no rebuttals file, nothing was left unfixed.

## Chunks
- [x] reader: the published narrowing, the record, `standing` (968f3af)
- [x] source check: stated ranges in the cache, `verify.narrowing` (d8b75fb)
- [x] CLI: the check wired in, the lines and JSON keys (69de9d9)
- [x] wire test, wire.md, README, changelog (6a03b1b)
- main merged at f418801 (4fkh; one changelog conflict, both entries kept). The whole suite on the working tree before the merge: 2964 passed, 1 skipped.
- One code review for the four chunks together, on the whole branch at f418801: the chunks do not change what a member sees one by one, and the brief asks for one independent whole-branch review.

## Notes
- Prior work read: the design review and revised design on ai-tools-alerts#h29n (finding D1, rule 6), the close-out and notes of ai-tools-alerts#tavj, ai-tools-alerts#2wa6, `docs/superpowers/specs/2026-11-24-tyje-bot-patch-never-narrows-design.md` by its code, `spec/wire.md`.
- Agency execution: the agency tools are not available in this session; the plan is executed directly, chunk by chunk, with the tests of each chunk as its evaluator.
- The chunks were drafted in the working tree while the spec and plan reviews ran, and changed to follow each review before they were committed. Nothing was committed before the plan's review was disposed of.
- The first edit of the plan after the spec's review was made by a script that asserts each needle occurs once (it fails on a stale one); every later edit of a run document uses the Edit tool.
- Size: about 330 changed lines of code, about 1,450 with tests and documents. Not split: see the `decided:` comment on the issue.
