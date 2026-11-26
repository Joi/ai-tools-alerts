# Run: y484-withdrawn-reader
Instruction: Read TASK-ai-tools-alerts#y484.md in this worktree root, then run `kata show ai-tools-alerts#y484` and follow the brief and the dispatch rules pasted after this sentence. (The brief: ai-tools-alerts#y484, the reversible withdrawn state, D4 and D13; run as /do-it, starting rung medium.)
Stage: spec
Rung: medium (start-floor medium: constraint-lens, BR1 REV2 NOV1 INT2 FC1 = 7; no hard trigger; the dispatch floors it at medium too)
Lens: "Released readers must still show the alert." (in every review pass)
Spec: docs/superpowers/specs/2026-11-26-y484-withdrawn-reader-design.md   Plan: docs/superpowers/plans/2026-11-26-y484-withdrawn-reader.md
Agency project: —
Kata: ai-tools-alerts#y484 (poster half split to ai-tools-alerts#kk2q)
Limits: wall clock 5 hours of working time from the 2026-11-26T05:11Z dispatch (the session stood at its usage limit from 05:12Z to about 06:20Z); review shape one independent pass per artifact on gpt-6-astra, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Last reviewed: spec 3f25dc38bb0a32cc997012f959d4a49e097e685d
Last reviewed: plan 57e242989ff349b77af8bb3b14c741bc5d14c9e4

## Scorecards
Pass 1 [spec]: 1B/4S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
spec: passes 1 · gpt-6-astra through fresheyes · the BLOCKER and three SUBSTANTIVE fixed in the spec, one SUBSTANTIVE rebutted

Spec findings and what was done:
1. BLOCKER: the withdrawal and notice questions have separate results in the check's cache; a run cut short could contradict the withdrawal, leave notice unread, and the notice reading would apply unchecked after 72 hours, the contradiction never entering the refusal memory. Fixed: criterion 4a and `pull.offer_said`, one answer for the reader and the refusal memory, in which a contradiction of either question counts for both.
2. SUBSTANTIVE: "a source that publishes again brings the thread back" cannot hold after a claimed thread has decayed. Fixed: criterion 7 says so; expiry does not change; a test before and after.
3. SUBSTANTIVE: a curator's hold governs over a confirmed withdrawal. Fixed: stated as the exception in criterion 2, tested in both orders.
4. SUBSTANTIVE: a relay-bot reply whose first line is `retract` is not ignored whole today (its claim and a named level are collected before the guard). Fixed by narrowing criterion 9 to what the code does: it retracts nothing and its block is not read.
5. SUBSTANTIVE, rebutted: the message of the review snapshot commit does not describe the change. That commit is a dangling review snapshot and never lands.

Pass 1 [plan]: 1B/4S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
plan: passes 1 · gpt-6-astra through fresheyes · all five fixed in the plan (the BLOCKER in the spec too)

Plan findings and what was done:
1. BLOCKER: an older confirmation of the withdrawal would hide the thread while a newer result for notice reads support above notice. Fixed: support above notice makes `offer_said` False first, and the thread is hidden only when the notice answer does not contradict; a test with the stub and one through the real cache.
2. SUBSTANTIVE: the plan's `"none"` rows said None where today's check says False. Fixed: `"none"` keeps today's answers.
3. SUBSTANTIVE: the refusal line read only the withdrawn state's result. Fixed: it reads both asked states; a CLI test of a notice-derived refusal.
4. SUBSTANTIVE: the count line's wording is asserted in tests/test_curator_hold_cli.py. Fixed: the plan names the assertion.
5. SUBSTANTIVE: no test that an incomplete read prevents or ends a confirmation. Fixed: three rows added to Task 3.

Pass 1 [code:reader]: 2B/4S/2C/0R · fixed -/- · velocity = (—→8, escalation no)
code:reader: passes 1 · Stage 2 gpt-6-astra through fresheyes, Stage 1 a same-model reviewer, in parallel on snapshot 435516aa8eecc9ed4dad73b3159bcf9d18fafbc1

Code findings and what was done (both reviewers; the same defect counted once):
1. BLOCKER (Stage 2): both states confirmed while withdrawn, then the advisory published again at notice and only the notice state refreshed: its result is still "confirmed", the older withdrawal confirmation stands, and the thread stays hidden against fresh support.
2. BLOCKER (Stage 2; Stage 1 F1, verified there by running): the reverse order. An older notice confirmation and a newer contradiction of the withdrawal read as "the source gives exactly notice": the thread is lowered to notice and the root leaves the refusal memory.
   Fixed together, by design: a withdrawal is one question with one cached result (spec 4a as revised). `pull.offer_said` and the second asked state are gone; `verify.lowering(..., "withdrawn")` is False only for support above notice, None for exactly notice, and answers `whole` for ending a refusal. Cost, stated in the spec: a claimed thread whose source supports exactly notice waits 72 hours.
3. SUBSTANTIVE (Stage 2): the failed-read CLI test never made a failed read (the check's clock did not move). Fixed: the clock moves, the test asserts the request was made, and a second CLI test ends a refusal and starts the wait.
4. SUBSTANTIVE (Stage 1 F2): a curator's retraction or level after the withdrawal overwrites the offer, so criterion 2's "in whichever order" was false. Fixed in the spec and `spec/wire.md` (the curator's later word on the level takes the offer; never hidden by it: the higher side) and tested for four curator words.
5. SUBSTANTIVE (Stage 1 F4): the 4a tests were weaker than the spec's wording. Replaced with the one-question tests, through the real cache and the CLI.
6. COSMETIC (Stage 1 F3): an unclaimed thread whose source gives exactly notice was refused for good. Gone with the redesign (None, then 72 hours); tested.
7. COSMETIC (Stage 1 F5): the released-reader test sent the reply without its claim. Fixed: the reply carries a claim of level `none`.
Rung after the pass: medium. No BLOCKER or SUBSTANTIVE finding is left unfixed. The BLOCKER fix changed behaviour, so it is committed and gets the one delta pass (`fresheyes --since 435516a`), as the review cycle rules.

Pass 2 [code:reader]: 0B/1S/0C/0R · fixed 8/8 prior · velocity ↓ (8→1, escalation no)
code:reader: passes 2 · the delta, gpt-6-astra through `fresheyes --since 435516a` at head a3318b6ac9344e3e4916ee8594559ab20214d228

Delta finding and what was done:
1. SUBSTANTIVE (the reviewer called it major and blocking; taken as SUBSTANTIVE because it errs high: a refusal that never ends keeps the alert at its level): with one question asked at `none`, a refused withdrawal no longer ended when the advisory was corrected to stop naming the product, since that read is `unauthoritative` at `none`. Fixed in the commit after a3318b6: `judge` at `none` calls whole reads of authorities that do not name the product `silent`, and `lowering(whole=True)` takes it; a CLI test ends a refusal that way and runs the 72 hours. Not reviewed again: the review cycle allows one delta. `git diff a3318b6..HEAD` shows it.

## Chunks
- [ ] reader: the withdrawal on the wire, in `pull.py`, in the source check and in the CLI, with its tests and documents

## Notes
- Landing lane: this repository has no `.repoman-managed` marker, so the brief's lane applies: `scripts/test-gate.sh`, one independent review, a pull request this session merges. The dispatch text's repoman steps do not apply.
- Split before building (kata comment on y484, 2026-11-26): the poster half is ai-tools-alerts#kk2q.
- The session started at main 5506dd4 (hh5s, 3t4p, 0z4e, swfe merged).
- Execution: the Agency tools the pipeline names are not available in this session; the one chunk was built in the session itself, test first, and reviewed by both stages.
- A stray review: the fresheyes script was called once with `--help`, which it read as scope text and started a detached review of nothing. Stopped by pid within a minute; it counts for no pass.
- Watchdog: four fresheyes runs (spec, plan, code, delta), each `FRESHEYES_DONE REASON=-`. No stall, no fallback.
- Skip-temptations: none acted on. The plan's CLI test of "the withdrawal contradicted and notice unread" could not be built as written (one run reads both states of one thread); the redesign to one question removed the case.
- The source check's cache keeps version 5: `silent` is a new reason, and a result stored before it reads as not settled, which is the safe reading.
