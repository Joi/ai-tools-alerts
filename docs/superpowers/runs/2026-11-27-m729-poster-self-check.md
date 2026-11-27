# Run: m729-poster-self-check
Instruction: Read TASK-ai-tools-alerts#m729.md in this worktree root, then run `kata show ai-tools-alerts#m729` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: done
Rung: heavy (start-floor heavy: hard-trigger, BR1 REV1 NOV1 INT1 FC2 = 6; the evaluator named "secrets, auth or credential handling" for the change to what the checkpoint key signs, a torn call it resolved to the higher floor; the dispatch floor was medium)
Lens: "the service self-corrects with no human in the loop"
Last reviewed: spec 6d99ae259b63516d0950d8821c6f9e60a40a14af
Spec: docs/superpowers/specs/2026-11-27-m729-poster-self-check-design.md   Plan: docs/superpowers/plans/2026-11-27-m729-poster-self-check.md
Agency project: 01a21d06-0cbe-74b5-a496-4f5ad8f48714 (two tasks: chunk 1, chunk 2)
Kata: ai-tools-alerts#m729
Limits: wall clock 5 hours from 2026-11-27T12:10Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases this issue keeps pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker and no repoman registry row, so the unmanaged rule applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — pass 1 (fresheyes, gpt-6.1-sol, 6d99ae2, watchdog FRESHEYES_DONE REASON=-). Fixed in 7a483a2: settling by text (now by signed id), ownership recorded after the send (now before it, in the transport), a lost record re-trusting the mirror (the start takes the served checkpoint, the ledger and the owed list only), the store filling with foreign events, pruning by age, an owed reply to a foreign root. Rebutted: the pre-upgrade unknown renewal; the mirror's own capped files (not this design's). The blocker fixes changed the design, so the one delta runs `--since 6d99ae2` with the rebuttals.
Pass 2 [spec]: 0B/2S/0C/0R · fixed 6/7 prior · velocity ↓ (7→2, escalation no)
spec — pass 2, the delta (fresheyes, gpt-6.1-sol, `--since 6d99ae2`, head 7a483a2, FRESHEYES_DONE REASON=-): two major findings, no rebuttal overturned. Both fixed in b94e143 with no further pass: settling asks the sent record (no journal key, no `SendResult.signed`), and a pull that reports the store full clears the foreign events and pulls once more. spec — passes: 2 · elapsed: about 25 min.
Last reviewed: plan b94e1438ad3707911592f26333fbecea21961fa1
Pass 1 [plan]: 2B/4S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
plan — pass 1 (fresheyes, gpt-6.1-sol, b94e143, FRESHEYES_DONE REASON=-). Fixed in b97826a: a lost record let settling fall back to text and record a copy (settling never falls back to text with a checkpoint key); `mine` kept events just given up; the lock file was outside the path checks; rollback ignored a refused digest in `withheld`; the crash test did not prove the transport wrote the id. Rebutted: the full-store recovery (one export is at most 4,000 events against 20,000; the claim is narrowed in the spec, a pull-level filter is a follow-up). The first fix changed behaviour, so the one delta runs `--since b94e143` with the rebuttal.
Pass 2 [plan]: 0B/0S/0C/0R · fixed 5/6 prior · velocity ↓ (6→0, escalation no)
plan — pass 2, the delta (fresheyes, gpt-6.1-sol, `--since b94e143`, head b97826a, FRESHEYES_DONE REASON=-): passed, no finding, the rebuttal stands. plan — passes: 2 · elapsed: about 20 min.

Gate: `scripts/test-gate.sh` on be1ead8: 3383 passed, public scan clean.
Last reviewed: code be1ead8040f0169adda5a41aeb997879768a6d86 (whole branch, `git diff origin/main...be1ead8`)
Pass 1 [code:whole-branch]: 4B/2S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
code — pass 1, Stage 2 (fresheyes, gpt-6.1-sol, be1ead8, FRESHEYES_DONE REASON=-). Fixed in the next commit: an old checkpoint served again could restart the record (only a fresh checkpoint of the current manifest counts); a full store kept an unstarted record from starting; the record was not fsynced in its directory before a send. Rebutted: overflow by a new foreign batch when the poster's own history is near the limit (ai-tools-alerts#pdag); the first digest after the record starts; a failed Japanese copy. Stage 1 (same-model subagent) stopped on the seat's usage limit before it reported; it was run again on the fixed head.
Brief: the TASK file was empty; the brief arrived as comment qazgkf with directive hgkba4 while this run was under way (acknowledged). It adds: stay inside the worktree, no rollout (a note on ai-tools-alerts#5fry), main merged before the last review pass and before the merge.
Pass 2 [code:whole-branch]: 1B/1S/0C/0R · fixed 3/6 prior · velocity ↓ (6→2, escalation no)
code — pass 2, the delta (fresheyes, gpt-6.1-sol, `git diff be1ead8 fc26f74`, FRESHEYES_DONE REASON=-): the three fixes checked; two findings, both fixed in bf0c3dc with no further pass (a still-fresh older checkpoint could restart the record: now only one not numbered below the poster's own count; a note for an id already written did not sync again). No rebuttal overturned.
code — Stage 1 (same-model subagent, on fc26f74 with main merged): 0 blockers, 3 substantive, 4 cosmetic. Fixed in bf0c3dc: a foreign post that left the mirror before the digest was never said; a record that could not be read was overwritten; a test assertion that could not fail; README wording. Rebutted: the full-store path starts the record without the served checkpoint (it runs before the certificate is chosen; the strict side); the renewal test through a real Relay (see Notes).
Gate: `scripts/test-gate.sh` on bf0c3dc: 3504 passed. Main merged three times since (kk2q and nx25; p93w and aabw; 53fy), with conflicts in the signer, the run and the changelog resolved by hand; two of main's new tests that post under the bot's key after a first run now record the id (test_signer.py, test_renew.py). On 4842e09 (main at 80b0900 merged): 3618 passed, public scan clean.
After the last reviewed code (bf0c3dc): the merges of main, the two test lines above, one changelog sentence, and this record. No behaviour of this branch changed after bf0c3dc.

## Chunks
- [x] the sent record and the check (be1ead8; review fixes fc26f74, bf0c3dc)
- [x] docs: CHANGELOG, README (be1ead8, bf0c3dc)

## Notes
- Follow-ups filed: ai-tools-alerts#cftg (the member strike rule), #9cch (the poster's other reads of its mirror copy), #pdag (a pull-level filter before the store limit).
- Plan deviations in the build: the path-collision case is a new test in `tests/poster/test_sent.py`, not an addition to the one in `test_signer.py`; the "renewal with an unknown outcome through a real Relay" test is not written, because the hook is in `Relay.send`, which every kind of send goes through, and the two transport tests and the two settle tests exercise it with a real `Relay`; no existing test needed an `as_sent` helper (the mirror's default checkpoint lists what the tests post, so the record takes it).
- Mutation check: with the signer's filter and the settle-by-id filter removed, 13 of the 35 tests in `tests/poster/test_sent.py` fail; restored, all pass.
- I edited the spec and plan with a script after their reviews (exact-match replacements, each asserted to occur once), not with the Edit tool the skill names; every replacement was checked afterwards.
- The run stopped for about four hours on the seat's usage limit (2026-11-27 22:13 to 2026-11-28 02:00 JST); the liveness watcher's needs-review label was removed on resuming.
- Wall clock: over the brief's five hours counting that stop; about four hours of work, most of it in six gate runs of 15 to 20 minutes and seven review passes.
- Rollout note left on ai-tools-alerts#5fry (install after a `checkpoint=sent` run, with nothing pending).
- Skip temptations: starting the build before the plan's delta verdict (I wrote `sent.py` and its unit tests while reviews ran; nothing was committed until the plan passed).
- My mistake, 2026-11-27: `fresheyes.sh --help` is not a help flag; it started a detached review with "--help" as its scope (handle 20261127-211716-785f8a). Stopped within a minute by ending its own process group; no verdict, nothing used from it.
- The brief file TASK-ai-tools-alerts#m729.md is empty (0 bytes); the issue body and its one comment are the brief.
- Split before the start (two deliverables, over 600 lines together): the member strike rule is ai-tools-alerts#cftg; `notice:` comment on m729.
- Prior work read: issue m729 and comment ft97js; the design review on ai-tools-alerts#h29n (finding D14, revised rules 7 and 10, the "relay-bot key only" row of the table); ai-tools-alerts#ek5q and #vzc3 (both closed: the checkpoint exists and is signed on the poster machine with a key the relay VM never holds; the relay-bot key is still read on the VM for other channels, jibot-code#7z60); signer.py (nfm3, gtw9), the jsje `dropped` count in the digest as the pattern for a line said once. `kata search` for "foreign event own key self-check" and "probation strike" returned m729 and h29n only: no earlier attempt, no dead end.
