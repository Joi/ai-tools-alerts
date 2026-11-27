# Run: 9cch-poster-mirror-reads
Instruction: Read TASK-ai-tools-alerts#9cch.md in this worktree root, then run `kata show ai-tools-alerts#9cch` and follow the brief and the dispatch rules pasted after this sentence. (The dispatch rules: /do-it, starting rung floored at medium; scripts/test-gate.sh, one independent review, a pull request this session merges.)
Stage: done
Rung: medium (start-floor medium: default, BR1 REV1 NOV1 INT0 FC1 = 4; hard trigger none; no lens; the evaluator called it torn between light and medium and took the higher, which is also the dispatch floor)
Last reviewed: spec 39a16f065de8615fad21fa25520cf4f8d3d667a5
Last reviewed: plan 1a1d9343591560a5fa462fafc9cb6bc530b2b721
Last reviewed: code 7443e3556d67a9f3acad9ff8578e786acefa5566 (whole branch), then delta to 8e92df9eef3bf39c3fcb00fc26c37596327b2178 (passed)
Spec: docs/superpowers/specs/2026-11-28-9cch-poster-mirror-reads-design.md   Plan: docs/superpowers/plans/2026-11-28-9cch-poster-mirror-reads.md
Agency project: — (no agency tools in this session; see Notes)
Kata: ai-tools-alerts#9cch
Limits: wall clock 5 hours from 2026-11-27T22:08Z; one independent review each of spec, plan and code, one delta only after a BLOCKER fix that changes behaviour; completion check: a test per read with a forged relay-bot event passes in scripts/test-gate.sh.

## Scorecards
Pass 1 [spec]: 0B/2S/1C/0R · fixed -/- · velocity = (—→3, escalation no)
spec: passes: 1 · elapsed: 6 min. Fixed both SUBSTANTIVE: (1) the curator-translation pass could translate from a copy with a forged block while the record is not started, and that translation stays: the pass now waits for the record (`translate=no-record`); (2) the tests lacked the forged-block path and a forged `of:` translation: both added. COSMETIC, not acted on: the snapshot commit's message (a dangling review snapshot, never pushed; later snapshots name their artifact).

Pass 1 [plan]: 0B/2S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
plan: passes: 1 · elapsed: 9 min. Fixed both SUBSTANTIVE, in the plan and in the tests: (1) the fake mirror's default checkpoint lists a forgery, so a first run adopts it: the waiting test serves no checkpoint and asserts the forged id stays out of the record; (2) the digest and copy tests attacked a thread that was not on the mirror: `_export` and `_attacked` put it there and assert the replay reads it.

Pass 1 [code:own-reads]: 1B/3S/2C/0R · fixed -/- · velocity = (—→6, escalation no)
code: whole branch at 7443e3556d67a9f3acad9ff8578e786acefa5566 (git diff origin/main...HEAD). Independent (fresheyes, gpt-6.1-sol, high): 1 BLOCKER, fixed: the pass asked whether the record was started, pulled the mirror, then judged the copy by a second read of the record; a record lost in between handed it the whole copy. The read inside the pass is now strict and ends the pass `no-record`. Same-model review beside it: 3 SUBSTANTIVE, all fixed: (1) `_own` failed open for the translation read when the check raised (the same strict read answers it); (2) README and changelog said translation waits one run without saying that a poster with no usable certificate keeps waiting; (3) the no-key test did not pin the guard (it now fails if the record is asked, and covers all three reads). 2 COSMETIC: a comment reworded; the settling test asserts on `_mirror`'s return, left as it is. The BLOCKER fix changes behaviour: one delta pass follows.
Pass 2 [code:own-reads]: 0B/0S/0C/0R · fixed 4/4 prior · velocity ↓ (6→0, escalation no)
code: passes: 2 · the delta (fresheyes --since 7443e35, gpt-6.1-sol, high) passed with no findings on 8e92df9. The rung stayed medium: the BLOCKER was fixed, and the one delta is the bounded independent look its fix gets.

review: fresheyes pass=2 blocker=1 substantive=0 fixed=1 rebutted=0 oid=8e92df9eef3bf39c3fcb00fc26c37596327b2178

## Chunks
- [x] own-reads — one helper, four reads, tests, changelog; review clean after the delta, 2 passes. Commits b9d6410 (the build), 7443e35 (plan-review test fixes), 8e92df9 (code-review fixes).

## Notes
- Prior work searched (kata search "poster mirror copy foreign relay-bot events"): m729 (closed; filed this issue), pdag (open; the pull-level filter, not this issue), 5fry (rollout), h29n (the design). No experiment issue on this.
- This repo has no `.repoman-managed` marker and no registry row: the landing is the brief's (scripts/test-gate.sh, one independent review, a pull request merged by this session), not a repoman handoff.
- Order slip: the build was started and its first commit (b9d6410) made while the plan review was still running, to use the wait. The review's two findings were about test setup and are fixed in the commit after it; no step of the plan changed.
- Tool slip: several spec, plan and run-record edits were made with a script that asserts exactly one match before replacing, not with the Edit tool. None was a silent no-op.
- Mutation check: with `Run._own` returning the copy unchanged, 8 of the new tests fail; with the wait for the record turned off, both cases of the waiting test fail.
- Gate: `scripts/test-gate.sh` fails its public scan in the shared clone on other sessions' local refs. None of the scan's hit ids is reachable from this branch or origin/main (0 in common), so the gate is run in a clone that holds this branch alone.
- Gate results, each in a clone of this branch alone: b9d6410: 3629 passed, 1 skipped, scan clean. 8e92df9: 3632 passed, 1 skipped, scan clean. The commit after 8e92df9 is this record alone.
- No fresheyes run stalled or was killed; every pass ended FRESHEYES_DONE.
- Skip temptations: none acted on. The plan was written although the change is about 60 lines of code.
- Agency execution (Step 3) is not available: the session lists no agency tools. The one chunk is built in this session and reviewed as the rung requires.
