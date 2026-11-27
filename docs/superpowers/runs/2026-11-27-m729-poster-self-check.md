# Run: m729-poster-self-check
Instruction: Read TASK-ai-tools-alerts#m729.md in this worktree root, then run `kata show ai-tools-alerts#m729` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: spec-review
Rung: heavy (start-floor heavy: hard-trigger, BR1 REV1 NOV1 INT1 FC2 = 6; the evaluator named "secrets, auth or credential handling" for the change to what the checkpoint key signs, a torn call it resolved to the higher floor; the dispatch floor was medium)
Lens: "the service self-corrects with no human in the loop"
Last reviewed: spec 6d99ae259b63516d0950d8821c6f9e60a40a14af
Spec: docs/superpowers/specs/2026-11-27-m729-poster-self-check-design.md   Plan: docs/superpowers/plans/2026-11-27-m729-poster-self-check.md
Agency project: —
Kata: ai-tools-alerts#m729
Limits: wall clock 5 hours from 2026-11-27T12:10Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases this issue keeps pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker and no repoman registry row, so the unmanaged rule applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — pass 1 (fresheyes, gpt-6.1-sol, 6d99ae2, watchdog FRESHEYES_DONE REASON=-). Fixed in 7a483a2: settling by text (now by signed id), ownership recorded after the send (now before it, in the transport), a lost record re-trusting the mirror (the start takes the served checkpoint, the ledger and the owed list only), the store filling with foreign events, pruning by age, an owed reply to a foreign root. Rebutted: the pre-upgrade unknown renewal; the mirror's own capped files (not this design's). The blocker fixes changed the design, so the one delta runs `--since 6d99ae2` with the rebuttals.

## Chunks
- [ ] the sent record and the check (aitools_alerts/poster/sent.py, signer, main, transport, inputs, compose)
- [ ] docs: CHANGELOG, README

## Notes
- My mistake, 2026-11-27: `fresheyes.sh --help` is not a help flag; it started a detached review with "--help" as its scope (handle 20261127-211716-785f8a). Stopped within a minute by ending its own process group; no verdict, nothing used from it.
- The brief file TASK-ai-tools-alerts#m729.md is empty (0 bytes); the issue body and its one comment are the brief.
- Split before the start (two deliverables, over 600 lines together): the member strike rule is ai-tools-alerts#cftg; `notice:` comment on m729.
- Prior work read: issue m729 and comment ft97js; the design review on ai-tools-alerts#h29n (finding D14, revised rules 7 and 10, the "relay-bot key only" row of the table); ai-tools-alerts#ek5q and #vzc3 (both closed: the checkpoint exists and is signed on the poster machine with a key the relay VM never holds; the relay-bot key is still read on the VM for other channels, jibot-code#7z60); signer.py (nfm3, gtw9), the jsje `dropped` count in the digest as the pattern for a line said once. `kata search` for "foreign event own key self-check" and "probation strike" returned m729 and h29n only: no earlier attempt, no dead end.
