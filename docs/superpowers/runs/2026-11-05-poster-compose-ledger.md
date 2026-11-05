# Run: poster-compose-ledger
Instruction: Task ai-tools-alerts#h2gf B3 (post composition + advisory ledger), per TASK-ai-tools-alerts#h2gf.md. Start at medium. Non-repoman ending (ff-merge to main by the session per the brief).
Stage: code-review:chunk1
Rung: medium (start-floor medium: evaluator BR1 REV0 NOV1 INT2 FC1 = 5, constraint lens, no hard trigger; Lens: "B1's and B2's poster tests stay green"; "Nothing in a fixture, test, log or kata comment may carry a real secret or a fleet host name")
Spec: docs/superpowers/specs/2026-11-05-poster-compose-ledger-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-compose-ledger.md
Agency project: —
Kata: ai-tools-alerts#h2gf
Last reviewed: spec+plan 4081e68288f5ccade597908c866619dfb80d9d8a
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/9S/0C/0R · fixed -/- · velocity = (—→11, escalation no)   # fresheyes gpt-6-astra on snapshot 4081e682, 1 critical + 10 major. Graded BLOCKER: reply patches bypass the publication rules (fixed: _publishable, private-path guard, hostile-patch test); replies drop "unverified" (fixed: reason kw). SUBSTANTIVE fixed: directory fsync after replace; merge keeps every member id (was already so in code; spec text fixed, later-run lookup test); changes() id conflict and unbounded unions (changes() dropped, reply caps aliases 50/sources 20); strict wire decoder (parse_reply, duplicate/NaN/unfinished tests); leak/size checks on untracked files (plan stages first). Rebutted: 24 h expiry re-opens resend (the brief prescribes it); scope display name as product identity (B1 c:hhhxn9; follow-up filed); snapshot commit message (dangling review snapshot, as B2). No delta pass on the spec: medium rung; the code pass covers the fixes.
passes: spec+plan 1 · elapsed ~12 min

## Chunks
- [ ] chunk 1 — compose.py, ledger.py, test_compose.py, test_ledger.py

## Notes
- Agency MCP tools are not loaded in this session; execution is inline by the executor (as B2 did), recorded here.
- A5 (z4hs) has not landed and has no pushed branch at dispatch; the reply patch shape is written down here and in the landing comments on z4hs and kfq6.
- Order: tests and code were written while the spec+plan review ran (new files only, as B2 did); the tests were not run red before the implementation existed. Recorded, not hidden.
- Size: code + tests ~880 lines, over the ~600 rule; decided to keep one landing (kata comment) rather than split mid-run.
- Gate before commit: scripts/test-gate.sh 366 passed; import one-liner exit 0; staged leak grep prints nothing.
