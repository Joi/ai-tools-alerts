# Run: qwpw-digest-daily-weekly
Instruction: Read TASK-ai-tools-alerts#qwpw.md in this worktree root, then run `kata show ai-tools-alerts#qwpw` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: committing
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-24-qwpw-digest-daily-weekly-design.md   Plan: docs/superpowers/plans/2026-11-24-qwpw-digest-daily-weekly.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#qwpw
Last reviewed: spec+plan 878721f842f0da3b426f747059e61800ea93a838
Last reviewed: code fcaf792f1aeb56a1844c015cf385ad99b0976dd1 (whole branch), delta --since fcaf792 at 45e6540864518f4a2b852674b1365770b1144d69

## Scorecards
Pass 1 [spec+plan]: 0B/9S/1C/0R · fixed -/- · velocity = (—→10, escalation no)   # fresheyes, gpt-6.1-sol high, REASON=-; its 'major' read as SUBSTANTIVE (nothing built yet); 5 fixed, 4 rebutted, the snapshot message cosmetic
spec: passes: 1 · elapsed: ~15 min
Pass 1 [code:branch, Stage 1]: 0B/2S/5C/0R · fixed -/- · velocity = (—→7, escalation no)   # same-model subagent, at fcaf792
Pass 1 [code:branch]: 3B/0S/1C/0R · fixed -/- · velocity = (—→4, escalation no)   # fresheyes whole branch, gpt-6.1-sol high, REASON=-; its 'major' read as BLOCKER (two retirement defects; the plan's mutation line)
Pass 2 [code:delta]: 1B/0S/1C/0R · fixed 3/3 prior · velocity ↓ (4→2, escalation no)   # fresheyes --since fcaf792 --rebuttals, at 45e6540, REASON=-; no rebuttal overturned

## Chunks
- [x] daily short form and weekly summary — fcaf792; review fixes in the next commit

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; it could only raise to heavy on one (as faxq, 9kgk).
- Spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as faxq and 9kgk did.
- Prior work: 8ke5 (no leads in the digest; listed once by cutoff and roots), 9kgk (notices never post in real time), q03f (catalog reads held before the digest), t8jr/r0ra (CLI freshness is the checkpoint, not the digest), ny5g (level report in the digest). capability-search was run for the parent issue (0 hits).
- Spec+plan dispositions: in the spec's 'Review dispositions' section. Fixed: baseline week (first Monday after a mid-week install recovered), withdrawal filter before counting, retire posted and withdrawn notices, rollback jq covers journaled items, test migration names test_live_replay and test_catalog. Rebutted: unknown/refused digest wedge (pre-existing; ai-tools-alerts#jsje), catalog snapshot lost on a failed send then drain (pre-existing, rarer now; v46a), a summarized notice later raised is listed by its root (the summary names no id), cursor migration (one line once, at upgrade, only for a size-cut backlog).
- Test migration of existing test_main/test_live_replay/test_catalog failures delegated to a same-model helper (tests only); compose tests and the new tests/poster/test_digest_weekly.py written here.
- Mutation: roots_since by listed instead of posted_at fails test_a_thread_is_listed_once_by_its_root.
- Gate: scripts/test-gate.sh in this worktree exits 1 on the public scan's history pass: 66 objects reachable only from local refs/rescue/2026-11-23/* that other sessions left on this clone, none reachable from this branch or origin/main (checked with rev-list --objects). Tracked as ai-tools-alerts#a373. The same gate on a clean clone holding only this branch and origin/main: exit 0 at fcaf792 (public scan and the whole suite).
- Whole-branch dispositions. Fixed: a held fix group retired by one member's root (fresheyes; `_posted` needs every id); a notice held under a former name not retired (fresheyes; `_posted` reads current and former names); the plan's mutation line (fresheyes); nonexistent ISO weeks accepted (fresheyes; `week_ok`); tests for a posted notice, a retracted notice, the refused-summary fallback (Stage 1); the Japanese quiet line's double colon, a mirror link the guard refuses (falls back to the default), the oversized test's union, a test name, a long line (Stage 1 cosmetics). Not done: `entries_since`/`listed_at` are now unused by the digest (Stage 1 cosmetic); left, since the ledger tests and the stored entries still carry them; removal is not this slice.
- Mutations for the review fixes: any-id retirement fails the held-group test; held-scope-only fails the former-name test; Monday-only weekly fails the missed-Monday test.
- Delta (at 45e6540): the mirror-link fallback had no test (fixed: test_the_digest_links_a_public_mirror_and_falls_back_to_the_default); the week_ok docstring named 2026-W53 as nonexistent (fixed: 2025-W53). No further pass (Review Cycle).
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
