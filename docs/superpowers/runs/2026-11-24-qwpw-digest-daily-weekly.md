# Run: qwpw-digest-daily-weekly
Instruction: Read TASK-ai-tools-alerts#qwpw.md in this worktree root, then run `kata show ai-tools-alerts#qwpw` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: executing
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-24-qwpw-digest-daily-weekly-design.md   Plan: docs/superpowers/plans/2026-11-24-qwpw-digest-daily-weekly.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#qwpw
Last reviewed: spec+plan 878721f842f0da3b426f747059e61800ea93a838

## Scorecards
Pass 1 [spec+plan]: 0B/9S/1C/0R · fixed -/- · velocity = (—→10, escalation no)   # fresheyes, gpt-6.1-sol high, REASON=-; its 'major' read as SUBSTANTIVE (nothing built yet); 5 fixed, 4 rebutted, the snapshot message cosmetic
spec: passes: 1 · elapsed: ~15 min

## Chunks
- [ ] daily short form and weekly summary

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; it could only raise to heavy on one (as faxq, 9kgk).
- Spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as faxq and 9kgk did.
- Prior work: 8ke5 (no leads in the digest; listed once by cutoff and roots), 9kgk (notices never post in real time), q03f (catalog reads held before the digest), t8jr/r0ra (CLI freshness is the checkpoint, not the digest), ny5g (level report in the digest). capability-search was run for the parent issue (0 hits).
- Spec+plan dispositions: in the spec's 'Review dispositions' section. Fixed: baseline week (first Monday after a mid-week install recovered), withdrawal filter before counting, retire posted and withdrawn notices, rollback jq covers journaled items, test migration names test_live_replay and test_catalog. Rebutted: unknown/refused digest wedge (pre-existing; ai-tools-alerts#jsje), catalog snapshot lost on a failed send then drain (pre-existing, rarer now; v46a), a summarized notice later raised is listed by its root (the summary names no id), cursor migration (one line once, at upgrade, only for a size-cut backlog).
- Test migration of existing test_main/test_live_replay/test_catalog failures delegated to a same-model helper (tests only); compose tests and the new tests/poster/test_digest_weekly.py written here.
- Mutation: roots_since by listed instead of posted_at fails test_a_thread_is_listed_once_by_its_root.
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
