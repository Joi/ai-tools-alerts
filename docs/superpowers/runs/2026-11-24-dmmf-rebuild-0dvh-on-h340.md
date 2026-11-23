# Run: dmmf-rebuild-0dvh-on-h340
Instruction: ai-tools-alerts#dmmf (mode do-it, starting rung floored at medium). Brief: `TASK-ai-tools-alerts#dmmf.md` — bring pull request 8's behaviour (0dvh) onto current main, on top of h340's authoritative-source rules, keeping 0dvh's recorded decisions; gate, one independent review, merge the pull request with the no-reply author, close dmmf and 0dvh on the merge commit.
Stage: code-review:whole-branch
Rung: medium (start-floor medium: the dispatch brief floors it there; no hard trigger: no secret, credential or deploy path in the diff)
Lens: "the collector record is a pointer; what a post states is read from the vendor's page or CISA's catalog" (h340) · "Readers at v0.1.4 still parse every post" (0dvh) · "no host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record" (brief)
Spec: docs/superpowers/specs/2026-11-24-dmmf-rebuild-0dvh-on-h340-design.md   Plan: docs/superpowers/plans/2026-11-24-dmmf-rebuild-0dvh-on-h340.md
Agency project: — (no agency tools in this session; the plan is executed directly)
Kata: ai-tools-alerts#dmmf (blocks ai-tools-alerts#0dvh)
Wall-clock limit: 4 h. Review shape: at most three review rounds (brief); one independent pass on the spec and plan together, one on the whole branch, one delta only if a BLOCKER fix changes behaviour. Completion check: `scripts/test-gate.sh` green, both live replays passing.

## Scorecards

## Chunks
- [x] merge — 18b4b91 (signed); ten poster tests fail at it, as on the WIP branch
- [x] inputs from the page — range sentinel, severity_word
- [x] tests — the ten fixed, five new, two mutation checks
- [x] docs and record

## Notes
- Order: the ten failing tests were the investigation, so the fixes were written before the spec. The spec records the decisions they embody; the review judges both.
- Spec and plan are reviewed in one independent pass (brief: three review rounds at most; the whole-branch review and a possible delta take the other two).
- Decided (kata comment): an inexpressible page range is UNEXPRESSED; the block severity is the page's word only (`severity_word`); the age limit keeps the record's published date for the confirming page (demote-only), with a follow-up to read the page's own date.
