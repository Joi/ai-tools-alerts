# Run: 8ke5-digest-leads-and-empty-replies
Instruction: Read TASK-ai-tools-alerts#8ke5.md in this worktree root, then run `kata show ai-tools-alerts#8ke5` and follow the brief and the dispatch rules (do-it, starting rung floored at medium; not repoman-managed: land by fast-forward to main after the gate and one independent review; reinstall on the poster host).
Stage: code-review:branch (whole-branch review launched at 53f6532f4b78675e2db22567c846340be84960cd; gate 1125 passed)
Rung: medium (start-floor medium: constraint-lens; evaluator BR1 REV2 NOV1 INT2 FC1 = 7, hard-trigger none; dispatch floor medium as well)
Lens: "Readers at v0.1.4 are installed on member machines: a post they cannot parse is a regression. Do not change the block's required keys."
Spec: docs/superpowers/specs/2026-11-23-8ke5-digest-leads-and-empty-replies-design.md   Plan: docs/superpowers/plans/2026-11-23-8ke5-digest-leads-and-empty-replies.md
Agency project: 01a204d9-d21f-7484-b8ec-ba4d957b6bdc
Kata: ai-tools-alerts#8ke5
Last reviewed: spec 22021d97d0b9baaa59e8eceaf48ddecc346948f1

## Scorecards
Pass 1 [spec]: 0B/5S/0C/1R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, REASON=-)
  spec passes: 1 · fixed 5 (legacy listed_at freeze; alias line filter; existing tests named; rollback strips the current ledger, never restores; uv path) · rebutted 1 (snapshot commit message: a dangling review snapshot, never landed; real commits carry descriptive messages)

Pass 1 [plan]: 0B/4S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high, snapshot ea70def8, REASON=-)
  plan passes: 1 · fixed 4 (replay runs a 09:20 digest each day and asserts listing on 11-07 and 11-08 only; whole marks-and-kinds test rewritten on primary sources, "see the release" removed; listed_at never null; host name removed from spec and manifest, public scan)
Pass 1 [code:branch]: 1B/1S/4C/0R · fixed -/- · velocity = (—→6, escalation no)   (Stage 2 fresheyes gpt-6.1-sol high on origin/main...53f6532, REASON=-: 2 major; Stage 1 same-model subagent: 0B/0S/4C)
  B1 fixed: a held notice left out for no primary source was marked digested, so its later confirmation never listed; now it leaves held unmarked, and a confirmation while held replaces the snapshot (two regression tests, both fail on 53f6532).
  S1 fixed: spec and plan named no exploitation exception; both now do.
  C1 fixed: learned sources pass compose._sources first. C2-C4 not changed: an exploitation-only reply does not re-list (matches the issue's level/fix/action rule); an unverified high root is left out of the digest (issue item 1); extra validator tests noted, not added.
Pass 2 [code:branch delta]: 1B/0S/0C/0R · fixed 2/2 prior · velocity ↓ (2→1, escalation no)   (fresheyes --since 53f6532 --rebuttals, reviewed 6cdfa06, REASON=-; no rebuttal overturned)
  B fixed: refreshing a held snapshot dropped the earlier sighting's ids; the new snapshot now carries them (regression test fails without the fix). No further pass (ruling jibot-code#41e2).

## Chunks
- [x] chunk 1 — compose: no lead lines, no ledger-key aliases (poster tests: compose 54 passed)
- [x] chunk 2 — main + ledger: no source/alias-only replies, digest lists an advisory once (poster 500 passed; the same-run cutoff test fails with the fix removed)
- [x] chunk 3 — live-feed replay test (3 passed; 3 failed on 0dba6fc)

## Notes
- decided (execution): exploitation learned at the same level still replies though its only changed key is sources; design section 5 lists "exploitation is confirmed" as a reply trigger and 4yr1's test covers it. Rejected: suppress it (drops a landed 4yr1 behaviour the design keeps).
- plan amended (execution): CVE-2026-88968 is listed once, on 11-08 (the 09:20 schedule puts the 11-07 digest before its 11:20 root), not on 11-07 and 11-08.
- Spec and plan edits after review were made with checked Python replacements (each asserted one match) or Edit; noted against the Edit/Write-only rule.
- Prior work: kata qg7p (digest grouping: lead lines were introduced there; this run removes them), 9mx8 design comment (Redundancy, section 5, Do now 2 and 3), mz81/k5tr mention guard, 4yr1 no-fix wording.
