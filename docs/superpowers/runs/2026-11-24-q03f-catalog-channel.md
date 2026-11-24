# Run: q03f-catalog-channel
Instruction: Read TASK-ai-tools-alerts#q03f.md in this worktree root, then run `kata show ai-tools-alerts#q03f` and follow the brief and the dispatch rules (/do-it, starting rung floored at medium).
Stage: verifying
Rung: medium (start-floor medium: dispatch floor and evaluator, BR2 REV1 NOV1 INT2 FC2 = 8)
Lens: catalog events never in feed.json/critical.json nor in the signed checkpoint; no human in the loop; no live install or post from this session.
Spec: docs/superpowers/specs/2026-11-24-q03f-catalog-channel-design.md   Plan: docs/superpowers/plans/2026-11-24-q03f-catalog-channel.md
Agency project: —
Kata: ai-tools-alerts#q03f (split: ai-tools-alerts#8nb4 CLI side; rollout: ai-tools-alerts#q3fd)
Last reviewed: spec 9c22c07663e308039869b691ecf99c96d15994d1
Last reviewed: plan af07bb28976ee7f26aab5f61d20a4f3f03a15026
Last reviewed: code (whole branch) b2ce5b3e841843ab3f84a25c6f864b3162cdfef3; delta --since b2ce5b3 at aa534bd
Pre-handoff review: — (not a repoman-managed repo: pull request, merged by this session after the gate and one independent review)

## Scorecards
Pass 1 [spec]: 2B/7S/0C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6.1-sol high, snap 9c22c07)
  B1 exporter freezes on bad catalog spec: fixed (catalog skipped, alert files written first).
  B2 sends inside ledger lock / before checkpoint: fixed (inventory under lock, sends after lock and checkpoint, own lock, 20 sends / 120 s).
  S3 held notices vanish at digest: fixed (inventory file written before digest); backfill and post-digest re-sightings rebutted as limits of the poster's own hold(), filed v46a.
  S4 curator corrections/withdrawals: fixed by contract (alert thread wins in the reader rule, 8nb4); catalog-only curator path noted on c1g2.
  S5 identity drops products: fixed (key and reader rule are product + id).
  S6 out products via channel_if: fixed (explicit scope_of + starts check).
  S7 exporter catalog isolation/runtime: fixed (catalog after alert files and checkpoint, LIMIT in query, failures skip).
  S8 tests for isolation: fixed (criteria 5-7 and plan tests).
  S9 snapshot commit message: rebutted (dangling review snapshot, never on a branch).
  passes: 1 · elapsed: ~12 min
Pass 1 [plan]: 2B/4S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, snap af07bb2)
  All six fixed; dispositions in the plan's Amendments section.
  passes: 1 · elapsed: ~13 min
Pass 1 [code:branch]: 2B/4S/1C/0R · fixed -/- · velocity = (—→7, escalation no)   (fresheyes gpt-6.1-sol high, git diff origin/main...b2ce5b3; Stage 1 same-model in parallel: 0B/2S/3C, both S overlap)
  B1 FIFO at catalog spec blocks the run: fixed (non-blocking open, regular-file check, poster and exporter; tests).
  B2 exporter catalog step unbounded: fixed (75 s alarm over the whole step, psql output bound; test).
  S older snapshot overwrites newer (also Stage 1): fixed (merge stamped with run time; test).
  S byte estimate differs from writer: fixed (measured as written; unicode round-trip test).
  S former product names dropped (also Stage 1): fixed (formerly resolves as Run._former; test).
  S refused sends bypass the cap: fixed (attempts counted; test).
  C docstring (also Stage 1): fixed. Stage 1 C: spec said 20,000 keys: fixed. Stage 1 C: deadline starts after the lock wait: kept (documented; the pass runs after the checkpoint and off the ledger lock).
  passes: 1 · elapsed: ~18 min
Pass 2 [code:delta]: 2B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (7→2, escalation no)   (fresheyes --since b2ce5b3 at aa534bd)
  B catalog psql output buffered before the bound, counted in characters: fixed (Popen read in chunks, bytes counted as they arrive, killed past the bound or the 45 s timeout; tests with multibyte, endless and sleeping output).
  B equal whole-second stamps let an older snapshot win: fixed (stamp is nanoseconds read under the ledger lock, strictly increasing in a process; test).
  No further pass (review cycle: the delta's BLOCKERs are fixed and named in the kata comment).

## Chunks
- [x] 1 catalog lane in the poster (spec/catalog-channel.json loader, poster/catalog.py, run wiring, config path)
- [x] 2 exporter writes catalog.json
- [x] 3 docs (design.md catalog section, wire.md note) and tests pinning the feed rule

## Notes
- Agency MCP tools are not loaded in this session (no mcp__agency__* tools); executed the plan directly, chunk by chunk, with the tests as the per-task check.
- Rung stays medium: every BLOCKER and SUBSTANTIVE finding of the spec and plan passes was fixed or rebutted (none survives).
- Prior work: kata search "catalog.json" (q03f, 9mx8, 6ghg, wa6n, t8jr, vzc3); t8jr note c:dp781t gives the two wire conditions; wa6n note c:30j9w4 names ScopeEntry.scope_class. capability-search was run by the issue author (0 hits).
- Gate: scripts/test-gate.sh in the shared clone fails the public scan on objects reachable only from local refs/heads/rescue/2026-11-23/* (none reachable from this branch or origin/main; checked with git rev-list --objects). The gate is run instead in a fresh single-branch clone of this branch plus origin/main, which is what the pull request publishes: b2ce5b3 passed (2361 passed, 1 skipped).
- Size: ~860 changed lines, of which ~300 code, ~470 tests, ~110 docs; kept as one deliverable (the producer side) after the CLI split.
- Split decided on kata (decided: comment): CLI consumer side to 8nb4.
