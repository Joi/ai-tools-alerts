# Run: q03f-catalog-channel
Instruction: Read TASK-ai-tools-alerts#q03f.md in this worktree root, then run `kata show ai-tools-alerts#q03f` and follow the brief and the dispatch rules (/do-it, starting rung floored at medium).
Stage: executing
Rung: medium (start-floor medium: dispatch floor and evaluator, BR2 REV1 NOV1 INT2 FC2 = 8)
Lens: catalog events never in feed.json/critical.json nor in the signed checkpoint; no human in the loop; no live install or post from this session.
Spec: docs/superpowers/specs/2026-11-24-q03f-catalog-channel-design.md   Plan: docs/superpowers/plans/2026-11-24-q03f-catalog-channel.md
Agency project: —
Kata: ai-tools-alerts#q03f (split: ai-tools-alerts#8nb4 CLI side; rollout: ai-tools-alerts#q3fd)
Last reviewed: spec 9c22c07663e308039869b691ecf99c96d15994d1
Last reviewed: plan af07bb28976ee7f26aab5f61d20a4f3f03a15026
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

## Chunks
- [ ] 1 catalog lane in the poster (spec/catalog-channel.json loader, poster/catalog.py, run wiring, config path)
- [ ] 2 exporter writes catalog.json
- [ ] 3 docs (design.md catalog section, wire.md note) and tests pinning the feed rule

## Notes
- Agency MCP tools are not loaded in this session (no mcp__agency__* tools); executed the plan directly, chunk by chunk, with the tests as the per-task check.
- Rung stays medium: every BLOCKER and SUBSTANTIVE finding of the spec and plan passes was fixed or rebutted (none survives).
- Prior work: kata search "catalog.json" (q03f, 9mx8, 6ghg, wa6n, t8jr, vzc3); t8jr note c:dp781t gives the two wire conditions; wa6n note c:30j9w4 names ScopeEntry.scope_class. capability-search was run by the issue author (0 hits).
- Split decided on kata (decided: comment): CLI consumer side to 8nb4.
