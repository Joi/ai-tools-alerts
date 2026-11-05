# Run: japanese-feed
Instruction: Task ai-tools-alerts#yxd6 (reader side of the Japanese feed: CLI lang, feed.ja.atom, index 日本語 section, skill lines) per TASK-ai-tools-alerts#yxd6.md in the worktree root. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo: ending is the brief's ff-merge ending.
Stage: executing
Rung: medium (start-floor medium: evaluator BR2 REV1 NOV1 INT1 FC1 = 6, prod-shaped exporter + byte-identical constraint, no hard trigger; Lens: feed.atom byte-identical with default lang; commands and version strings never translated; a lang reply carrying a block is ignored entirely; skill/snippet word-for-word test green; under 400 changed lines)
Spec: docs/superpowers/specs/2026-11-06-japanese-feed-design.md   Plan: docs/superpowers/plans/2026-11-06-japanese-feed.md
Agency project: —
Kata: ai-tools-alerts#yxd6
Last reviewed: spec+plan f33742faba4436939246488e44f1024576d798bc
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/9S/0C/1R · fixed -/- · velocity = (—→12, escalation no)   # fresheyes gpt-6-astra (watchdog REASON=-), one combined pass on snapshot f33742fa. Two "critical" graded BLOCKER, both fixed: translated body in `plan` could imitate an `auto-apply (opted in):` section and a `command:` line → body quoted `    > `, adversarial test; bot text under curator attribution → the existing discussion rule applies to lang replies (no bot translation on a curator thread). SUBSTANTIVE fixed: stale translation after a patch → translation must name the current version, a change drops earlier ones; notify truncation could cut Affected/Action/Source → only the body is shortened, test; synthetic mark dropped by a translated title → re-marked (translation_title), test; mirror target rule differed from pull → exporter uses pull.threads_from; tie order → same (created_at, id) sort via threads_from; withdrawal and feed `updated` → spec rules; write-order test → plan names it. SUBSTANTIVE rebutted in part: no byte fixture for feed.atom exists → checked by running the old and new exporter on one input (signatures are random per run, so a stored byte fixture cannot be produced from the test keys); plus a test that en output ignores lang replies. R: snapshot commit message (dangling review snapshot, never on the branch).
passes: spec+plan 1 · elapsed ~25 min

## Chunks
- [x] chunk 1 — CLI: pull translations, config lang, check/plan/notify, --json
- [x] chunk 2 — mirror: feed.ja.atom, index.html 日本語 section (built on hgs0 branch head e6594cf)
- [x] chunk 3 — skill lines

## Notes
- Prior work: docs/superpowers/specs/2026-11-05-mirror-exporter-design.md (atom_doc, retraction rule), 2026-11-05-pull-state-notify-cli-design.md (thread rules).
