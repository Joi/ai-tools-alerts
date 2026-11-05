# Run: launch-readiness
Instruction: Read TASK-ai-tools-alerts#hgs0.md in this worktree root, then run `kata show ai-tools-alerts#hgs0` and follow the brief and the dispatch rules (do-it, rung floored at medium; non-repoman ending: fetch, rebase, gate, push branch, ff-merge main from the primary checkout, close with evidence).
Stage: code-review:branch
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, prod-shaped public output, no hard trigger; Lens: none; dispatch floor medium). Review model gpt-6-astra (brief: security-shaped).
Spec: docs/superpowers/specs/2026-11-06-launch-readiness-design.md   Plan: docs/superpowers/plans/2026-11-06-launch-readiness.md
Agency project: 01a1adfb-fb0a-718a-b056-da10c6126de8 (task 01a1adfc-0a5e-72f4-8ffd-0e59e077d8ce)
Kata: ai-tools-alerts#hgs0
Last reviewed: spec+plan 2db17eb48e24ad22b78188f544be9e881776f26d; code:branch e6594cf8c9b4dadc6f7918c08a5b60be29ce4fd4 (whole branch origin/main...HEAD)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/7S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes gpt-6-astra (watchdog REASON=-) on snapshot 2db17eb4. Seven "major", graded SUBSTANTIVE. Fixed: page threads from both channels (a curator reply in critical.json retracts a feed root); reader's 400-day retention applied; events past MAX_TIMESTAMP left off (was a crash in _iso); --mirror-url must be https with a host and no quote/bracket/backslash/space; adversarial tests (manifest retracted, curator level, quoted href parsed back, forged author, cap, primary fallback); rollback names the VM checkout update and index.html removal. Rebutted: the review snapshot's commit message (a dangling commit-tree object, never on the branch). Not mirrored, stated in spec: the CLI's 8 MiB / 10,000-event refusal.
passes: spec+plan 1
Pass 1 [code:branch]: 1B/3S/4C/0R · fixed 6/7 prior (spec+plan; 1 rebutted) · velocity ↑ (7→8, escalation yes)   # Stage 1 (same-model subagent) ∥ Stage 2 fresheyes gpt-6-astra (REASON=-) on origin/main...e6594cf. BLOCKER (fresheyes, graded so because it changes what the public page shows and the reviewer called it blocking): the page dropped events past MAX_TIMESTAMP before building threads, so a far-future curator retraction the CLI applies was missed → threads from every accepted event, only undatable roots left off; regression test compares page and CLI. SUBSTANTIVE fixed: --mirror-url backslash not refused (both reviewers; the committed check lost the backslash to string escaping) → URL_REFUSED set incl. backslash, tab, CR, LF, tests; README lines "anyone may reply" and keygen "post or discuss" contradicted the members-only directive (Stage 1) → reworded. Cosmetic fixed: stray <ul> in the subscribe section (both), expired advisories now marked "Expired:" (pull.active's rule), comment on effective_manifest's bundled-manifest preference, spec index_doc signature. BLOCKER fix changed behaviour → one delta pass (fresheyes --since e6594cf --rebuttals).

## Chunks
- [x] chunk 1 — kind-9 filter + no "(untitled)" Atom entries (mirror/export_mirror.py, tests/mirror/test_export.py)
- [x] chunk 2 — index.html (mirror/export_mirror.py, tests/mirror/test_export.py)
- [x] chunk 3 — README Status

## Notes
- Prior work: kata search "landing page" / "index.html alerts page": only this issue. capability-search 'static index generator': nothing (per the issue body). Prior run docs/superpowers/runs/2026-11-05-mirror-exporter.md (C1) set the exporter's conventions.
- Caddy (cell-fleet ops/buzz/compose-overlays/buzz-aitools/Caddyfile.pair, read only): `handle_path /alerts/* { root * /srv/alerts; file_server; header Cache-Control "max-age=60" }`. file_server's default index list includes index.html and browse is off, so /alerts/ serves /srv/alerts/index.html with no config change. Note: `handle_path /alerts/*` does not match the bare `/alerts` (no slash), which falls to the relay; a link should use the trailing slash. No cell-fleet change needed for /alerts/.
- Order: code written while the spec+plan pass ran (its snapshot is dangling), as C1 did. Agency composed the prompt; execution inline. All three chunks land in one commit (one exporter file, the tests for it, README).
- Checkpoint before the code review: directive c:yjb4ze (manifest posters only; members-only channels; Atom subtitle) applied in a second commit, acked on the issue. The test curator 4755f0bf... is not in trust/manifest.json v3, so the poster filter drops its posts.
- Mutation checks: indexing feed.json alone fails test_index_reads_both_channels_as_the_cli_does; disabling the kind filter fails test_admin_kinds_dropped_from_every_output (the CLI-reader test still passes by design: the CLI ignores those kinds).
