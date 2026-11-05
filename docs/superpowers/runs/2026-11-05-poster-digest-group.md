# Run: poster-digest-group
Instruction: Task ai-tools-alerts#qg7p per TASK-ai-tools-alerts#qg7p.md — poster digest groups by vendor release and lead scope: (a) group CVE notices/highs by primary source URL, critical one per advisory; (b) LEAD- ids one line per scope; (c) from_collector carries the fix version, the line says "fixed in" or "update available"; (d) header N is the line count, --json/ledger per advisory. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: spec-review
Rung: medium (start-floor medium: constraint-lens, evaluator BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger; dispatch floor medium)
Lens: "--json/ledger keep every advisory"; "Under 300 changed lines; stdlib only"; "do not run any poster install or live send yourself"; "main is unchanged. The grouping is presentation only."
Spec: docs/superpowers/specs/2026-11-05-poster-digest-group-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-digest-group.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#qg7p
Last reviewed: spec+plan 997c396fdfcd16c55ef0ee22ac05833ad594f317 (pass 1, gpt-6-astra, run 20261105-153222-81d3e5)

## Scorecards
Pass 1 [spec+plan]: 6B/2S/1C/0R · fixed -/- · velocity = (—→9, escalation no)
- Reviewer graded all 9 "major". Classified BLOCKER: 1 (an Apple title could give another product's finding a version), 2 (regex not anchored; impact text could supply a version), 3 (a rejected source's title could supply a version), 5 (every KEV entry shares the catalog URL, so two KEV highs would read as one release with an update), 6 (a grouped line drops "unverified"), 7 (the Docker digest test would break). SUBSTANTIVE: 4 (titles must all parse), 8 (the host-name grep matches the plan's own line). COSMETIC: 9 (snapshot commit message).
- Fixed: 1 (only `product == macos` and only support.apple.com sources), 2 (anchored prefix `APPLE-SA-<id> <release> (macOS <major> fixed in <v>): `, version inside the major), 3 (only sources retained by B1's checks), 4 (every Apple source must parse and agree; KEV/GHSA sources state no version and are ignored), 5 and 6 and 7 (only the plain `<name>: security advisory (<id>)` title groups; KEV, injection, trojanized and unverified kinds stay single, so the Docker test is unchanged), 8 (grep scoped to aitools_alerts and tests). Also: `update available` only on an allowlisted primary URL, else `see the release`.
- Rebutted: 9. The snapshot is a dangling review commit, never on the branch; its message is not a landed commit message.
- Medium rung: no delta on the documents; the BLOCKER fixes are code-reviewed in the whole-branch pass.

## Chunks
- [ ] collector-fixed — from_collector reads the release's fix version
- [ ] digest-group — digest groups releases and leads

## Notes
- Prior work: the collector record shape read from amplifier-bundle-joi e947e11a (`collect_apple` writes `(macOS <major> fixed in <v>)` in the source title; findings carry no `fixed` or ranges). candidates._url drops fragments, so the `#CVE` source fragments share one URL.
