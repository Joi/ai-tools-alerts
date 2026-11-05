# Run: poster-digest-group
Instruction: Task ai-tools-alerts#qg7p per TASK-ai-tools-alerts#qg7p.md — poster digest groups by vendor release and lead scope: (a) group CVE notices/highs by primary source URL, critical one per advisory; (b) LEAD- ids one line per scope; (c) from_collector carries the fix version, the line says "fixed in" or "update available"; (d) header N is the line count, --json/ledger per advisory. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: done
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

Pass 1 [code:whole branch 14baa29]: Stage 1 0B/1S/4C · fresheyes (gpt-6-astra, run 20261105-154116-51727d) 4B/0S/0C · fixed -/- · velocity = (—→9, escalation no)
- fresheyes B1 = Stage 1 S1 (one cause: a LEAD- id grouped whatever its title, so "unverified", "trojanized" and a high rating became "N unrated leads"): fixed; a lead groups only with the plain title at notice. Test: two unverified trojanized high leads and two plain high leads stay four lines.
- fresheyes B2 (spec Approach paragraph for from_collector still described the loose regex): fixed; it now states the implemented algorithm. Stage 1 C3 is the same finding.
- fresheyes B3 (plan said fullmatch for a prefix pattern): fixed; the plan says `re.match`.
- fresheyes B4 (plan expected `update available` for a non-allowlisted fixture host): fixed; the plan names both cases the tests pin.
- Stage 1 C2 (an unusable `fixed` value also falls back to the Apple title): kept; the version is still Apple's, and S6 now says "absent or unusable".
- Stage 1 C4 (the label is the last path segment, so an index URL reads `release security`): left; only plain CVE advisories sharing one URL and product group, which on today's inputs is a release page; the wording is the only effect and nothing leaks.
- Stage 1 C5 (main's size loop can split one release across days): left; the count on each day's line is that day's members, nothing is lost, and grouping makes an oversized digest rare.
- B1 changed behaviour: one delta pass `--since 14baa292d5ca063bf20171eeacffd3c35e7e608b`.
Pass 2 [code:delta --since 14baa29, head bdb99c5]: 0B/1S/0C/0R · fixed 5/5 prior · velocity ↓ (9→1, escalation no)
- fresheyes (gpt-6-astra, run 20261105-154653-15f007), graded major; classified SUBSTANTIVE (test coverage; the reviewer found the code correct): the lead test used only high leads, so it did not pin the title rule on its own. Fixed after the delta: two unverified trojanized notice leads stay two lines. No standing rebuttal overturned. No further pass (ruling jibot-code#41e2).

## Chunks
- [x] collector-fixed — from_collector reads the release's fix version
- [x] digest-group — digest groups releases and leads

## Notes
- Prior work: the collector record shape read from amplifier-bundle-joi e947e11a (`collect_apple` writes `(macOS <major> fixed in <v>)` in the source title; findings carry no `fixed` or ranges). candidates._url drops fragments, so the `#CVE` source fragments share one URL.
- Rebased on origin/main 3777e4c (hhe3: schema.validate marks a reserved id's title `SYNTHETIC TEST: ...`; h260 cli). The reviewed commits became d0b97ad, 849cde4, faf18a4, ac2dbe5. One adaptation commit 4149ddf after the last reviewed tree: a marked plain title still groups, a single line adds no second mark, a synthetic group line reads `SYNTHETIC TEST: <product>: ...`. It is not a BLOCKER fix and had no further pass (ruling jibot-code#41e2); `git diff ac2dbe5 4149ddf` shows it. Suite on 4149ddf: 775 passed, 1 skipped.
- roborev: the repo is not enrolled (`roborev repo list` has no ai-tools-alerts row), so no post-push check runs; the one delta pass ran before the push.
- Evaluator and spec review: spec/plan edits after the first review were made with a python replace (not Edit), checked by grep; later edits used Edit.
