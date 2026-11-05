# Run: poster-candidate-adapters
Instruction: start at medium. Task: ai-tools-alerts#6j8x, plan docs/plan.md Task B1 (Candidate adapters), brief TASK-ai-tools-alerts#6j8x.md in the worktree. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra. Not repoman-managed: non-repoman ending (ff-merge to main from primary checkout).
Stage: done
Rung: medium (start-floor medium: evaluator BR1 REV0 NOV1 INT1 FC1 = 4, PII-shaped medium floor; no hard trigger; Lens: none)
Spec: docs/superpowers/specs/2026-11-05-poster-candidate-adapters-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-candidate-adapters.md
Agency project: —
Kata: ai-tools-alerts#6j8x
Last reviewed: spec+plan 216d4f10922446e2a6802e3f5169f81853b6ee47; code:branch 1e1cf717384bf0737ba89aea4951dccebb3c2335 (whole branch origin/main...HEAD); delta 661303c6841ea98457c8ef67ee2cb79006ae0ebf (--since 1e1cf717)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/3S/0C/1R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6-astra, one combined pass. critical x2 graded BLOCKER: private text through kept fields (paths, kata refs, local versions in fixed/affected), host scrub missing hint/published_at → private-content guard, hint vocabulary, timestamp grammar, heartbeat never fills fixed/affected, whole-candidate backstop. major graded SUBSTANTIVE: forged exploited → KEV-only; sentinel fixed → version grammar; privacy tests on pre-redacted fixtures → per-adapter synthetic tests. Rebutted: snapshot commit message (dangling review snapshot, never on a branch). All B/S fixed; medium rung has no spec delta — the whole-branch code pass reviews the implementation of these fixes.
passes: spec+plan 1 · elapsed ~20 min
Pass 1 [code:branch]: 6B/9S/4C/0R · fixed -/- · velocity = (—→19, escalation yes)   # Stage 1 (same-model subagent) ∥ Stage 2 fresheyes gpt-6-astra on origin/main...1e1cf71. BLOCKER: affected-range ReDoS (both stages), backtick-wrapped paths, percent-encoded host/path/kata ref in URLs, host-naming product kept with host replaced, deep-nesting RecursionError, live kata refs in fixture → all fixed. SUBSTANTIVE fixed: fixed "1.x" wildcard, plan's collector-test wording, lowercase/`|`/file: paths, capitalised kata refs, two-segment keys + host-as-object + string host_coverage, internal source hosts (localhost, non-global IPs, .ts.net, .<vm-domain>, .local), percent-decoding, control/bidi/surrogate characters. SUBSTANTIVE rebutted: size over 600 (decided), local version in product_text without a host (rule input; B3 composes from scope display name, filed on h2gf), feeds.json-shape KEV items trusted for exploited (provenance is B4's: it must pass the catalog it fetched; filed on B4), bare #xxxx not a kata ref. Cosmetic fixed: timestamp fromisoformat, ensure_ascii=False; cosmetic left: heartbeat product fallback when ids supply the id. BLOCKER fixes changed behaviour → one delta pass (fresheyes --since 1e1cf71 --rebuttals).
Pass 2 [code:delta]: 0B/3S/0C/0R · fixed 15/15 prior (11 fixed, 4 rebutted) · velocity ↓ (19→3, escalation no)   # fresheyes gpt-6-astra --since 1e1cf717 --rebuttals (5 standing). major graded SUBSTANTIVE, all fixed: percent-encoded hostnames bypassed the internal-host check (now any % in netloc is rejected); unsafe-character check missed URLs and heartbeat ids[] fallbacks; fixed truncated into a new valid version before validation. No standing rebuttal overturned. Last pass per ruling jibot-code#41e2.
passes: code 2 (one whole-branch, one delta)

## Chunks
- [x] chunk 1 — fixtures, poster package, adapters, tests, pyproject package list (1e1cf71; review fixes in the next commit)

## Notes
- TDD order: the implementation was written while the spec review ran, before the tests; tests were then written against the spec and run red→green for the review fixes (2 failures found, fixed). Recorded, not hidden.
- Size: 907 added lines before review fixes; 323 are fixture JSON the plan requires. decided on the kata issue: count code+tests against the 600-line rule.
- Landed: rebased onto origin/main 62f0b95 (A2 schema.py landed meanwhile; its Source has the same fields, B2 swaps the import), gate 155 passed, ff-merged to main at 9ed88fafce7e12d19105a8593ea236dc8e9a632f (pre-rebase heads 1e1cf71, 661303c, 4778ceb are c157b23, d03c573, 9ed88fa). The last fix commit (9ed88fa) disposes of the delta's three SUBSTANTIVE findings and had no further pass, per ruling jibot-code#41e2.
- roborev: ai-tools-alerts is not enrolled; post-push check skipped. The behaviour-changing BLOCKER fixes had their fresheyes delta before the push.
- Agency MCP tools (mcp__agency__*) are not loaded in this session; execution is inline by the executor per the plan. Recorded, not skipped silently.
- aitools_alerts/schema.py (A2, j153) is absent at start: Source is defined in candidates.py; B2 (31x7) reconciles.
