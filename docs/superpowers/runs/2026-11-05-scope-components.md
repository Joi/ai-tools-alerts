# Run: scope-components
Instruction: ai-tools-alerts#qme5: per-component product identity in scope.json (schema version 4) — brief at TASK-ai-tools-alerts#qme5.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: done
Rung: medium (start-floor medium: evaluator BR2 REV2 NOV1 INT2 FC1 = 8, no hard trigger; medium by the version refusal and the instruction's constraints, and the dispatch floor; Lens: "Under 400 changed lines." / "spec/scope.json is not signed by the manifest; no manifest change.")
Spec: docs/superpowers/specs/2026-11-05-scope-components-design.md   Plan: docs/superpowers/plans/2026-11-05-scope-components.md
Agency project: —
Kata: ai-tools-alerts#qme5
Last reviewed: spec+plan 1efd1d79eead759b8e6a43f22bec6bf45dc87fad; code:branch 4a52ff8f5f424d8ab938e21a08a0112c9e5238a5 (origin/main...HEAD, rebased on 6718eb9); code:delta a08bcf1c0b99ac2cfdf68ff88896474aa96caa4a (--since 4a52ff8f)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 1B/5S/1C/0R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 1efd1d79 (FRESHEYES_DONE REASON=-). All seven called "major"; graded here. BLOCKER fixed: an entry fallback kept `components`, so compose's guard would withhold it → scope_of empties components on every return, test_entry_fallback_composes_under_the_entry_name. SUBSTANTIVE fixed: "Ubuntu linux kernel" resolved to Ubuntu with a kernel version → Linux kernel listed first; test_load_scope_rejects_bad_entries was vacuous under version 4 → fixtures carry version 4 plus a valid control. SUBSTANTIVE rebutted (3): exploited continuity across the rename, the persisted outbox/held state, inventory's fallback on a refused scope (reasons in Notes). COSMETIC rebutted: the snapshot commit's subject (a dangling review snapshot, never on the branch).
passes: spec+plan 1
Pass 1 [code:branch]: 1B/5S/4C/0R · fixed 3/6 prior (3 rebutted) · velocity ↑ (7→10, escalation no)   # Stage 1 (same-model subagent: 0B/3S/4C) ∥ Stage 2 fresheyes gpt-6-astra on origin/main...4a52ff8f (FRESHEYES_DONE REASON=-, 3 "major"). BLOCKER fixed: "openclaw/clawhub" resolved to OpenClaw (an earlier entry) → OpenClaw not_match [clawhub]. SUBSTANTIVE fixed: "Docker runc" fell to Docker → runc gains "docker runc"; "Microsoft Edge (Chromium-based)" posted as Chromium → Chromium not_match "chromium-based"; the not_match test ignored component names → now refuses them; the plan's leak grep matched its own text → scoped to code, data and tests. SUBSTANTIVE rebutted: "Docker Desktop containerd" resolves to containerd (deliberate order). COSMETIC: "linux-kernel" added; spec sentence on check corrected; case-sensitive names rebutted (predates the change; line limit); headroom noted. Fix commit a08bcf1.
Escalation: none. The BLOCKER was fixed inside the pass; the rung stays medium, and the behaviour-changing fix gets the one delta (ruling jibot-code#41e2).
passes: code 1 (one whole-branch)
Pass 2 [code:delta]: 0B/0S/0C/0R · fixed 5/6 prior (1 rebutted) · velocity ↓ (10→0, escalation no)   # fresheyes gpt-6-astra --since 4a52ff8f --rebuttals (5 standing) on a08bcf1 (FRESHEYES_DONE REASON=-). PASSED; no rebuttal overturned. No further pass (ruling jibot-code#41e2).
passes: code 2 (whole-branch + delta)

## Chunks
- [x] chunk 1 — schema v4 components, scope_of resolution, compose guard, check aliases, inventory probes, scope.json, tests (4a52ff8, review fix a08bcf1)

## Notes
- Prior work read: run record docs/superpowers/runs/2026-11-05-scope-not-match.md (3r9h), 2026-11-05-scope-bounded-match.md (x838). kata search "scope component product identity": only qme5 and kfq6 (B4). capability-search "scope components": no overlapping tool.
- The brief names aitools_alerts/match.py; it does not exist (as 3r9h found). The member matcher is check.match over inventory.collect; the shared reader is schema.load_scope.
- Agency: the agency MCP tools are not loaded in this session; execution inline, as in the earlier runs.
- Rebuttal (spec pass, exploited continuity): a containerd CVE posted earlier under "Docker" keeps that thread, critical and delivered. A later candidate resolving to containerd starts a second root, at a level computed from its own input; ledger.merge inheriting `exploited` only within one scope is the 3r9h/B2 rule against crossing scopes, and widening it needs ledger.py (shared with #9sa2). Transitional and bounded to advisories that are still arriving.
- Rebuttal (spec pass, persisted outbox/held): those texts were composed and approved by the code that was running; they publish what the pre-landing poster would have published. Rewriting persisted state is a migration the coordinator's reinstall does not ask for.
- Rebuttal (spec pass, member refusal): schema.load_scope refuses every version but 4 for both callers. inventory.collect never raises by contract and, without scope, names each probe by its ecosystem, which is in IDENTITY, so matching and planning are the same as with names. Scope is not otherwise read by the member, so there is no path where a stale file changes what the member does.
- Red first: 17 failed / 135 passed on the base tree for the five touched test files. Size: 297 insertions + 102 deletions = 399 changed lines over aitools_alerts, spec, tests; trust/ diff empty.
- Gate (scripts/test-gate.sh, python3 -m pytest -q): 840 passed, 1 skipped on a08bcf1. Size: 297 insertions + 101 deletions = 398 changed lines over aitools_alerts, spec, tests; trust/ diff empty; leak grep over added code/data/test lines 0.
- roborev: ai-tools-alerts is not enrolled (as in 3r9h); post-push check skipped. The behaviour-changing BLOCKER fix had its fresheyes delta before the push.
