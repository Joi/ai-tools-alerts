# Run: alerts-bootstrap
Instruction: Start at medium. Task: TASK-jibot-code#zq90.md in this worktree (plan Task A1 of docs/plan.md): pyproject + aitools_alerts/nostr.py (pure-Python BIP-340 + NIP-19 bech32) with tests, .kata.toml + kata project ai-tools-alerts, scripts/test-gate.sh, trust root key minted into Kura with trust/root.pub committed, eleven follow-up kata issues A2-C1, README Status section. Non-repoman repo; security-shaped review with FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: spec-review
Rung: heavy (start-floor heavy: hard-trigger secrets/credential handling — mints the root signing key into Kura; BR2 REV2 NOV2 INT2 FC2 = 10; Lens: none)
Spec: docs/superpowers/specs/2026-11-05-alerts-bootstrap-design.md   Plan: docs/superpowers/plans/2026-11-05-alerts-bootstrap.md
Agency project: —
Kata: jibot-code#zq90
Last reviewed: spec 628e9be4 → delta 248c603f; plan 628e9be4 → delta 248c603f (one combined delta pass)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec]: 0B/5S/0C/1R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6-astra; reported "major" x6, graded: 5 substantive (cache copy, cleanup paths, vector coverage, mint-twice order, leaky secret check), 1 rebutted (snapshot commit message)
Pass 1 [plan]: 1B/6S/0C/1R · fixed -/- · velocity = (—→8, escalation no)   # fresheyes gpt-6-astra; critical: secret check printing matches → fixed; majors fixed except snapshot commit message (rebutted)

## Chunks
- [ ] chunk 1 — package scaffold + nostr primitives + tests + gate script
- [ ] chunk 2 — kata binding, trust root mint, root.pub, README Status
- [ ] chunk 3 — eleven kata issues + epic comment (no repo diff)

## Notes
- Agency MCP tools (mcp__agency__*) are not loaded in this session; execution is inline by the executor per the plan's chunks. Recorded, not skipped silently.
- Spec and plan passes ran in parallel (both on snapshot 628e9be4) and their delta as one combined pass, to keep fresheyes launches at the heavy-rung minimum.
- Rebuttal (spec+plan): snapshot commit message "do-it review snapshot" — a dangling commit-tree snapshot, never on a branch or pushed.
