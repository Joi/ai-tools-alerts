# Run: e3-live-acceptance
Instruction: start at medium. Task: jibot-code#gs18 E3 live acceptance of the ai-tools alert service, per TASK-jibot-code#gs18.md in the worktree root. Repo ai-tools-alerts is NOT repoman-managed; the deliverable is evidence lines plus trust/manifest.json v2/v3 commits.
Stage: spec
Rung: heavy (start-floor heavy: hard-trigger — set by the dispatch brief: a live deploy path (manifest ship to the relay VM) and signing-key handling (root key through Kura, a minted test curator key))
Spec: docs/superpowers/specs/2026-11-05-e3-live-acceptance-design.md   Plan: docs/superpowers/plans/2026-11-05-e3-live-acceptance.md
Agency project: — (see Notes)
Kata: jibot-code#gs18
Last reviewed: —
Pre-handoff review: — (not repoman-managed)

## Scorecards

## Chunks
- [ ] C1 — manifest v2 (test curator added), land, ship, mirror serves v2
- [ ] C2 — fresh-machine install against the live mirror, hook installed
- [ ] C3 — curator post (auto-apply plan) and curator retract (items 4 and 5, curator half)
- [ ] C4 — synthetic KEV via the poster, relay-bot plan, relay-bot retract, digest (needs ai-tools-alerts#akq9)
- [ ] C5 — manifest v3 (test curator removed), land, ship, revoked events drop; delete key and venv
- [ ] C6 — model-turn counter; evidence lines on jibot-code#gr5b and gs18

## Notes
- Order change from the brief: ai-tools-alerts#akq9 is open (owner joi-host-c) at pickup, so items 1, 2 and the curator half of 4 and 5 run first, as the brief allows.
- Start-floor evaluator not dispatched: the dispatch brief fixes the rung (heavy, hard triggers named). Recorded instead of skipped silently.
- Agency execution not used: every task is a live operator step that handles the root signing key or the test curator key, or posts to member channels; handing those to Agency workers would put key handling and live posts outside this session's control. Executed inline; each step's evidence is a command and its output.
- Review: the brief sets one fresheyes pass (gpt-6-astra) on the manifest commits and this run manifest. Spec and plan get one same-model subagent pass each before execution because live steps cannot wait for an independent pass per artifact; the whole-branch independent pass covers spec, plan, manifest and both manifest commits.
