# Run: curator-subcommand
Instruction: ai-tools-alerts#gctv A7 curator subcommand per TASK-ai-tools-alerts#gctv.md — start at medium (dispatched; never light). Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:whole-branch
Rung: heavy (start-floor heavy: hard-trigger credential handling — reads the curator nsec and signs and sends under it; brief also says heavy), above the dispatch's "start at medium"
Spec: docs/superpowers/specs/2026-11-05-curator-subcommand-design.md   Plan: docs/superpowers/plans/2026-11-05-curator-subcommand.md
Agency project: — (executed inline, as A1 to A5 did)
Kata: ai-tools-alerts#gctv
Last reviewed: spec+plan 6cfa9f2f
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/12S/0C/1R · fixed -/- · velocity = (—→13, escalation no)   # fresheyes gpt-6-astra on snapshot 6cfa9f2f (REASON=-), 13 major, none critical. SUBSTANTIVE fixed (10): role manifest fell back to the bundled one across a root switch (revocation rollback) → newest manifest known for the requested root; amend lookup used another root's state → refused unless pulled under the requested root; verifier applied the patch dict, not the serialized post → the signed reply is replayed through pull.advisories (retract state included), first line always the CLI's, one-line fence-free notes; ordering by created_at could put the amendment before one it saw → created_at after the thread's newest event; stale state could revert list fields → amend and retract pull first; recv-only deadline → the whole exchange runs in a joined worker thread, socket closed on overrun; RelayError escaped the CLI → every transport failure is RelayError, CLI exit 1, tested; no primary-source check → required; critical missing from the feed → critical posts to critical and feed, amend/retract by advisory id reply to every open thread; missing negative tests → added (wrong root, mis-signed, tampered, malformed keys, transport failures); leak-check scope → code and tests only, generated-key assertions. SUBSTANTIVE rebutted (1): size over 600 lines → kept as one deliverable (relay and curator are one interface; decided on the issue). R: snapshot commit message (a dangling review snapshot, never on a branch; as in A2 to A5).
passes: spec+plan 1 · no BLOCKER, so no spec/plan delta; the whole-branch code pass reviews the amended spec and plan with the code.

## Chunks
- [ ] chunk 1 — relay, curator, CLI, tests

## Notes
- Prior work: kata issue gctv itself; A5 run manifest (docs/superpowers/runs/2026-11-05-pull-state-notify-cli.md) set the reader rules this task writes for; B3's compose.apply_patch is reused for the patch contract.
- Start-floor: hard trigger (credential handling) floors at heavy by rule; recorded without a separate evaluator subagent, as the brief fixes the rung at heavy and the rubric cannot go lower than a hard trigger.
- Agency MCP tools are not available in this session; executed inline, as A1 to A5 did.
- Code is written while the spec/plan pass runs on a frozen snapshot (A5's convention); findings are applied to spec, plan and code together.
