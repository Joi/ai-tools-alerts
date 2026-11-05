# Run: pull-state-notify-cli
Instruction: start at medium (dispatched; never light). Task: ai-tools-alerts#z4hs (A5) per TASK-ai-tools-alerts#z4hs.md — pull.py, state.py, config.py, notify.py, cli.py, the twelve plan tests, mirror fixtures and the console script, per docs/plan.md Task A5. Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:whole-branch
Rung: heavy (start-floor heavy: hard-trigger credential handling — init --make-key writes key.nsec, notify reads and sends a Telegram bot token; BR1 REV1 NOV1 INT1 FC2 = 6; Lens: none), above the dispatch's "start at medium"
Spec: docs/superpowers/specs/2026-11-05-pull-state-notify-cli-design.md   Plan: docs/superpowers/plans/2026-11-05-pull-state-notify-cli.md
Agency project: — (executed inline, as A1 to A4 did)
Kata: ai-tools-alerts#z4hs
Last reviewed: spec+plan 493549fb
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 3B/8S/0C/1R · fixed -/- · velocity = (—→12, escalation no)   # fresheyes gpt-6-astra on snapshot 493549fb (REASON=-), 3 critical + 9 major. BLOCKERs fixed: (1) override trust persisted and a root switch erased the pinned floor → manifest stored per root, CLI refuses state from another root; (2) a verified revocation was discarded when a feed failed → the verified manifest is accepted and prunes stored events even when an event file is unreadable; (3) relay-bot patches could expire or re-scope a curator alert → only a curator amends a curator thread; a relay-bot patch on its own thread cannot lower or expire it; posted_by is always the root's role. SUBSTANTIVE fixed: concurrent pulls could roll back → flock + re-read in State.locked; dedupe before verify → verify before an id is claimed; plan printed a command with no fixed → "notify only, no command"; missing tests (unknown-key reply, curator patch on bot thread, telegram failure paths) → added; acceptance command lost the env on later commands → exported, exact script in Notes; leak grep matched its own pattern → scoped to code and fixtures; last_pull contract contradiction → last attempt recorded with last_ok_at; run --json/--quiet for A6 → added. Also from A7's interface: a `level:` line plus a block now applies both. Rebutted (R): snapshot commit message (a dangling review snapshot, never on a branch; same rebuttal as A2 and A4).
passes: spec+plan 1 · heavy delta for the spec/plan BLOCKER fixes is folded into the whole-branch code pass (it reviews the fixed spec, plan and code together), as A4 did.

## Chunks
- [x] chunk 1 — config, state, pull (verification, replies), mirror fixtures, tests/test_pull.py (6f58030)
- [x] chunk 2 — notify, cli, console script, package data, tests/test_cli.py (1715330; spec/plan review fixes in the next commit)

## Notes
- kata search "pull state notify cli": only z4hs itself. capability-search notify/mirror/pull: two unrelated hits (bundle-development skill, drive-sync script); no overlapping tool.
- Code was written while the spec/plan pass ran (the review reads a frozen snapshot); its findings were applied to spec, plan and code together afterwards.
- Agency: not used, as in A1 to A4; executed inline.
- Acceptance script: /private/tmp/claude-501/-Users-joi-repos--worktrees-z4hs-a5-pull-state-notify-cli/0752004f-48ed-40dd-8892-724997e0bc96/scratchpad/install.sh (venv in the scratchpad, pip install of a copy of the repo, HOME=$S/home, AITOOLS_ALERTS_TRUST_ROOT exported). Output: "pulled manifest v1: 2 new events, 2 stored, dropped: none" / "CRITICAL: Claude Code fixture critical (synthetic, not a real advisory) [Claude Code 2.1.318: affected] ..." / "2 advisories, 1 matches on this machine"; installed site-packages/aitools_alerts/spec and /trust hold the JSON files and root.pub.
