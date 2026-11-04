# Run: alert-channels
Instruction: start at medium. Task: jibot-code#wpbd per TASK-jibot-code#wpbd.md (Plan Task E1: create #security-feed and #security-critical on buzz.ai-tools.md, VM buzz-send wrapper in ops/vm/buzz-send, spec/channels.json, tests/test_channels.py, ops/vm/README.md). Non-repoman ending.
Stage: executing
Rung: heavy (start-floor heavy: hard-trigger secrets/credential handling + live deploy path; BR2 REV1 NOV1 INT1 FC2 = 7; Lens: "No change to any other channel, the relay image, Caddy or compose."; installed wrapper byte-identical to ops/vm/buzz-send (sha256); nsec never on argv or in a log, bad key file fails without printing contents)
Spec: docs/superpowers/specs/2026-11-05-alert-channels-design.md   Plan: docs/superpowers/plans/2026-11-05-alert-channels.md
Agency project: 01a1a8f7-51c5-7ad5-a37d-c0e6da60abdf (tasks c1-wrapper 01a1a8f7-68d7, c2-vm 01a1a8f7-68d9, c3-records 01a1a8f7-68da)
Kata: jibot-code#wpbd
Last reviewed: spec+plan 1b0b3b51 (pass 1, fresheyes gpt-6-astra, combined) → delta ceda2c33 (pass 2)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 3B/3S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6-astra on 1b0b3b51. B: regex-only key validation (→ python3 -I checksum+range on stdin), -r accepts FIFO/dir (→ -f && -r, timeouts in tests), test contract (printenv newline, 6 argv tokens). S: deletion check window (→ --since + <500 rows + thread lookup), final installed sha after landing (→ ending step), snapshot commit message (rebutted: dangling snapshot).
Pass 2 [spec+plan delta]: 3B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (6→3, escalation no)   # fresheyes gpt-6-astra on 1b0b3b51..ceda2c33 with rebuttals file; prior B1-B3, S5 confirmed fixed. New B: empty-file nondisclosure assertion vacuous (test already guards; plan text fixed), send_ts undefined (captured before send), get capped at 200 (verified messages.rs:363 on VM; check now --limit 200 and <200 rows). All fixed; last pass for these artifacts. Rebuttal of snapshot message not overturned.
passes: spec 2, plan 2 (combined) · elapsed ~12 min

## Chunks
- [ ] chunk 1 — ops/vm/buzz-send wrapper + tests (repo only)
- [ ] chunk 2 — live VM: channels, owner, wrapper install, setup message sent and deleted
- [ ] chunk 3 — spec/channels.json, tests/test_channels.py, ops/vm/README.md, README Status

## Notes
- Prior work: kata search "buzz-send channels security-feed" found nothing; capability-search buzz-send hit cell-fleet ops/buzz/acp-spike/buzz-send (a socket-activated grammar-checking signer for the ACP spike, different trust boundary — kept, not reused; see spec Alternatives). Parent decision gr5b c:8qna4r: wrapper source of truth is this repo.
- Probe 2026-11-05 on the VM: `buzz channels add-member --role owner|admin|member|guest|bot`; no `--version`. Write access (buzz-auth access.rs check_write_access, buzz-relay ingest.rs check_channel_membership): member OR open-visibility channel; no role-gated posting, Guest not enforced on ingest. So security-critical cannot be write-restricted.
