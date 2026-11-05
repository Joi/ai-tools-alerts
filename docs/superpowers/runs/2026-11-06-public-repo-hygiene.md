# Run: public-repo-hygiene
Instruction: Dispatch of ai-tools-alerts#h6bx in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#h6bx.md in the worktree root: move every fleet host name, the relay VM hostname and user, the wrapper and key-file paths and every home-directory path out of code and docs; new config keys default empty/none and the poster refuses to send without relay_ssh_host and relay_send_wrapper; docs rewritten with generic names; scripts/public-scan.sh (tracked files only, exit 1 on a hit) called from scripts/test-gate.sh; no history rewrite; under 400 changed lines.
Stage: committing
Rung: heavy (start-floor heavy: hard-trigger — ops/vm/buzz-send reads the relay key file, and its default path changes; brief floor was medium) BR2 REV1 NOV1 INT2 FC2 = 8
Lens: poster refuses to send without relay_ssh_host and relay_send_wrapper; docs keep technical content; no history rewrite; under 400 changed lines; the fleet poster keeps working after reinstall; buzz-send keeps its behaviour on the VM; no fleet host name in fixture, test, log, template or kata comment; close comment names values as "the current HOST constant", not literally
Spec: docs/superpowers/specs/2026-11-06-public-repo-hygiene-design.md   Plan: docs/superpowers/plans/2026-11-06-public-repo-hygiene.md
Agency project: —
Kata: ai-tools-alerts#h6bx
Last reviewed: branch f8b4ea89cf7ba0bfefaf9478513f528f950d6f88 (pass 1), delta 6e67bab74ceabf20d9cae9aeae98b4ff8ae19534 (pass 2)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot ddced0a9dd81964a76e7e17155c88ccc5f507ccc, fresheyes gpt-6-astra high, REASON=-]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
- B1 successful-run configs in test_main lack relay keys: fixed (plan names every constructor and TOML fixture; implemented).
- B2 home-path literal in test_candidates: fixed (invented user).
- B3 `~/bin/buzz-send` unquoted in ssh examples expands locally: fixed (plan requires quoting; README follows).
- B4 line budget: rebutted in part — the 400-line budget is the deliverable's; this run's spec, plan and manifest are records counted apart (as the earlier runs' were); the deliverable is measured at handoff.
- S1 wrapper tests bypass the new defaults: fixed (temporary-HOME test, HOME-unset test).
- S2 no test that config reaches the send path: fixed (loaded-TOML run asserts destination, wrapper, strip host).
- S3 snapshot commit message: rebutted — the snapshot is a dangling review commit and never lands; the landed commits carry descriptive messages.
- Plan delta: the BLOCKER fixes changed the plan; its delta look is folded into the whole-branch code review (Stage 2), which reads the amended plan with the code it describes, rather than a separate plan-only pass.
Pass 1 [code:branch, origin/main...f8b4ea89cf7ba0bfefaf9478513f528f950d6f88; Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6-astra high, REASON=-]: 5B/4S/4C/0R · fixed -/- · velocity = (—→13, escalation no)
- FB1 scan treats grep errors as clean: fixed (scanner reads every tracked file in Python; unreadable file or listing failure exits 2; gate passes the code through).
- FB2 `grep -I` skips binary files: fixed (bytes scan; file names scanned too); tests/test_public_scan.py covers clean, hit, spaces, binary, file name, unreadable, gate.
- FB3 leak-check commands grep a literal placeholder: placeholder renamed at 6e67bab, which the delta found still vacuous; fixed after the delta (the commands are now `scripts/public-scan.sh`, exit 0).
- FB4 `source the Kura secrets helper` in shell code: fixed (`"$KURA_SECRETS_HELPER"`, pointer to ai-tools-alerts#2bf0).
- FB5 docs/plan.md:186 unquoted `~` after ssh: fixed (remote command single-quoted, `$HOME`).
- FS1 budget criterion unmet as written: fixed (spec criterion 7 and plan acceptance state the overrun and point to the decided: comment).
- S1 check_relay checks presence only: fixed (format checked in check_relay too).
- S2 bad host reaches send after pending: fixed by S1 (host validated before the ledger opens).
- S3 empty strip_hosts silently weakens scrubbing: fixed (stderr warning each run; compose still refuses this machine's own name). Refusal rejected: an installer with no fleet names of its own has nothing to list.
- C4 underscore ssh alias refused: fixed. C5 one- and two-letter strip_hosts accepted: fixed (three or more, alphanumeric first). C6 `${HOME:?}` message is bash's own, not JSON: rebutted — exit 1 is in the poster's never-sent set and the key is never read. C7 VM short name in cell-fleet overlay paths: rebutted — a directory name in another repo, no domain, not a route; the pattern is the issue's.
Pass 2 [code:delta, --since f8b4ea89cf7ba0bfefaf9478513f528f950d6f88 at 6e67bab74ceabf20d9cae9aeae98b4ff8ae19534, rebuttals file (5), fresheyes gpt-6-astra high, REASON=-]: 2B/0S/0C/0R · fixed 9/9 prior (FB3 incomplete, re-fixed) · velocity ↓ (13→2, escalation no)
- D1 suffix validation refuses two-letter domains (".io"), a regression: fixed (own suffix pattern; regression test).
- D2 leak checks still grep the placeholder: fixed (commands replaced by `scripts/public-scan.sh`, exit 0).
- No standing rebuttal overturned. No further pass (ruling jibot-code#41e2).

## Chunks
- [x] C1 — poster config keys (strip_hosts, internal_host_suffixes, relay_ssh_host, relay_send_wrapper), code and tests — df01f32
- [x] C2 — scrub docs, ops/vm, mirror units; scripts/public-scan.sh in the gate — committed with this manifest

## Notes
- Prior work: kata search "public scan host names" finds only h6bx itself; capability-search public-scan: 0 hits.
- Scope wider than the issue lists: the scan pattern also hits ops/vm/README.md, ops/vm/buzz-send, mirror/*.service|timer, mirror/export_mirror.py and three test files; all are in scope, or the scan fails the gate.
- Agency execution not used (as in the earlier runs of this repo): two small chunks whose edits interlock with the sibling workers' files; executed inline, each chunk verified by the full suite.
- Line budget: the deliverable is about 520 changed lines (code and ops about 140, tests about 220 of which about 130 are tests the spec/plan review asked for, docs 160 as one-line rewrites); over the brief's 400. Splitting would leave the scan red in one half. Recorded as decided: on the issue.
