# Run: poster-guard-shlex-status
Instruction: Dispatch of ai-tools-alerts#zeqm in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#zeqm.md in the worktree root: repo side only (the live Match block and root-owned authorized_keys are already applied by the coordinator). Item 1: ops/vm/aitools-poster-shell checks python3's exit status and refuses on any failure, with a test that feeds a non-UTF-8 byte under LANG=en_US.UTF-8 and expects a refusal. Item 2: ops/vm/sshd-match-aitools-poster.conf gains AllowStreamLocalForwarding no, DisableForwarding yes, PermitUserRC no; update ops/vm/README.md's sshd -T expectations and test_sshd_match_reference. Item 3: README documents the root-owned authorized_keys (mode 644, directory 755 root-owned) and why. Under 150 changed lines. Security-shaped: review on gpt-6-astra.
Stage: spec-review
Rung: heavy (start-floor heavy: hard-trigger — SSH auth surface and a live-installed guard; BR=1 REV=1 NOV=1 INT=1 FC=2 total=6; dispatch floor was medium; kata notice posted)
Lens: "refuses on any failure"; "refuse anything else"; "The guard does not change the locale it passes to python, sudo or the wrapper"; "Every existing test in tests/test_poster_shell.py passes unchanged except test_sshd_match_reference"; "test_bash3_fails_closed unchanged"; "Under 150 changed lines"; "no fleet host names"
Spec: docs/superpowers/specs/2026-11-06-poster-guard-shlex-status-design.md   Plan: docs/superpowers/plans/2026-11-06-poster-guard-shlex-status.md
Agency project: —
Kata: ai-tools-alerts#zeqm
Last reviewed: spec+plan 6a441c70bae1ef428eb67455ca209d0805b22b6e (pass 1)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot 6a441c70bae1ef428eb67455ca209d0805b22b6e, fresheyes gpt-6-astra high, REASON=-]: 2B/3S/1C/0R · fixed -/- · velocity = (—→6, escalation no)
- B1 the fix turns the unbalanced-quote case from `argument count 0` into `unparsable command`, against "existing tests unchanged": fixed (spec criterion 5 names the two reason changes; both inputs still refused).
- B2 a quoted token with a newline (`'messages<LF>send'`) is rebuilt by the line protocol into the allowed seven arguments: fixed (NUL-delimited output, `mapfile -d ''`, bash 4.4+; new refusal case). Behaviour change to the design.
- S1 a root-owned `.ssh` in a user-owned home can be renamed aside: fixed (README asks for a root-owned home too; notice to the coordinator).
- S2 the plan's hostname grep carried the host names: fixed (the public scan's untracked terms file does it).
- S3 the real-python test may pass before the fix where python falls back to UTF-8 mode: fixed (spec says it is end-to-end coverage; the fake-python test is the deterministic regression; baseline verified on this Mac).
- C1 snapshot commit message: rebutted (a dangling review snapshot, never on any branch).
Pass 1 [code:branch, origin/main...4fd1965fb81f8031d46fc8fc8219054a3f8e5797; Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6-astra high, REASON=-]: 1B/0S/2C/0R · fixed -/- · velocity = (—→3, escalation no)
- FB1 the plan said the `'messages<LF>send'` case is refused as `subcommand`; it is refused at `argument count 6` (the test already says so): fixed in the plan. Doc-only, so no delta pass (ruling jibot-code#41e2).
- Stage 1: no B/S. Mutation checks: dropping python's status fails 3 tests, going back to newline delimiting fails 2; adversarial locales (C, UTF-8, SJIS, GB18030, Big5, ISO8859-1) all refused, allowed shape passes in each.
- C1 on bash 4.2/4.3 `mapfile -d` prints usage text before the JSON refusal: rebutted (still refused, exit 1; the VM runs bash 5; the README says 4.4).
- C2 the real-python test does not pin which check refuses: fixed (docstring says it is end-to-end and names the deterministic test).
- Spec/plan delta: not run as a separate pass; the whole-branch code pass reads the amended spec and plan with the code, as on w75s, a5hk and h6bx. That code pass is this run's heavy first pass for code, with a delta if a BLOCKER fix there changes behaviour.

## Chunks
- [ ] guard exit status + Match block + README + tests

## Notes
- Repro before any change: the installed guard, given `.../buzz-send messages send --channel <uuid> --content - \xff <64 hex>` under LANG=en_US.UTF-8, reached `sudo` (python printed 7 arguments, then raised UnicodeEncodeError; the guard accepted n=7).
- Agency: not used, as on the earlier runs of this build (w75s, a5hk, h6bx); one chunk of four files.
