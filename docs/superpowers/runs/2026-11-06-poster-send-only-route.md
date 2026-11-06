# Run: poster-send-only-route
Instruction: Dispatch of ai-tools-alerts#w75s in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#w75s.md in the worktree root: repo side only, nothing live — ops/vm/aitools-poster-shell (the login-shell guard exactly as installed, from c:pj71er), ops/vm/sudoers-aitools-poster and ops/vm/sshd-match-aitools-poster.conf as reference files with generic user names, an ops/vm/README.md section (install steps, poster-side ssh alias, test list including the `ssh -F /dev/null` lesson), a note in ops/vm/buzz-send that under sudo HOME is the target user's, tests/test_poster_shell.py against a fake wrapper; no fleet names, no addresses; under 300 changed lines.
Stage: spec
Rung: medium (start-floor medium: prod-shaped, BR1 REV0 NOV1 INT1 FC1 = 4; no hard trigger)
Lens: the login-shell guard exactly as installed (byte for byte the c:pj71er text); repo side only, nothing live; no fleet names, no addresses; under 300 changed lines
Spec: docs/superpowers/specs/2026-11-06-poster-send-only-route-design.md   Plan: docs/superpowers/plans/2026-11-06-poster-send-only-route.md
Agency project: —
Kata: ai-tools-alerts#w75s
Last reviewed: —
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot d333b0cbd5907fadfb8b8a192dabf32d08281756, fresheyes gpt-6-astra high, REASON=-]: 5B/0S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
- B1 subsystems (internal-sftp) bypass the login shell: fixed (README install step 6 checks `sshd -T -C` subsystem and stops; test 5 sftp refused).
- B2 environment passing (AcceptEnv BASH_ENV/PATH, PermitUserEnvironment): fixed (step 6 checks `acceptenv` LANG LC_* at most and `permituserenvironment no`).
- B3 sudo/HOME note unverified: fixed (note made conditional on `env_reset`; step 6 checks `sudo -V` and `sudo -l -U`).
- B4 appended Match + `sshd -t` do not prove effective config: fixed (step 6 `sshd -T -C` with the poster's connection parameters, stop on difference).
- B5 negative tests do not separate enforcement from failed login: fixed (each with `-v`, counted only with the poster key authenticated; real channel requests for -L and -R).
- The reviewer could not read kata (daemon unavailable in its sandbox) so criterion 1 was unverified by it; the guard was extracted mechanically from c:pj71er (awk over `kata show`), and the code review sees it.
- Spec/plan delta: the fixes are doc text; the whole-branch code review reads the amended spec, plan and README with the code (as on a5hk and h6bx).
Pass 1 [code:branch, origin/main...a8dd8a32d46f547496ad1dcdb950337996e8f191; Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6-astra high, REASON=-]: 5B/3S/4C/0R · fixed -/- · velocity = (—→12, escalation no)
- FB1 key authorized before the policy checks: fixed (checks are step 5, before the key in step 6).
- FB2 per-user/command sudo Defaults not checked: fixed (grep of Defaults for the poster, relay user and wrapper).
- FB3 `sshd -T` prints `forcecommand none`: fixed.
- FB4 test 6 cannot meet the "authenticated" condition: fixed (own criterion; BatchMode and publickey only).
- FB5 gate passes when bash 4+ is missing: fixed (the guard fixture fails, with the install hint). Behaviour change, so one delta pass.
- S1 guard trusts partial python output (UnicodeEncodeError after 7 args under a UTF-8 locale): rebutted here — the guard must match the installed file and the fix is a live reinstall; filed ai-tools-alerts#zeqm.
- S2 a global RELAY_USER replace breaks the guard: fixed (anchored sed in step 2).
- S3 Match block leaves stream-local forwarding at its default: fixed in the README (restrict is required, and why); the Match-block change is live, in zeqm.
- C4 metacharacter test's cwd check meaningless: fixed (removed). C5 skip on no bash 4: fixed by FB5. C6 root-owned authorized_keys, C7 locale ranges: in zeqm.

## Chunks
- [ ] guard + reference files + README + buzz-send note + tests

## Notes
- Agency: not used, as on the earlier runs of this build (a5hk, h6bx manifests: Agency project —); one chunk of six files, built directly.
- The superseded `ops/vm/buzz-send-guard` exists only on origin branch `w75s-guard` (commit 4cc38da), never on main; this branch does not carry it.
