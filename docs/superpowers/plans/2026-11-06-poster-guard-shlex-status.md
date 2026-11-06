# Plan: poster-guard-shlex-status

Spec: docs/superpowers/specs/2026-11-06-poster-guard-shlex-status-design.md
One chunk, one commit (plus review-fix commits).

## Chunk 1 — guard exit status, NUL boundaries, hex lists, Match block, README, tests

Tests first (they must fail against the current guard where noted):

- [ ] `tests/test_poster_shell.py`: `_make_guard`'s `run` takes an optional
      `lang` and sets `LANG` in the env when given (default env unchanged).
- [ ] New `test_python_failure_after_partial_output_refused`: write a fake
      `python3` into `guard.fake` that prints the seven-argument split of
      `remote_argv(CHANNEL, wrapper=guard.wrapper)` (NUL after each) and exits
      1; the guard, given the matching command, is refused with
      `unparsable command`. The deterministic regression for item 1.
- [ ] New `test_non_utf8_argument_refused_under_utf8_locale`: command bytes
      `<wrapper> messages send --channel <uuid> --content - \xff <64 hex>`
      passed as a bytes argument, `lang="en_US.UTF-8"`; assert exit 1, one
      JSON `user_error` line starting `aitools-poster-shell: refused`, and no
      `sudo-argv`/`wrapper-argv`. Reason not pinned (`unparsable command`
      where python honours the locale, `argument 8` where it falls back to
      UTF-8 mode). Fails against the current guard on this Mac (verified in
      the manifest repro); elsewhere it is end-to-end coverage.
- [ ] New refusal case in `test_other_shapes_refused`: tail
      `"'messages\nsend' --channel <uuid> --content -"` → `argument count 6`
      (the token stays one argument; the current guard rebuilds seven and
      accepts).
- [ ] Existing cases whose reason changes (spec criterion 5):
      unbalanced quote → `unparsable command`; reply id with an embedded
      newline → `reply-to id`. Nothing else in the file changes.
- [ ] `test_sshd_match_reference`: expect the three added lines in file order.

Code:

- [ ] `ops/vm/aitools-poster-shell` line 23 (the `mapfile ... < <(python3 ...)`
      line) becomes the `shopt -s lastpipe` line plus the NUL-delimited
      pipeline from the spec. Header comment: one line on why (python's exit
      status, exact argument boundaries).
- [ ] Lines 29 and 33: `[0-9a-f]` → `[0123456789abcdef]` in both patterns.
- [ ] `ops/vm/sshd-match-aitools-poster.conf`: append
      `AllowStreamLocalForwarding no`, `DisableForwarding yes`,
      `PermitUserRC no` after `PermitTunnel no`.
- [ ] `ops/vm/README.md`: "needs bash 4 or later" → "4.4 or later";
      step 5 adds `allowstreamlocalforwarding no`, `disableforwarding yes`,
      `permituserrc no`; step 6: home directory, `.ssh` and `authorized_keys`
      root-owned (755, 755, 644) with the reason, and the `restrict` sentence
      corrected (`restrict` stays required); test 4 adds a remote Unix-socket
      forward that must fail.

## Verification

- `python3 -m pytest tests/test_poster_shell.py -q` — the new tests fail
  against the current guard as noted, all pass after.
- `scripts/test-gate.sh` — public scan clean (it holds the fleet host names
  in its untracked terms file), whole suite passes; any pre-existing failure
  named with its issue.
- `git diff --stat origin/main -- ops tests`: under 150 lines.

## After the commit

- kata `notice:` on ai-tools-alerts#zeqm: the README now asks for a
  root-owned home directory on the VM; the coordinator applies it with the
  guard reinstall.

## Acceptance

Spec criteria 1–8 and 2a.

## Rollback

`git revert` the commit; the live guard is reinstalled from the reverted
file by the coordinator.
