# Plan: poster guard reads the relay user from a file

Spec: docs/superpowers/specs/2026-11-06-poster-guard-relay-user-file-design.md
Kata: ai-tools-alerts#25mh

One chunk, three files.

## Chunk 1: guard, tests, README

- [ ] `ops/vm/aitools-poster-shell`
  - line 15 `RELAY_USER="RELAY_USER"` → `RELAY_USER_FILE=/etc/aitools-poster/relay-user`
  - line 16 `WRAPPER=...` moves below `fail()` (line 21), after the new read
    and check from the spec's Approach; text of the `WRAPPER=` line unchanged
  - header comment: one sentence naming the file
- [ ] `tests/test_poster_shell.py`
  - `_make_guard(tmp_path, bash, relay_user="relayuser\n")`: writes
    `tmp_path/relay-user` (or not, when `relay_user is None`; a directory
    when it is the sentinel `DIR`), and rewrites the one
    `RELAY_USER_FILE=/etc/aitools-poster/relay-user` line of the copy to the
    temporary path, asserting the line occurs once, as for `WRAPPER=`
  - `FAKE_SUDO` checks `$3` against `bin/expect-user`, which `_make_guard`
    writes from `relay_user`, so each good name is checked as its own user;
    `test_allowed_shape_reaches_the_wrapper` expects `relayuser`
  - `test_tracked_guard_is_executable_and_names_no_relay_user`: the
    placeholder is gone, the path line is present, and the guard reads no
    `AITOOLS_*` variable
  - new `test_relay_user_file_refused` parametrized: missing, directory,
    empty, `"\n"`, `"a\nb\n"`, `"relayuser\n\n"`, `"Relay\n"`, `"1relay\n"`,
    `"relay user\n"`, `"../x\n"`, `"a"*33`, `"relayuser\r\n"`, and a NUL
    embedded, trailing and leading — each refused
    with the right reason, also for an interactive login (refusal comes first)
  - new `test_relay_user_file_good_names`: `"relayuser"` (no newline),
    `"_r-1\n"`, `"a"*32` reach sudo as that user
  - `test_bash3_fails_closed` untouched (it uses the default good file)
- [ ] `ops/vm/README.md`
  - files table: row for `/etc/aitools-poster/relay-user`, 644 root, written
    by the VM's operator, not tracked
  - guard paragraph: one sentence on where the user comes from and the refusal
  - Install step 2: plain `install -o root -g root -m 755`; new text: write the
    file (`install -d -o root -g root -m 755 /etc/aitools-poster`, then
    `printf '%s\n' <user> > ...`, `chown root:root`, `chmod 644`)

## Verification

```
python3 -m pytest tests/test_poster_shell.py -q
git commit ...; scripts/test-gate.sh   # the repo's gate: public scan (terms from the untracked file) then pytest
git diff --stat origin/main   # under 100 lines outside docs/superpowers
```

The public scan is the host-name check: its terms live outside the repo, so
no tracked file, this plan included, spells them.

Mutation checks: drop the trailing-newline strip (every newline-terminated
name refused → good-name tests fail); widen `{0,31}$` (33 characters accepted
→ fails);
replace the listed characters with `[a-z]` (still passes here; noted, the
locale test is out of scope); delete the `-f` check (missing-file test sees a
second stderr line or a different reason → fails).

## Acceptance

Spec criteria 1–7.

## Rollback

`git revert` the commit; on the VM reinstall the previous guard with the
user substituted.
