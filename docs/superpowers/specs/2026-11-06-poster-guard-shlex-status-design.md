# Poster guard: refuse when the shlex step fails partway; Match block closes stream-local forwarding

Kata: ai-tools-alerts#zeqm (found by the w75s code review, finding S1, S3, C6, C7).

## Problem

1. `ops/vm/aitools-poster-shell` splits the client command with
   `mapfile -t argv < <(python3 ... shlex.split ...) || fail`. The `|| fail`
   sees only mapfile's status, never python's. sshd accepts `LANG` and `LC_*`
   from the client, so with `LANG=en_US.UTF-8` and a non-UTF-8 byte in the
   eighth argument, python prints the first seven arguments and then raises
   `UnicodeEncodeError`. The guard counts seven, accepts, and runs a command
   other than the one sent. Reproduced on this branch before any change: the
   guard reached `sudo`. Every accepted prefix is itself an allowed send, so it
   is not a privilege bypass, but the guard's contract is "refuse anything
   else".
   A second defect in the same step (found in the spec review): python
   prints one argument per line and mapfile splits on newlines, so a quoted
   token holding a newline becomes two arguments. `'messages<LF>send'`
   splits into six arguments and is rebuilt as the allowed seven.
2. The hex checks use `[0-9a-f]`, a range whose meaning in bash `=~` depends on
   the locale's collation; the client sets the locale.
3. The Match block leaves `AllowStreamLocalForwarding` at its default (yes) and
   does not set `DisableForwarding` or `PermitUserRC`; only the key's
   `restrict` option closes Unix-socket forwarding and `~/.ssh/rc`.
4. The README installs `authorized_keys` owned by the poster user, so that
   user could rewrite or drop the `restrict` line if anything ever let it run
   a command other than the one allowed shape.

Items 3 and 4 are already live on the relay VM (c:x1bqsj). This change is
the repo side: the guard fix, the reference file, the README, the tests. The
coordinator reinstalls the guard when it lands.

## Success criteria

1. The guard refuses (`refused: unparsable command`, exit 1, wrapper not run)
   whenever python3 exits non-zero, whatever it printed first. Test: a fake
   `python3` first in `PATH` prints a valid seven-argument split and exits 1;
   the guard refuses.
2. Test with the real python3: the command above (non-UTF-8 byte as argument
   8, a valid reply id as argument 9) under `LANG=en_US.UTF-8` is refused and
   the wrapper does not run. It fails against the current guard wherever
   python honours that locale (macOS, a Linux with the locale installed);
   where python falls back to UTF-8 mode it passes the byte through and the
   argument checks refuse it, so the test is end-to-end coverage and the
   fake-python test of criterion 1 is the deterministic regression.
2a. Argument boundaries survive the split: python writes each argument
   followed by a NUL and the guard reads them with `mapfile -d ''`. Test: a
   command whose second token is `'messages<LF>send'` is refused.
3. The hex checks list their characters (`[0123456789abcdef]`) instead of a
   range, so no locale changes what they accept. The guard does not change
   the locale it passes to python, sudo or the wrapper.
4. Under a bash without `lastpipe` (macOS `/bin/bash` 3.2) every command is
   still refused with `refused: unparsable command`
   (`test_bash3_fails_closed` unchanged).
5. Every existing test in `tests/test_poster_shell.py` passes unchanged except
   `test_sshd_match_reference`, which pins the three new lines, and two
   refusal reasons that change because the defect is fixed: the unbalanced
   quote is refused as `unparsable command` (python now fails on it, where
   before it printed nothing and the count was 0), and the reply id with an
   embedded newline is refused as `reply-to id` (it stays one argument). Both
   are still refused.
6. `ops/vm/sshd-match-aitools-poster.conf` adds
   `AllowStreamLocalForwarding no`, `DisableForwarding yes`, `PermitUserRC no`.
7. `ops/vm/README.md` install step 5 expects `allowstreamlocalforwarding no`,
   `disableforwarding yes`, `permituserrc no` from `sshd -T`; step 6 installs
   `authorized_keys` root-owned, mode 644, in a root-owned `.ssh` of mode 755,
   inside a home directory that is root-owned too (mode 755), and says why:
   the poster user cannot edit the `restrict` line, and with the home
   root-owned it cannot rename `.ssh` aside and put its own in place
   (StrictModes accepts a path owned by root or by the user, so ownership of
   the file alone does not stop a swap). The guard never writes to the home
   directory. The home-directory step is new on the VM, so the kata issue gets
   a `notice:` for the coordinator. The sentence saying
   `restrict` is the only thing closing Unix-socket forwarding is corrected
   (both now close it; `restrict` stays required).
8. Under 150 changed lines excluding these three run artifacts; no fleet host
   names (checked by `scripts/public-scan.sh`, whose terms live outside the
   repo); `scripts/test-gate.sh` passes.

## Approach

Item 1: replace the process substitution with a pipeline whose last stage
runs in the current shell:

```bash
shopt -s lastpipe 2>/dev/null || fail "refused: unparsable command (needs bash 4.4 or later)"
python3 -I -c 'import shlex,sys; [print(a, end="\0") for a in shlex.split(sys.argv[1])]' "$cmd" 2>/dev/null \
  | mapfile -d '' -t argv || fail "refused: unparsable command"
```

`set -o pipefail` is already on, so the pipeline's status is python's when
python fails. `lastpipe` takes effect because a script has no job control, so
`argv` is set in the guard's own shell. NUL cannot occur inside an argument
(sshd passes the command as a C string), so it is an exact delimiter.
`mapfile -d` needs bash 4.4. bash 3.2 has neither `lastpipe` nor `mapfile`,
so it refuses at the `shopt` line with the same message prefix; a 4.2 or 4.3
bash refuses at `mapfile -d` through the same `|| fail`.

Item 2 (locale): explicit character lists in the two `=~` patterns.

Assumes: the relay VM's bash is 5 (Ubuntu 24.04 ships 5.2); the README's
"bash 4 or later" becomes "bash 4.4 or later".

## Alternatives considered

- Sentinel last line from python: works, but checks a proxy for success
  instead of the status itself.
- Keeping one argument per line and refusing any argument that contains a
  newline: also closes the reconstruction, but NUL delimiting removes the
  ambiguity instead of detecting it.
- `AuthorizedKeysFile` outside the home (for example
  `/etc/ssh/authorized_keys/%u`): the strongest form, but it changes the live
  Match block the coordinator just applied; a root-owned home gives the same
  result with one `chown`.
- `wait $!` after the process substitution: needs bash 4.4 and is easier to get
  wrong (the `$!` of a process substitution).
- Temporary file plus exit code: needs `mktemp` and cleanup on every exit
  path; the pipeline needs neither.
- `export LC_ALL=C` in the guard: fixes collation but also changes the locale
  python, sudo and the wrapper see; the wrapper posts Japanese text, so the
  narrower change (explicit lists) is safer.
- Making python pass undecodable bytes through (`surrogateescape`): the
  argument checks would then refuse them, but the brief asks for refusal on
  any python failure, which this change gives regardless of encoding.

## Blast radius and rollback

The guard is the poster's only route to post. A wrong guard refuses every
send (posts queue on the poster and retry) or, worse, accepts too much; the
tests pin both directions. The live guard changes only when the coordinator
reinstalls it, with the README test list after. Rollback: reinstall the
previous `ops/vm/aitools-poster-shell` from git. The Match block and README
lines describe what is already live.

## Open questions

None.
