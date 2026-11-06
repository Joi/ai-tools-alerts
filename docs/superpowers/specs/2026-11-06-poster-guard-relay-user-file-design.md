# Poster guard: read the relay user from an untracked file

Kata: ai-tools-alerts#25mh (discovered from ai-tools-alerts#zeqm).

## Problem

`ops/vm/aitools-poster-shell` ships with `RELAY_USER="RELAY_USER"`, because
the public repo cannot name the relay VM's login user. The install step edits
that line by hand. On 2026-11-06 the coordinator installed the zeqm build as a
plain copy and every send was refused
(`refused: program /home/RELAY_USER/bin/buzz-send`) until the line was
substituted by hand; the 02:20Z poster run would have failed.

## Success criteria

1. The guard reads the relay user from `/etc/aitools-poster/relay-user`
   before it looks at the client command. The file holds one line: the user
   name, with or without a trailing newline.
2. The guard refuses with its one-line JSON error (`user_error`, message
   `aitools-poster-shell: refused: ...`, exit 1, sudo and the wrapper not run)
   when the file is missing or not a regular file (`relay user file missing`),
   or is empty, holds more than one line, or holds anything other than a
   plain POSIX user name (`relay user file is not one user name`). A plain
   name matches `^[a-z_][a-z0-9_-]{0,31}$`; the check lists its characters,
   as the hex checks do, because the client sets the locale and a range
   follows the locale's collation.
3. `WRAPPER` is derived from it as today: `/home/<user>/bin/buzz-send`, and
   `sudo -n -u <user>`.
4. No placeholder remains in the tracked guard: the install is a plain
   `install -o root -g root -m 755` of the tracked file.
5. Tests: missing file, a directory in its place, empty file, two lines,
   malformed names (uppercase, leading digit, a space, a slash, 33
   characters, a carriage return, a NUL anywhere), and a good name, with and without a trailing newline, that
   reaches sudo as that user. Every existing guard test still passes.
6. `ops/vm/README.md` documents the file: path, one line, owner root,
   mode 644, directory `/etc/aitools-poster` root 755, and that the VM's
   operator (the coordinator) writes it; the install step no longer edits the
   guard.
7. Under 100 changed lines, excluding these run artifacts.

## Approach

Line 15 becomes `RELAY_USER_FILE=/etc/aitools-poster/relay-user`, and
`WRAPPER=` moves below `fail()` with the new check, before the `-c` check:

```bash
[ -f "$RELAY_USER_FILE" ] || fail "refused: relay user file missing ($RELAY_USER_FILE)"
RELAY_USER=""
{ ! IFS= read -r -d '' RELAY_USER; } 2>/dev/null < "$RELAY_USER_FILE" \
  && RELAY_USER="${RELAY_USER%$'\n'}" \
  && [[ "$RELAY_USER" =~ ^[abcdefghijklmnopqrstuvwxyz_][abcdefghijklmnopqrstuvwxyz0123456789_-]{0,31}$ ]] \
  || fail "refused: relay user file is not one user name ($RELAY_USER_FILE)"
WRAPPER="/home/$RELAY_USER/bin/buzz-send"
```

`read -d ''` reads the whole file in one call: it returns 0 only when it
stops at a NUL, so a file holding a NUL anywhere is refused (bash would
otherwise drop the byte and turn `relay<NUL>user` into `relayuser`; found in
the spec review). At end of file it returns 1 with everything read. One
trailing newline is stripped; the pattern holds no newline and bash's `$`
anchors at the end of the string, so a second line or a second newline is
refused. `2>/dev/null` comes before `<` so a redirect failure (an unreadable
file) is silent and refused by the `||`. `read` is a builtin in bash 3 too,
so `test_bash3_fails_closed` keeps refusing at the `lastpipe` step.

The read runs before the interactive-login check, so a missing or bad file
is the first refusal anyone sees: a misconfigured install fails loudly on the
first send instead of hiding behind the command checks.

## Decision: no environment override

The dispatch brief offered a path override "through one environment variable
the guard reads before anything else, documented as test-only". Rejected: a
login shell that takes the relay user's identity from its environment is a
lever for whoever can set that environment. Today sshd accepts only `LANG`
and `LC_*` and `PermitUserEnvironment no`, but the guard would then depend on
that for who it sudoes to. The tests already rewrite one line of a copy of the
guard (`WRAPPER=`); they rewrite the `RELAY_USER_FILE=` line the same way, so
the checks they exercise are the installed ones and the installed guard reads
no variable at all. Recorded on kata as `decided:`.

## Alternatives considered

- Derive the user from the owner of a file (`stat`): GNU and BSD `stat` differ,
  and a file's owner is a weaker statement than its content.
- Read the user from the sudoers file: couples two files and parses sudoers.
- Keep the placeholder and add an install script: the failure was a plain
  copy; any manual step can be skipped again.

## Blast radius and rollback

One script, its tests and the README. On the VM the file already exists (the
coordinator wrote it); the coordinator installs the landed guard as a plain
copy. If the file were wrong, every send is refused with a message naming the
file, the same fail-closed outcome as the incident, but self-describing.
Rollback: reinstall the previous guard with the user substituted by hand.

## Open questions

None.
