# The poster's send-only relay route: sources of truth and docs

Kata: ai-tools-alerts#w75s (parent jibot-code#gr5b).

## Problem

The poster used to reach the relay VM with the fleet ops key and a full
shell, so a compromised poster Mac could run any Buzz command as jibot
(channel delete, add-member). The hand part of w75s is live: a Unix user
`aitools-poster` on the relay VM whose login shell is a guard allowing one
command shape, a sudoers rule that runs the wrapper as the relay user, an
sshd Match block for that user, a dedicated ed25519 key with `restrict`, and
a poster-side ssh alias. None of it is in the repo, so the next rebuild of
the VM cannot reproduce it and nobody can diff the installed files against a
source of truth.

## Success criteria

1. `ops/vm/aitools-poster-shell` is byte for byte the guard text posted in
   c:pj71er, where the coordinator already substituted the placeholder
   `RELAY_USER` for the relay user (the install step replaces it). Mode 755
   in git.
2. `ops/vm/sudoers-aitools-poster` holds the installed sudoers line with
   `RELAY_USER` for the relay user, plus comment lines saying where it is
   installed (`/etc/sudoers.d/aitools-poster`, mode 440, `visudo -cf`
   before moving it in) and that its `*` wildcards also match spaces, so the
   guard is the strict check and the rule only narrows the program and the
   leading arguments.
3. `ops/vm/sshd-match-aitools-poster.conf` holds the installed Match block
   with a comment header (append at the end of `sshd_config`, `sshd -t`
   before a reload).
4. `ops/vm/README.md` gains one section, "The poster's send-only route",
   with: why; the install steps (user with the guard as login shell and no
   password, the guard, sudoers via `visudo -cf`, the Match block tested
   with `sshd -t` before a reload, per-user `authorized_keys` with one
   `restrict` line); that the private network route is the VM's own OpenSSH
   and not the provider's public ssh edge; the poster-side ssh alias
   (`Host`, `HostName <private address>`, `User aitools-poster`,
   `IdentityFile`, `IdentitiesOnly yes`); an effective-policy check before
   the key is authorized (`sshd -T -C user=aitools-poster,...` for the
   forwarding, TTY, tunnel, key-file, `permituserenvironment`, `acceptenv`,
   `forcecommand` and `subsystem` values, no in-process sftp; `sudo -l -U
   aitools-poster` lists only the rule; `sudo -V` shows `env_reset` keeping
   no `HOME` or `BUZZ_*`), with a stop when any differs; and the poster config keys
   `relay_ssh_host` and `relay_send_wrapper` (the wrapper's absolute path,
   since the guard compares argv[0] exactly); and the test list: a shell
   command refused, interactive login refused, the allowed shape reaches the
   relay, local and remote forwarding denied (a real channel request), sftp
   refused, other users denied the key, each refusal counted only when `-v`
   shows the poster key authenticated,
   and the lesson that a one-key test must use `ssh -F /dev/null -o
   IdentitiesOnly=yes -i <key>` or read `Server accepts key` in `-v` output,
   because ssh otherwise offers other keys from the ssh config and agent.
   The section touches no other section (ai-tools-alerts#fzr2 edits the same
   file in parallel).
5. `ops/vm/buzz-send` header gains a note: run through the guard's sudo,
   HOME is the relay user's (under the default `env_reset` policy, checked
   at install, sudo sets HOME to the target user's), so the HOME defaults
   find that user's key and CLI,
   and the `BUZZ_SEND_*` overrides do not pass through. No code change.
6. `tests/test_poster_shell.py` runs the tracked guard with bash and
   `subprocess` against a fake `sudo` and a fake wrapper in a temporary
   directory: the test copy replaces only the `WRAPPER=` line (asserted to
   occur once) and puts the fake `sudo` first on PATH. Cases: allowed shape
   with and without `--reply-to` reaches the wrapper with the same argv and
   stdin, and the fake sudo saw `-n -u RELAY_USER --`; refused: no `-c`
   (interactive), extra arguments to the shell, empty command, unparsable
   quoting, wrong program, wrong subcommand, uppercase or malformed channel
   id, `--content` other than `-`, malformed reply id, wrong argument 8,
   extra arguments, shell metacharacters (`;`, `$(...)`, backticks) that do
   not run. A refusal exits 1 with one JSON error line and never runs the
   wrapper. A test pins the sudoers and Match files' key lines.
7. The tracked tree names no fleet host, address, VM name or the relay
   user: the public scan in `scripts/test-gate.sh` passes on the branch
   head, and the diff is grepped for the fleet names before the review.
8. Under 300 changed lines in the deliverables (run records counted apart).

## Approach

Copy the guard and the two reference files from c:pj71er with the generic
names. Tests follow `tests/test_buzz_send.py`: stub executables written
into `tmp_path`, bash run directly. The fake `sudo` records its argv,
checks `-n -u <user> --`, and execs the rest. Commands are built with
`shlex.join(remote_argv(...))` where possible, the same function the poster
uses, so a drift between the poster and the guard fails a test.

## Alternatives considered

- An environment override for the wrapper path in the guard (like
  `BUZZ_SEND_KEY_FILE`): rejected; sshd can pass client variables through
  `AcceptEnv`, and the guard is the security boundary. The test substitutes
  one line in a copy instead.
- Tightening the sudoers wildcards: rejected for this task; the file must be
  the installed one, and the guard already pins every argument. Noted in the
  file instead.
- `ForceCommand` in the Match block instead of a login shell: not what is
  installed; the login shell also covers subsystem requests that go through
  the shell. Documented as a check (sftp refused), not changed.

## Blast radius / rollback

Repo files and docs only; nothing live changes. Rollback is a revert.

## Open questions

None. The brief's "delete that file" for `ops/vm/buzz-send-guard`: the file
exists only on origin branch `w75s-guard` and never landed; this branch does
not carry it, and that branch is deleted after this lands.
