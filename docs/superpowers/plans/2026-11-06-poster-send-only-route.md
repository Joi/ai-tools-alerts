# Plan: poster-send-only-route

Spec: docs/superpowers/specs/2026-11-06-poster-send-only-route-design.md
One chunk, one commit (plus review-fix commits).

## Chunk 1 — guard, reference files, README, note, tests

- [ ] `ops/vm/aitools-poster-shell`: the guard from c:pj71er verbatim
      (`RELAY_USER="RELAY_USER"`); `chmod 755`; `git add --chmod=+x`.
- [ ] `ops/vm/sudoers-aitools-poster`: comment header (install path, mode
      440, `visudo -cf` then move, replace RELAY_USER, wildcard caveat), then
      the one installed line.
- [ ] `ops/vm/sshd-match-aitools-poster.conf`: comment header (append last,
      `sshd -t` before reload, keep a backup), then the six-line Match block.
- [ ] `ops/vm/buzz-send`: add the sudo/HOME note to the paragraph on the
      HOME defaults (comment only; `git diff ops/vm/buzz-send` shows only
      `#` lines).
- [ ] `ops/vm/README.md`: append "## The poster's send-only route" after the
      last section; generic placeholders (`<relay-vm>`, `<user>` as the file
      already uses, `<private address>`, `<poster-alias>`).
- [ ] `tests/test_poster_shell.py`: fixture builds tmp dir with fake
      `sudo` (records argv NUL-separated, asserts `-n -u RELAY_USER --`,
      execs remaining argv) and fake wrapper (records argv and stdin);
      guard copy with the `WRAPPER=` line replaced (count == 1);
      `run(args, stdin)` helper calls `bash <copy> ...` with
      `PATH=<fake>:<system PATH>`. Allowed cases built from
      `aitools_alerts.poster.transport.remote_argv`. Parametrised refusals
      per spec criterion 6. Sudoers/Match file pins.

## Verification

```bash
python3 -m pytest -q tests/test_poster_shell.py tests/test_buzz_send.py
scripts/test-gate.sh            # public scan + whole suite
git diff origin/main --stat     # deliverables under 300 lines
git diff origin/main | grep -niE '<fleet names from the brief>'   # run from a scratch file; expect no output
```

Known pre-existing failure: ai-tools-alerts#rvw5 (tests/poster/test_main.py
order-dependent); not this run's.

## Acceptance

Spec criteria 1–8. Gate green apart from rvw5 if still open.

## Rollback

`git revert` of the chunk commit.
