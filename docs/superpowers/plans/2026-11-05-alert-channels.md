# E1 alert channels — implementation plan

Spec: `docs/superpowers/specs/2026-11-05-alert-channels-design.md`. Issue jibot-code#wpbd. Branch `wpbd-alert-channels-on-ai-tools-relay`, base 3ce587e.

Rules for every step: shell scripts longer than one line are written to the session scratchpad and run as files (jibot-code#y1f2); remote scripts go to the VM on stdin (`ssh <relay-vm> 'bash -s' < script`), so the key is read and exported only on the remote side; no remote script prints `BUZZ_PRIVATE_KEY` or runs `set -x`; nothing from `~/.buzz-keys` is copied off the VM.

## Chunk 1 — the wrapper and its tests (repo only)

Files: create `ops/vm/buzz-send`, `tests/test_buzz_send.py`.

- [ ] **1.1 Failing tests** in `tests/test_buzz_send.py` (pytest, `subprocess.run(["bash", WRAPPER, ...])`, env built from scratch with `PATH` only plus the overrides):
  - stub CLI in `tmp_path/buzz`: `#!/usr/bin/env bash` writing each arg followed by NUL (`printf '%s\0' "$@"`) to `argv`, `printf '%s' "${BUZZ_PRIVATE_KEY-}"` to `key`, `printf '%s' "${BUZZ_RELAY_URL-}"` to `relay`, `printf '%s' "${BUZZ_AUTH_TAG-UNSET}"` to `authtag` (no trailing newlines, so exact comparison works), `cat` to `stdin`, then `exit "${STUB_EXIT:-0}"`. The test reads `argv` and splits on NUL, dropping the final empty element.
  - key fixture: `nostr.nsec(secrets.token_hex(32))` (guard the rare out-of-range scalar by regenerating) written to `tmp_path/agent.nsec` with a trailing newline, mode 600.
  - every `subprocess.run` carries `timeout=10`, so a wrapper that blocks fails the test instead of hanging it.
  - `test_key_reaches_child_only_in_env`: args `["messages", "send", "--channel", "X", "--content", "-"]` (six tokens); the parsed argv equals that list; the `key` file equals the nsec exactly; the nsec string appears in no argv token.
  - `test_relay_pinned_and_auth_tag_cleared`: caller env sets `BUZZ_RELAY_URL=http://evil` and `BUZZ_AUTH_TAG={}`; child sees `https://buzz.ai-tools.md` and no auth tag.
  - `test_caller_key_env_overridden`: caller env `BUZZ_PRIVATE_KEY=nsec1other…`; child sees the file's key.
  - `test_stdin_and_exit_pass_through`: stdin `hello\n` arrives byte-exact; `STUB_EXIT=5` gives exit 5.
  - `test_refuses_private_key_and_relay_flags`: `--private-key x`, `--private-key=x`, `--relay x`, `--relay=x` each exit 1, stub never runs (no argv file).
  - parametrized `test_bad_key_file_fails_closed` over: missing path; empty file; a directory; a FIFO (`os.mkfifo`; nobody writes it, so a wrapper that opens it would block and trip the timeout); shape-malformed text containing a distinctive token; an nsec with its last checksum character changed; `nostr.nsec("00"*32)`-shaped zero scalar built with the bech32 encoder (or, if `nostr.nsec` refuses it, the 64-zero hex form); the hex form of the curve order `n`; an `npub` in place of an nsec. Each: exit 1, stub never runs (no `argv` file), stderr is one JSON line with `"error":"user_error"`, and neither the distinctive token nor the file's (stripped) contents appear in stdout or stderr — the contents check applies only when the stripped contents are non-empty (an empty string is a substring of everything).
  - `test_hex_key_accepted`: 64 lowercase hex of a valid scalar works and reaches the child unchanged.
  - `test_validator_agrees_with_nostr`: for 20 random valid keys and the bad cases above, the wrapper's verdict matches whether `nostr.nsec_to_hex` accepts the nsec.
- [ ] **1.2 Run** `python3 -m pytest -q tests/test_buzz_send.py` — FAIL (no wrapper).
- [ ] **1.3 Write `ops/vm/buzz-send`** per the spec's wrapper section:
  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  umask 077
  KEY_FILE="${BUZZ_SEND_KEY_FILE:-$HOME/.buzz-keys/agent.nsec}"
  BUZZ="${BUZZ_SEND_BUZZ:-$HOME/buzz/target/release/buzz}"
  fail() { printf '{"error":"user_error","message":"buzz-send: %s"}\n' "$1" >&2; exit 1; }
  for a in "$@"; do case "$a" in --private-key|--private-key=*|--relay|--relay=*) fail "refused flag ${a%%=*}";; esac; done
  [ -f "$KEY_FILE" ] && [ -r "$KEY_FILE" ] || fail "key file missing, not a regular file, or not readable: $KEY_FILE"
  key="$(<"$KEY_FILE")" 2>/dev/null || fail "key file read failed: $KEY_FILE"
  key="${key//[[:space:]]/}"
  [[ "$key" =~ ^nsec1[02-9ac-hj-np-z]{58}$ || "$key" =~ ^[0-9a-f]{64}$ ]] || fail "key file malformed: $KEY_FILE"
  printf '%s' "$key" | python3 -I -c "$VALIDATOR" >/dev/null 2>&1 || fail "key file malformed: $KEY_FILE"
  export BUZZ_PRIVATE_KEY="$key"; unset key
  ```
  `VALIDATOR` is a single-quoted Python heredoc-free string defined above, reading `sys.stdin`, that implements bech32 decode with checksum (hrp `nsec`, BIP-173 constant 1), requires 32 bytes, and checks `1 <= int < n`; for hex it checks the range only; it exits 0 or 1 and prints nothing. `set -o pipefail` makes a python failure fail the pipeline.
  ```bash
  export BUZZ_RELAY_URL=https://buzz.ai-tools.md
  unset BUZZ_AUTH_TAG
  exec "$BUZZ" "$@"
  ```
  Header comment: purpose, caller contract, why env not argv, the overrides being test-only conveniences that grant nothing to the key's own uid.
  Note: the flag scan refuses those strings anywhere in argv, including as a `--content` value; content goes on stdin (`--content -`) for every caller in this project, so that is acceptable and documented in the header.
- [ ] **1.4 Run** — PASS. Also `bash -n ops/vm/buzz-send` and `shellcheck ops/vm/buzz-send` if installed.
- [ ] **1.5 Commit** `feat: VM send wrapper buzz-send (key from file, never argv)`; `chmod 755` in git (installed 700 on the VM).

Acceptance: all tests in 1.1 pass; gate passes.

## Chunk 2 — live VM state

- [ ] **2.1 Pre-check script** (`$SCRATCH/vm-precheck.sh`): export the key and relay on the remote side, `buzz channels list --limit 500 | jq -r '.[]?.name // empty'` (adjust to the actual JSON shape seen) and abort if `security-feed` or `security-critical` exists. Also `ls -la ~/bin/buzz-send` must say no such file.
- [ ] **2.2 Create script** (`$SCRATCH/vm-create.sh`): the two `channels create` commands from the spec verbatim, capturing each JSON; print only the JSON (ids, names, descriptions). Record both UUIDs.
- [ ] **2.3 Owner script**: `channels add-member --channel <id> --pubkey 18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29 --role owner` on both; then `channels members` and `channels get` on both.
- [ ] **2.4 Install wrapper**: `scp ops/vm/buzz-send '<relay-vm>:bin/buzz-send.new'`, then remote `chmod 700` and `mv -f` onto `~/bin/buzz-send`; compare `sha256sum` remote vs `shasum -a 256` local.
- [ ] **2.5 Proof**: remote script runs
  `printf '%s' 'channel check from jibot (setup, not an alert) - Jibot' | ~/bin/buzz-send messages send --channel <feed> --content -`, prints the JSON, extracts the event id, runs `~/bin/buzz-send messages delete --event <id>` and prints its JSON and exit status, then `buzz-send messages get --channel <feed> --since $((send_ts - 60)) --limit 200`, requiring exit 0, fewer than 200 rows (the CLI caps `get` at 200, `messages.rs:363` on the VM's a5dbdf5e6, so a full page means the window may be truncated and the check fails), and the id absent; `send_ts=$(date +%s)` is captured on the VM immediately before the send. `buzz-send messages thread --channel <feed> --event <id>` is also run and recorded (exit status and output), as supporting evidence only.
- [ ] **2.6 Reads**: `buzz-send messages get --channel <critical> --limit 1` exit 0; `buzz-send channels list --member` shows both.
- [ ] **2.7 Notice comment** on jibot-code#wpbd: `notice: created #security-feed <uuid> and #security-critical <uuid> on buzz.ai-tools.md as jibot; Joi owner on both; buzz-send installed; setup message <event id> sent and deleted (<result>)`, plus the write-restriction finding.

Acceptance: spec criteria 1–5.

Rollback: `buzz channels delete --channel <id>` for each; `rm ~/bin/buzz-send`.

## Chunk 3 — repo records

Files: create `spec/channels.json`, `tests/test_channels.py`, `ops/vm/README.md`; modify `README.md` (Status).

- [ ] **3.1 Failing test** `tests/test_channels.py`: `json.loads((ROOT/"spec/channels.json").read_text())`; keys == `{"feed","critical"}`; each `str(uuid.UUID(v)) == v`; `feed != critical`. Run — FAIL.
- [ ] **3.2 Write `spec/channels.json`** with the two UUIDs from 2.2. Run — PASS.
- [ ] **3.3 `ops/vm/README.md`**: sections What is on the VM (channels table: name, UUID, type, visibility, description, owners jibot creator + Joi `18eafd07…`; wrapper path/mode/sha256), How it was made (the commands of 2.2–2.5 with the key line shown as `BUZZ_PRIVATE_KEY="$(cat ~/.buzz-keys/agent.nsec)"` on the remote side), Write access (the probe finding and source paths), Recreate (channel UUIDs change on re-creation, so `spec/channels.json` must be updated and A7/B4/C1 readers follow), Event id field for B4.
- [ ] **3.4 README Status**: add the E1 line and the sentence "Buzz cannot restrict who posts in an open channel, so `#security-critical` is open: only keys in the trust manifest are trusted by the CLI, and anyone may reply."
- [ ] **3.5 Gate** `scripts/test-gate.sh` — PASS. Commit `feat: alert channel ids, VM README, README status`.

Acceptance: spec criteria 6–8.

## Review and ending

- Whole-branch fresheyes (`FRESHEYES_GPT_MODEL=gpt-6-astra`, watchdog) on `origin/main...HEAD`, Stage 1 in parallel; BLOCKERs fixed, SUBSTANTIVE fixed or rebutted; delta only if a BLOCKER fix changed behaviour.
- `git fetch origin`; rebase if main moved; push the branch; ff-merge to main from the primary checkout; push main.
- Final deploy identity: compare `ssh <relay-vm> sha256sum '~/bin/buzz-send'` with `git show origin/main:ops/vm/buzz-send | shasum -a 256`; on a mismatch reinstall (2.4) and run `buzz-send channels get --channel <feed>` (exit 0, no message). Record the final sha256 in the close-out.
- Close-out comment (commits, VM outputs with ids, review evidence line), `kata close --done --commit`; comment the landed sha and UUIDs on ai-tools-alerts#gctv and #kfq6; `/finish-worktree`.
