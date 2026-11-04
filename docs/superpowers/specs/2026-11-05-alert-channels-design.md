# E1: the two alert channels, the VM send wrapper, spec/channels.json

Issue: jibot-code#wpbd (parent jibot-code#gr5b). Plan: `docs/plan.md` Task E1, amended by gr5b decision c:8qna4r (the wrapper's source of truth is this repo, `ops/vm/buzz-send`; no cell-fleet copy).

## Problem

The poster (Task B4) and the mirror (Task C1) need two channels on the ai-tools Buzz relay (`https://buzz.ai-tools.md`) and their UUIDs in the repo. The poster sends over SSH to the relay VM, and the send must not put jibot's nsec on any argv or in any log. Neither the channels nor the wrapper exist yet.

## Success criteria

1. `buzz channels list` on the VM, as jibot, shows `security-feed` and `security-critical`, both `stream`, `open`, with the descriptions in the brief.
2. `buzz channels members --channel <id>` shows Joi's relay identity `18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29` with role `owner` on both.
3. `/home/relay/bin/buzz-send` exists, mode 700, byte-identical to `ops/vm/buzz-send` (sha256 match), and `printf '%s' '<text>' | buzz-send messages send --channel <feed> --content -` returns exit 0 and an event id.
4. The one setup message, text exactly `channel check from jibot (setup, not an alert) - Jibot`, is deleted with `buzz messages delete` (exit 0), and a later complete-window `buzz messages get` on the feed (see Proof message) does not list it.
5. A member can read both channels: `buzz messages get --channel <id>` as jibot exits 0 on each (jibot's key; a read as Joi needs Joi's nsec, which this session does not use; see Assumptions).
6. `spec/channels.json` is `{"feed": "<uuid>", "critical": "<uuid>"}`; `tests/test_channels.py` asserts both are canonical UUIDs and distinct; `scripts/test-gate.sh` passes.
7. `tests/test_buzz_send.py` exercises the wrapper with a stub CLI: the key reaches the child only in `BUZZ_PRIVATE_KEY`, never argv; `BUZZ_RELAY_URL` is pinned; stdin, arguments and exit status pass through; a missing, empty, non-regular (FIFO, directory), shape-malformed, bad-checksum or out-of-range key file fails closed without starting the CLI and without echoing the file.
8. `ops/vm/README.md` documents what is on the VM, how it was made, how to recreate it; the root README Status says whether writes on `security-critical` can be restricted.

## Approach

### Channels (live state, approved in the design, Joi 2026-11-05)

One SSH session to `relay-vm.example` runs a script fed on stdin. On the remote side it exports `BUZZ_PRIVATE_KEY="$(cat ~/.buzz-keys/agent.nsec)"` and `BUZZ_RELAY_URL=https://buzz.ai-tools.md`, then:

- `buzz channels list` first; if a channel named `security-feed` or `security-critical` already exists, stop (no duplicate, no change to another channel).
- `buzz channels create --name security-feed --type stream --visibility open --description "Security alerts for people running AI agents: a daily digest and real-time highs. Agents: parse the aitools-alert block."`
- `buzz channels create --name security-critical --type stream --visibility open --description "Fix-now alerts only. A post here also interrupts your agent."`
- `buzz channels add-member --channel <id> --pubkey 18eafd07… --role owner` on each.
- `buzz channels members` and `buzz channels get` on each, output kept for the issue.

No `--template` (it resolves desktop templates). Only the JSON stdout comes back to this Mac; it carries ids and pubkeys, never key material.

### Write restriction on `#security-critical`

Probed on the VM's source (`crates/buzz-auth/src/access.rs` `check_write_access`, `crates/buzz-relay/src/handlers/ingest.rs` `check_channel_membership`, buzz at a5dbdf5e6): a write is allowed to any channel member OR to anyone on an `open` channel; no role gates posting, and the `guest` role ("read-only" in its doc comment) is not checked on ingest. Buzz cannot restrict writes on an open channel, and making it `private` would stop members from finding and joining it. So the channel stays open and the root README Status says, in one sentence, that only keys in the trust manifest are trusted by the CLI and anyone may reply.

### The wrapper `ops/vm/buzz-send`

Bash, `set -euo pipefail`, `umask 077`, never `set -x`.

- Key file: `${BUZZ_SEND_KEY_FILE:-/home/relay/.buzz-keys/agent.nsec}`; CLI: `${BUZZ_SEND_BUZZ:-/home/relay/buzz/target/release/buzz}`. The overrides exist for the tests; they give a caller nothing it lacks, since the only caller is `relayuser`, who can read the key file anyway.
- The key file must be a regular, readable file (`[ -f ] && [ -r ]`; a FIFO, directory or missing path fails before any read, so a read can never block). Read it with bash's `$(<file)` (no subprocess argv carries it), checking the read's status, and strip whitespace.
- Validate fully before the CLI runs: a shape check in bash (`^nsec1[02-9ac-hj-np-z]{58}$`, the bech32 alphabet, or 64 lowercase hex), then `python3 -I` with the key on **stdin** (never argv) checks the bech32 checksum, the `nsec` prefix, a 32-byte payload, and the scalar range `1 <= k < n` (secp256k1 order) for both forms. The checker prints nothing; only its exit status is read. On a missing, non-regular or empty file, a failed read, or any validation failure: one line on stderr in the CLI's JSON error shape naming the file path, never its contents, and exit 1, with the CLI never started. (python3 3.12 is on the VM; `aitools_alerts.nostr.nsec_to_hex` is the reference for the same checks, and the tests compare the two.)
- `export BUZZ_PRIVATE_KEY` and `export BUZZ_RELAY_URL=https://buzz.ai-tools.md` (overwriting whatever the caller set), unset `BUZZ_AUTH_TAG`, then `exec "$BUZZ" "$@"`. The key is in the child's environment, readable by the same uid via `/proc/<pid>/environ` only; it is never on argv, so `ps` does not show it.
- A `--private-key` argument from the caller is refused (exit 1): the wrapper's job is to be the key's only route, and a caller passing a key on argv defeats it. `--relay` is refused too, so the wrapper only ever authenticates to the pinned relay.

Installed at `/home/relay/bin/buzz-send`, mode 700, by `scp` of the repo file plus `chmod`, then verified by sha256 against the repo copy. Because review fixes and a rebase can change the file after that install, the ending re-checks the installed sha256 against `git show origin/main:ops/vm/buzz-send` after landing; on a mismatch it reinstalls and re-runs a no-post check (`buzz-send channels get --channel <feed>`, exit 0) — no second message.

### Proof message

`printf '%s' 'channel check from jibot (setup, not an alert) - Jibot' | /home/relay/bin/buzz-send messages send --channel <feed> --content -`; parse the event id from stdout; `buzz-send messages delete --event <id>`; then `buzz-send messages get --channel <feed> --since <send time - 60> --limit 200` must exit 0, return fewer than 200 rows (the CLI caps `get` at 200, so a full page could hide the event and fails the check) and not contain the id; the send time is the VM's `date +%s` taken just before the send. `buzz-send messages thread --channel <feed> --event <id>` is recorded as supporting evidence. The event id, the JSON field that carries it (for B4's transport), and the delete result go on the issue.

### Repo files

- `spec/channels.json`: `{"feed": "<uuid>", "critical": "<uuid>"}`, two-space JSON, trailing newline.
- `tests/test_channels.py`: load, assert exactly the two keys, `uuid.UUID(v)` round-trips to the same lowercase string, values differ.
- `tests/test_buzz_send.py`: runs `ops/vm/buzz-send` under `bash` with `BUZZ_SEND_BUZZ` pointing at a stub script in `tmp_path` that writes its argv, `BUZZ_PRIVATE_KEY`, `BUZZ_RELAY_URL` and stdin to files and exits with a chosen code. Test keys are generated per test (random bytes, nsec-encoded with `aitools_alerts.nostr`), never a real key.
- `ops/vm/README.md`: channels (names, UUIDs, type, visibility, descriptions, owners), the wrapper (path, mode, what it does, install and verify commands), the write-restriction finding, and the recreate procedure.
- `README.md` Status: E1 done line plus the one-sentence trust statement.

## Alternatives considered

- **`BUZZ_PRIVATE_KEY=$(cat …)` inline in each SSH command (plan B4's first draft).** The remote shell expands it, so it is not on the local argv, but every caller repeats the key-handling and a typo puts it on a remote argv. One wrapper is one place to get it right.
- **Reuse cell-fleet's `ops/buzz/acp-spike/buzz-send`.** It is a socket-activated signer that parses a NUL-framed grammar for an untrusted agent user on a cell. Here the caller is the key's own uid over SSH; a grammar would add parsing risk and nothing else. Kept as is in cell-fleet; not used.
- **A cell-fleet copy of the wrapper (plan E1 as written).** Dropped by the gr5b decision: one source of truth in this repo.
- **Making `#security-critical` private to restrict writes.** Private channels are invite-only, so members could not self-join to be interrupted. Rejected; the trust model rests on signatures checked against the manifest, not on who can post.
- **Granting Joi `admin` instead of `owner`.** The brief asks for owner; owner is what the ops-room channels use for Joi's identity.

## Blast radius and rollback

- Live relay: two new channels, two membership rows, one message created and deleted (a tombstone remains in the feed's history, which is the delete's normal effect). No other channel, no image, Caddy or compose change. Rollback: `buzz channels delete --channel <id>` on each (Joi or jibot as owner) and remove `/home/relay/bin/buzz-send`.
- Repo: new files only, plus the README Status line. Rollback: revert the commit.

## Assumptions

- Assumes: jibot's key on the VM is a relay member able to create open channels (it created the ops-room channels).
- Assumes: verifying a read as Joi needs Joi's nsec (`~/.buzz-keys/joi.nsec` is RETIRED per cell-fleet ops/buzz/README.md, and the live identity's key is Joi's); there is no safe read path as Joi from this session, so the read check runs as jibot, as the brief allows.
- Assumes: `buzz messages send` prints JSON with the event id; the field name is confirmed live and recorded for B4.

## Open questions

None blocking.
