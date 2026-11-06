# The relay VM: what this service keeps there

The ai-tools Buzz relay runs on `<relay-vm>` (user `<user>`) and answers at `https://buzz.ai-tools.md`. This repo owns the VM-side pieces of the alert service; the relay itself (image, Caddy, compose) belongs to cell-fleet `ops/buzz/` and this service changes none of it.

Created 2026-11-05 under jibot-code#wpbd.

## Channels

| key in `spec/channels.json` | name | UUID | type | visibility |
|---|---|---|---|---|
| `feed` | `security-feed` | `599adb9f-4f9f-4b19-aee3-66667c3293e8` | stream | open |
| `critical` | `security-critical` | `ac446e7a-1e2c-4d74-ac8d-9c16ecb3801b` | stream | open |

Descriptions:

- `security-feed`: "Security alerts for people running AI agents: a daily digest and real-time highs. Agents: parse the aitools-alert block."
- `security-critical`: "Fix-now alerts only. A post here also interrupts your agent."

Owners of both: jibot (`d4f04ff67b3fa209cefdce90ca6e07df8bcb1aea72b9d49f31935c55601839c1`, the creator) and Joi (`18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29`).

### Who can post

Buzz cannot restrict posting on a channel by role. A write is accepted from any channel member, or from any relay member on an `open` channel (`crates/buzz-auth/src/access.rs` `check_write_access`, `crates/buzz-relay/src/handlers/ingest.rs` `check_channel_membership`, buzz at `a5dbdf5e6`); no role gates posting, and the `guest` role is not checked on ingest. Every key must first be a relay member: the relay refuses AUTH from any other key (`restricted: not a relay member`), even one added to a channel (jibot-code#gs18, 2026-11-05). A new poster's key is added with `buzz-npub-add` and removed with `buzz-admin remove-member`. Making `security-critical` private would stop members from joining it. So both channels are open, anyone may reply, and trust comes from the CLI: it accepts an alert only when its signing key is in the trust manifest.

## `buzz-send`

`~/bin/buzz-send`, mode 700, owner `<user>`. Source: `ops/vm/buzz-send` in this repo; the installed file must be byte-identical.

It reads jibot's key from `~/.buzz-keys/agent.nsec`, checks it (regular file, nsec checksum and length or 64 hex, scalar in range), exports it as `BUZZ_PRIVATE_KEY` with `BUZZ_RELAY_URL=https://buzz.ai-tools.md`, clears `BUZZ_AUTH_TAG`, refuses `--private-key` and `--relay`, and execs `~/buzz/target/release/buzz` with the caller's arguments. The key is never on an argv. Message text goes on stdin:

```bash
printf '%s' "$text" | ssh <relay-vm> '~/bin/buzz-send' \
  messages send --channel <uuid> --content - [--reply-to <event id>]
```

`messages send` prints JSON; the new event's id is the `event_id` field, for example `{"accepted":true,"event_id":"<64 hex>","mention_pubkeys":[],"message":""}`.

Install or update, then verify:

```bash
scp ops/vm/buzz-send '<relay-vm>:bin/buzz-send.new'
ssh <relay-vm> 'chmod 700 ~/bin/buzz-send.new && mv -f ~/bin/buzz-send.new ~/bin/buzz-send && sha256sum ~/bin/buzz-send'
git show origin/main:ops/vm/buzz-send | shasum -a 256   # must match
ssh <relay-vm> '~/bin/buzz-send' channels get --channel 599adb9f-4f9f-4b19-aee3-66667c3293e8
```

## How the channels were made

Each block ran on the VM through `ssh <relay-vm> 'bash -s' < script`, so the key was read and exported on the remote side only:

```bash
B=~/buzz/target/release/buzz
BUZZ_PRIVATE_KEY="$(cat ~/.buzz-keys/agent.nsec)"; export BUZZ_PRIVATE_KEY
export BUZZ_RELAY_URL=https://buzz.ai-tools.md
$B channels create --name security-feed --type stream --visibility open \
  --description "Security alerts for people running AI agents: a daily digest and real-time highs. Agents: parse the aitools-alert block."
$B channels create --name security-critical --type stream --visibility open \
  --description "Fix-now alerts only. A post here also interrupts your agent."
$B channels add-member --channel <uuid> --pubkey 18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29 --role owner   # each channel
$B channels members --channel <uuid>
```

Do not use `--template`: it resolves desktop-app templates. The wrapper was then proved with one setup message to `security-feed` (event `8041594b112353003521718654d253ad787bf49465b932348086481b1d4881d4`), deleted with `buzz-send messages delete --event <id>`; the record is on jibot-code#wpbd.

## Recreating

1. Install `buzz-send` as above.
2. Check neither name exists. The listing must succeed and parse before its absence means anything; a failed listing is not permission to create:

   ```bash
   list="$(~/bin/buzz-send channels list --limit 500)" || { echo "listing failed; stop"; exit 1; }
   echo "$list" | jq -e 'type == "array"' >/dev/null || { echo "listing not a JSON array; stop"; exit 1; }
   echo "$list" | jq -e 'length < 500' >/dev/null || { echo "listing hit the 500 cap and may be truncated; stop"; exit 1; }
   echo "$list" | jq -e 'map(.name) | (index("security-feed") or index("security-critical")) | not' >/dev/null \
     || { echo "a security channel already exists; stop"; exit 1; }
   ```
3. Run the create and add-member commands above (through `buzz-send`, or with the remote-side key export).
4. New channels get new UUIDs: update `spec/channels.json`, this table, and tell the readers of `spec/channels.json` (the poster, the mirror exporter, the member CLI). Members must re-join.
5. To remove: `buzz-send channels delete --channel <uuid>` for each, and delete `~/bin/buzz-send`.

## The exporter copy

The mirror exporter on the VM runs from a pinned commit of this repo, never a clone the VM pulls. cell-fleet's `ops/buzz/compose-overlays/buzz-aitools/install-mirror.sh <dir>` ships `aitools_alerts/`, `mirror/`, `spec/` and `trust/` from a local directory as they are on disk, unpacks them into a new `~/.ai-tools-alerts.d/<id>`, and points the `~/ai-tools-alerts` symlink at it. It does not check git state, so give it a fresh export of the release, not a working checkout that may hold local edits:

```bash
d="$(mktemp -d)" && git -C <ai-tools-alerts checkout> archive v0.1.0 | tar -x -C "$d"
git -C <ai-tools-alerts checkout> rev-parse 'v0.1.0^{commit}'   # record this sha on the kata issue
./install-mirror.sh "$d"
```

The installer's `<id>` is a timestamp, so the recorded sha is the only note of what is deployed. The exporter publishes `trust/root.pub` from the deployed copy as `https://buzz.ai-tools.md/alerts/root.pub`, beside `manifest.json`, so a reader can compare the root with GitHub's.
