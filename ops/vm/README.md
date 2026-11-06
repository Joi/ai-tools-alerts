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

## The poster's send-only route

The poster does not use the relay user's ssh key or shell. It logs in as a separate Unix user, `aitools-poster`, whose login shell is a guard that runs one command shape and nothing else, so a compromised poster Mac can post messages as jibot but cannot delete channels, add members or read the key (ai-tools-alerts#w75s). Sources of truth, all in `ops/vm/`:

| file | installed at | mode |
|---|---|---|
| `aitools-poster-shell` | `/usr/local/bin/aitools-poster-shell` | 755, root |
| `sudoers-aitools-poster` | `/etc/sudoers.d/aitools-poster` | 440, root |
| `sshd-match-aitools-poster.conf` | appended to `/etc/ssh/sshd_config` | — |

sshd runs a login shell as `<shell> -c "<client command>"`. The guard refuses a login with no `-c` (interactive), splits the command with `shlex`, allows only `/home/<user>/bin/buzz-send messages send --channel <uuid> --content - [--reply-to <64 hex>]` (the argv `aitools_alerts.poster.transport.remote_argv` builds), and runs it as `<user>` through `sudo -n`. The key file stays readable by `<user>` alone. The guard refuses when python3's split fails at any point, and reads the arguments NUL-delimited so a quoted newline cannot rebuild an allowed shape; it needs bash 4.4 or later (`lastpipe`, `mapfile -d`).

The route is the VM's own OpenSSH on its private network address. The provider's public ssh name is an edge that admits keys from the account's key list and ignores per-VM `authorized_keys` options, so it is not this route.

### Install

On the VM, as root, with `<user>` the relay's login user:

1. `useradd --create-home --shell /usr/local/bin/aitools-poster-shell aitools-poster`; leave the password locked.
2. Install the guard with its one line `RELAY_USER="RELAY_USER"` set to `<user>` (`sed 's/^RELAY_USER="RELAY_USER"$/RELAY_USER="<user>"/'`; a global replace breaks it), then `install -o root -g root -m 755`.
3. Write the sudoers file with every `RELAY_USER` replaced, run `visudo -cf <file>`, then `install -o root -g root -m 440` it into `/etc/sudoers.d/`.
4. Back up `sshd_config`, append the Match block at the end, run `sshd -t`, and reload sshd only when it passes.
5. Before any key is authorized, check the effective policy. `sshd -T -C user=aitools-poster,host=<poster>,addr=<poster address>` must print `authorizedkeysfile /home/aitools-poster/.ssh/authorized_keys`, `allowtcpforwarding no`, `allowagentforwarding no`, `x11forwarding no`, `permittty no`, `permittunnel no`, `allowstreamlocalforwarding no`, `disableforwarding yes`, `permituserrc no`, `permituserenvironment no`, `forcecommand none`, an `acceptenv` of `LANG LC_*` at most, and no `subsystem ... internal-sftp` (an in-process subsystem never runs the login shell; an accepted `BASH_ENV` would run code before the guard). `sudo -l -U aitools-poster` must list only the one rule, `sudo -V` must show `env_reset` with no `HOME` or `BUZZ_*` kept, and `grep -r Defaults /etc/sudoers /etc/sudoers.d` must show no line for `aitools-poster`, `<user>` or `buzz-send`. If any of these differs, stop.
6. `~aitools-poster/.ssh/authorized_keys`, one line: `restrict ssh-ed25519 <poster public key> aitools-alerts-poster`. The file is owned by root, mode 644; `.ssh` and the home directory `/home/aitools-poster` are owned by root, mode 755 (`chown root:root`, then `chmod`). Root ownership means the poster user cannot edit the file to drop `restrict`, and with the home directory root-owned it cannot rename `.ssh` aside and put its own in place: sshd's StrictModes accepts a path owned by root or by the user, so owning the file alone does not stop that swap. The guard writes nothing to the home directory. `restrict` stays required: it and the Match block each close forwarding and `~/.ssh/rc`, so one mistake in either leaves the other.

On the poster Mac, a key of its own (`ssh-keygen -t ed25519 -N '' -f ~/.ssh/aitools_alerts_poster`, no passphrase because launchd runs the poster) and an ssh alias:

```
Host <poster-alias>
    HostName <VM private address>
    User aitools-poster
    IdentityFile ~/.ssh/aitools_alerts_poster
    IdentitiesOnly yes
```

The poster config then sets `relay_ssh_host = "<poster-alias>"` and `relay_send_wrapper = "/home/<user>/bin/buzz-send"`, the absolute path, since the guard compares the program exactly.

### Test after every install

From the poster Mac, each with `-v` and `-o ConnectTimeout=20`. Tests 1 to 5 count only when the same output shows `Authenticated to ... using "publickey"` with the poster key, so it is the guard or sshd refusing and not a failed login:

1. A shell command is refused: `ssh <poster-alias> ls` prints `refused: argument count 1`.
2. An interactive login is refused: `ssh <poster-alias>` prints `PTY allocation request failed` and `refused: interactive login`.
3. The allowed shape reaches the relay: `printf x | ssh <poster-alias> /home/<user>/bin/buzz-send messages send --channel 00000000-0000-0000-0000-000000000000 --content -` returns the relay's `not a channel member` error, which shows the guard, sudo, the wrapper and the key all ran.
4. Forwarding is denied in both directions: with `ssh -N -L 9999:127.0.0.1:22 <poster-alias>` running, `nc 127.0.0.1 9999` makes ssh print `administratively prohibited`; `ssh -N -o ExitOnForwardFailure=yes -R 9999:127.0.0.1:22 <poster-alias>` exits with `remote port forwarding failed`, and so does a remote Unix-socket forward, `-R /tmp/aitools-poster-test.sock:127.0.0.1:22`.
5. sftp is refused: `sftp <poster-alias>` ends with `Connection closed`: sshd ran the sftp-server command through the guard, which refused it (`refused: argument count 1`).
6. Other users are denied the key (the one test with no login): `ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey -i ~/.ssh/aitools_alerts_poster <user>@<VM private address> true` fails with `Permission denied (publickey)`, and `-v` shows the key offered and no `Authenticated to`.

A test of one key must offer only that key. Without `-F /dev/null -o IdentitiesOnly=yes -i <key>`, ssh also offers the keys named in the ssh config and the agent, and the server may accept one of those; with `-v`, the line `Server accepts key: <file>` names the key that was used. A test on 2026-11-06 read a fleet key's login as the poster key's for this reason.
