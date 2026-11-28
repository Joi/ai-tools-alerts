# The relay VM: what this service keeps there

The ai-tools Buzz relay runs on `<relay-vm>` (user `<user>`) and answers at `https://buzz.ai-tools.md`. This repo owns the alert service's one VM-side piece, the mirror exporter; the relay itself (image, Caddy, compose) belongs to cell-fleet `ops/buzz/` and this service changes none of it.

Created 2026-11-05 under jibot-code#wpbd.

## Release files

Every file this page installs on the VM comes from a verified release, never from a working checkout or a branch. The pinned release is `v0.5.0`, commit `f6a545c1b88101050d7a874c2817c64e25834fda`, the same pin as the top-level README. Export it once and take every file below from `$rel`:

```bash
unset rel
c=<ai-tools-alerts checkout>
git -C "$c" fetch --tags origin &&
  git -C "$c" -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.5.0 &&   # the principal and fingerprint in the README
  test "$(git -C "$c" rev-parse 'v0.5.0^{commit}')" = f6a545c1b88101050d7a874c2817c64e25834fda &&
  d="$(mktemp -d)" && git -C "$c" archive -o "$d/release.tar" f6a545c1b88101050d7a874c2817c64e25834fda && tar -x -C "$d" -f "$d/release.tar" &&
  rm "$d/release.tar" && test -f "$d/mirror/export_mirror.py" && rel="$d" ||
  echo 'VERIFICATION FAILED: install nothing'
```

Every step is chained, so `$rel` is set only when the tag check, the commit check and the export all succeed; if it prints the failure line, or `echo "${rel:?}"` fails, install nothing. The steps below write `${rel:?}`, which stops a command when `$rel` is unset. `$rel` is a plain export with no `.git`, so local edits and untracked files in the checkout cannot reach it.

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

## No poster key on the VM

The poster signs every post on the poster machine and sends it to `https://buzz.ai-tools.md/events` itself (`aitools_alerts/poster/transport.py`); it does not log in to the VM. No key of the trust manifest (`trust/manifest.json`) is kept on the VM, in any file or backup (ai-tools-alerts#vzc3). The relay's own administration (member intake, invite links) uses a separate relay-admin key that is not in the manifest and so cannot sign an alert the CLI accepts.

To check, copy this repository to the VM and run, as a user that can read every path named:

```bash
python3 ops/vm/scan-for-poster-keys.py --manifest trust/manifest.json <relay user home> /etc /root /usr/local
```

It looks inside every file and every tar or gzip archive under those paths, archives inside archives included, for strings shaped like a Nostr secret key, derives each one's public key in memory and compares it with the manifest's posters. It prints paths and counts only. Exit 0 means no poster key was found and every path was read; exit 1 means a key was found or a path could not be read. The database volume holds only signed public events and is not scanned.

Toolchain trees on the VM carry upstream test fixtures the scan cannot open: deliberately corrupt archives and zstd samples. Each one fails the scan as `UNREAD`. To accept one, list its exact `UNREAD:` text in a file and pass `--allow-unread <file>`; the scan still prints it, as `ALLOWED UNREAD`, and every other unread path still fails. Only a path whose raw bytes were searched can be accepted, so a key stored in such a file in plain text is still found; a file too large or unreadable, a walk error and a missing root always fail. Each line must equal the unsanitized text: a `?` the scan prints for a control or non-ASCII byte matches nothing. Keep the list outside this repository, with the run's record.

## Channel administration

Channel changes (create, add a member, delete) are signed by a channel owner. jibot's key is held on the poster machine, not the VM, so run the Buzz CLI on that machine, with the key exported from the secrets helper in that shell only and never on a command line:

```bash
BUZZ_PRIVATE_KEY="$(get_secret <relay key secret name>)" BUZZ_RELAY_URL=https://buzz.ai-tools.md \
  buzz channels get --channel 599adb9f-4f9f-4b19-aee3-66667c3293e8
```

Joi's curator key is the other owner of both channels.

## How the channels were made

On 2026-11-05, with jibot's key (the record is on jibot-code#wpbd):

```bash
buzz channels create --name security-feed --type stream --visibility open \
  --description "Security alerts for people running AI agents: a daily digest and real-time highs. Agents: parse the aitools-alert block."
buzz channels create --name security-critical --type stream --visibility open \
  --description "Fix-now alerts only. A post here also interrupts your agent."
buzz channels add-member --channel <uuid> --pubkey 18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29 --role owner   # each channel
buzz channels members --channel <uuid>
```

Do not use `--template`: it resolves desktop-app templates.

## Recreating

1. Check neither name exists. The listing must succeed and parse before its absence means anything; a failed listing is not permission to create:

   ```bash
   list="$(buzz channels list --limit 500)" || { echo "listing failed; stop"; exit 1; }
   echo "$list" | jq -e 'type == "array"' >/dev/null || { echo "listing not a JSON array; stop"; exit 1; }
   echo "$list" | jq -e 'length < 500' >/dev/null || { echo "listing hit the 500 cap and may be truncated; stop"; exit 1; }
   echo "$list" | jq -e 'map(.name) | (index("security-feed") or index("security-critical")) | not' >/dev/null \
     || { echo "a security channel already exists; stop"; exit 1; }
   ```
2. Run the create and add-member commands above.
3. New channels get new UUIDs: update `spec/channels.json`, this table, and tell the readers of `spec/channels.json` (the poster, the mirror exporter, the member CLI). Members must re-join.
4. To remove: `buzz channels delete --channel <uuid>` for each.

## The exporter copy

The mirror exporter on the VM runs from a pinned commit of this repo, never a clone the VM pulls. cell-fleet's `ops/buzz/compose-overlays/buzz-aitools/install-mirror.sh <dir>` ships `aitools_alerts/`, `mirror/`, `spec/` and `trust/` from a local directory as they are on disk, unpacks them into a new `~/.ai-tools-alerts.d/<id>`, and points the `~/ai-tools-alerts` symlink at it. It does not check git state, so give it the verified export from Release files (above), not a working checkout that may hold local edits:

```bash
./install-mirror.sh "${rel:?}"   # record f6a545c1b88101050d7a874c2817c64e25834fda on the kata issue
```

The installer's `<id>` is a timestamp, so the recorded sha is the only note of what is deployed. The exporter publishes `trust/root.pub` from the deployed copy as `https://buzz.ai-tools.md/alerts/root.pub`, beside `manifest.json`, so a reader can compare the root with GitHub's.

## The poster's ssh route: the checkpoint only

Until ai-tools-alerts#vzc3 the poster also sent each post through this route, as `~/bin/buzz-send messages send ...`, and `buzz-send` read jibot's key from a file in the relay user's home: whoever held the VM could read that key and sign alerts. Posts now go to the relay over HTTPS, signed on the poster machine (No poster key on the VM, above), and the send shape, `buzz-send` and the key files were removed from the VM after the HTTPS path had sent from a scheduled hourly run. Their files are in this repository's history before vzc3 (`ops/vm/buzz-send`).

What remains is a put-only route for the feed checkpoint (ai-tools-alerts#nfm3), a signed document the relay does not store. It holds no key. The vzc3 removal took the whole route off the VM; the checkpoint's rollout installs it again with the steps below.

The release pinned in Release files above (v0.5.0) carries this route, as v0.1.6, v0.1.7, v0.1.8, v0.2.0, v0.2.1, v0.3.0 and v0.4.0 did. Every release before v0.1.6 predates this route: v0.1.5's guard still allows the retired send shape and has no `mirror-put`. Take every file of this section from the `$rel` the Release files block sets. Before installing anything, check that export, and stop if either check fails:

```bash
test -f "${rel:?}/ops/vm/mirror-put" &&
  ! grep -q 'bin/buzz-send' "${rel:?}/ops/vm/aitools-poster-shell" &&
  ! grep -q 'buzz-send' "${rel:?}/ops/vm/sudoers-aitools-poster" &&
  echo 'checkpoint-only route files: ok' || echo 'WRONG RELEASE: install nothing'
```

The poster logs in as a separate Unix user, `aitools-poster`, whose login shell is a guard that runs one command shape and nothing else, so a compromised poster machine can replace the stored checkpoint (which the exporter publishes only when the checkpoint key signed it) but cannot post, delete channels, add members or read any key (ai-tools-alerts#w75s). Sources of truth, all in `ops/vm/` of the verified release (`${rel:?}/ops/vm/`, Release files, above); copy them to the VM from `$rel`, never from a checkout:

| file | installed at | mode |
|---|---|---|
| `aitools-poster-shell` | `/usr/local/bin/aitools-poster-shell` | 755, root |
| `sudoers-aitools-poster` | `/etc/sudoers.d/aitools-poster` | 440, root |
| `mirror-put` | `/home/<user>/bin/mirror-put` | 700, `<user>` |
| — (not tracked) | `/etc/aitools-poster/relay-user` | 644, root; directory 755, root |
| — (made by `mirror-put`) | `/home/<user>/alerts-inbox/` | 700, `<user>`; `checkpoint.json` 600 |
| `sshd-match-aitools-poster.conf` | appended to the sshd config the VM's listener reads | — |

sshd runs a login shell as `<shell> -c "<client command>"`. The guard refuses a login with no `-c` (interactive), splits the command with `shlex`, allows only `/home/<user>/bin/mirror-put checkpoint` (the argv `aitools_alerts.poster.transport.put` builds), and runs it as `<user>` through `sudo -n`. `<user>` is the one line of `/etc/aitools-poster/relay-user`, which the VM's operator writes and the repo does not track, because this public repo does not name the relay's login user; the guard refuses every command when that file is missing, empty, longer than one line, or not a plain user name (`^[a-z_][a-z0-9_-]{0,31}$`), and reads no environment variable for it. The guard refuses when python3's split fails at any point, and reads the arguments NUL-delimited so a quoted newline cannot rebuild an allowed shape; it needs bash 4.4 or later (`lastpipe`, `mapfile -d`).

The route is the VM's own OpenSSH on its private network address. The provider's public ssh name is an edge that admits keys from the account's key list and ignores per-VM `authorized_keys` options, so it is not this route.

### Install

On the VM, as root, with `<user>` the relay's login user:

1. `useradd --create-home --shell /usr/local/bin/aitools-poster-shell aitools-poster`; leave the password locked.
2. Write the relay user file: `install -d -o root -g root -m 755 /etc/aitools-poster`, then `printf '%s\n' <user> > /etc/aitools-poster/relay-user`, `chown root:root` and `chmod 644` it. Root ownership keeps the poster user from naming another sudo target. Install the guard as a plain copy of the release's file, copied over from `${rel:?}/ops/vm/aitools-poster-shell`: `install -o root -g root -m 755 aitools-poster-shell /usr/local/bin/`, then check that `sha256sum /usr/local/bin/aitools-poster-shell`, run on the VM, matches `shasum -a 256 "${rel:?}/ops/vm/aitools-poster-shell"`, run where `$rel` is.
3. Write the sudoers file from `${rel:?}/ops/vm/sudoers-aitools-poster` with every `RELAY_USER` replaced, run `visudo -cf <file>`, then `install -o root -g root -m 440` it into `/etc/sudoers.d/`.
4. Back up the sshd config, append the Match block from `${rel:?}/ops/vm/sshd-match-aitools-poster.conf` at the end, run `sshd -t`, and reload sshd only when it passes.
5. Before any key is authorized, check the effective policy. `sshd -T -C user=aitools-poster,host=<poster>,addr=<poster address>` must print `authorizedkeysfile /home/aitools-poster/.ssh/authorized_keys`, `allowtcpforwarding no`, `allowagentforwarding no`, `x11forwarding no`, `permittty no`, `permittunnel no`, `allowstreamlocalforwarding no`, `disableforwarding yes`, `permituserrc no`, `permituserenvironment no`, `forcecommand none`, an `acceptenv` of `LANG LC_*` at most, and no `subsystem ... internal-sftp` (an in-process subsystem never runs the login shell; an accepted `BASH_ENV` would run code before the guard). `sudo -l -U aitools-poster` must list only the one rule, `sudo -V` must show `env_reset` with no `HOME` or `BUZZ_*` kept, and `grep -r Defaults /etc/sudoers /etc/sudoers.d` must show no line for `aitools-poster`, `<user>` or `mirror-put`. If any of these differs, stop.
6. `~aitools-poster/.ssh/authorized_keys`, one line: `restrict ssh-ed25519 <poster public key> aitools-alerts-poster`. The file is owned by root, mode 644; `.ssh` and the home directory `/home/aitools-poster` are owned by root, mode 755 (`chown root:root`, then `chmod`). Root ownership means the poster user cannot edit the file to drop `restrict`, and with the home directory root-owned it cannot rename `.ssh` aside and put its own in place: sshd's StrictModes accepts a path owned by root or by the user, so owning the file alone does not stop that swap. The guard writes nothing to the home directory. `restrict` stays required: it and the Match block each close forwarding and `~/.ssh/rc`, so one mistake in either leaves the other.
7. Install `mirror-put` from `${rel:?}/ops/vm/mirror-put`: `install -o <user> -g <user> -m 700 mirror-put /home/<user>/bin/`, and compare its `sha256sum` with the release's.
8. Install the exporter copy from the same release ("The exporter copy"), whose unit passes `--checkpoint-key %h/ai-tools-alerts/trust/checkpoint-key.json --inbox %h/alerts-inbox`. Until `trust/checkpoint-key.json` exists in the deployed copy, the exporter publishes neither new file and behaves as before.

On the poster machine, a key of its own (`ssh-keygen -t ed25519 -N '' -f ~/.ssh/aitools_alerts_poster`, no passphrase because launchd runs the poster) and an ssh alias:

```
Host <poster-alias>
    HostName <VM private address>
    User aitools-poster
    IdentityFile ~/.ssh/aitools_alerts_poster
    IdentitiesOnly yes
```

The poster config then sets three keys together (any one without the others is a config error and the poster does not run): `checkpoint_key_file = "<absolute path>"`, `relay_ssh_host = "<poster-alias>"` and `relay_put_wrapper = "/home/<user>/bin/mirror-put"`, the absolute path, since the guard compares the program exactly. Then run `aitools-alerts-poster checkpoint-keygen --config <toml>`, which creates the key file and the poster's record of owed posts and prints the npub; the trust root then signs the certificate for that npub (`scripts/sign-checkpoint-key.py`), and it is landed as `trust/checkpoint-key.json` and deployed with the exporter copy. Until the certificate is served the poster's summary line ends `checkpoint=no-certificate`. The full order, with the release steps around it, is in the rollout issue for this feature.

### Checkpoint checks

Checks, from the poster machine, after the install:

- `printf '[]' | ssh <poster-alias> /home/<user>/bin/mirror-put checkpoint` prints `mirror-put: not one JSON event object` and exits 1: the guard, sudo and the script ran, and nothing was stored.
- `ssh <poster-alias> /home/<user>/bin/mirror-put manifest` prints `refused: argument 2`: the guard allows the one word only.
- After the poster's next run, the exporter's journal line ends `checkpoint=published seq <n>`, and the mirror serves `checkpoint-key.json` and `checkpoint.json`.

What the poster's ssh key can do on the VM: replace `~/alerts-inbox/checkpoint.json` with other bytes. The exporter publishes those bytes only if the checkpoint key signed them.

### Test after every install

From the poster Mac, each with `-v` and `-o ConnectTimeout=20`. Tests 1 to 5 count only when the same output shows `Authenticated to ... using "publickey"` with the poster key, so it is the guard or sshd refusing and not a failed login:

1. A shell command is refused: `ssh <poster-alias> ls` prints `refused: argument count 1`.
2. An interactive login is refused: `ssh <poster-alias>` prints `PTY allocation request failed` and `refused: interactive login`.
3. The retired send shape is refused: `printf x | ssh <poster-alias> /home/<user>/bin/buzz-send messages send --channel 00000000-0000-0000-0000-000000000000 --content -` prints `refused: argument count 7`.
4. Forwarding is denied in both directions: with `ssh -N -L 9999:127.0.0.1:22 <poster-alias>` running, `nc 127.0.0.1 9999` makes ssh print `administratively prohibited`; `ssh -N -o ExitOnForwardFailure=yes -R 9999:127.0.0.1:22 <poster-alias>` exits with `remote port forwarding failed`, and so does a remote Unix-socket forward, `-R /tmp/aitools-poster-test.sock:127.0.0.1:22`.
5. sftp is refused: `sftp <poster-alias>` ends with `Connection closed`: sshd ran the sftp-server command through the guard, which refused it (`refused: argument count 1`).
6. Other users are denied the key (the one test with no login): `ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey -i ~/.ssh/aitools_alerts_poster <user>@<VM private address> true` fails with `Permission denied (publickey)`, and `-v` shows the key offered and no `Authenticated to`.

A test of one key must offer only that key. Without `-F /dev/null -o IdentitiesOnly=yes -i <key>`, ssh also offers the keys named in the ssh config and the agent, and the server may accept one of those; with `-v`, the line `Server accepts key: <file>` names the key that was used. A test on 2026-11-06 read a fleet key's login as the poster key's for this reason.
