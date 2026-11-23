# The poster signs on the poster machine (ai-tools-alerts#vzc3)

## Problem

`README.md:21` says someone who takes the relay machine can delay or hide alerts but cannot forge one. It is false today: the relay bot's secret key (the `relay-bot` key of the trust manifest) is a file in the relay user's home on the relay VM, and the poster's only send path is ssh to the VM, where `ops/vm/buzz-send` reads that file and runs the Buzz CLI. Whoever takes the VM can sign relay-bot criticals that interrupt every matching member (adversarial review, finding H1).

## What the relay requires (read from its source at the deployed commit)

- `POST https://<host>/events` takes one signed Nostr event as the JSON body, authorised by a NIP-98 header: `Authorization: Nostr <base64 of a kind 27235 event>` with tags `u` (the exact URL), `method` (`POST`), `payload` (sha256 hex of the exact body) and a nonce; `created_at` within 60 seconds of the relay's clock; each auth event id is accepted once (replay guard).
- The event's `pubkey` must equal the NIP-98 signer (`ingest.rs`: "event pubkey does not match authenticated identity"). So the poster signs both, with the same key.
- The signer must be a relay member (jibot is).
- The response is `{"event_id", "accepted", "message"}` with 200; a rejected event is 400 with the reason; auth failures 401/403; rate limits 429.
- A stream message is kind 9 with tags `["h", <channel uuid>]`, and a direct reply adds `["e", <parent id>, "", "reply"]` (`buzz-sdk` `build_message`, `thread_tags`). The poster only ever replies to a thread root, so a reply never needs the nested `root` + `reply` pair. Live events in the mirror have exactly these shapes.
- The CLI's mention preflight (an `@name` in the text becomes a `p` tag after a membership lookup) is the CLI's, not the relay's. Events the poster builds carry no `p` tags, so a bot post never pings anyone.

## Approach

1. `aitools_alerts/poster/transport.py` becomes an HTTPS sender. `Relay(key_hex, url)` signs a kind 9 event (`nostr.sign_event`) and a NIP-98 auth event over the exact body, and POSTs with `http.client` (standard library; certificate verification on; no redirect is followed). Outcomes keep their meaning:
   - `ok`: HTTP 200, `accepted: true`, and `event_id` equal to the id computed locally. `accepted: false` with a `duplicate` message also is `ok` with the local id, since the id is the signed event's hash and the relay already holds it.
   - `failed` (certainly not stored; next hour): the connection or TLS handshake failed before any byte of the request was sent; HTTP 401, 403, 404 or 429; HTTP 400 whose body is not the relay's JSON error or whose reason does not begin `invalid:` (a `restricted:` policy, a proxy's page); `accepted: false`; the key could not be read or is not the manifest's relay-bot key.
   - `refused` (this text never posts; withheld, ai-tools-alerts#8acj): HTTP 413, or HTTP 400 with the relay's JSON error `{"error": "invalid: ..."}`. At the deployed commit `a5dbdf5e6` every `invalid:` rejection in `ingest.rs` (25 sites) is about the event itself (its kind, tags, content or size), so resending it unchanged cannot succeed; the deployed relay has no write fence or other temporary condition reported as `invalid:`. Anything the poster cannot read as that exact shape is `failed`, never `refused`, so an unrecognised response cannot withhold an alert.
   - `unknown` (may be stored; a human resolves): any failure once the first byte of the request may have been written (timeout, reset, a partial write, a slow response past the deadline), any other status (5xx, 408), a 200 that does not parse or whose id differs from the local one.
   - Bounds: the connect step has a 20-second timeout; the whole send (connect, write, response) runs under one 90-second wall-clock deadline in a daemon thread, the pattern of `translate.bounded`, so a response dripped a byte at a time cannot outlive it and the ledger lock is released on time; the response body is read up to 64 KiB, more is `unknown`; the connection is closed in every path. The old ssh path's bound was 120 seconds per send.
2. The key: `relay_key_secret` in the config names a secret in the secrets helper (`secrets_helper`, already used for translation). It is read once per run, on the first send, with the helper pattern `translate.read_key` already uses (stdout pipe only, a read-only throwaway cache, never argv, file or log); `read_key` takes the secret name as a parameter. The poster derives the public key and refuses to send (outcome `failed`, message names no key material) unless it is the `relay-bot` key of the bundled trust manifest: a post from any other key would be dropped by every member's CLI anyway.
3. Config: `relay_ssh_host` and `relay_send_wrapper` are removed; `relay_url` (default `https://buzz.ai-tools.md`, `https://` only, host only) and `relay_key_secret` (required for `run`) are added; `run` requires `secrets_helper`. `pending` and `resolve` need neither, as before.
4. `main.Run` takes a `send(channel_id, text, reply_to) -> SendResult` callable instead of an ssh runner; `main.run` builds the real one. Every existing pre-send check stays (`transport.check_send` replaces `remote_argv` as the shape check).
5. The ssh route is retired: `ops/vm/buzz-send`, `aitools-poster-shell`, `sudoers-aitools-poster`, `sshd-match-aitools-poster.conf` and their tests leave the repo; `ops/vm/README.md` says the poster no longer touches the VM and how the channels are administered from a machine that holds the key.
6. `README.md:21` says what is true at merge: the bot's key is held on the poster machine and not on the relay machine, so taking the relay machine lets an attacker delay or hide alerts but not sign one; what the relay machine still controls (the mirror, and the root copy it serves until the third-origin issue lands) is named.

## Live sequence (operator steps, each with a `notice:` comment on vzc3)

1. Before merge, on the poster Mac: back up the poster config (named copy beside it), set `relay_url`, `relay_key_secret`, drop the two ssh keys, install the poster from this branch, and wait for a scheduled hourly run (launchd, not a manual command) that sends. The gate for step 3 is that run's summary line with a send (`roots`, `copies`, `replies`, `digest` or `ja` above 0), the event id that run recorded (the ledger entry's channel id written at that run's time, or the digest's id in the journal's digest record), and the same event verified in the mirror's `feed.json` (`nostr.verify_event`, pubkey the relay-bot key). A manual run is no substitute. If no scheduled run sends before the 09:00 Tokyo digest, the 09:20 run is the proof.
2. The VM's other uses of the same key (member intake `buzz-npub-add`, `buzz-invite-mint`, the `#buzz-tech` daily post) move to a separate relay-admin key that is not in the trust manifest: jibot-code#7z60, landed through repoman.
3. Then, on the VM, in this order:
   - The key's backup is the secrets store off the VM, already holding the same key (checked: it derives to the relay-bot pubkey). No copy of the key is kept on the VM in any form, including as a rollback copy.
   - Remove `~/.buzz-keys/agent.nsec`, `agent.sec.hex` (and the public-key files beside them).
   - Delete, never rewrite, every backup tarball under the VM's backup directory that holds the key (each nests `scaffolding.tar.gz` with `home/.buzz-keys`). Rewriting would break the backup's own `MANIFEST.txt` hashes and, through the next pull, replace the off-VM original. Before deleting each one, its pulled copy on the off-VM backup host must match the VM's `.sha256`. The pull is `rsync -az` with no `--delete` (cell-fleet `ops/buzz/the off-VM backup host/buzz-backup-pull.sh`), so deleting a VM copy leaves the off-VM backup host's original in place, untouched and complete. The next nightly backup, made after the key files are gone, holds no poster key.
   - Remove the `aitools-poster` route: the user and its home, `/etc/sudoers.d/aitools-poster`, `/etc/aitools-poster/`, `/usr/local/bin/aitools-poster-shell`, the sshd Match block (sshd_config backed up as a named copy, `sshd -t`, reload) and `~/bin/buzz-send`. These hold no secret, so their named backups stay on the VM.
   - Verify with a scan script run on the VM: every regular file under the relay user's home, `/etc`, `/root` and `/usr/local`, and every member of every tar archive found there (recursing into nested archives), is searched for strings shaped like a Nostr secret (`nsec1…` bech32 or 64 hex at a token boundary); each candidate's public key is derived in memory and compared with the trust manifest's posters. Nothing is printed but paths and a count; any match, or any file or archive it cannot read, fails the check. The docker volumes (the database holds only public events) are out of scope and named as such.
4. Merge, reinstall the poster from `main`, confirm the next hourly run.

## Success criteria

- `scripts/test-gate.sh` passes; new tests cover each outcome above, the NIP-98 header (url, method, payload hash, created_at, kind, signer), the event shape (kind 9, `h` tag, reply tag), the pubkey check, key-read failures, and that the key never appears in a result, stderr or exception text.
- One real hourly run on the poster Mac sends through the new path, and the event verifies in the mirror.
- After step 3, the scan script of step 3 exits 0 on the VM: no file or archive member there holds a secret whose public key is a trust-manifest key.
- Tests cover a stalled and a slowly dripped response (the deadline ends the send as `unknown`), a failure after the request write began (`unknown`, never `failed`), and that a 400 the poster cannot read as the relay's `invalid:` error is `failed` and the item is sent again by the next run.
- `README.md` and `ops/vm/README.md` state nothing that is false at the merge commit.

## Alternatives considered

- Keep ssh and send a pre-signed event through a VM-side forwarder: the forwarder still needs a NIP-98 header signed by the event's author, so the poster signs it anyway; the hop adds a moving part and a VM account for nothing.
- A new alerts-only key in a re-signed manifest, leaving jibot's key on the VM: removing jibot from the manifest drops every past jibot thread from members' clients (`pull._filter` keeps only current keys), and the root key is the trust anchor; not worth spending here.
- Resolve `unknown` sends automatically by querying the relay for the locally known event id: useful, but a separate change to the pending/resolve flow; filed as a follow-up.

## Blast radius and rollback

The poster's send path changes completely. A bug shows as `failed` or `unknown` sends in the hourly summary; `unknown` stops further sends until resolved, as today. Rollback before step 3: reinstall the previous poster and restore the config backup; the ssh route still exists. After step 3 the route is gone; rollback is restoring the route from its named backups on the VM and the key from the secrets store, which a rollback would put back on the VM and so undo the fix (README.md:21 then has to change back too).

## Assumes

- The poster Mac reaches `https://buzz.ai-tools.md` directly (members' clients do; checked from the fleet).
- The relay's clock and the poster Mac's are within 60 seconds (both NTP).
