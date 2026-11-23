# Plan: the poster signs on the poster machine (ai-tools-alerts#vzc3)

Spec: `docs/superpowers/specs/2026-11-23-poster-signs-locally-design.md`. Rung: heavy.

Shell rule for every step and subagent: a multi-line script goes in a scratchpad file and is run as a file; `rm -rf` on a variable path is `"${var:?}"`; no secret on a command line or in output.

## Chunk A: the HTTPS sender

### A1. `aitools_alerts/poster/translate.py`
- [ ] `read_key(helper, runner=subprocess.run, *, name=KEY_NAME)`: the secret name becomes a parameter (validated `^[A-Z][A-Z0-9_]{0,63}$`), still passed only in the helper's environment; `_DROP_ENV` drops the named variable as well as `KEY_NAME`. Error texts stay generic ("key unavailable"), never the name's value.
- [ ] Existing translate tests' assertions pass unchanged; one new test: a custom name reaches the helper's environment and a stale copy of that variable is dropped.

### A2. `aitools_alerts/poster/transport.py` (rewrite)
- [ ] Constants: `MAX_CONTENT = schema.MAX_POST_CHARS`, `DEADLINE = 90` (whole send, wall clock), `CONNECT_TIMEOUT = 20`, `IO_TIMEOUT = 30` (per socket op), `MAX_RESPONSE = 64 KiB`, `MAX_STDERR = 2000`, `_UUID`, `_HEX64`.
- [ ] The send runs in a daemon thread joined with `DEADLINE` (as `translate.bounded`). One `threading.Lock` guards a two-field gate `{phase: "connecting" | "writing", cancelled: bool}`. The worker, after connect and before its first write, takes the lock: if `cancelled` it closes and returns without writing; else it sets `phase = "writing"` and releases. The caller at the deadline takes the lock: if `phase == "connecting"` it sets `cancelled = True` and returns `failed` (no byte can be written afterwards, whatever DNS or connect does later); if `"writing"` it returns `unknown`. An exception in the worker before the gate is `failed`, after it `unknown`. The connection is closed in a `finally` inside the worker. Test: a fake connect that blocks past the deadline, then completes, never writes.
- [ ] `check_send(channel_id, content, reply_to)`: the shape check `main` runs before marking pending (UUID channel, 64-hex reply or None, non-empty text within the cap and without NUL); raises ValueError. Replaces `remote_argv`.
- [ ] `message_event(channel_id, content, reply_to, *, created_at) -> dict` (unsigned): kind 9, tags `[["h", ch]]` plus `["e", reply_to, "", "reply"]` for a reply.
- [ ] `auth_header(sec_hex, url, body, *, created_at, nonce) -> str`: kind 27235, tags `[["u", url], ["method", "POST"], ["payload", sha256(body)], ["nonce", nonce]]`, content "", `Nostr ` + base64(JSON).
- [ ] `class Relay(url, key_source, *, expected_pubkey, connect=None, clock=time.time)`: `key_source()` returns the hex key or raises `KeyUnavailable`; read on first `send` and cached; derives the pubkey and compares it with `expected_pubkey` (mismatch: every send `failed`, message "relay key is not the manifest's relay-bot key"). `send(channel_id, content, reply_to) -> SendResult`.
  - connect phase (`http.client.HTTPSConnection(host, 443, timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())`, `.connect()`): any OSError/`ssl.SSLError`/`http.client.HTTPException` → `failed` (nothing sent).
  - request phase (`conn.sock.settimeout(IO_TIMEOUT)`, asserted on the fake socket; `request("POST", "/events", body, headers)`, `getresponse()`, read at most `MAX_RESPONSE+1`): timeout, reset, any exception → `unknown`.
  - classify `(status, body)` per the spec table (pure function `classify(status, body, event_id)`, tested directly): 200 + `accepted: true` + same id → ok (the deployed relay answers a resend of a stored event this way, message `duplicate:`); 200 + `accepted: false` with a message starting `duplicate` → ok with the local id; 200 + `accepted: false` otherwise → failed; any other 200 → unknown; 413 → refused; 400 with JSON `{"error": "invalid: ..."}` → refused; any other 400, 401, 403, 404, 429 → failed; anything else → unknown.
  - `SendResult(ok, event_id, exit_code=status or None, stderr=<short reason, never key material>, outcome, message)`; `message` for `refused` is the relay's reason, printable-only, at most 300 characters.
- [ ] The URL: `relay_url` is `https://<host>` (no path, port, userinfo, query); the NIP-98 `u` is `https://<host>/events`.

### A3. `aitools_alerts/poster/inputs.py`
- [ ] Remove `relay_ssh_host`, `relay_send_wrapper`, `_SSH_HOST`, `_WRAPPER` if unused elsewhere.
- [ ] Add `relay_url: str = "https://buzz.ai-tools.md"` (checked `^https://[a-z0-9.-]+$`) and `relay_key_secret: str | None = None` (`^[A-Z][A-Z0-9_]{0,63}$`).
- [ ] `check_relay()`: `relay_key_secret` and `secrets_helper` set, both shapes valid; message names the missing keys.
- [ ] A config that still carries `relay_ssh_host` or `relay_send_wrapper` gets a ConfigError naming them as retired (clearer than "unknown keys").

### A4. `aitools_alerts/poster/main.py`
- [ ] `Run(..., send, ...)` replaces `ssh`; `deliver` calls `transport.check_send(...)` where it called `remote_argv`, and `self.send(channel_id, text, reply_to)` where it called `transport.send`. `drain_ja` and the curator pass use the same path (check every `transport.` reference).
- [ ] `run(now, config, *, send=None, ...)`: `send` None builds `transport.Relay(config.relay_url, key_source, expected_pubkey=<relay-bot pubkey of pull.bundled_manifest()>)` where `key_source = lambda: translate.read_key(config.secrets_helper, name=config.relay_key_secret)`; no bundled manifest or no relay-bot key there → config error before the ledger opens.
- [ ] The stderr line for a non-ok send prints `r.stderr[-300:]`, which never holds key material (A2).

### A5. Tests
- [ ] `tests/poster/test_transport.py` rewritten: event shape (root and reply), NIP-98 header (decode, verify signature with `nostr.verify_event`, u/method/payload/nonce, created_at = clock), the event verifies and its id is the one returned; each `classify` row of the spec; connect failure → failed; failure after the write began → unknown; a stalled response and a dripped response end at the deadline as unknown (deadline shortened by monkeypatch); a 64 KiB+ body → unknown; key unavailable → failed and neither stderr nor the exception names the key; pubkey mismatch → failed; key read once per Relay; a fake connection records the request (no network).
- [ ] `tests/poster/test_main.py`: a 400 that is not the relay's `invalid:` JSON leaves the item for the next run, which sends it.
- [ ] `tests/poster/conftest.py`: `no_real_ssh` becomes a guard that makes `http.client.HTTPSConnection` raise in poster tests.
- [ ] `tests/poster/test_main.py`: `FakeSSH` → `FakeRelay(channel_id, text, reply_to)` returning `SendResult`s with the same queue words (ok, fail, unknown, refuse); `ssh` names → `relay`; config fixture uses `relay_key_secret`/`secrets_helper`; the two route tests at :1208 and :1237 become relay-config tests.
- [ ] `tests/poster/test_translate.py` and `tests/poster/test_live_replay.py` import `FakeSSH` from `test_main` and pass `ssh=`: migrate both to `FakeRelay`/`send=`, keeping every failure and retry assertion (A1's "translate tests unchanged" means their assertions, not their fixture names).
- [ ] `tests/poster/test_inputs.py`: the relay config tests for the new keys and the retired-key message.
- [ ] Remove `tests/test_buzz_send.py`, `tests/test_poster_shell.py` (their sources leave in B).

Acceptance A: `scripts/test-gate.sh` passes. Verification: `scripts/test-gate.sh`.

## Chunk B: docs and the retired VM route

- [ ] `git rm ops/vm/buzz-send ops/vm/aitools-poster-shell ops/vm/sudoers-aitools-poster ops/vm/sshd-match-aitools-poster.conf`.
- [ ] `ops/vm/README.md`: the poster does not log in to the VM and no alert-poster key is kept there; channel administration (`buzz channels ...`) runs on a machine that holds the key, with the key exported from the secrets helper in that shell only; "The poster's send-only route" section replaced by a short "Retired" note naming what was removed from the VM and when (dates filled at the live step, in a later docs commit only if needed). Keep the channel table, exporter section.
- [ ] `README.md:21`: the true statement per spec §6. `README.md:35`: drop "including the `buzz-send` wrapper". `README.md` "For the fleet: the poster": one paragraph on `relay_url`, `relay_key_secret`, `secrets_helper`, and that the poster signs locally.
- [ ] `CHANGELOG.md` Unreleased: one paragraph.
- [ ] `ops/vm/scan-for-poster-keys.py` (stdlib, imports `aitools_alerts.nostr` from the repo copy it runs beside, or a vendored minimal pubkey derivation; reads the manifest's poster pubkeys from a path argument) and `tests/test_scan_for_poster_keys.py`: a planted key in a plain file, a renamed file, a tar member and a tar inside a tar each fail; a non-manifest key passes; an unreadable file fails; output never contains the key.
- [ ] `scripts/public-scan.sh` passes (no host, VM, tailnet or home-path names).

Acceptance B: gate passes; `git grep -n -E 'relay_ssh_host|relay_send_wrapper|buzz-send|aitools-poster-shell|remote_argv|SSH_OPTIONS'` returns hits only in this allowlist: `aitools_alerts/poster/inputs.py` (the retired-key refusal), `tests/poster/test_inputs.py` and `tests/poster/test_main.py` (its tests), `tests/test_install_path.py` (the assertion that nothing of the route is installed), `README.md` (the line saying a config naming the retired keys is refused), `ops/vm/README.md` (the retired note), `CHANGELOG.md`, and `docs/` (history: `docs/plan.md`, `docs/superpowers/`). No `ssh` call remains in `aitools_alerts/poster/` (`git grep -n '"ssh"' aitools_alerts/poster` is empty).

## Live steps (after review, before merge; each gets a `notice:` comment)

1. Poster Mac: back up `~/.config/aitools-alerts-poster/config.toml` to `config.toml.bak-vzc3-<date>` and record the installed version's sha; edit the config (remove the two ssh keys; add `relay_key_secret`, keep `secrets_helper`); install the branch build as the existing install is made (`uv tool install --force <fresh git archive of the branch head>`; record the sha); dry check: `aitools-alerts-poster pending --config ...`. Before replacing anything, record the scheduled command's resolved path (`readlink` of `~/.local/bin/aitools-alerts-poster`), the mechanism (`uv tool`), and the installed sha. The proof is a scheduled (launchd) run that sends: its log line with a send counter above 0, the event id that run recorded (a ledger entry's channel id whose time is that run's, or the digest's id in the journal's digest record), and that event found in the mirror's `feed.json`, `nostr.verify_event` true and pubkey equal to the manifest's relay-bot key. Not a manual run.
2. jibot-code#7z60 lands (separate worktree, repoman), and its live step moves intake, invites and the `#buzz-tech` post to the relay-admin key.
3. VM, per spec step 3: the key's backup is the secrets store (no copy stays on the VM); delete the key files; delete (never rewrite) each VM backup tarball that holds the key once the off-VM backup host's pulled copy matches its `.sha256` (the pull has no `--delete`, so the off-VM backup host keeps the original); remove the route (named backups of `sshd_config` and the route files, which hold no secret); run the scan script (`ops/vm/scan-for-poster-keys.py`, added in chunk B: walks the given roots and nested tar members, derives pubkeys of nsec/64-hex candidates in memory, compares with `trust/manifest.json`, prints paths and counts only, exit 1 on a match or an unreadable path).
4. Merge the PR, reinstall from `main`, confirm the next hourly run, close vzc3 on the merge commit.

## Rollback

Before step 3: reinstall the previous poster with the recorded mechanism (`uv tool install --force` of a `git archive` of the recorded sha), restore `config.toml.bak-vzc3-<date>`, and check that `readlink ~/.local/bin/aitools-alerts-poster` is the recorded path and the next scheduled run sends.

After step 3 (the route and key are gone from the VM): this restores the vulnerability, so it is a last resort and README.md:21 must be reverted in the same change. Before step 3 removes anything, save named copies on the VM of `/etc/passwd`, `/etc/shadow` and `/etc/group` lines for `aitools-poster` (as text in `/root/vzc3-route-backup/`), its `authorized_keys`, `/etc/aitools-poster/relay-user`, the guard, the sudoers file, `sshd_config` and `~/bin/buzz-send`. Recovery: put the key file back from the secrets store first (`buzz-send` exits at once without it, so route test 3 needs it), re-create the user with `useradd` as `ops/vm/README.md` at the previous commit describes, restore those files with their modes and owners, `visudo -cf`, `sshd -t`, reload sshd, run that README's six route tests from the poster Mac, reinstall the previous poster and restore its config.
