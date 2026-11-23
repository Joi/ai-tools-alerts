# Plan: the poster signs the checkpoint; the VM receives and publishes it

Spec: `docs/superpowers/specs/2026-11-23-nfm3-poster-checkpoint-design.md`. Kata: ai-tools-alerts#nfm3. Branch `nfm3-poster-checkpoint`, stacked on `6whv-reader-checkpoint`. Tests first in each chunk.

## Changes after the plan's review (these supersede the lines below where they differ)

- Owed entries are `{"id", "bytes", "since", "root"}` and are written by `signer.record_sent` from the send path (`Run.deliver`, the Japanese replies) at the acknowledgement, not collected in memory until the end of the run. `settle_owed` drops only ids present on the mirror and entries older than 72 hours; there is no count or byte cap and no eviction.
- `window` returns `None` when the must-list events (owed ids, the roots owed replies name, and for every eligible thread its root and curator replies) exceed the budget; the run then signs nothing and says `checkpoint=too-large`. Otherwise whole threads newest first fill what is left; a skipped thread whose listed events are all older than the 398-day line also gets its newest event listed. "Owed threads first" is replaced by listing the owed reply's recorded root.
- `read_key` opens with `O_NONBLOCK` as well as `O_NOFOLLOW`; a test gives it a FIFO with no writer under a timeout.
- `Config.check_paths` includes `checkpoint_key_file` and the owed file; tests give each collision and assert nothing was written.
- `next_seq(now, last_seq, published_seq)`: the poster also fetches the mirror's `checkpoint.json`; when it is signed by this key its number is a floor. Test: the counter ran ahead of the clock, the state file is lost, the published checkpoint supplies the floor.
- Exporter: `cap()` keeps the exact pinned events (the published checkpoint's unconditionally; the candidate's when the union fits), not "threads holding pinned ids"; the published checkpoint is the ordering floor whenever its own signature is valid, whichever key signed it. Tests: a pinned root whose thread grows past the count cap and past the byte cap; a key rotation with a candidate dated before the published checkpoint.
- Tests added to chunk 1: the mirror pull fails in the run that sent a post, and the run dies right after the acknowledgement: the next run's checkpoint lists the id; a run acknowledging 200 posts lists all of them or signs nothing; a newer thread of 990 small bot events does not push out an older thread's curator retraction; the salvaged old thread with its newest event keeps a fresh reader verified.

## Chunk 1: poster

Files: new `aitools_alerts/poster/signer.py`; `aitools_alerts/poster/inputs.py` (two config keys), `main.py` (collect acknowledged ids, call the signer at the end of `run`, `checkpoint-keygen`, the summary field), `transport.py` (`put`); `tests/poster/test_signer.py`, `tests/poster/test_transport.py`, `tests/poster/test_main.py`.

- [ ] `signer.py`, pure functions first, each with tests:
  - `read_key(path) -> str` (64 hex): refuses a path that is not absolute, a symlink, a non-regular file, an owner other than the running uid, any group or other permission bit, more than 200 bytes, anything `nostr.nsec_to_hex` or the hex check refuses. Opened with `O_NOFOLLOW`, and the checks run on the open descriptor (`fstat`), so the file checked is the file read. Error messages name the path, never the contents.
  - `keygen(path) -> npub`: `O_CREAT | O_EXCL`, mode 600, refuses an existing path; writes the nsec; returns the npub.
  - `load_owed(path)`, `save_owed(path, rec)`: `{"last_seq": int, "owed": [{"id", "bytes", "since"}]}`; a missing file is empty; a malformed one is treated as empty with a warning line (a lost count only raises `seq` to the clock; lost owed ids are the same as a lost state file, stated in the docstring).
  - `settle_owed(owed, sent, present, now)`: add `sent` (id, bytes), drop ids in `present`, drop entries older than 72 hours, cap at 90 ids and 200 KiB oldest first; returns the new list and the count dropped.
  - `window(events, manifest, owed, now) -> list[str]`: the spec's step 4. Uses `pull._thread_ref`, `pull._bound`, `manifest.role_of`; event size as the exporter measures it (compact JSON length + 1).
  - `next_seq(now, last_seq)`.
  - `sign(sec, manifest, ids, now, seq) -> dict` through `checkpoint.build_checkpoint`.
- [ ] `transport.put(kind, data: bytes, ssh=None, *, host, wrapper, timeout)`: argv `[wrapper, kind]`, `kind` must be `"checkpoint"`, `wrapper` must match the absolute-path pattern, same ssh options as `send`; returns `(ok, detail)` where ok needs exit 0 and a `{"stored": true}` line.
- [ ] `inputs.Config`: `checkpoint_key_file: Path | None`, `relay_put_wrapper: str | None`; `load_config` validates both (absolute path; the wrapper pattern); `owed_state` property.
- [ ] `main.Run`: `self.acked: list[tuple[str, int]]` appended where a send returns an id (`deliver`, the Japanese replies).
- [ ] `main.run`: after the translations, inside the ledger lock, `signer.run_checkpoint(config, now, acked, mirror_fetch, ssh, root)` wrapped so that no exception reaches the run's exit code; returns the summary token (`off`, `sent`, `failed`, `no-certificate`, `no-mirror`, `error`), and `owed_dropped=N` when not zero. `last_seq` is saved before the delivery.
- [ ] `main.main`: `checkpoint-keygen --config`.
- [ ] Tests, `tests/poster/test_signer.py`:
  - key file: each refusal above; the happy path for nsec and hex; `keygen` then `read_key`; `keygen` refuses an existing file; the key appears in no captured output and no argv seen by the fake ssh, across a whole run;
  - `window`: every case of the spec's success criteria for the window (whole threads newest first within 990; the 398-day edge; events dated after the signing time; the oversized thread skipped with root and curator replies salvaged and bot replies not; owed threads first; byte budget with large events);
  - `settle_owed`: add, clear on presence, 72-hour drop, the 90-id and byte caps;
  - `next_seq`: clock ahead of last; same second; clock behind last;
  - a run with throwaway keys (the `env` fixture of `tests/poster`, its in-memory mirror with a certificate naming the test checkpoint key): the fake ssh receives one `put` whose stdin loads, verifies under the certificate, lists every mirror event and the ids sent in the run; summary ends `checkpoint=sent`;
  - certificate choice: no certificate anywhere, a certificate for another key, an expired one: nothing is sent, `checkpoint=no-certificate`; a newer mirror certificate beats an older bundled one; a certificate for a new manifest on the mirror is used after the mirror's manifest changes;
  - the suppression attack over four runs (the mirror never shows the acknowledged post; the checkpoint of run 1 is dropped): runs 2 to 4 each list the owed id; a `checkpoint=True` reader pull of that mirror with run 4's checkpoint ends `mirror incomplete`; with the clock 73 hours on, the id is dropped and `owed_dropped=1` is in the summary;
  - a run without the config keys is byte-for-byte the summary it was plus `checkpoint=off`, and sends no extra ssh command;
  - a failing pull, a failing delivery and an exception inside the signer never change the run's exit code.
- [ ] Verify: `python3 -m pytest -q tests/poster`.

## Chunk 2: relay VM

Files: new `ops/vm/mirror-put`; `ops/vm/aitools-poster-shell`, `ops/vm/sudoers-aitools-poster`, `ops/vm/README.md`; `tests/test_mirror_put.py` (new), `tests/test_poster_shell.py`.

- [ ] `mirror-put`: `set +x; set -euo pipefail; umask 077`; exactly one argument `checkpoint`; reads stdin through `head -c 262145` into a temp file in the inbox directory (created mode 700); refuses over 262144 bytes; validates with `python3 -I -c` (one JSON object, exactly the seven NIP-01 keys, on stdin, nothing on argv); `mv -f` into place; prints `{"stored":true,"bytes":N}`; every refusal prints one JSON error line and exits 1, leaving the previous file. `BUZZ_SEND_`-style test overrides are not added: the inbox is `${HOME:?}/alerts-inbox`, and tests run it with `HOME` set to a temp directory.
- [ ] Guard: after the relay-user checks, branch on the argument count: 2 words and `argv[0] == /home/$RELAY_USER/bin/mirror-put` and `argv[1] == checkpoint` → `exec sudo -n -u "$RELAY_USER" -- "$PUT" checkpoint`; else the existing shape checks unchanged.
- [ ] sudoers: the exact command `/home/RELAY_USER/bin/mirror-put checkpoint` appended to the rule.
- [ ] `ops/vm/README.md`: the new file, its install and verify lines, the inbox directory, the exporter's new arguments.
- [ ] Tests: `mirror-put` (bash 4+, like the guard's tests): stores valid input atomically with mode 600 in a 700 directory; refuses oversize, empty, non-JSON, an array, an object with a missing or extra key, a second argument, another kind (`manifest`), no argument; a refusal leaves the previous file byte-identical; no temp file left behind. Guard: the new shape reaches a fake `mirror-put` with stdin intact; `mirror-put manifest`, `mirror-put checkpoint x`, `mirror-put` alone, another directory's `mirror-put`, and the existing refusal matrix all refused; `test_sudoers_reference_matches_the_guard` extended to the second command; `transport.put`'s argv passes the guard (as `remote_argv`'s does today).
- [ ] Verify: `python3 -m pytest -q tests/test_mirror_put.py tests/test_poster_shell.py tests/test_buzz_send.py`.

## Chunk 3: exporter and end to end

Files: `mirror/export_mirror.py`, `mirror/aitools-alerts-mirror.service`; `tests/mirror/test_export.py`, new `tests/test_end_to_end.py`.

- [ ] `export(..., checkpoint_key=None, inbox=None)` and the two CLI options. `publish_trust(...)`: the certificate check; the published checkpoint (from `out/checkpoint.json`, re-verified under the certificate, else ignored); the candidate; `cap(events, m, generated_at, pinned=ids)` keeps threads holding pinned ids first, measured against the caps, with the union-then-published fallback of the spec; the candidate is published when all its ids are exported; files written in the order manifest, root.pub, checkpoint-key.json, the event files, checkpoint.json, page and feeds. `summary_line` gains the checkpoint field.
- [ ] Unit file: `--checkpoint-key %h/ai-tools-alerts/trust/checkpoint-key.json --inbox %h/alerts-inbox`.
- [ ] Tests (`tests/mirror/test_export.py`): each refusal of the spec (other key, other manifest, dated ahead, older than published; certificate invalid, expired, for another manifest: not published, export goes on); held back while a listed event is not exported, published on the run it is; write order (the checkpoint file's mtime order, or a write log from a wrapped `write_atomic`); events pinned by a published checkpoint survive a cap that would drop them; two disjoint 990-event checkpoints (published stays, candidate waits, then published); without the options the output is byte-identical to today's for the same rows; the unit's ExecStart test with the new arguments, the certificate file absent (as on main before the rollout) and present.
- [ ] `tests/test_end_to_end.py`: poster run (throwaway keys, fake ssh that pipes into the real guard and `mirror-put` under bash 4+, skipped with a reason otherwise but with a pure-Python stand-in always run) → exporter with `--inbox` → `pull.fetch(..., checkpoint=True)` on the output reads verified and shows the alert; then a second alert: the poster's next checkpoint lists it as owed before the exporter has it, the exporter holds the checkpoint back for one run and publishes it on the next; a reader pulling between the two stays verified on the earlier checkpoint. The released v0.1.4 reader pulls the same output. The exporter's reader tests that piece 3 moved to the writers' pull return to the member pull where they now have a checkpoint.
- [ ] `README.md` ("For the fleet: the poster"), `CHANGELOG.md`.
- [ ] Verify: `python3 -m pytest -q`.

## Rollback

Revert the merge commit; on the VM reinstall the previous guard, sudoers file and unit and remove `mirror-put` (rollout issue). Without the two poster config keys and the exporter options, behaviour is today's.
