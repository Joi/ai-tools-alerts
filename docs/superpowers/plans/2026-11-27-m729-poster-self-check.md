# Plan: the poster checks its own key (ai-tools-alerts#m729)

Spec: `docs/superpowers/specs/2026-11-27-m729-poster-self-check-design.md`. One branch, one pull request. Two chunks; the second is text only.

Line numbers are those of `dd4d195` (main when the branch was cut).

## Chunk 1: the sent record and the check

### Task 1.1: `aitools_alerts/poster/sent.py` (new) and `tests/poster/test_sent.py` (new)

- [ ] Record `{"since": None, "ids": {}, "foreign": {}, "said": []}`; `MAX_SAID = 200`; read limit 64 MiB.
- [ ] `_locked(path)`: a context manager holding `fcntl.LOCK_EX` on `<path>.lock` (created mode 600). Every function that writes reads the record inside it.
- [ ] `load(path) -> dict`: the record, or an empty one when the file is missing, unreadable, not JSON or of another shape (keys exactly the four; ids 64 hex; times ints; `since` int or None; `said` a list of 64 hex). Unreadable or malformed says one stderr line (`aitools-alerts-poster: sent record <path> is unreadable; started again`); missing says nothing.
- [ ] `note(path, event_id, now)`: add one id (64 hex, else nothing) and write (`state.write_json`), only when the id is new. Raises OSError.
- [ ] `holds(path, attempted_at) -> set | None`: the recorded ids when the record is started and `attempted_at >= since`; else None (the caller then matches by text).
- [ ] `check(path, events, m, now, adopt=None, channels=None) -> set`:
  - `bots`: ids of `events` with `manifest.role_of(m, pubkey) == "relay-bot"` and `pull._bound(ev, channels or pull.channel_ids())`.
  - `since is None`: with `adopt is None` return `set()` and write nothing; else add every id of `adopt` at `now`, set `since = now`, say `sent record <path>: started with N ids (the served checkpoint, the ledger, the owed list)`.
  - `foreign = bots - ids`; `rec["foreign"] = {i: old.get(i, now)}`; `said` keeps only ids still foreign. `ids` is never pruned.
  - Write only when the record changed; an OSError (the lock or the write) is said on stderr and the computed set is still returned.
- [ ] `unsaid(path) -> list`: sorted ids of `foreign` not in `ids` and not in `said`, at most `MAX_SAID`.
- [ ] `mark_said(path, ids)`: add to `said` those still in `foreign`. Raises OSError.
- [ ] Tests (`tests/poster/test_sent.py`, on a `Mirror` and a tmp path): the start takes `adopt` only (a relay-bot event on the mirror and not in `adopt` is foreign at once); nothing judged or written before it; a curator's event and one bound to another channel never foreign; `note` ends it; first-seen time kept; `said` dropped when the event is recorded or leaves `events`; an id 500 days old and not on the mirror is still in `ids`; a damaged file and one of another shape start again from `adopt`; a failed write returns the set; two processes noting 50 ids each lose none (`multiprocessing`, or two threads with the lock taken through separate file descriptors).

Verify: `python3 -m pytest tests/poster/test_sent.py -q`.

### Task 1.2: config, journal shape, transport

- [ ] `inputs.py`: `Config.sent_state` (`<ledger>.sent.json`) after `owed_state` (line 162); add it to the file lists of `check_paths` (line 192) and `check_catalog_paths` (line 210) and to the error text.
- [ ] `inputs.py` line 478: the digest item's `adv` may carry `foreign`: a non-empty list of at most 200 distinct 64-hex strings (`set(adv) - {"week", "dropped", "foreign"}`).
- [ ] `transport.py`: `Relay.__init__(..., on_signed=None)`. In `Relay.send`, after signing and before `_post`: when `on_signed` is set, call it with `event["id"]`; any exception returns `SendResult(False, None, None, "the sent record could not be written", "failed")` and nothing is sent.
- [ ] `main.py` `relay_sender(config)` (line 2219): `on_signed=lambda eid: sent.note(config.sent_state, eid, int(time.time()))` when `config.checkpoint_key_file is not None`, else None.
- [ ] Tests: `test_signer.py::test_key_and_owed_files_join_the_path_collision_check` gains the sent record; `test_inputs.py`: a journal with a digest item carrying `foreign` loads, and one with a bad value is refused; `test_transport.py`: `on_signed` is called with the event's id before `connect`; when it raises, `connect` is never called and the outcome is `failed`; `relay_sender` with a checkpoint key writes the id to the sent record, and without one writes no file.

Verify: `python3 -m pytest tests/poster/test_inputs.py tests/poster/test_transport.py tests/poster/test_signer.py -q`.

### Task 1.3: the signer

- [ ] `ledger.py`: `Ledger.event_ids() -> set`: every root id, channel copy id and reply id of every entry (what `has_event` searches).
- [ ] `signer.run_checkpoint(..., known=frozenset())` (line 415). After the certificate is accepted and the served checkpoint is read (line 476): `adopt = {o["id"] for o in rec["owed"]} | set(known) | (set(cp.events) if this key signed the served checkpoint else set())`; `foreign = sent.check(config.sent_state, st.events.values(), m, now, adopt=adopt)`; `mine = {i: e for i, e in st.events.items() if i not in foreign}`.
- [ ] From there every read of the copy uses `mine`: `settle_gone(rec["gone"], mine, ...)` (line 486), the `present` set and `_later` of `settle_owed` (lines 495-496), `lapsed` (line 500), `window` (line 503).
- [ ] A full store: when the pull's error is `state limit reached: new events not stored` and a manifest is accepted under `root`, `foreign = sent.check(path, st.events.values(), m, now)` (no `adopt`); when any, drop them from the stored copy, save, and run `read_mirror` once more; then go on as usual (`no-mirror` when the error stands).
- [ ] The stored copy: at line 488-490, also drop `foreign - serving` (a foreign event the mirror no longer serves), in the same `st.accept` and `save_events`; when only that set is non-empty the save still happens.
- [ ] `listable` (line 498) also leaves out an owed entry whose `root` is in `foreign`.
- [ ] `suppress |= foreign` for `window` only: the `threads_suppressed` count is taken before, and `,foreign=N` is appended after it in the token.
- [ ] `main.py` `run` (line 2375): `known = led.event_ids() | set(state["digest_ids"]) | {it["sent"] for it in state["outbox"] + r._withheld_items() if it.get("sent")}`.
- [ ] Module docstring: replace "nor that the legitimate poster wrote an event signed by the bot key" with what now holds.
- [ ] Tests (`tests/poster/test_sent.py`, on the `signing` fixture and `PutRelay` of `test_signer.py`):
  - a foreign relay-bot root posted to the mirror after the first run is in no later checkpoint; the summary ends `,foreign=1`; the real alert beside it is listed; the token still starts `sent`;
  - a foreign reply (a `{"level":"notice"}` block) in a real relay-bot thread is left out, the root is listed;
  - a curator reply to a foreign root is not listed; an owed entry whose root is the foreign root is not listed;
  - a foreign renewal does not keep listed a claimed root whose real renewals have lapsed;
  - end to end: a member `State` pulls the mirror with that checkpoint stored (`_reader_pull` of `test_signer.py`); `pull.advisories` names the real alert and not the forged one, and the pull has no error;
  - the first run takes what the served checkpoint lists (a relay-bot event on the mirror, listed by the mirror's checkpoint: listed again, no `foreign=`); with the served checkpoint signed by another key, a relay-bot event neither owed nor in the ledger is foreign on the first run;
  - criterion 6: after a foreign event was left out, delete the sent record; the next run still leaves it out;
  - a foreign event removed from the mirror is gone from the poster's stored events after the next run;
  - with `pull.MAX_STORED_EVENTS` patched low and the store filled by foreign events, the run clears them, pulls again and signs (`checkpoint=sent`).
- [ ] Existing tests that put a relay-bot event on the mirror after a first run stand in for the poster's own post. Each records the id through one helper in `test_signer.py` (`as_sent(env, *events)`, a call of `sent.note`), next to the line that posts it. Expected in `test_signer.py`, `test_settle.py`, `test_translate.py`, `test_end_to_end.py`, `test_main.py`, `test_renew.py`; found by running the suite. No assertion of an existing test is weakened.

Verify: `python3 -m pytest tests/poster -q`.

### Task 1.4: the run

- [ ] `main.py` `Run._owed` (line 372): before `signer.record_sent`, `sent.note(self.config.sent_state, eid, self.now)`, in the same `try`: an OSError from either sets `owe_failed` and raises `LedgerError` (the message names the file that failed).
- [ ] `Run._delivery` (line 480): when `checkpoint_key_file` is set, `ids = sent.holds(path, min(p["at"], it.get("tried", p["at"])))`; when not None, keep only hits whose id is in it. An unreadable record gives None (text, as today).
- [ ] `Run.digest` (line 1902): after `_withdrawn` succeeded, when `checkpoint_key_file` is set: `st = State.load(mirror_dir)`, `sent.check(path, st.events_for(root).values(), st.accepted(root), self.now)` in a `try` that says any exception on stderr; then `foreign = sent.unsaid(path)` (its own `try`: an unreadable record gives none). Pass `foreign=bool(foreign)` to both `compose.digest` calls; `snap` gains `"foreign": foreign` when non-empty.
- [ ] `Run._record`, digest branch (line 926): when not replayed and `it["adv"].get("foreign")`, `sent.mark_said(...)`; an OSError is said on stderr.
- [ ] `compose.digest(..., foreign: bool = False)`: `_DIGEST[lang]["foreign"]`, its own paragraph after the withheld line and before the weekly summary, on the quiet path too.
- [ ] Tests:
  - settling by id: an unknown root send whose id is in the record; the mirror then holds that event and an earlier-dated copy of its text under another id; `settle` records the recorded id, and the copy is foreign in that run's checkpoint; the same when the journal item carries no trace of the attempt but its pending mark (a run that died mid-send);
  - an attempt older than the record's start settles by text as before, and so does every case of `test_settle.py` without a checkpoint key (unchanged);
  - a renewal whose send had an unknown outcome through a real `Relay` (a connection fake that drops after the request) and that the mirror shows: not foreign;
  - a run that dies right after a send through a real `Relay` (the existing "the run dies after the acknowledgement" pattern): the id is in the sent record;
  - digest: after a foreign event, `--digest-now` carries the line in the English post and the Japanese reply, on a quiet day and with an alert listed; the next day's digest does not; a digest whose send failed says it again; an event recorded before the digest is not said;
  - `tests/poster/test_compose.py`: the line passes the publication guard in both languages and is absent by default;
  - a failed write of the sent record in `_owed` stops the run and signs nothing; the replay records it.

Verify: `python3 -m pytest tests/poster -q`, then `scripts/test-gate.sh`.

### Acceptance (chunk 1)

- Spec criteria 1 to 6, each by a named test above.
- `scripts/test-gate.sh` passes (public scan, whole suite).

## Chunk 2: docs

- [ ] `CHANGELOG.md`: a new section above `## 0.3.0`, `## Unreleased`, one entry: what the poster does, how the record starts, the summary token `,foreign=N`, the digest line, the new files (`.sent.json`, its lock), rollback (the outbox free of a digest item with `foreign`), the limits of the spec, install between runs, and that the member half is ai-tools-alerts#cftg.
- [ ] `README.md`: line 268 (the poster's checkpoint paragraph): the sent record and `,foreign=N`; line 21 (trust paragraph): one sentence that a relay-bot event the poster did not sign is in no checkpoint.
- [ ] `scripts/public-scan.sh` passes (no host name, no local path).

Verify: `scripts/test-gate.sh`.

## Rollback

Revert the merge commit. `<ledger>.sent.json` and its lock are ignored by an older poster. An older poster refuses a journal holding a digest item with `foreign`: revert when no digest waits in the outbox, or let it send first.

## Order

1.1, 1.2 (independent), then 1.3, then 1.4, then chunk 2. One commit per chunk; the gate after the last.
