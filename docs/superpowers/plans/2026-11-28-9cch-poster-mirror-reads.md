# Plan: the poster's other reads of its mirror copy leave out foreign events (ai-tools-alerts#9cch)

Spec: `docs/superpowers/specs/2026-11-28-9cch-poster-mirror-reads-design.md`.
One chunk; it lands whole. Expected size: about 40 lines of code, 150 of tests.

## Chunk 1: own-reads

### Step 1: the tests, failing first (`tests/poster/test_sent.py`, a new section at the end)

Fixtures already there: `signing` (a poster with a checkpoint key), `_forged`,
`on_mirror`, `PutRelay`, `FakeRelay`, `T0`, `at`, `HOUR`. Each test first runs the
poster once (`signing.run(relay=PutRelay())`) so the signer starts the record.

- [ ] `test_own_returns_the_copy_without_the_foreign_events` (unit, `sent.own`):
  an unstarted record returns the same mapping; a started one drops the forged
  root and keeps a noted relay-bot event and a curator's event; with nothing
  foreign the same object comes back.
- [ ] `test_settling_reads_no_foreign_event`: after a forged root, `Run._mirror`
  returns relay-bot events without it and with the poster's own.
- [ ] `test_a_forged_thread_a_curator_retracted_is_not_among_the_withdrawn_roots`:
  `Run._withdrawn` roots hold a retracted curator thread and not the forged root
  a curator retracted.
- [ ] `test_forged_replies_take_no_real_thread_out_of_the_digest`: a relay-bot
  thread of the poster's (a collector finding posted by the first run), then a
  forged `retract` reply and a forged withdrawal block in it; the 09:00 digest
  lists the thread. Passes before and after: it pins what the issue feared.
- [ ] `test_forged_replies_keep_no_copy_from_posting`: the `lost` setup of
  `tests/poster/test_copy_on_raise.py` under `signing`, the same forged replies,
  the critical copy still posts.
- [ ] `test_a_forged_translation_does_not_stop_the_posters_own`: curator
  translation on (`translate_curator=True` on `signing.config`), a curator root, a
  forged `lang: ja` reply to it under the bot key; the pass calls the model once
  and sends the poster's reply.
- [ ] `test_a_curators_reply_in_a_forged_thread_is_not_translated`: a forged root,
  a curator's amendment in it; the pass makes no call, sends nothing, and the
  translate state's `done` does not hold the amendment. Then `sent.note` of the
  root's id (it was the poster's after all) and the next run translates it.
- [ ] `test_a_forged_translation_of_an_amendment_does_not_stop_the_posters_own`:
  a curator root, its amendment, and a forged `lang: ja` / `of:
  <amendment id>` reply; the pass makes two calls and sends two replies.
- [ ] `test_a_forged_block_shapes_no_translation`: a relay-bot root the poster
  signed (posted through `on_mirror(sec=m.bot_sec)` and noted with `sent.note`), a
  forged block under the bot key that adds a product named `Forged Product` and
  changes the title, then a curator's amendment; the one model input and the one
  reply sent contain neither `Forged Product` nor the forged title.
- [ ] `test_the_pass_waits_for_the_record` (parametrized: first run, record lost):
  with the record not started, the run's summary says ` translate=no-record `, the
  model is not called and nothing Japanese is sent, even with the forged block of
  the test above on the mirror; the signer starts the record in that run and the
  next run translates from the advisory without the forged block.
- [ ] `test_without_a_checkpoint_key_the_reads_take_the_whole_copy` (`env`, no
  key): `Run._mirror` returns the relay-bot root on the mirror, and no sent record
  is written.
- [ ] `test_a_check_that_raises_leaves_the_read_as_it_was`: `sent.own` patched to
  raise; `_withdrawn` still answers and stderr says one line.

Run: `python3 -m pytest tests/poster/test_sent.py -q -k "own or settling or forged or without_a_checkpoint or raises"`.
Expected before step 2: the unit test and the changed-behaviour tests fail
(`AttributeError: sent.own`, the forged root in the result, no translation sent).

### Step 2: the helper (`aitools_alerts/poster/sent.py`)

- [ ] Add `own` to `__all__` and, after `check`:

```python
def own(path, events: dict, m, now: int, channels=None) -> dict:
    """``events`` ({id: event}, the poster's whole copy of the mirror) without the
    foreign ones (``check``, run here without ``adopt``: an unstarted record judges
    nothing and the copy comes back whole). The same mapping when none is foreign."""
    foreign = check(path, events.values(), m, now, channels=channels)
    return {i: e for i, e in events.items() if i not in foreign} if foreign else events
```

- [ ] Add `started` to `__all__` and, after `holds`:

```python
def started(path) -> bool:
    """Whether the record has been started: before that nothing is judged."""
    try:
        return load(path)["since"] is not None
    except OSError:
        return False
```

- [ ] Module docstring: one sentence after the `signer.run_checkpoint` one naming
  the other reads (`main.Run._own`, 9cch).

### Step 3: the reads (`aitools_alerts/poster/main.py`)

- [ ] `Run._own(self, events, m)` beside `_foreign` (about line 1996):

```python
def _own(self, events: dict, m) -> dict:
    """9cch: the mirror copy's events without the relay-bot events this poster did
    not sign (``sent.own``), for every read of the copy outside the signer. The
    copy as it is without a checkpoint key (no record is kept), without a manifest,
    and, with one line on stderr, when the check itself fails: no read waits on it."""
    if self.config.checkpoint_key_file is None or m is None:
        return events
    try:
        return sent.own(self.config.sent_state, events, m, self.now)
    except Exception as e:  # noqa: BLE001
        _say(f"own-key check of the mirror copy stopped: {type(e).__name__}")
        return events
```

- [ ] `_mirror` (line 501): `self._own(st.events_for(root), m).values()` in the return.
- [ ] `_withdrawn` (line 1990): `pull.threads_from(list(self._own(st.events_for(root), m).values()), m)`.
- [ ] `curator_events` (line 732): keep `self.mirror_ids = set(st.events)`, then
  `evs = self._own(st.events, m)`; `out` initialised separately.
- [ ] `translate_curator` (line 768), right after the `off` return:

```python
if self.config.checkpoint_key_file is not None and not sent.started(self.config.sent_state):
    return "no-record"  # 9cch: nothing is translated from a copy that cannot be judged yet
```

  Before the translate state is read, so the pass reads and writes nothing. The
  module docstring's paragraph on `translate_curator` (line 86) gains the sentence.
  A record that exists and cannot be read (`OSError`) reads as not started: the
  pass waits for the run in which it reads again.
- [ ] Docstrings of the three say "without the relay-bot events this poster did
  not sign (9cch)".

### Step 4: changelog and verification

- [ ] `CHANGELOG.md`, unreleased section, one entry in the style of m729's.
- [ ] `python3 -m pytest tests/poster -q`, then `scripts/test-gate.sh`.
- [ ] Mutation check: with `_own` returning `events` unconditionally, the
  changed-behaviour tests fail; record the count in the run record.

## Acceptance

- Spec success criteria 1 to 4.
- `grep -n "events_for\|st\.events" aitools_alerts/poster/main.py` shows no read
  of the copy that decides something without `_own` (the `_foreign` check and
  `mirror_ids` are the two stated exceptions).

## Rollback

Revert the commit. No state or format changed.
