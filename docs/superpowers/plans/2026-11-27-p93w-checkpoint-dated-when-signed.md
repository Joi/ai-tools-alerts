# Plan: the checkpoint is dated when it is signed (ai-tools-alerts#p93w)

Spec: `docs/superpowers/specs/2026-11-27-p93w-checkpoint-dated-when-signed-design.md`. Three chunks, in this order; each ends with its tests green. Tests are written first in each chunk and seen to fail.

Run tests with `python3 -m pytest -q <paths>` from the worktree root. Never set `GIT_DIR`, `GIT_WORK_TREE` or `GIT_INDEX_FILE`.

## Chunk 1: the signer

Files: `aitools_alerts/poster/signer.py`, `tests/poster/test_signer.py`.

- [ ] Tests, in `tests/poster/test_signer.py`:
  - `test_the_checkpoint_is_dated_when_it_is_signed`: with the `signing` fixture, a bot post on the mirror dated `T0 + 40`, recorded as owed (`signer.record_sent(..., T0)`); `signer.run_checkpoint(config, T0, clock=lambda: T0 + 90.7, ssh=relay, fetch=m.fetch, root=m.root)`. The checkpoint has `created_at == seq == T0 + 90`, `valid_until == T0 + 90 + DAY`, lists the post, and the post is still owed (settled by the run's start, as before). A second post dated `T0 + 95` on the mirror is not listed.
  - `test_a_post_of_this_run_the_mirror_already_shows_is_listed_or_nothing_is_signed`: `MAX_LISTED` patched small, the window filled by curator-corrected threads (must-listed), one owed post dated `T0 + 40` on the mirror, `clock=lambda: T0 + 90`: the answer is `too-large`, nothing is put. With room, it is listed. The same with the owed post a level reply to a claimed root, recorded with `renewal=(T0, T0)`: `too-large`, and it stays owed.
  - `test_a_clock_behind_the_run_and_no_clock_date_the_checkpoint_at_the_runs_time`: `clock=lambda: T0 - 500` and `clock=None` both give `created_at == T0`.
  - `test_a_lost_state_holds_signing_by_the_signing_time`.
  - `test_a_level_change_from_before_a_lost_state_keeps_its_root_out_until_its_reply_or_a_later_confirmation_is_held`: two claimed roots on the mirror; `changes=[(root, t, u), ...]` with `u = t + 7200` (the reply was sent again two hours after its first attempt). None listed with no reply; with no `changes`, all listed. Root A stays out with a renewal confirmed before `t`, with one confirmed at exactly `u` and checked later, and with one confirmed between `t` and `u`; root B is listed once a level reply dated `t + 5` is held. Root A is listed once a renewal confirmed at `u + 3600` is held. A third root gets only a level reply dated `t - 300` and stays out. A pair naming a root the copy does not hold changes neither the list nor the summary.
- [ ] `answered(root, t, u, events, m) -> bool` (new, exported): any relay-bot event `ev` with `pull._thread_ref(ev) == root` that names a level in `pull._RANK` in its block and has `created_at >= t`, or whose `pull._renewal(ev, "relay-bot")` has `confirmed_at > u`.
- [ ] `run_checkpoint(config, now, *, ssh=None, fetch=None, root=..., suppress=frozenset(), clock=None, changes=())`:
  - after the `off` return: `start = int(now)`; `now = max(start, int(clock()))` when `clock` is not None, else `start`. `start` is used for what `settle_owed` may settle by, and nowhere else: both the `present` set and the `_later` renewals given to it are taken from the copy's events with `created_at <= start`, as today. (A level reply of this run, owed with `renewal=(start, start)`, would otherwise be made redundant by its own date and leave the must-list.) `settle_owed` still gets `now` for its 72 hours. Everything else uses `now`.
  - after `settle_owed`: `seen = [e for e in st.events.values() if e["created_at"] <= now]`; `suppress |= {r for r, t, u in changes if r in st.events and not answered(r, int(t), int(u), seen, m)}`.
- [ ] Docstrings: the module text (dated at the signing; the level-change rule), `run_checkpoint` (`clock`, `changes`), the comment above `settle_owed`'s call (why settlement keeps the run's start), `window` ("Events dated after ``now``": the signing time).
- [ ] Verify: `python3 -m pytest -q tests/poster/test_signer.py`.

Acceptance: the new tests pass; every earlier test in the file passes unchanged.

## Chunk 2: the run

Files: `aitools_alerts/poster/main.py`, `tests/poster/test_renew.py`, `tests/poster/test_main.py` or `test_signer.py` for the `main.main` test.

- [ ] Tests:
  - `tests/poster/test_renew.py::test_after_a_lost_state_a_level_change_made_before_it_is_passed_to_the_signer`: `critical(env)`, a step down at day 44 with the KEV source blocked (both channels acknowledged), the state file removed, a run an hour later. `run_checkpoint` (wrapped as the neighbouring tests wrap it) receives `changes` equal to each channel root of the thread with `T0 + 44 * DAY` twice (attempted and recorded in one run). A second test: the step's send has an unknown outcome at day 44 and the mirror shows it two days later (as `test_a_level_change_recorded_by_a_later_run_counts_from_its_attempt` does); after a loss the triple is `(root, T0 + 44 * DAY, T0 + 46 * DAY)`. With the state file intact it receives none. After a later level change (a second run that records one after the loss) it receives none. A thread with no level change passes none.
  - `test_the_poster_command_dates_checkpoints_by_the_machines_clock`: `main.main(["run", ...])` with `main.run` replaced records `clock is time.time`.
  - `test_the_runs_clock_reaches_the_signer`: `env.run(clock=lambda: T0 + 30, relay=PutRelay())` signs a checkpoint with `created_at == T0 + 30`.
- [ ] `Run.level_changes(self) -> list`: `[]` when `config.checkpoint_key_file is None`; `hold = signer.load_owed(config.owed_state, self.now)["hold_until"]`; `[]` when `hold <= 0`; `lost = hold - signer.OWED_S`; for `e in self.led.entries()` with `e.claim is not None` and `e.changed` and `max(e.changed) <= lost`: `(root, max(e.changed), e.last_change)` for `root in sorted({e.root_event_id, *e.channel_ids.values()})`.
- [ ] `run(..., clock=None)`: `signer.run_checkpoint(config, now, ..., suppress=frozenset(r.unrenewed), clock=clock, changes=r.level_changes())`, inside the existing `try`.
- [ ] `main()`: `run(int(time.time()), cfg, ..., clock=time.time)`.
- [ ] `Run.renew`'s docstring: one sentence naming `level_changes`.
- [ ] Verify: `python3 -m pytest -q tests/poster`.

Acceptance: the new tests pass; `tests/poster` passes.

## Chunk 3: the reader's rule, stated and tested

Files: `spec/wire.md`, `aitools_alerts/pull.py` (docstrings only), `tests/test_wire_compat.py`, `CHANGELOG.md`, `README.md` if it states the old dating.

- [ ] `tests/test_wire_compat.py`: `CLAIM_READERS = ("v0.1.8", "v0.2.0", "v0.2.1", "v0.3.0")`. `test_an_event_dated_after_its_checkpoint_is_admitted_and_its_claim_waits`, parametrized over `CLAIM_READERS` and run for this reader in the same body:
  - `mirror_now()`; a claimed critical root dated `now - 20 * DAY`; a renewal (claim confirmed at the root's time, checked at `now - 300`) dated `now - 300`; a stored checkpoint dated `now - 600` listing both (`m.checkpoint(ids=[...], now=now - 600)`).
  - A dump script for the claim readers that prints `pull.head_clock(State.load())[0]` and `pull.active(threads, *head_clock)` levels. Each reader: the pull exits 0, the clock is `now - 600`, the thread shows `critical`.
  - A control mirror with the root alone under a checkpoint dated `now - 600`: `high` on each.
  - Then `m.checkpoint(now=now - 100)` over the same events, a second pull: `critical`, clock `now - 100`.
  - A third mirror tells the hold from a reader that counts the late claim at once: the late event's claim is checked one day after the root (it holds critical to day 15 only). Under the checkpoint dated before the event: `critical` (not judged). Under the next checkpoint: `high` (judged, and the claim does not hold critical).
- [ ] `spec/wire.md`: "What the poster sends" gains the checkpoint's date; the bullet of "How this reader computes expiry" that says the checkpoint is dated at the start of the run is rewritten (both dates named, the reader does not refuse, why); the sentence after the claim list names the level-change rule after a lost state file. The intro's "released reader (v0.1.4 to v0.1.7)" is left as it is.
- [ ] `pull.py`: the module text and `active`'s docstring, where they say the poster's checkpoint lists posts dated after it.
- [ ] `CHANGELOG.md`: an "Unreleased" section above 0.3.0.
- [ ] Verify: `python3 -m pytest -q tests/test_wire_compat.py tests/test_expiry.py`, then the whole suite with `scripts/test-gate.sh` in a clone that holds this branch alone (`git clone --single-branch --branch p93w-self-correct-p93w file://<worktree> <scratch dir>`).

Acceptance: the new test passes on the four tags and this reader; the gate exits 0.

## Rollback

Revert the commits. No state shape changed: the released poster reads the state record and the ledger this one writes.
