# Plan: renewals, the step down and claimed roots (ai-tools-alerts#gtw9)

Spec: `docs/superpowers/specs/2026-11-26-gtw9-renewals-and-step-down-design.md`. One branch, one pull request. Build order: chunk 1, chunk 3 (the signer's `record_sent(renewal=)` and `run_checkpoint(suppress=)` are what chunk 2 calls), chunk 2 with the switch last, chunk 4. The poster suite is run after chunks 2 and 3 are both in.

Added after the plan review (each is in the spec): `Entry.root_ids` and the rule that a standing claim names one of them; `Ledger.record_reply(changed_at=)`, given the time of the item's pending mark or first attempt; the renewal after a lost checkpoint state is due until sent, by the `hold_until` the record keeps, and its roots are left out meanwhile; `Run.unrenewed` also takes the channel root of every unsent level reply of an enrolled thread, and a due step that was not journaled; the comparisons are inclusive (`<=` half the TTL, `<=` STEP_EARLY), so the daily tests see days 7, 14, 21, 28 and 44; `signer._frontier` keeps one reply per pair of times before it drops the redundant ones; the signer protects a renewal only in a thread whose root carries a claim. Tests for each are in `tests/poster/test_renew.py`, `test_signer.py` and `test_ledger.py`.

## Chunk 1: ledger and compose

- [ ] `aitools_alerts/poster/ledger.py`: `Entry.claim: str | None`; `_entry_ok` accepts the optional key as a non-empty string; `Ledger.set_claim(root, text)` writes it and saves only on a change.
- [ ] `aitools_alerts/poster/compose.py`: `RENEWAL`, `UNCONFIRMED`; `renewal_post()` returns the guarded line, with no block; `level_post(prev, level, reason=None)` appends the sentence to the level line. The block and the parse-back check are unchanged.
- [ ] Tests (`tests/poster/test_ledger.py`, `tests/poster/test_compose.py`): an entry with and without `claim` loads; an empty or non-string `claim` is malformed; `set_claim` on an unknown root raises; `renewal_post()` has no `aitools-alert` block and `pull._patch` reads none; `level_post` with a reason parses back to the same advisory and its last block is exactly `{"level": ...}`.

Verify: `python3 -m pytest tests/poster/test_ledger.py tests/poster/test_compose.py -q`.

## Chunk 2: the poster's pass (`aitools_alerts/poster/main.py`)

- [ ] `Run._parsed(text)`: the claim a tag's text holds when it is well formed and of a level, else None.
- [ ] `Run._stand(root, it, enrol)`: after a root is recorded (`enrol=True`), and after a copy or reply is recorded (`enrol=False`): the item's claim becomes the standing claim when the thread is enrolled (or `enrol`) and it was checked no earlier than the one held.
- [ ] `Run._owed(eid, text, tag, root, reply, level)`: shared by `_owe` and the renewal sends; passes `renewal=` to `signer.record_sent` for a reply whose claim is of a level, and the run's time twice for a reply whose block names a level.
- [ ] `Run._checked(e)`, `Run._confirming(e, old) -> (bool, text | None)`, `Run._life(e, rs, c, k)` as the spec's "What a run's read says" and "Renewal".
- [ ] `Run.renew()`: steps down (`_step_down`), collects what is due (half the TTL and a gain; or forced by a lost checkpoint state), sends in the hour-rotated order within `MAX_RENEWALS`, ends after three unacknowledged sends, and leaves in `self.unrenewed` the channel roots of each thread whose due renewal was not acknowledged everywhere and whose life ends within two hours.
- [ ] `plan_known` and `copies`: a copy's claim only for an enrolled thread (`entry.claim is not None`): this run's reading, else `_checked`.
- [ ] `run()`: `r.renew()` after the alert work, also after `_Stop`, not after a `LedgerError`; `_Stop` from a step down's send sets exit 1. `signer.run_checkpoint(..., suppress=r.unrenewed)`. The summary's ` renewed=N[/M]`.
- [ ] `ROOT_CLAIMS = True`, last.
- [ ] Tests: `tests/poster/test_renew.py`, the cases the spec lists. Existing tests that pin unclaimed roots or call a three-argument sender on a post that now has a claim are updated: `test_claims.py` (the two "as shipped" tests become the enrolled and legacy cases), `test_catalog.py`, `test_copy_on_raise.py`, `test_end_to_end.py`, `test_settle.py`, `test_recompute.py::test_the_rollback_steps_name_every_key_an_older_poster_refuses` (the changelog names `claim` in a ledger entry and `renewal` in an owed entry).

Verify: `python3 -m pytest tests/poster -q`.

## Chunk 3: the signer (`aitools_alerts/poster/signer.py`)

- [ ] `renewals_of(ev, m)`: the time pairs a reader counts for a relay-bot reply (its claim's when `pull._renewal` takes it; its own date twice when its block names a level).
- [ ] `_later(events, m)`, `_redundant(pairs, root, later)`.
- [ ] `_entry_ok`: optional `renewal`, two integers, only with a root. `record_sent(..., renewal=None)`.
- [ ] `settle_owed(owed, present, now, later) -> (kept, dropped, suppress)`: a renewal entry past `OWED_S` stays unless redundant.
- [ ] `settle_gone`: a late held renewal that is not redundant is a `fix`.
- [ ] `window`: for a must-listed thread, `core` includes each relay-bot reply carrying a renewal that no other reply of the thread makes redundant.
- [ ] `run_checkpoint(..., suppress=frozenset())`: the union of the caller's roots, `settle_gone`'s and `settle_owed`'s; late renewal entries are off the must-list.
- [ ] Tests in `tests/poster/test_signer.py`: the spec's three, and the three-tuple of `settle_owed` in the existing test.

Verify: `python3 -m pytest tests/poster/test_signer.py tests/test_checkpoint.py tests/test_checkpoint_pull.py -q`.

## Chunk 4: readers and words

- [ ] `tests/test_wire_compat.py`: replace `test_why_root_claims_are_off...` with a feed that has a claimed root, renewals (`confirmed_at` unchanged), and a step down with its reason; every released reader and this one, now and at days 30, 50 and 100: released never below this one. Keep the decaying-root test as the statement of why renewals exist.
- [ ] `spec/wire.md` "The claim" and "How this reader computes expiry": what the poster sends now (roots, renewals, the step down, the cadence).
- [ ] `CHANGELOG.md`: the change, what the release session must know (the poster must keep running; rollback is forward only once a claimed root is recorded), and the keys older code refuses.
- [ ] Module docstrings (`main.py`, `signer.py`).

Verify: `python3 -m pytest tests/test_wire_compat.py tests/test_expiry.py -q`, then `scripts/test-gate.sh`.

## Acceptance (the issue's)

- 403 for 30 days: renewed, critical on a reader of r0ra (`test_renew.py`).
- At 45 days (less the day the spec explains) the step down with its reason (`test_renew.py`).
- A confirming source: a new `confirmed_at` (`test_renew.py`).
- Released readers at the same or a higher level (`test_wire_compat.py`).

## Rollback

Revert the merge commit before any claimed root is recorded. After that the ledger holds `claim` keys the old code refuses: roll forward.
