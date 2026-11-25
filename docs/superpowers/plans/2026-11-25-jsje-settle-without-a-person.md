# Plan: the poster settles an unknown or refused send without a person (ai-tools-alerts#jsje)

Spec: `docs/superpowers/specs/2026-11-25-jsje-settle-without-a-person-design.md`. One chunk, one commit, under 600 changed lines.

## Chunk 1: settle, expire, supersede

### `aitools_alerts/poster/inputs.py`

- [x] `_STATE_KEYS` gains `dropped`; `new_state` sets 0; `load_state` adds 0 to a state without it and requires a non-negative int.
- [x] `_item_ok`, digest branch: the snapshot may carry `dropped` (a non-negative int), beside `week`.

### `aitools_alerts/poster/recompute.py`

- [x] `raised(entry, scope, copy, rs) -> str | None`: `held(support(...)[0])` when it ranks above `entry.level`, else None. Reads only; `judge` is unchanged.

### `aitools_alerts/poster/compose.py`

- [x] `digest(..., dropped: int = 0)`: added to the withheld count; on a quiet day with `dropped > 0` the withheld line follows the quiet line. With `dropped == 0` every output is byte for byte what it was.

### `aitools_alerts/poster/main.py`

- [x] Constants: `SETTLE_SKEW = 600`, `MIRROR_FRESH = 3600`, `GIVE_UP = 72 * 3600`, `WITHHELD_SECONDS = 3 * 86400`.
- [x] `_unrecordable(r, it, eid) -> str | None`: the checks `resolve --delivered` makes before it writes (id already recorded; a root whose ids a thread holds; a copy or reply with no thread). `resolve` calls it; no behaviour change there.
- [x] `Run._mirror(root, fetch)`: `State.load` + `pull.fetch(checkpoint=False)` under `translate.bounded(…, 120)`, capturing each fetched body. Returns `(relay-bot events of the accepted manifest, {channel: generated_at epoch})`, the second empty when the pull reported an error or a file's `generated_at` does not parse; `None` when there is no accepted manifest or the state cannot be read.
- [x] `Run._delivery(it, p, events)`: the match of spec section 1; the oldest recordable event's id or None.
- [x] `Run.settle(root, fetch)`: for each pending entry with no acknowledged journal item: clear a withheld item's mark; record a delivery; expire at 24 h with a fresh channel file, at 72 h without, at 24 h with no item. Counts `n["settled"]` (delivered), `n["resent"]` (expired); one stderr line each.
- [x] `Run.expire_withheld()`: spec section 2; `state["dropped"] += 1`, `n["dropped"] += 1`.
- [x] `Run._rate(c, scope, entry)` and `Run._thread_level(level, reason, entry)`: the rating lines of `one` and the cap of `plan_known`, moved, not changed. `one` and `plan_known` call them.
- [x] `Run.yields(e, level)`, `Run._clears(c, scope, entry)`, `Run.make_way(merged)`; `_judge` and `one` call them as the spec says. Counts `n["superseded"]`.
- [x] `run()`: `r.expire_withheld(); r.settle(...)` after `gather`/`merge` and before `r.observe`; `r.make_way(merged)` before `r.drain()`. The summary appends ` settled=delivered:N,resent:N,dropped:N,superseded:N` when any is non-zero. The per-run "withheld=N refused by the relay" line says the items are dropped after three days.
- [x] `Run.digest`: passes `dropped=self.state["dropped"]`, the snapshot carries it when non-zero, `_record` subtracts it (never below 0).
- [x] Module docstring: the two paragraphs on `pending`/`resolve` and `withheld` say what a run now does by itself.

### Added after the spec and plan review (spec, "Review dispositions")

- [x] `inputs._item_ok`: a journal item may carry `tried` (an int).
- [x] `Run.settle`: before an expiry, `it["tried"] = min(first attempt, …)`, saved; `_delivery`'s floor is `tried`; an unsent item with `tried` and no pending entry is matched each run and never expired there.
- [x] `Run.drop_unsent_lowerings`: a level item with `tried` counts as one a channel has.
- [x] `Run.expire_withheld`: a reply whose journaled advisory is the ledger's goes back to the journal and its key into `Run.retried`; `_withhold` drops and counts a refused item whose key is in `retried`.
- [x] `Run.yields`: eligibility from the reply's own block (`schema._last_block`): a level below the raise's alone; or ids, sources and a severity word alone with no `tried` and an advisory the ledger does not hold.
- [x] Tests: a delivery that shows after a repeat (unknown, and failed); an expired unknown lowering is sent again and the raise follows; a refused reply another channel has is sent once more, then given up; a raise does not supersede a fix reply another channel has; `yields` on a source-only reply in each state; the rollback keys.
- [x] Mutations added: the floor is the attempt in flight; a `tried` lowering is dropped; a source-only reply another channel has is superseded; a partial reply is dropped at expiry; any poster's key settles.

### Docs

- [x] `README.md`: the paragraph on unknown sends and the `pending`/`resolve` bullets.
- [x] `CHANGELOG.md`: one entry under the unreleased heading, with the rollback line; the ny5g sentence that names this issue is left as history.

### Tests: `tests/poster/test_settle.py` (new), using `env`, `FakeRelay`, `Mirror` from `test_main.py` / `mirror_helpers.py`

- [x] an unknown root the mirror shows is recorded by the next run, nothing sent again, the Japanese reply queued (criterion 1)
- [x] the same for an unknown reply and an unknown digest
- [x] an event with other text, another channel, another thread, a curator's key, or dated before the attempt does not settle it
- [x] not on a fresh mirror: still pending at 23 h, sent again at 24 h (criterion 2)
- [x] a mirror whose file is old, or whose pull fails: still pending at 24 h, sent again at 72 h
- [x] a pending entry with no journal item is expired at 24 h; a withheld item's leftover mark is cleared at once
- [x] a withheld reply is dropped after three days, planned anew, counted in the next digest and only that one (criterion 3, slow path)
- [x] a thread whose critical-channel lowering was refused is raised by the next run's KEV read; the lowering never reaches that channel (criteria 3 and 4)
- [x] the same with the lowering unsent after a failed send, raised by a candidate (criterion 4, `make_way`)
- [x] a raise does not supersede: an unknown send; a reply that carries a fix; a refused root (criterion 5)
- [x] `recompute.raised` agrees with `judge` on a raise and writes nothing to the state
- [x] `compose.digest(dropped=…)`: the count on a day with alerts and on a quiet day; unchanged with 0
- [x] a state without `dropped` loads as 0

### Verification

```
python3 -m pytest tests/poster -q
scripts/test-gate.sh
```

Mutations to try before review (each must fail a named test): drop the `created_at` floor in `_delivery`; expire at 24 h without the `generated_at` test; let `yields` ignore `pending_for`; let `yields` take any reply.

### Acceptance

The four acceptance lines of the issue, as spec criteria 1 to 4, pass; the existing suite passes unchanged except tests that asserted a thread waits for `resolve` (each such change is named in the run record).

### Rollback

Revert the commit; stop the poster's timer, rewrite the state file with the `jq` line of the spec (it writes a new file and replaces the old one), start the timer.
