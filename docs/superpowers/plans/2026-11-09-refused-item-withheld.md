# Plan: a refused item is withheld; the run goes on (ai-tools-alerts#8acj)

Spec: docs/superpowers/specs/2026-11-09-refused-item-withheld-design.md

One chunk, `withheld`. Budget: under 200 changed lines (code + tests, excluding
these docs).

## Chunk: withheld

### Step 1 — transport (`aitools_alerts/poster/transport.py`)
- [ ] `_cli_error` (line 88) returns `(category, message, retryable)`; the two
      callers adjust.
- [ ] `_classify` (line 106): before `if rc in _NEVER_SENT`, `rc == 1` with
      category `user_error` and `retryable is False` returns `("refused", None)`.
- [ ] `SendResult` gains `message: str = ""`; `send` fills it for `refused`
      (one line, at most 300 characters). Module docstring names the fourth
      outcome.
- [ ] Tests (`tests/poster/test_transport.py`): exit 1 + user_error +
      retryable:false is `refused` with the message; exit 1 + user_error with
      retryable true or missing, and exit 1 with free text, stay `failed`;
      exit 2 + user_error/false stays as today (unknown).

### Step 2 — state (`aitools_alerts/poster/inputs.py`)
- [ ] `_STATE_KEYS` gains `withheld`; `new_state` sets `[]`.
- [ ] `load_state`: a missing `digest_ids` or `withheld` is filled with `[]`
      (generalising line 336); `withheld` validated by `_withheld_ok`: dict with
      exactly `key, items, message, at`; `items` non-empty, every one `_item_ok`,
      `items[0]["key"] == key`; `message` str; `at` int. Outbox key uniqueness
      unchanged (withheld keys are checked at requeue, not at load).

### Step 3 — run (`aitools_alerts/poster/main.py`)
- [ ] `Run._withhold(it, message)`: stores the group only while the withheld
      list's JSON stays within `MAX_JA_BYTES` (else dropped, said). group = `[it]` plus, for a root, the outbox
      copies with `root is None` sharing its ids and scope; remove them from the
      outbox; append `{"key", "items", "message", "at": now}` to
      `state["withheld"]`; save; count `ja_failed` for a Japanese item, else
      `withheld`; `_say` one line naming the key and message.
- [ ] `deliver` (line 166): when `r.outcome == "refused"`: `_withhold` (saves),
      then `led.clear_pending`, return True. failed/unknown unchanged. A
      Japanese item is removed and counted `ja_failed`, never stored.
- [ ] `enqueue` (line 432): skip an item no longer in the outbox.
- [ ] `busy` (line 420): also true when a withheld item (non-ja) of the same
      scope shares an id, or when any item names the root of the ledger thread
      these ids look up to (an update arriving under another alias).
- [ ] `digest` (line 594): return when a withheld group holds a digest.
- [ ] `run` (after `r.save()` near line 842, and on every path that loaded the
      state): one `_say` line when `state["withheld"]` is non-empty.
- [ ] `pending` (line 868): one line per withheld group; the totals line gains
      ` withheld=N` only when the list is non-empty (existing exact assertions
      stay green).
- [ ] `resolve` (line 891): new keywords `requeue=False, drop=False`; a
      withheld key is settled before the pending lookup: requeue (refused when a
      key is journaled again) appends the items unchanged to the outbox; drop
      removes the group; both clear a pending mark left on the group's keys,
      before saving, unless the key is journaled again as a live item. The old
      `--not-delivered needs --reason` guard is relaxed for `requeue`/`drop`;
      `main` adds `--requeue`, `--drop` to the mutually exclusive group and
      forwards them. CLI tests run `--requeue` and `--drop` end to end.
      (Amended after the code review: `--text-file` removed for the line budget.)
- [ ] `one()` (line 458): after `enqueue`, a candidate whose item was withheld
      is deferred, so `--drop` plans it anew. `deliver`: a second English
      refusal in one run raises `_Stop` after withholding it.
- [ ] Module docstring: one paragraph on withheld items.

### Step 4 — tests (`tests/poster/test_main.py`)
- [ ] `FakeSSH` gains a `"refuse"` outcome: exit 1, stderr the CLI line
      `{"error":"user_error","message":"…","retryable":false}`.
- [ ] Acceptance: three advisories (high), the first send refused: `withheld=1`,
      `roots=2`, marks saved (`collector` watermark set), exit 0, state
      `withheld` holds the key and message, the stderr line printed.
- [ ] A refused root withholds its copy too (critical KEV), and the next run
      sends neither and defers a new candidate under the same id (`busy`).
- [ ] A network failure (`fail`) still stops the run: the existing
      `test_one_failure_stops_further_sends` also asserts `withheld == []`.
- [ ] A refused digest blocks new digests until resolved.
- [ ] `pending` lists the withheld item with its message and no post text;
      `resolve --requeue` puts it back and the next run posts it; `resolve --drop`
      removes it and the deferred candidate posts next run; a key not withheld
      is refused; a second refusal in one run exits 1.
- [ ] A refused Japanese reply is dropped; the other Japanese replies send.
- [ ] A refused reply holds its thread when the same update arrives under
      another alias.
- [ ] Old state without `withheld` loads (extend
      `test_old_state_without_digest_ids_loads` or a new small test).

## Verification
- `python3 -m pytest tests/poster -q` while building.
- `scripts/test-gate.sh` on the committed head (public scan + whole suite).
- `git diff --stat origin/main -- aitools_alerts tests` under 200 lines.

## Acceptance
Spec success criteria 1–9; the issue's acceptance fixture as the first test of
Step 4.

## Rollback
Stop the hourly job; settle each withheld group with `resolve`; always remove
the `withheld` key (the previous version refuses it even empty); revert and
reinstall; restart the job (spec, Blast radius).
