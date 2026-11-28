# Plan: a channel that lacks the thread's standing level reply is sent it again (ai-tools-alerts#aqtf)

Spec: `docs/superpowers/specs/2026-11-28-aqtf-per-channel-level-design.md`. One pull request, two chunks. Each task is test first: write the test, see it fail, make it pass. `python3 -m pytest tests/poster -q` after each chunk; `scripts/test-gate.sh` before the review.

## Chunk 1: the ledger and the journal item

### Task 1.1: `Entry` fields and properties (`aitools_alerts/poster/ledger.py`)

- [ ] `Entry`: `lacks: dict | None`, `copied: dict | None`, `uneven: bool | None`, after `withdrawn`.
- [ ] `Entry.gone`: with `lacks` absent, `withdrawn` names every channel; else some channel in `withdrawn` is not in `lacks`.
- [ ] `Entry.standing`: `wire.WITHDRAWN` if `gone` else `level`.
- [ ] `Entry.word(channel)`: `withdrawn` if listed, else `lacks[channel]`, else `copied[channel]`, else `level`.
- [ ] `Entry.lacking`: with `lacks` absent and not `gone`, `{ch: "withdrawn"}` for each channel in `withdrawn` (the kk2q entry); else `{ch: word(ch)}` for each channel in `lacks`.
- [ ] `_entry_ok`: `lacks` by `_lacks_ok` (non-empty dict; keys a proper subset of `channel_ids`; values a level or `withdrawn`; `withdrawn` exactly for a channel in the `withdrawn` list; not both a withdrawn channel outside `lacks` and one inside); `copied` a non-empty dict of the thread's channels to levels; `uneven` is `True`.

Tests (`tests/poster/test_reconcile.py`, section "the ledger"): the four properties for each stored shape (no field; `withdrawn` all; `withdrawn` some with no `lacks`; `withdrawn` some with `lacks` either side; `lacks` at a level; `copied`); a ledger file with each bad `lacks`, `copied`, `uneven` is refused with `LedgerError`; a ledger file kk2q wrote loads.

### Task 1.2: `record_reply` and `add_channel` (`ledger.py`)

- [ ] `record_reply(..., again=False)`. With `withdrawn` not None, `said` is `withdrawn` or `adv.level`:
  - `said != before.standing`: `lack` = every channel except the reply's own, a channel whose word is `said` under a withdrawal, and a channel with `copied[ch] == said`;
  - else `lack` = `before.lacking` minus the reply's channels;
  - the reply's channels take `said`; `withdrawn`, `lacks`, `copied` are rewritten from the words and `lack` (`copied` always removed); `again` sets `uneven`.
  - `entered` uses `not before.gone` in place of `not held`.
  - `left` (kk2q: a reply that ends the state in a withdrawn channel counts once for its time) is false for `again`: a reply the reconciliation sent changes no level of the thread and adds no time to `changed`. A journal item of kk2q's own that lands later still counts.
- [ ] `add_channel(root, channel, event_id, level=None)`: for a new channel, `said = level or e["level"]`; a `gone` thread gets `lacks[channel] = said`; else `said != e["level"]` gets `copied[channel] = said`.

Tests: two channels, a raise recorded in one names the other in `lacks` and the second record clears it; a lowering to notice with the other channel in `lacks` at notice keeps it there; a withdrawal recorded in one channel with the other already withdrawn names nothing; the reply that ends a withdrawal in one channel names the other; `again=True` sets `uneven` and only with a level word; `add_channel` with a level above the thread's writes `copied`, and the reply recorded next names no channel and removes it; `add_channel` on a withdrawn thread writes `lacks`; `changed` gains one time when the state is entered and none when the withdrawal reaches the second channel; a level reply recorded with `again` in a withdrawn channel leaves `changed` as it was, and the same reply without `again` adds its time. Existing `tests/poster/test_ledger.py` passes unchanged.

The `uneven` rule has its regression test here: a thread whose two channels hold one reply each, one of them recorded with `again`, and an advisory with an alias; `Run._stated` returns the first id alone (without `uneven` the equal counts would return the alias too, and a claim could name it).

### Task 1.3: the journal item (`aitools_alerts/poster/inputs.py`)

- [ ] `_item_ok`: `again` is an allowed key; it must be `True` and the item a reply.

Tests: `inputs.load_state` accepts a state with an `again` reply in `outbox` and in a `withheld` group; refuses `again` on a root and `again: false`.

Acceptance for the chunk: the new ledger and inputs tests pass; `tests/poster/test_ledger.py`, `test_inputs.py`, `test_withdrawn_state.py` pass (one kk2q expectation changes in chunk 2).

## Chunk 2: the run

### Task 2.1: the state is the standing reply's

- [ ] `entry.withdrawn` becomes `entry.gone` in `main.py`: `_clears`, `_record` (the lowering note), `plan_known` (two), `drop_unsent_lowerings`, `copies`, `_renew`, `level_changes`, `digest`; in `catalog.snapshot`; in `recompute.raised` and `recompute.judge`.
- [ ] `tests/poster/test_catalog.py::test_a_withdrawn_thread_that_no_longer_starts_at_its_level_still_leaves_the_inventory` builds its entry as a `SimpleNamespace` with `withdrawn`; it now sets `gone` (True, then False), the attribute `catalog.snapshot` reads.
- [ ] `_level_items`: `again=level == prev.level` in place of `bool(entry.withdrawn)` (the only use of `again` is to allow the thread's own level).
- [ ] `_withdrawal_items(entry, claim, channels=None)`.
- [ ] `_record` (copy): `add_channel(..., level=<the level the copy's block states>)`.
- [ ] `_record` (reply): `record_reply(..., again=it.get("again") is True)`.
- [ ] `_stated`: first id only when `entry.uneven`.

### Task 2.2: `Run.reconcile(up)` and its place in `recompute`

- [ ] `Run.refused: set`, filled in `_withhold` with the root of a refused reply.
- [ ] `reconcile(up)` as the spec's "What a run sends": entries oldest first; lacking channels split by `RANK.get(word, -1) < RANK.get(standing, -1)`; skip synthetic, `refused`, `withdrew` with a standing level, `busy`; claim by `_claim` then `_checked`, kept only when its level is the standing word's (`_claim_of`); items marked `again`; one stderr line; `enqueue`.
- [ ] `recompute`: raises, `reconcile(up=True)`, lowerings, `reconcile(up=False)`, `copies`. A withdrawal goes to the channels whose word is not `withdrawn`. A leaving reply goes to every channel; with a lacking channel and a verdict at or below the ledger's level it names the ledger's level.
- [ ] `renew` (the `finally`): the root of every lacking channel of a claimed thread joins `unrenewed`.
- [ ] Module docstring: one sentence.

Tests (`tests/poster/test_reconcile.py`, through `main.run` with `FakeRelay`, helpers from `test_advisory_recompute.py` and `test_withdrawn_state.py`):

1. Criterion 1: a critical-by-malware thread in two channels at high in the ledger... concretely: post a malware advisory with no fix (critical, two channels); lower the ledger entry to high in both by `edit`, then let the read raise it; relay `("ok", "refuse")`; the entry holds `lacks`; hourly runs with a refusing relay for four days send that channel the level at most at the journal's pace and never the other; then an accepting relay: one reply to that channel, `lacks` gone, `uneven` set, the item carried the claim.
2. Criterion 2 and 3 and the old-ledger case: from an edited entry (`lacks={"critical": "critical"}` at ledger level high; `withdrawn=["feed"], lacks={"critical": "critical"}`), one run sends the one reply; the next sends nothing.
3. Criterion 5: after each of the above, four more hourly runs send nothing.
4. Criterion 6: two threads edited, one lacking a raise and one a lowering; the order of the two sends in one run; with relay `("fail",)` only the raise was attempted.
5. Criterion 7: with an item of the thread in `outbox` (relay `"fail"` the run before) nothing more is planned; the run in which the retried reply is refused again ends with code 0 and plans nothing for the thread.
6. Criterion 8: an entry `withdrawn=["critical"], lacks={"critical": "withdrawn"}`, eight days after its claim, with a relay that refuses the first send: the reconciliation's reply is refused and withheld, so the thread is still partly withdrawn when the renewal pass runs, and the renewal goes to both channels. `recompute.judge` on such an entry starts a wait when the source withdraws again, and gives none for an entry whose standing reply is the withdrawal.
7. Criterion 10: stop a run between the acknowledgement and the record (a relay that answers ok while `Ledger.record_reply` raises once), then the next run records it with `uneven`.
8. The candidate's raise to critical through `plan_known`: after the run no `lacks`, no `copied`; later runs send nothing; with relay refusing the feed's reply, the critical channel is sent nothing in the next runs.
9. The checkpoint (`signer.run_checkpoint` wrapped to record `suppress`): in the run where the reply sent once more is refused and given up, nothing of the thread is in the journal, the withheld list or pending, and `suppress` is exactly the lacking channel's root. That is the case only the ledger scan covers (the withheld item already kept the root out before). Also: after the channel takes the reply, `suppress` is empty; a channel that lacks the withdrawal is kept out too. Mutation: without the scan the middle assertion fails.
10. `tests/poster/test_withdrawn_state.py::test_a_reply_that_ends_the_state_passes_the_withdrawal_one_channel_still_lacks`: the expectation becomes both channels sent `critical`.

### Task 2.3: documents

- [ ] `spec/wire.md` "By channel": the poster keeps, for each channel, whether it holds the thread's standing level reply; a channel that lacks it is sent it again, the withdrawal included; a thread is withdrawn when its standing reply is the withdrawal.
- [ ] `CHANGELOG.md`, Unreleased, first: what changes, what an operator should know (the three ledger keys, the journal key, going back), what it does not cover (a reply with no level; the unknown send).

Acceptance for the chunk: the ten tests pass; `python3 -m pytest tests/poster -q` passes; `scripts/test-gate.sh` exits 0.

## Verification

- `python3 -m pytest tests/poster/test_reconcile.py tests/poster/test_ledger.py tests/poster/test_withdrawn_state.py -q`
- `scripts/test-gate.sh` (the public scan, then the whole suite) at the head that is reviewed, and again after main is merged.
- Mutation check: with `reconcile` made to return at once, criteria 1 to 3 fail; with the new-standing rule made word-only, the notice test of task 1.2 fails.

## Rollback

Revert the merge commit, only while no ledger entry holds `lacks`, `copied` or `uneven` and no journal item holds `again`. No release, install or signing step is part of this plan; the release session gets a note on ai-tools-alerts#5fry.

## Order and landing

Chunk 1, chunk 2, gate, merge `origin/main`, one independent whole-branch review (`git diff origin/main...HEAD`) with a same-model review in parallel, fixes, gate, merge main again if it moved, pull request, merge with the no-reply author, close the issue on the merge commit.
