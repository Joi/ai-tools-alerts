# Plan: the poster reaches, sends and leaves the withdrawn state (ai-tools-alerts#kk2q)

Spec: `docs/superpowers/specs/2026-11-27-kk2q-poster-withdrawn-state-design.md`. One chunk, test first in each task. Line numbers are of the tree at dd4d195.

Run the tests of a task with `python3 -m pytest -q <file>`; the chunk's check is `scripts/test-gate.sh`.

## Chunk: poster

### Task 1: `recompute` reaches and leaves the state

Built after Task 2's `Entry.withdrawn` field, which its tests construct (plan review finding 1): the order of work is 2, 1, 3, 4, 5, 6.

Files: `aitools_alerts/poster/recompute.py`, `tests/poster/test_advisory_recompute.py`.

- [ ] Tests (unit, with `thread(...)`, `reads(...)`, `hourly(...)`):
  - a thread at high and one at notice, floor notice, reviewed advisory withdrawn: `judge` gives nothing for 24 hours of hourly whole reads, then `("due", "withdrawn")`; the wait record's level is `withdrawn`;
  - not `withdrawn` but `("due", <floor>)` or nothing, as today: floor high; an unreviewed withdrawn advisory (unknown: nothing); two counted advisory readings of which one is not withdrawn and does not name the product (due notice from high; nothing at notice); a KEV entry listed (held at its level);
  - a wait toward notice whose reads turn all-withdrawn starts over;
  - a failed read inside the wait pauses it;
  - `Entry(withdrawn=["feed"])`: a read that supports high gives `("raise", "high")` when the kept level is high, critical or notice; a withdrawn read gives nothing and leaves no wait; an unknown read gives nothing; a whole read that neither supports nor states the withdrawal gives `("raise", "notice")`; a floor of high gives `("raise", "high")` with the advisory still withdrawn; `raised` agrees on the first and the floor case and says None for the notice case;
  - `load`: a state with a `withdrawn` wait and a `["GHSA-…", "withdrawn"]` lowered row loads; other words are still refused.
- [ ] `recompute.py`: `withdrawal(counted)`; `_leaving(entry, found, known, counted, rs)`; `judge` (the withdrawn branch after `held`, and the target after `level`, line 384 on); `raised` (line 340); `_ok` (lines 94 and 97): `_LEVELS + (wire.WITHDRAWN,)` for a wait's level and a lowered row; module docstring's last paragraph.

Acceptance: the new tests pass; every existing test of `test_advisory_recompute.py`, `test_recompute.py`, `test_recompute_names.py` passes except the two that state today's "lowers to notice and stays" behaviour, which Task 4 rewrites.

### Task 2: the ledger's flag

Files: `aitools_alerts/poster/ledger.py`, `tests/poster/test_ledger.py`.

- [ ] Tests: `record_reply(..., {"feed": id}, withdrawn=True)` keeps `level` and `advisory`, sets `withdrawn` to `["feed"]` and `lowered`, appends one time to `changed`; the critical channel's call makes it `["critical", "feed"]` (sorted) and appends none; `withdrawn=False` for one channel at the same level removes that channel and appends a time; for the second channel at the same `now` it removes the key and appends none; at a later `now` it appends again; at another level the first call appends one time, not two; `withdrawn=None` on a withdrawn entry leaves the list; an entry whose `withdrawn` is `true`, `[]`, a string or a list naming a channel the thread has no root in is malformed; an entry without the key loads.
- [ ] `ledger.py`: `Entry.withdrawn: list | None = None` (after `root_ids`, line 89); `_entry_ok` (line 131); `record_reply` (line 379).

### Task 3: the posts

Files: `aitools_alerts/poster/compose.py`, `tests/poster/test_compose.py`.

- [ ] Tests: `withdrawal_post()` ends in the block exactly `{"level":"withdrawn"}`, `wire.is_withdrawal` of it, `schema.parse_post` of it is None and `compose.parse_reply(text, prev)` is None (no level a reader of the schema takes); `level_post(prev, prev.level)` still raises and `level_post(prev, prev.level, again=True)` gives `{"level": prev.level}`; `level_report([[G, "withdrawn"], [G2, "notice"]], None)` names both in English and Japanese, and still drops an unknown word.
- [ ] `compose.py`: `WITHDRAWAL` line and `withdrawal_post()` beside `level_post` (line 692); `again` on `level_post`; `level_report` (line 715).

### Task 4: `main` sends, records and guards

Files: `aitools_alerts/poster/main.py`, `tests/poster/test_advisory_recompute.py`, `tests/poster/test_copy_on_raise.py` or `test_renew.py` where their fixtures fit, `tests/poster/test_recompute.py` (`levels` helper).

- [ ] Tests through `main.run` (`post`, `hours`, `entries`, `state` of `test_advisory_recompute.py`; one collector, `moves(relay, channel)`, of every level-only block, a level or `withdrawn`, since `levels` and `hours` keep only text that begins `Level is now` and would miss the withdrawal in a toggle count; the toggle tests assert the first two replies, `(25, "withdrawn")` and `(48, "high")`, so a poster that sends nothing cannot pass):
  - a reviewed advisory at high, withdrawn: nothing for 24 hours, at hour 25 one reply per channel with the withdrawal block and a claim tag whose level is `none`; the ledger keeps `level` high and has `withdrawn`, `lowered`, one new `changed` time; nothing more for 35 hours; the recompute state's `lowered` holds `[G, "withdrawn"]` and the next digest's level line names it;
  - published again at high: the next run sends `{"level":"high"}` (equal to the kept level), the flag is gone, the reply's claim is of level high;
  - the malware thread (critical, two channels): the withdrawal in both channels, then `{"level":"critical"}` in both (rewrites `test_a_malware_advisory_withdrawn_and_published_again_returns_to_critical`);
  - published again not naming the product: `{"level":"notice"}`;
  - `test_a_withdrawn_unreviewed_advisory_lowers_nothing` also asserts no `withdrawn` key;
  - toggles: withdrawn every other hour for a week, no reply; withdrawn every other two days for 16 days, at most three replies in any seven days;
  - a thread with floor high, withdrawn: lowered to high or kept, never the withdrawal (rewrites `..._lowers_to_notice_and_stays` into the floor case and the state case);
  - a withdrawn thread at critical with a feed root only gets no critical copy (`copies`), is skipped by `_renew` (no renewal, no step, not in `unrenewed`) and by the digest's root list;
  - a candidate at a higher level for a withdrawn thread: `plan_known` plans no level change and no copy; a candidate with a new fix replies without a level;
  - a withdrawal one channel refused to acknowledge (send failed after the first channel recorded it) is sent to the second channel by the next run; one no channel has is dropped when the advisory is published again before it is sent;
  - `yields`: a raise passes an unsent withdrawal;
  - the run that records a withdrawal (a journaled one replayed while the advisory is already published again) sends no reply that ends it; the next run does, an hour later (the fake relay signs no events and dates none, so the run is the test's clock); and in `tests/test_wire_compat.py`, with events signed as the poster signs them, `pull.threads_from` reads the two replies by date in both orders, which is what the rule rests on;
  - a critical thread withdrawn in both channels, published again, the critical channel refusing the level reply: the ledger lists `["critical"]`, keeps `level`, and after the journal gave the reply up (`retried`, refused again) a later run sends `{"level":"critical"}` to the critical channel only, and the key is gone; the same with the level read being high while the feed left at critical: the critical channel is sent critical, not high.
- [ ] `main.py`: `Run._patch` (static, beside `_tag`, line 236); `_record` reply branch (lines 905 to 925; it adds the root to `self.withdrew`, a set made in `__init__`); `_withdrawal_items`, and `again` and `channels` in `_level_items` (line 1486); `drop_unsent_lowerings` (line 1513); `recompute` (line 1640: skip a raise of a root in `self.withdrew`; for a withdrawn thread whose list is partial and whose verdict is not above `e.level`, the level is `e.level` and the channels are the listed ones); `yields.lesser` (line 603); `_clears` (line 625); `copies` (line 1686); `digest` (line 1934); `_renew` (line 1819); `plan_known` (lines 1375 and 1436).

### Task 4b: tests that state today's behaviour, and the catalog (plan review findings 2 and 3)

Files: `tests/poster/test_copy_on_raise.py`, `tests/poster/test_claims.py`, `aitools_alerts/poster/catalog.py`, `tests/poster/test_catalog.py`.

- [ ] `test_a_raise_on_a_thread_with_both_channels_sends_no_copy` (line 76) and `test_a_withdrawal_and_the_raise_after_it_each_carry_their_claim_in_every_channel` (line 136) expect the withdrawal block in both channels where they expected notice; `test_claims.level_claims` also takes a reply that begins with `compose.WITHDRAWAL`.
- [ ] `catalog.snapshot` gives `{key: None}` for a withdrawn thread and `catalog.remember` takes that key out of the inventory, sent or not, so neither a block that waited unsent nor one a fix changed is posted at the kept level; the thread is catalogued anew when it leaves the state. Test with the catalog lane on: an unsent block, the thread withdrawn, a fix learned, no catalog send; the state ended, one catalog root with the fix.

### Task 5: the checkpoint keeps listing a withdrawn thread

Files: `aitools_alerts/poster/signer.py`, `tests/poster/test_signer.py`.

- [ ] Tests (the `_lapsed(m)` fixtures at line 908): a claimed root at critical whose renewals ran out is lapsed; the same thread with a relay-bot withdrawal reply is not; with a later relay-bot reply naming critical and no renewal since, it is lapsed again once that reply's date no longer holds critical.
- [ ] `signer.lapsed` (line 256): skip a thread whose `offered` is `pull.WITHDRAWN`; docstring.

### Task 6: the poster's own events on released readers, and the documents

Files: `tests/test_wire_compat.py`, `spec/wire.md`, `CHANGELOG.md`, module docstrings.

- [ ] `test_a_relay_bot_withdrawal_is_refused_by_every_released_reader` builds the reply's text with `compose.withdrawal_post()` and its tag with `rules.claim_text` of a withdrawn reading. A second test for every released tag: root, the poster's withdrawal, then `compose.level_post(prev, prev.level, again=True)`: the alert is shown at its level throughout; this reader ends the withdrawal (`offered` is None after the level reply). Both run on a root without a claim and on a root with one (within the claim's life the alert is shown at its level on the readers that compute expiry too). `v0.3.0` joins the tag list as its own group (`WITHDRAWAL_READERS`): it reads the withdrawal and, with no source check in the harness, shows the alert as the others do. The tag is required: if it cannot run, the compatibility check is not done and the run says so.
- [ ] `spec/wire.md`: the last paragraph of "A withdrawal" says what the poster sends, when, and how it leaves; the renewal bullet and the checkpoint paragraph say what a withdrawn thread gets. `CHANGELOG.md`: an `Unreleased` entry with the cost to readers 0.1.8 to 0.2.1 and the rollback note. `recompute.py` and `signer.py` docstrings.

## Verification

- `python3 -m pytest -q tests/poster tests/test_wire_compat.py tests/test_wire.py` while building.
- `scripts/test-gate.sh` (the public scan, then the whole suite) in a clone that holds this branch alone, before the review and at the final head.

## Acceptance

The spec's eight success criteria, each by a test named above: 1 and 2 (Task 4 first three, Task 6), 3 (Task 4 fifth), 4 (Task 4 toggles), 5 (Task 6), 6 (Task 4 guards, Task 5), 7 (Tasks 1 and 4), 8 (no test waits on input; nothing is added to `pending` or review).

## Rollback

Revert the merge while no thread is withdrawn. After one is, see the spec's "Blast radius and rollback".

## Landing

Merge `origin/main` before the review and again before the merge. One independent whole-branch review. A pull request, merged with `gh pr merge <n> --merge --author-email` and the no-reply address. A comment on ai-tools-alerts#5fry for the release session. No install, signing or release here.
