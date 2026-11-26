# Plan: a relay-bot narrowing is checked by the member like a lowering (ai-tools-alerts#swfe)

Spec: `docs/superpowers/specs/2026-11-26-swfe-narrowing-checked-like-lowering-design.md`. Line numbers are of main at 8f91677.

Order: each chunk is test first, then code, then `python3 -m pytest -q <its test files>`. One commit per chunk. The whole gate runs once, after chunk 4, in a clone holding only this branch (`scripts/test-gate.sh`).

## Chunk 1: the reader keeps a narrowing and `standing` applies it

`aitools_alerts/pull.py`

- [ ] `Thread` (line 119): add `narrowed: tuple | None = None`, `narrowed_by: str | None = None`, `narrowings: tuple = ()`, `narrow_refused: bool = False`, `narrow_waiting: bool = False`, with the comment block of the tavj fields as the model.
- [ ] New `narrow_key(root_id, products) -> str`: SHA-256 hex of the JSON of `[root_id, [asdict(p) for p in products]]` with sorted keys. In `__all__`.
- [ ] `_Hold` (line 969): slots and `__init__` gain `narrowed`, `narrowed_by` (both None) and `keys` (a dict used as an ordered set of `narrow_key`s).
- [ ] New `_narrowing(adv, p) -> tuple | None`, beside `_bot_patch` (line 1010): None unless `"products" in p`; validate the block's list alone on `adv` (`schema.validate` of `adv` with its lists cut to `LIST_LIMITS`, `products` replaced, `posted_by` kept; any exception gives None); `()` when `len(adv.products) <= _JOIN_SCAN` and `all(_covered(e, stated) for e in adv.products)`; else `tuple(stated)`. So a flooded widest state, which is not compared entry by entry, takes every valid list as an offer.
- [ ] `_bot_reply` (line 1033): after the level-only branch and before `_bot_patch`, compute `offer = _narrowing(h.wide, p)` against the widest state as it is before this reply joins. When it is not None and differs from `h.narrowed`: a non-empty offer sets `h.narrowed, h.narrowed_by = offer, ev["id"]` and adds its key (the root id is `t[6][0]`) to `h.keys`; `()` sets both to None. The same list again keeps the first reply's id. A block whose `products` do not validate changes neither.
- [ ] `threads_from`, the curator branch (line 1150): a curator block that names `products` and applied sets `h.narrowed = h.narrowed_by = None`.
- [ ] `threads_from`, the `hold` dict (line 1188): `narrowed`, `narrowed_by` and `narrowings` (the keys, a tuple).
- [ ] `offers` (line 1266): record `t.narrowed_by` under the same rule as `t.offered_by` (listed, root listed, earlier of recorded time and `now`).
- [ ] `_stood` (line 1287): take the reply id as a parameter; the lowering call passes `t.offered_by` and keeps its `t.offered not in (None, NONE)` condition.
- [ ] `standing` (line 1294): rename the present body `_level_standing` unchanged; `standing` calls it and then `_narrow(t, out, now, check, since)`:
  - `out` unchanged when `t.narrowed is None`, `t.wide is None`, `out.retracted`, or a hold is in force (`_held(t, now)`);
  - `said = check.narrowing(widest(t), t.narrowed)` when `check` has that attribute, else None; an exception in it is not caught (the CLI's check does not raise);
  - True, or None and stood: `replace(out, adv=replace(out.adv, products=list(t.narrowed)))`;
  - else `replace(out, narrow_refused=said is False, narrow_waiting=said is None and since is not None and t.narrowed_by in since)`.
  The early return of `_level_standing` (`t.held_until is None and t.offered is None`) returns `t`, whose `adv` is the widest state: `_narrow` then works on it.
- [ ] Docstrings: `_apply_patch`, `advisories`, `standing`, `offers`, the module text where it says a reply never narrows.

Tests, new file `tests/test_narrowing.py` (helpers from `tests/test_curator_hold.py` and `tests/test_unchecked_lowering.py`):

- a narrower list is kept as `narrowed` with its reply's id, and `wide`, `adv` and `widest` are unchanged;
- `narrowings` holds the key of every list the thread published, the ended ones too; the key depends on the root and on the list;
- on a widest state past `_JOIN_SCAN` entries a valid list is still an offer, and `standing` applies it;
- the same list again keeps the first id; another narrower list takes the new id;
- a list that covers the widest state ends the offer; an invalid `products` block changes nothing; a curator's `products` block ends it;
- a relay-bot narrowing on a curator's own thread gives no offer;
- `standing` with a check whose `narrowing` says True, False, None; with and without `since`; at 72 hours less one second and at 72 hours; with `now` None;
- during a curator's hold the narrowing is not applied, and it is after the hold;
- a level lowering and a narrowing on one thread are decided separately;
- `offers` records the narrowing reply only while a checkpoint lists it and its root, and drops it when the offer ends;
- `tests/test_bot_patch.py` passes unchanged (the join and the `narrowing` count).

Acceptance: `python3 -m pytest -q tests/test_narrowing.py tests/test_bot_patch.py tests/test_unchecked_lowering.py tests/test_curator_hold.py tests/test_pull.py`.

## Chunk 2: the source check states ranges and answers `narrowing`

`aitools_alerts/verify.py`

- [ ] `VERSION = 4` (line 57).
- [ ] New `_pair(range, first_patched) -> list | None`: the range with whitespace removed; None when the range is None, or `versions.check("0", range, fixed) is None`; else `[range, fixed]`. Import `versions`.
- [ ] `_record` (line 295): a `ranges` dict. For `ghsa`: for each package of the reading, `rs.read(source, {**fields, "packages": [pkg]})` names the products it binds to; append `_pair(...)`, which may be None, to each product's list, each distinct item once. For `osv`: every product the reading binds to has `[None]`. For `kev`: `{}`.
- [ ] `_shape_ok` (line 519): a source record has exactly the old keys and `ranges`; `ranges` is a dict of strings to lists of at most `MAX_PAIRS` items, each None or a two-item list that `_pair` returns unchanged. A result entry has `at`, `products`, and optionally both `ranges` (same value shape) and `whole` (bool).
- [ ] `_Run.thread` (line 684): set `self.stated = {"ranges": ..., "whole": complete}`: per product, the items of every counted record that is an authority for it (`support[p][1]`), each distinct item once, cut to `MAX_PAIRS`. On the early return (first read failed) `self.stated = None`.
- [ ] `MAX_PAIRS = (MAX_ALIASES + 1) * ruleset.MAX_PACKAGES`, beside `MAX_CACHE_BYTES`: the most one product of one thread can have (the first id and at most `MAX_ALIASES` more, each reading at most `MAX_PACKAGES` entries). Nothing is cut to it; it is only the shape check's bound.
- [ ] `run` (line 786): every write goes through a new `_entry(now, products, stated, held, whole)`. It stores the ranges this run read (`job.stated`) and, when it read none, keeps the ranges the entry before had. `whole` is true only on the normal write when the products written are the ones this run computed (`_settled` returned them) and the thread's reads were whole. A kept contradiction of the level over a failed read, and both budget-exhausted writes, store `whole` false: a new time never renews a confirmation, and what a cut-short run read still refuses.
- [ ] New `narrowing(adv, products, cache, now) -> bool | None`, after `lowering`, as the spec's "The comparison" says: rules 1 to 4, entries grouped by name once so a flooded list costs its length, not its square. In `__all__`.

Tests, new file `tests/test_verify_narrowing.py` (helpers from `tests/test_verify.py`):

- `_record` keeps `["<9.9.9", "9.9.9"]` for Claude Code from the fixture advisory; an unreadable range and a missing range give a None item beside the readable ones; an OSV record gives `[None]`; a KEV record gives `{}`;
- one unreadable range beside a readable one: a list below the readable range is still False, the advisory's own list is None;
- two entries for one product, one the advisory's and one with a higher `fixed`: False;
- an entry in another ecosystem, alone and beside the thread's own ecosystem entry the thread held: False, never True;
- an entry under a name the thread does not carry: None;
- a cache of version 3, and one whose `ranges` hold a string no `_pair` returns, load empty;
- `narrowing`: the advisory's own entry True; `fixed` above False; `fixed` below False; a shorter range False; a wider lower bound True; `fixed` absent in the entry True; a product dropped that the source names False; a product dropped that only KEV names None; an attacker-writable advisory (not `lowers`) None; a result 49 hours old None for True and still False for False; a partial read (`whole` false) None for True and False for False; `cache` None gives None; an unchanged product needs no source.

- a level contradiction kept over three days of failed reads: the entry's time moves, `whole` is false, the advisory's own list is None and a shorter one still False;
- a run cut short by the request budget after the advisory arrived (with and without an earlier whole result): the ranges are kept, `whole` is false, a shorter list is False, the advisory's own list None;
- `MAX_PAIRS` is the product of the two limits.

Existing tests that pin what this chunk changes on purpose, amended in this chunk: `tests/test_verify.py::test_nothing_a_source_says_is_stored` (it asserted that `9.9.9` is not in the cache and that a source record has five keys; it now asserts that the only version text kept is the advisory's pair, and still that no sentinel, vector or package name is); `tests/test_curator_hold_cli.py::test_a_refresh_the_budget_cut_short_does_not_pass_for_a_fresh_confirmation` (the pinned entry gains `ranges` and `whole` false).

Acceptance: `python3 -m pytest -q tests/test_verify_narrowing.py tests/test_verify.py tests/test_unchecked_lowering.py tests/test_curator_hold_cli.py`.

## Chunk 3: the CLI

`aitools_alerts/cli.py`

- [ ] `NARROW_WAITING_LINE` beside `WAITING_LINE` (line 56).
- [ ] `Entry` (line 179): `narrow_refused: bool = False`, `narrow_waiting: bool = False`; `_entries` fills them with `any(...)` over the copies.
- [ ] `_matches` (line 265): `wide` covers threads with `pull.asks(t)` or a narrowing; `a.asked` gains `(w, here)` for each narrowing thread.
- [ ] `_matches` (line 257): after `pull.active`, a thread whose standing list's key is in `st.refused` gets `narrow_refused=True` (the check may read nothing today).
- [ ] `_note_offers.step` (line 304): the lowering's logic is unchanged and no longer skips the rest of the loop. `refused` is first cut to the root ids and the `narrowings` keys of the stored threads. For a thread with `t.narrowed_by in want`: the key is `pull.narrow_key(t.root_id, t.narrowed)`; False from `check.narrowing` adds it, True removes it; while it is there the reply's time is `now`. `held` (line 331) also names `t.narrowed_by` of every thread whose standing list's key is in `st.refused`.
- [ ] `cmd_run` (lines 876 and 885): one local function gives `(root id, level, repr of the products)` per thread, used for `before` and for the comparison after the source check, so an unchanged run still prints one listing.
- [ ] `_matches`: `a.asked` also gains the state the narrowing would leave (`t.wide` with the published list). It is read from the same ids in the same run, so an alert is not "not verified" after its narrowing applied.
- [ ] `_Check.narrowing` (line 335); `_lowering_check` (line 356) builds a check when any thread has `pull.asks(t)` or a narrowing.
- [ ] `_source_lines` (line 434): the refusal line comes from the entries it is given (`threads`, which `_matches` marked from the refusal memory), not from the loop at line 451 that rebuilds threads without that memory. It is produced before the return for a missing cache, so it prints with `verify = "off"` too. A CLI the root calls too old, or whose ruleset is out of date, prints none, as for every source-check line.
- [ ] `cmd_verify` (line 484): the lowerings line only when a lowering was asked about; the narrowings line when one was.
- [ ] `_match_json` (line 501): `narrowing_refused`, `narrowing_waits`.
- [ ] `cmd_check` (line 593): the waiting line.

Tests, new file `tests/test_narrowing_cli.py` (helpers from `tests/test_unverified_cli.py`), the acceptance cases first:

1. the reply raises `fixed` past the advisory's: the wider entry stays, the refusal line prints in `verify` and `check`, `narrowing_refused` is true, and 30 days of checkpoints apply nothing;
2. the reply matches the advisory: applied in the `run` that reads the source; a member on a version at or past the fix no longer matches;
3. the fetch failing (and `verify = "off"`): the wider entry and `narrowing_waits` until checkpoints 72 hours apart, then applied; a reply backdated by its signer waits the same;
4. refused; then the corrected list is confirmed and applied; then the cache is deleted, every read fails and the refused list is sent again: not applied after 72 hours and more, and reported refused;
5. a refused list does not stop another list of the thread, whose own 72 hours run with the reads failing; a refused lowering does not stop the narrowing, and the other way round;
5a. a correct entry sent with one whose `fixed` is past the advisory's is refused; an entry moved to another ecosystem is refused;
5b. `run` on a machine whose version the confirmed list no longer covers prints "After the source check:" and no match; a run in which nothing changed prints one listing;
5c. the same list, the same reply and the same cache, and only the source changes to state it: the next daily re-read by `run` forgets the refusal and applies the list, with no other command;
5d. a remembered refusal is printed after the check is turned off;
6. the hook's command (`run --json`) reads no source for a narrowing;
7. a CLI the root calls too old, or whose ruleset is out of date, applies no narrowing unchecked.

Acceptance: `python3 -m pytest -q tests/test_narrowing_cli.py tests/test_unverified_cli.py tests/test_curator_hold_cli.py tests/test_verify_cli.py tests/test_cli.py`.

## Chunk 4: the released readers and the documents

- [ ] `tests/test_wire_compat.py`: a test, for v0.1.7, v0.2.0 and v0.2.1, that after a relay-bot reply narrowing `products` the released reader still shows the wider entry and still matches the installation, and that this reader shows the same until the narrowing is confirmed or has stood. A control for v0.1.4 and v0.1.6 under "what the format avoids" is not possible (nothing avoids it); `spec/wire.md` says what they do.
- [ ] `spec/wire.md` (line 63): replace the "not covered here" paragraph.
- [ ] `README.md`: the member-facing sentence beside the lowering's, and every sentence that says the source's range is not compared, or that nothing but ETags and ids is kept from a source, corrected.
- [ ] `CHANGELOG.md`: an Unreleased entry in the form of the tavj entry: what changes, what stays open.
- [ ] Run record: chunks ticked, scorecards.

Acceptance: `python3 -m pytest -q tests/test_wire_compat.py`, then `scripts/test-gate.sh` in a single-branch clone of this branch.

## Chunk 5: what the code review changed

One commit after the whole-branch review at f418801, covered by one delta pass.

- [ ] `pull.narrow_key(root_id, products=())`: over the sorted set of entries; with no products, the thread's mark.
- [ ] `verify.narrowing(adv, products, cache, now, shown=None, *, whole=False)`: compared with `shown` (the thread's `wide` entries), grouped by case-folded name; rule 4 folds into rule 2; `whole=True` answers True on a fresh whole read that does not contradict.
- [ ] `pull.standing` and the CLI pass `t.wide.products` as `shown`.
- [ ] `cli._note_offers`: a False adds the key and the mark; on a marked thread a list's time stays at the newest checkpoint until its check is True or `whole`; under the lock the threads, the checkpoint and the check are rebuilt from the refreshed state and left in `a.raw`, `a.clock`, `a.check`, which `_matches` then uses.
- [ ] Tests: the key of a list twice over and reordered; a refused list twice over, with a respelled copy and respelled, behind a lost cache and failing reads; a marked thread's other list waits only behind whole reads and then applies with nobody acting; the planted `fixed`, in `verify`, in the reader and end to end; a respelled entry held to the advisory; the older command that keeps a newer refusal; the older confirmation that does not apply over one; a retracted thread whose hold lapsed keeps its products.

Acceptance: the three narrowing test files and the suites of chunks 1 to 3; then the gate in a single-branch clone.

## After the chunks

- Merge `origin/main` before the whole-branch review and again before the merge (sibling sessions touch `pull.py`, `verify.py`, `cli.py`).
- One independent whole-branch review of `git diff origin/main...HEAD`; findings handled under the review cycle; evidence line on the issue.
- Comment on ai-tools-alerts#fa5a for the release session (no install step beyond the release itself; `verify.json` is rebuilt once).
- Comment on ai-tools-alerts#2wa6: what this delivers of it.
- Follow-up issue: a relay-bot widening of `fixed` past the source is flagged.
- Pull request; merge with the no-reply author address; check the merge commit's author; close the issue on it.

## Rollback

Revert the merge commit. No state migration: `verify.json` of version 4 is dropped by the older reader and rebuilt; `unverified.json` keeps its shape.
