# Plan: the poster lowers a level only on evidence held for 24 hours (ai-tools-alerts#ny5g)

Spec: `docs/superpowers/specs/2026-11-24-ny5g-lower-on-held-evidence-design.md`. One chunk, built test first. Line numbers are of `origin/main` at 64434bd.

## Chunk 1: recompute

### 1. `aitools_alerts/poster/ledger.py`

- [ ] `Entry` (line 38): three optional fields after `learned_sources`: `lowered: bool | None` (the thread has had a lowering), `changed: list | None` (times of its level changes in the last seven days), `floor: str | None` (the highest level readings of prose alone gave it).
- [ ] `_entry_ok` (line 75): `lowered`, when present, is a bool; `changed` a list of at most 50 ints; `floor` a level.
- [ ] `record_root` (line 217): optional `floor`, stored when it is a level.
- [ ] `record_reply` (line 294): when the level differs from the stored one, set `changed` to its entries younger than seven days plus `now`, and set `lowered` to True when `wire.is_lowering({"level": new}, was)`. Constant `QUIET = 7 * 86400` here; `recompute` reads it.
- [ ] New `entries()`: every entry, oldest first. New `learn_floor(root, level)`: store a level that differs (the caller passes the highest known).
- [ ] `_merged` (line 446): the ledger lends `exploited` only from entries not marked `lowered`. This is not the guard (merge runs before the journal drains, on a ledger that may not be reconciled): `Run.one` is, see section 5.

### 2. `aitools_alerts/poster/recompute.py` (new, about 190 lines)

Imports `ruleset`, `inputs` (read_json, write_json, `_catalog_ok`), `candidates.BOT_ID`, `ledger.QUIET`. Sends nothing; raises nothing a source's text can cause.

- [ ] Constants: `DWELL = 24 * 3600`, `MAX_GAP = 2 * 3600`, `SHRINK = 0.98`, `TRIP_MIN = 2`, `TRIP_SHARE = 0.2`, `RELEASE_AFTER = 7 * 86400`, `RELEASE = 2`, `MAX_LOWERED = 200`.
- [ ] `load(path) -> (state, replaced)` and `save(path, st)`: `{"kev": None | {"version", "peak", "at"}, "direct": None | sha256 text, "reported": None | date text, "recent": [times of lowerings in the last day], "listed": {root: [cveID]}, "dwell": {root: {"level", "version", "last": int | None, "held"}}, "lowered": [[id, level]], "tripped": None | {"since", "due"}}`. `load` checks every type; a missing file is the empty state; an unreadable or malformed one is the empty state with `replaced` true.
- [ ] `Copy(version, index, complete)` and `kev_copy(catalog, status, st, now, redirected) -> Copy | None`. None unless status is `ok` or `304`, `inputs._catalog_ok(catalog)`, and every item is a dict with a text `cveID` (the index key is the id trimmed and upper case). `digest` is the SHA-256 of the catalog as sorted JSON. On status `ok`, `st["direct"]` becomes the digest when `redirected is False`, else None; a 304 leaves it. `complete` needs: `st["direct"] == digest` (the cached body is the very body that came direct; one cached by a run that stopped before saying it was redirected does not match); `catalogVersion` text of 1 to 100 characters after trimming; a non-empty list; `count` an int equal to the list's length and to the number of distinct cveIDs; and the length at least `SHRINK` times the peak. Only a complete copy writes `st["kev"]`, and the peak only grows.
- [ ] `bare_ids(entry) -> set[str] | None`: over the published advisory's id and aliases and the ledger's `aliases`: a `BOT_ID` match gives its base id (CVE upper case; GHSA as `GHSA-` and lowercase); any other text makes the result None.
- [ ] `floor(entry, rs)`: `entry.floor` when it is a level; else the lower of `entry.level` and `rs.reading_cap`.
- [ ] `support(entry, scope, copy, rs) -> (found, known, listed, gone)` as the spec says; `listed` and `gone` are sets of the thread's CVE ids. `known` is False when `copy` is None or incomplete, `bare_ids` is None, any id's `ruleset.source_of` is not `kev`, or a listed CVE's reading raises `RulesetError` or gives the thread's product no support.
- [ ] `judge(entry, scope, copy, rs, st, now) -> ("raise", level) | ("due", level) | None`, as the spec's decision list; it alone writes `st["dwell"]` and `st["listed"]`. An unknown read, and a gone CVE never seen listed, clear the wait's `last`; time is added only when `last` is set and `0 <= now - last <= MAX_GAP`.
- [ ] `pause(st, root)`: clear the wait's `last`. `quiet(entry, now)`: no time in `entry.changed` younger than `QUIET`.
- [ ] `select(due, open_count, st, now) -> list`: the breaker. The count is `len(due)` plus the lowerings in `st["recent"]` younger than `TRIP_WINDOW` (24 h); what it returns is appended to `recent`. Count not more than `TRIP_MIN` or not more than `TRIP_SHARE * open_count`: clear `tripped`, return all. Else set `tripped` (keep `since`), and return `[]`, or the `RELEASE` oldest threads once `now - since >= RELEASE_AFTER`.

### 3. `aitools_alerts/poster/inputs.py`

- [ ] `Config.recompute_state` (after `owed_state`, line 136): `<ledger>.recompute.json`; added to `check_paths` before the mirror directory.
- [ ] `_item_ok` (line 334): a journal item may carry `floor`, a level.
- [ ] `urllib_fetch` (line 454): built on an opener with a redirect handler that follows as urllib does and remembers it; an answer that came through a redirect carries the header `REDIRECTED`. Optional `handlers` for tests. `fetch_kev` (line 500): optional `info` dict, set to `{"redirected": bool}` for a fetched catalog (a 304 sets nothing). The cache file is unchanged.

### 4. `aitools_alerts/poster/compose.py`

- [ ] `level_report(lowered, tripped, lang="en") -> str`: `""` when there is nothing to say; else a blank line and one line each: `Lowered since the last digest: <id> to <level>; ….` (at most 50 ids, then `and N more`) and `Level check: N threads are due to be lowered at once and are held back.` Japanese forms for `lang="ja"`. Only bare public ids are printed (`public_id`); the text passes `_guard`.

### 5. `aitools_alerts/poster/main.py`

- [ ] `gather` (line 976): optional `kev_out: dict | None = None`; the fetch branch stores `catalog`, `status` and `redirected` in it. The synthetic `--kev-file` branch stores nothing. Its three return values do not change.
- [ ] `Run`: a lazy `rc` property (`recompute.load(config.recompute_state)`, printing once when the file was replaced) and `save_rc()` (a write failure is a `LedgerError`, as for the journal).
- [ ] `_item` (line 108): optional `floor`, kept on the item only when given.
- [ ] `Run._level_items(entry, level)`: `compose.level_post(prev, level)`, one `reply` item per channel in `entry.channel_ids`, key id `<id>#level`, `adv` the thread's advisory with the new level, `root` the thread's root, no `ja`.
- [ ] `Run.observe(kev_out)`, called in `run` just before `r.drain()` (line 1121), so before any send: settle `rc["reported"]` (empty `lowered` when a digest of that date is in the journal, withheld, or is `state["digest_date"]`; then clear `reported`); `self.copy = recompute.kev_copy(...)`; `drop_unsent_lowerings()`; then `judge` every open exploited thread (step 2 below) and keep the verdicts on the run; save. All bookkeeping of the waits happens here, per thread, whatever the rest of the run does.
- [ ] `Run.drop_unsent_lowerings()`: over the journal items whose key holds `#level:`, grouped by `root`: a group with any item that is `sent` or pending is left whole; in the others, remove each item whose level is below its thread's ledger level (or whose thread is gone).
- [ ] `Run.recompute()`, called in `run` after the planning loop and before `r.digest` (line 1125): judge the threads this run posted (not in `observe`'s set); drop every verdict whose thread is gone, at another level than when judged, or busy now; then step 3. The judging itself (in `observe`, and here for new threads):
  1. Open threads are the ledger entries whose advisory id is not synthetic. Waits and listed marks of roots no longer in the ledger are dropped. A copy with a version that is not complete is said on stderr. A thread that is skipped (not exploited, out of scope, busy) has its wait paused.
  2. With or without a copy (without one every read is unknown, which each wait must be told): for each open thread with `exploited` and a scope that still resolves to its own name: skip when `self.busy(...)`; `judge`; collect raises and due lowerings.
  3. Filter due by `recompute.quiet`, pass through `select` with the number of threads judged, save the state, then enqueue every raise and every selected lowering. A `ValueError` from compose withholds that thread's change (`withheld` count), as elsewhere.
- [ ] `_record` (line 435): a root passes the item's `floor` to `record_root`; in the reply branch, when the item's level is below the entry's, append `[bare id, level]` to `rc["lowered"]` (once) and save, before `record_reply`.
- [ ] `one` (line 580): the entry is looked up before the level is computed; when it is marked `lowered` and the candidate is `exploited` with no `kev` reading, the flag is dropped for this planning. Then the candidate's prose floor, `rules._prose_level(replace(c, exploited=False), tier, verified, rs)[0]`; for a known thread `led.learn_floor(root, highest(floor, recompute.floor(entry, rs)))`; for a new one it is passed to `plan_new`, whose root item carries it.
- [ ] `plan_known` (line 714): when `entry.lowered` and `"level" in changes`, put `_level_items(entry, level)` after the copies, take `level` out of `changes`, and compose the reply against `replace(prev, level=level)`. `reply_post` gets `lowered=bool(entry.lowered)` always.
- [ ] `digest` (line 806): the report lines are appended to the English text inside the fit loop and to the Japanese text. With lowered ids: write `rc["reported"] = today` and save; journal the item; empty the list, clear `reported`, save; deliver.
- [ ] Module docstring: one paragraph on the recompute.

### 6. Tests

`tests/poster/test_recompute.py` (new). Unit tests for `kev_copy`, `support` and `floor`; the rest through `main.run` with the `env` fixture of `test_main.py`, one run an hour, a complete catalog of 200 other entries whose version changes every six hours:
- [ ] unit: `kev_copy` is None for status `unavailable` and `file` and for an entry that is not an object; incomplete for no version, no count, a count that disagrees, a cveID twice, an empty list; complete at 2% down; the peak does not fall and a copy 3% under it is incomplete 400 days on; what an incomplete copy lists is in its index.
- [ ] unit: `support` for listed, gone, no copy, a cut copy that lists it; unknown for a GHSA, `MAL-` or `LEAD-` id and for a CVE listed under another name; a ledger key (`CVE-…:slug`) reads as its CVE.
- [ ] unit: `floor` from the entry, and for an old entry `high` at critical, `notice` at notice.
- [ ] acceptance: after a KEV critical is posted, each of an empty body, 404, 429, 503, a half catalog, no version and a wrong count, every hour for 30 hours, sends no reply, leaves the level critical and begins no wait.
- [ ] an outage inside a wait adds no time: reads at hours 1 to 3 without the entry (two hours held), 503 from hour 4 to 39, a complete read at hour 40 that adds nothing, then one hour a read: 24 hours are held at hour 62, the 23rd complete read after the outage, and the lowering is sent there and not at 61; a new wait is lowered at its 25th hourly read (24 intervals); one 429 at hour 24 with 22 hours held delays the lowering to hour 27; a 503 at hour 24 in a run that stops at a failed send before the recompute does the same; complete reads alternating with 503 for 120 hours hold nothing; a poster that skips 38 hours gets nothing for them.
- [ ] a thread with a second CVE the catalog never listed is not lowered when both are absent, and is after the second has been seen once.
- [ ] unit: `judge` lowers a thread with floor `high` to high after 24 hourly complete reads and a version change, and leaves a thread already at its floor alone.
- [ ] a floor of high from the vendor's page is in the ledger after the first run and after a later candidate with no severity; that thread carries the page's GHSA id and is not lowered over ten days.
- [ ] acceptance: gone for a day of complete reads lowers once at hour 25 (one `level_post` in each channel, block exactly `{"level": "notice"}`, no Japanese reply, no `retract`), the entry has `lowered`, one `changed` time and `floor` notice, and 64 more hours send nothing.
- [ ] one unchanged `catalogVersion` for 39 hours does not lower; the next version does.
- [ ] a read that lists it starts the wait over.
- [ ] an old entry (no `floor`) is lowered to high and no further.
- [ ] a lost state file: absence lowers nothing for 56 hours; after one read that lists the entry, a day of absence lowers. A malformed state file is said on stderr and replaced.
- [ ] raise at once: the lowered thread, listed again, is raised in that run by a level-only reply in both channels, also from a cut catalog; gone again, it is lowered in the first run seven days after the raise and not one hour before.
- [ ] a source that toggles hourly for 72 hours moves nothing; one that is gone two days and back two, over sixteen days, never gives more than three level changes in any seven days, lowerings at least seven days apart, every raise in the first run that lists the entry.
- [ ] a lowering whose first send fails stays unsent when the next run gets a 404 from KEV, the journal is clear, and when the entry is then listed again nothing is lowered; a lowering delivered to one channel reaches the other in the next run although KEV answers 503, and is counted once.
- [ ] a whole catalog without the entry that came through a redirect lowers nothing in 30 hours; unit: `urllib_fetch` over a fake HTTPS handler marks an answer that followed a 302 and not a direct one, and `fetch_kev` reports it.
- [ ] hour 25, the critical channel's lowering acknowledged and `record_reply` failing: the next run, with KEV at 503, records it and sends the feed channel's; with a vendor candidate (fix, severity high) merged in that same run, the thread ends at high by a level-only reply and never at critical.
- [ ] the digest report with the recompute file left as by a stop after the journal write (`reported` is that digest's date) is not listed again; left as by a stop before it (`reported` names a date with no digest) it is listed in the next digest.
- [ ] three KEV threads due beside twenty other ledger threads: none is lowered.
- [ ] after a lowering, a raise and an unsent root, the only keys the 0.1.7 poster does not know are `lowered`, `changed`, `floor` on entries and `floor` on items (frozen key lists in the test).
- [ ] hour 24 with 22 hours held, in a run that stops at a failed send: a catalog that lists the CVE under another product's name delays the lowering to hour 27; one that lists it for this product drops the wait, and the lowering comes at hour 49.
- [ ] unit: `kev_copy` over a 304 is complete only for the body the last direct fetch returned; not for another body, not after a redirected fetch, not with a new state.
- [ ] four of five entries leaving one an hour: lowerings at hours 25, 26, 50, 50.
- [ ] breaker: with five KEV threads, four due at once lower none and the digest (English and Japanese) says so; two due lower both and the next digest lists them in one line, the one after does not; after seven days tripped two are lowered a run until none is left.
- [ ] a candidate with a fix and severity high for a lowered thread gives two replies in feed, the first level-only (`{"level": "high"}`, not critical: the exploited mark is not lent), the second with the fix and no level; the ledger's floor becomes high and nine more days of absence lower nothing.
- [ ] OpenSSH: the thread CVE-2026-123158 (`OpenBSD` / `OpenSSH`), its ledger entry stripped of `floor` as the live one is, stays critical through 48 hours of complete reads under ruleset version 1; with `ruleset.load` patched to a ruleset whose KEV rule gives `high`, it is lowered once to high 24 hours after the first read and stays there nine days.
- [ ] `level_report` prints bare ids only and is empty with nothing to say.

`tests/poster/test_ledger.py`: `record_reply` sets `lowered` and `changed` on a lowering, `changed` only on a raise, nothing when the level is equal, and drops times older than seven days; `record_root` and `learn_floor` keep a floor; an entry with a non-bool `lowered`, a non-level `floor` or a non-int in `changed` is refused; `merge` does not lend `exploited` from a lowered entry.

`tests/poster/test_inputs.py`: `check_paths` refuses a `kev_cache` equal to the recompute state; a journal item with `floor` loads, one with a `floor` that is not a level does not.

### 7. Docs

- [ ] `CHANGELOG.md`: Unreleased: what the poster now does, that a lowering is a level-only reply which no released reader applies (they keep the higher level), the new state file, what happens if CISA prunes the catalog by more than 2%, and the one-way rollback with its steps.

## Verification

- `python3 -m pytest tests/poster -q` while building; `python3 -m pytest -q` before the commit.
- `scripts/test-gate.sh` after the commit. If the public scan fails on other sessions' refs in the shared clone, compare `scripts/public-scan.sh --hit-ids` with the branch's objects and run the gate in a single-branch clone (recorded in the run record, without the scan's detail).

## Acceptance

Spec criteria 1 to 11. No existing test changes its assertions: every existing KEV fixture has no `catalogVersion`, so its reads are `unknown` and the recompute does nothing there.

## Rollback

With no entry marked `lowered`: revert the commit, delete `<ledger>.recompute.json`, and remove `lowered`, `changed` and `floor` from every ledger entry (a raise writes `changed` too) and `floor` from every journal item. After one: the spec's "Blast radius and rollback" steps, which put each lowered entry back at its highest level first.
