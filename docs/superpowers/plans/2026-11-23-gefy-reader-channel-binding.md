# Plan: reader channel binding and the event date bound

Spec: `docs/superpowers/specs/2026-11-23-gefy-reader-channel-binding-design.md`. Kata: ai-tools-alerts#gefy. Branch `gefy-reader-channel-binding`, landed by pull request.

Tests first in each chunk: write the failing test, see it fail, then the code.

## Chunk 1: reader (aitools_alerts/pull.py)

- [ ] `tests/mirror_helpers.py`: `Mirror.post` adds one `h` tag (the feed channel's id from `spec/channels.json`, or the critical channel's when `files == ("critical.json",)`) unless the caller's tags already carry an `h` tag or pass `h=None`; add a `kind` argument (default 9). Existing tests keep passing.
- [ ] `tests/fixtures/mirror/`: regenerate `manifest.json`, `feed.json`, `critical.json` with new throwaway keys (secrets discarded) so every event has its channel's `h` tag and a date in the past (2026-11-01, so a pull with the real clock admits it; advisories' `posted_at` likewise); update the three public keys in `README.md`. Same content as today: one relay-bot critical in both files, one curator high in the feed.
- [ ] New tests in `tests/test_pull.py`:
  - `test_event_of_another_kind_is_not_an_advisory`: a curator kind 1 note with an alert block and the feed `h` tag; `dropped["not-channel-post"] == 1`, no thread, not stored.
  - `test_event_without_a_channel_tag_is_not_an_advisory`: parametrised over no `h` tag, two `h` tags, an `h` tag with another UUID, an `h` tag with one element.
  - `test_unbound_reply_cannot_retract_or_patch`: a curator `retract` and a `level: notice` reply with no `h` tag leave the thread critical and not retracted.
  - `test_stored_unbound_event_is_ignored_then_removed`: write the event straight into `State` (as v0.1.4 would have stored it); `advisories` is empty before any pull; gone from `st.events` after a pull.
  - `test_future_dated_event_is_refused`: bot event at `now + 601` dropped as `future-dated` and not stored, at `now + 600` kept.
  - `test_future_dated_event_does_not_hide_a_frozen_mirror`: the ek5q attack 4: a genuine event, then a bot event ten years ahead; `stale_since` reports the genuine event's time after 3 days.
  - `test_stored_future_event_only_leaves_the_stale_check`: an event ten years ahead written straight into `State` (as v0.1.4 stored it): still part of `advisories`, kept by the next pull, absent from `freshness`.
  - `test_clock_set_back_keeps_a_stored_retraction`: pull a root and a curator `retract` at `now`; pull again with `now - 3600` from a mirror that omits the reply; the thread is still retracted and the reply still stored.
  - `test_broken_channel_spec_is_a_pull_error`: `spec/channels.json` replaced (monkeypatched `schema.SPEC_DIR`) by a missing file, non-JSON, a non-UUID value; `res.error == "bad channel spec"`, events and manifest unchanged, `last_pull` records the error; `advisories` raises `ChannelSpecError`; `freshness` returns no newest event.
  - `tests/test_cli.py`: `test_broken_channel_spec_is_one_error_line` for `check`, `plan X`, `notify`, `run` and `pull`: exit 1, one `aitools-alerts:` line on stderr, no traceback.
- [ ] Tests that pull the in-memory mirror (events dated 2099) through the real clock (`tests/test_cli.py`, `tests/test_curator.py`, poster tests): pass `now` where the call takes one, else patch `pull.time.time` in the test module's fixture. List each touched test in the commit message.
- [ ] `pull.py`: `MAX_AHEAD_S = 600`; `ChannelSpecError(ValueError)`; `channel_ids()` (validated lowercase UUIDs from `schema.SPEC_DIR / "channels.json"`, read on each call: two small reads a run); `_bound(ev, channels)`.
- [ ] `_filter(stored, fetched, m, floor, res, channels, now)`: after the signature and role checks, `not-channel-post` (stored and fetched), then `future-dated` (fetched and not stored only), counted once per id like the other reasons.
- [ ] `_fetch`: load `channel_ids()` first; on `ChannelSpecError` fail with `bad channel spec` (added to `PULL_ERRORS`); `record` then stores no freshness times.
- [ ] `advisories(state, dropped=None)`: skip unbound events; raises `ChannelSpecError` on a broken spec. `freshness(state, now=None)`: skip unbound events and events dated after `now + MAX_AHEAD_S`; a broken spec gives no newest event. `stale_since` passes `now`.
- [ ] `cli.main`: for `pull`, `check`, `notify`, `plan` and `run`, call `pull.channel_ids()` once before the command runs, and catch `pull.ChannelSpecError` with the other one-line errors. A broken spec therefore ends every command with exactly one line and exit 1, before `cmd_run` can print a pull error and then fail again in `_matches`.
- [ ] `_fetch.record`: `freshness(state, now=now)`, so the recorded times use the pull's own clock.
- [ ] Existing tests whose dates contradict the bound, each kept with its original coverage by moving its clock, not by deleting it: `tests/test_pull.py` stale tests (the event at `T0 + 90 days` is pulled with a `now` after it; direct `freshness` calls pass their clock); `tests/mirror/test_export.py` near lines 540 (next-day root and retraction: `run_export` gets a `now` after them), 730 and 931 (year-9999 and year-10000 retractions: they test Atom date handling, so the events are fed to `atom_doc` directly, or the export runs with a `now` that admits the year-9999 one; the year-10000 one is asserted not published).
- [ ] `tests/test_pull.py::test_live_feed_fixture_is_read_whole`: the ten real signed events of `tests/fixtures/poster/live-feed-2026-11-07-to-11.json`, served as a mirror with the bundled real manifest under the pinned root: every event id is stored, none is dropped, and the threads equal those `threads_from` builds from the raw events (skip with a reason if a fixture event's key is not in the bundled manifest).
- [ ] `tests/test_pull.py::test_released_reader_reads_the_regenerated_fixture`: `git archive v0.1.4 aitools_alerts spec trust` into a temp directory and run that reader in a subprocess (`python3 -m aitools_alerts.cli pull` then `check`, with the fixture root override and a temp HOME) against the regenerated fixture mirror: exit 0, two stored events, no traceback. Skipped with a reason when the tag is not in the clone.
- [ ] `tests/mirror/test_export.py`: the `ev` helper adds the feed `h` tag by default, since `export_mirror._threads` reads through `pull.advisories`.
- [ ] Verify: `python3 -m pytest -q tests/test_pull.py tests/test_cli.py tests/test_curator.py tests/mirror tests/poster` all pass.

Acceptance: the new tests fail on `origin/main` and pass; no existing test is deleted; the live replay test (`tests/poster/test_live_replay.py`) passes unchanged.

## Chunk 2: exporter

- [ ] `tests/mirror/test_export.py`: `test_future_dated_event_is_not_published` (a bot event at `now + 601` is absent from `feed.json`, counted `future`, summary line prints `future=1`; at `now + 600` it is published). Rewrite `test_far_future_timestamp_kept_in_json_not_atom`: an event dated past 9999-12-31 is not published at all; keep its Atom assertions for an event inside the bound.
- [ ] `mirror/export_mirror.py`: `clean(rows, m, now)` counts and drops `future`; `export` passes `now`; `summary_line` prints it.
- [ ] `README.md` and `CHANGELOG.md`: one entry each (what the reader now refuses).
- [ ] Verify: `scripts/test-gate.sh`.

Acceptance: gate green; `git diff origin/main --stat` under 600 changed lines outside `docs/superpowers/` and the regenerated fixture.

## Rollback

Revert the merge commit. No state or wire format changes.
