# Reader: channel binding and a bound on event dates

Kata: ai-tools-alerts#gefy, piece 1 of ai-tools-alerts#ek5q. Source: the adversarial review of 2026-11-23 (`docs/security/2026-11-23-adversarial-review.md` on branch `mythos-adversarial-review`), findings H2 (exploit 4) and M3.

## Problem

1. **An event is not bound to a kind or a channel (M3).** The exporter keeps kind 9 events of the two alert channels. The reader checks neither (`aitools_alerts/pull.py`, `_filter` and `threads_from`). Whoever controls what the mirror serves can serve any event a manifest key ever signed anywhere, for example a kind 1 note that quotes an alert block, and the reader takes it for an alert, a patch or a retraction.
2. **`created_at` has no upper bound (H2, exploit 4).** One event from the relay-bot key dated ten years ahead becomes the newest signed event for good, so `stale_since` never reports a frozen mirror again until the manifest itself is 90 days old.
The issue's last fix item, "list every retraction in the manifest", is not built: see Alternatives.

## Success criteria

- A kind 1 event with an alert block, signed by a curator key, served by the mirror: not an advisory, counted as dropped.
- A kind 9 event with no `h` tag, with two `h` tags, or with an `h` tag that names no channel in `spec/channels.json`: the same.
- The same events already in a state written by v0.1.4: not an advisory, and removed at the next successful pull.
- A fetched event the reader has not stored, dated more than 600 seconds after the reader's clock: refused, counted, never stored; `stale_since` still reports a mirror frozen for more than 3 days.
- An event already in stored state is never dropped or ignored for its date: a clock that jumps back does not undo a stored retraction or amendment. It only takes no part in the stale check while it is ahead of the clock, so an event v0.1.4 stored from attack 4 no longer hides a frozen mirror.
- The exporter does not publish an event dated more than 600 seconds after its own clock, so a released v0.1.4 reader is not served one by an honest mirror.
- A damaged `spec/channels.json`: `pull` fails with `bad channel spec` and changes no state; `check`, `plan`, `notify` and `run` print one error line and exit 1; none raises a traceback.
- The live feed fixture (`tests/fixtures/poster/live-feed-2026-11-07-to-11.json`, real events, each with one `h` tag) reads exactly as before.
- `scripts/test-gate.sh` passes.

## Approach

### Channel binding (reader)

`pull.py` gains `channel_ids()`: the two values of `spec/channels.json`, loaded once from the packaged `spec/` directory (`schema.SPEC_DIR`), each required to be a lowercase UUID. A missing or malformed file raises `pull.ChannelSpecError` (a `ValueError`): the package is damaged and no event can be bound. `_fetch` loads the ids before anything else and fails the pull with `bad channel spec` (added to `PULL_ERRORS`), recording the failure without computing freshness. `advisories` raises it; `freshness` returns no newest event. `cli.main` catches `ChannelSpecError` beside `StateError` and prints one line, exit 1.

`pull._bound(ev, channels)` is true when `ev["kind"] == 9` and the tags whose first element is `h` and that have a second element are exactly one, and its value is in `channels`. NIP-29 puts the group id in `h`; the relay sets it on every channel message, and the curator command and the poster already write it (`curator._sign`, `poster.main.curator_events` reads it).

It is applied in two places, because state written by v0.1.4 can already hold unbound events:

- `_filter` (every pull, stored and fetched events alike): an unbound event is dropped and counted as `not-channel-post`.
- `advisories(state)` and `freshness(state)` (every read): unbound stored events are skipped, so `check` after an upgrade and before the first pull is already correct. Binding does not depend on the clock, so skipping here can never drop a genuine channel event.

`threads_from(events, m)` itself does not change: the exporter and the poster call it with events they selected themselves (the exporter by the database's `channel_id` and kind 9).

The reader does not compare the `h` tag with the file an event came in (`feed.json` or `critical.json`): both files are one event set to the reader (`_filter` de-duplicates across them), and a curator reply in one channel may amend a root in the other.

### Bound on event dates (reader)

`MAX_AHEAD_S = 600`. The bound is an admission check: in `_filter`, a fetched event that is not already stored and has `created_at > now + MAX_AHEAD_S` is dropped and counted as `future-dated`. A stored event is kept whatever the clock says now. If stored events were re-judged against the clock, a clock set back by an hour would turn a recent stored retraction into a "future" event, re-activate the withdrawn alert and delete the retraction at the next pull; a mirror withholding that reply could then keep the alert alive. Admission is the only moment the bound can be applied without that risk.

`freshness(state, now=None)` leaves events dated after `now + MAX_AHEAD_S` out of the newest-event time (it changes nothing else), and `stale_since` passes its `now`. So a future-dated event that v0.1.4 already stored stays a part of its thread, as it is today, but no longer silences the stale warning.

Ten minutes: the issue asks for "a few minutes"; the design review (comments on ai-tools-alerts#h29n, rule 7) names 10 minutes for the same bound on the checkpoint, and one number for both is simpler to explain.

A member whose clock is far behind refuses genuine events as future-dated. They are counted in the pull summary (`dropped: future-dated N`) and stored at the first pull after the clock is right. A new alert is delayed on that machine, never lost, and the checkpoint of piece 3 makes the gap an explicit error.

### Exporter

`clean(rows, m, now)` drops a verified kind 9 poster event dated more than `MAX_AHEAD_S` after `now` and counts it as `future`; the summary line prints the count. The event stays in the relay's database and is published once its date is no longer ahead. The existing test `test_far_future_timestamp_kept_in_json_not_atom` asserts the opposite for dates past 9999-12-31 and is rewritten: such an event is not published. A bot key holder who dates an event ahead then reaches no reader through an honest mirror, including v0.1.4 readers, which have no bound.

## Alternatives considered

- **Bind in `threads_from`.** Rejected: the exporter and poster call it with pre-selected events and tests construct events without tags; binding at the reader's two entry points is the attack surface.
- **Refuse the whole pull when one event is future-dated.** Rejected: one bad event from a stolen bot key would freeze every reader. Dropping it loses nothing genuine.
- **Require the `h` tag to match the file.** Rejected: see above; it adds a failure mode and stops no attack, since both channels carry the same trust.
- **Re-judge stored events against the clock on every read.** Rejected: see the clock-rollback case above.
- **List every retraction in the manifest (the issue's last fix item), by a `--retract-from` sweep in `scripts/sign-manifest.py`.** Not built. A curator's `retract` reply withdraws one thread; the manifest's `retracted` list withdraws every thread that has ever carried the id or an alias, for every reader including v0.1.4. A sweep would silently widen each thread retraction into a global one and suppress a corrected re-post under the same id. The sweep's input (the capped mirror files) is also not a complete history, and an `--unretract` would be undone by the next sweep. The gap the item names, a mirror withholding a curator's retraction from a new reader, is closed by the checkpoint of pieces 2 to 4, which lists the retraction event itself. `--retract ID` by hand stays for a retraction that must outlive its signer's key.

## Compatibility with v0.1.4 readers

Nothing on the wire changes. Released readers keep working and gain only the exporter's refusal to publish future-dated events. `tests/test_pull.py` keeps a test that the regenerated fixture mirror, whose events now carry `h` tags, is read by the same rules v0.1.4 applies (signature, manifest key, block), since v0.1.4 ignores tags it does not know.

## Blast radius and rollback

- Reader: events without a channel `h` tag vanish from advisories. The relay sets the tag on every channel message (all ten events of the live fixture carry it), so no real alert is affected. The synthetic test mirror (`tests/fixtures/mirror/`) has events with no tags and dated 2099; it is regenerated with new throwaway keys, channel `h` tags and dates in the past. The in-memory test mirror (`tests/mirror_helpers.py`) tags every event with its channel, and tests that pull its 2099-dated events through the real clock pass a `now` or patch the clock.
- Rollback: revert the commit. No state migration: dropped events are fetched again at the next pull by a reverted reader.

## Assumes

- Every alert-channel event the relay stores carries exactly one `h` tag with the channel's UUID. Evidence: the live fixture; `curator.py` and the Buzz CLI path both write it. If a relay change ever dropped the tag, every alert would vanish for upgraded readers; the exporter's test over the live fixture is the tripwire.

## Open questions

None.
