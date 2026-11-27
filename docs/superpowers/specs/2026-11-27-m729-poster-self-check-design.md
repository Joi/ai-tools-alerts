# The poster checks its own key (ai-tools-alerts#m729, finding D14, poster half)

## Problem

The relay-bot key signs every alert. Removing a stolen key from the manifest needs the trust root, and so a person; the 2026-11-23 ruling says nobody is watching. Today the poster vouches for a thief's event itself: the checkpoint it signs each run lists every event in its verified copy of the mirror whose key the manifest names (`signer.window`), and `signer.py` says so in its own header ("It does not vouch ... that the legitimate poster wrote an event signed by the bot key"). A reader applies an event only when a checkpoint lists it, so the poster's signature is what carries a forged relay-bot event to every member.

The checkpoint key is in a file on the poster machine and never on the relay VM. The relay-bot key is read on the poster machine too, but the relay VM still reads the same key for other channels (jibot-code#7z60). A key taken from the VM is therefore the case this closes: the thief can post to the relay, and cannot sign a checkpoint.

The member strike rule, the other half of D14, is ai-tools-alerts#cftg.

## Success criteria

1. A relay-bot event in the alert channels that this poster did not send is in no checkpoint the poster signs, from the first run that sees it. When it is a root, no reply to it is listed either.
2. A member CLI that pulls a mirror serving that event, with the poster's checkpoint, shows no advisory from it (`pull.advisories`).
3. The first digest composed after the poster has seen the event carries one fixed line, in English and in the Japanese copy. The next digest does not repeat it for the same event.
4. Nothing the poster sent is ever taken for foreign: a post the relay acknowledged, a post whose send had no answer and that the mirror then shows, a post settled from the mirror or by `resolve --delivered`, a renewal, a Japanese reply, and everything on the mirror when the record is first made.
5. A checkpoint is signed in every run in which one is signed today. A foreign event never stops signing.
6. `scripts/test-gate.sh` passes.

## Approach

### The sent record

A new file beside the ledger, `<ledger>.sent.json` (`Config.sent_state`), written atomically under the ledger lock, in a new module `aitools_alerts/poster/sent.py`:

```
{"since": int | null, "ids": {event id: time}, "foreign": {event id: first seen}, "said": [event id]}
```

- `ids`: every event id this poster signed and sent, or took as its own at the baseline.
- `since`: when the baseline was taken; null until then.
- `foreign`: the relay-bot events in the poster's mirror copy at the last check that `ids` does not hold.
- `said`: the foreign ids a delivered digest has reported.

Why not ledger.json, which the issue names: the ledger keeps no id of a Japanese reply or a renewal, and the journal keeps only the last digests' ids. The checkpoint state (`<ledger>.checkpoint.json`) forgets an id once the mirror shows it. Neither is a list of what was sent.

Writes (`sent.note(path, event_id, now)`):

- `Run._owed`, beside `signer.record_sent`: every post the relay acknowledged, a replayed journal item and a settled one included, since both come through `deliver` and `_owe`. A write that fails stops the run as a failed `record_sent` does (`owe_failed`, `LedgerError`): the item stays in the journal and its replay records it; the run signs no checkpoint.
- A send whose outcome is `unknown`: `transport.SendResult` gains `signed`, the id of the event that send signed, set by `Relay.send` on that outcome only. `Run.deliver` and `Run._send_renewal` record it. Without this, a post the relay took and did not answer would be left out of the same run's checkpoint and listed an hour later, once `settle` had found it on the mirror. A write that fails here is said on stderr and stops nothing: `settle` records the id next run.

Both only when `checkpoint_key_file` is set, as `record_sent`.

### The check

`sent.check(path, events, m, now, adopt=None) -> set` returns the foreign ids among `events`: the events whose key has the role `relay-bot` in manifest `m`, bound to an alert channel (`pull._bound`), whose id `ids` does not hold.

- "Its own key" is every relay-bot key of the accepted manifest, not one public key. One checkpoint key belongs to one poster with one ledger (`signer.py`), so a relay-bot event this poster did not send is not its to vouch for, whichever relay-bot key signed it.
- Baseline: while `since` is null and `adopt` is given (the caller's ids of acknowledged posts the mirror has not shown yet, from the checkpoint state), every relay-bot event in `events` and every id in `adopt` is recorded, `since` is set and one stderr line says how many. The poster vouches for all of them today, so nothing is given up. While `since` is null and `adopt` is None, nothing is judged.
- It rewrites `foreign` (keeping each id's first time), drops from `said` what is no longer foreign, and drops from `ids` an id that is not among `events` and is older than `pull.RETENTION_S` (400 days): a thread that old has left every reader.
- A record that is missing, unreadable or of another shape is an empty one with `since` null: the next check with `adopt` takes a new baseline and says so. See "Limits".

Two callers, both under the ledger lock:

1. `signer.run_checkpoint`, after the mirror pull succeeded and before anything is settled or listed, with `adopt` = the ids of the owed entries. From there on it works on its copy without the foreign events: `settle_gone`, `settle_owed`, `_later`, `lapsed` and `window` all get the filtered events, and the foreign ids join `suppress`, so a thread whose root is foreign is left out whole (a curator's reply to it too). A foreign renewal cannot make a real one redundant, and a foreign level reply does not count in `lapsed`: both read what a reader of the checkpoint will hold. The summary token gains `,foreign=N`.
2. `Run.digest`, after its own mirror pull (`_withdrawn`), with no `adopt`: a foreign event that arrived since the last run is said in today's digest, not tomorrow's. Any exception here is said on stderr and the digest goes on with what the record holds.

### The digest line

`sent.unsaid(path)`: the ids in `foreign` that are in neither `ids` nor `said`. When there are any, `compose.digest(..., foreign=True)` adds one line after the list (and after the withheld count), on a quiet day too:

- en: `Warning: an event signed with this service's key was not sent by this service. No checkpoint lists it, so the CLI does not apply it.`
- ja: `警告: このサービスの鍵で署名され、このサービスが送信していないイベントがあります。チェックポイントに載せていないため、CLI はこれを適用しません。`

The digest's journal item carries the ids it reported (`adv["foreign"]`, at most 200, each 64 hex; `inputs` validates the key as it does `dropped`). When the digest is recorded as sent (`Run._record`, not on a replay), `sent.mark_said` adds them. A write that fails there is said on stderr: the line is repeated in the next digest. The line states no id, count or text of the event.

### Files

| File | Change |
|---|---|
| `aitools_alerts/poster/sent.py` | new: `load`, `note`, `check`, `unsaid`, `mark_said` |
| `aitools_alerts/poster/signer.py` | `run_checkpoint` calls the check and works on the filtered copy; header text |
| `aitools_alerts/poster/main.py` | `_owed` and unknown sends write the record; `digest` runs the check, passes `foreign`, journals the ids; `_record` marks them said |
| `aitools_alerts/poster/transport.py` | `SendResult.signed` |
| `aitools_alerts/poster/inputs.py` | `Config.sent_state`, in the path checks; the digest item's `foreign` key |
| `aitools_alerts/poster/compose.py` | the line, en and ja |
| `tests/poster/test_sent.py` and the existing poster tests | see "Tests" |
| `README.md`, `CHANGELOG.md` | what the poster now does, the summary token, the limits |

### Tests

- The record: baseline adopts the mirror's relay-bot events and the owed ids; a later unknown relay-bot event is foreign and a curator's never is; a noted id is not; an event outside the alert channels is not judged; pruning keeps what the mirror shows; a damaged file starts again; no judgement before the baseline.
- `run_checkpoint`: a foreign root is in no checkpoint and the token says `foreign=1`; a foreign reply in a real thread is left out and the thread is still listed; a curator reply to a foreign root is not listed; a foreign renewal does not keep a lapsed thread listed; a foreign event never stops signing.
- Acceptance, end to end: a member state pulls the mirror with that checkpoint and `pull.advisories` holds the real alert and not the forged one.
- A send with an unknown outcome that the mirror shows in the same run is listed by that run's checkpoint.
- The digest carries the line once, in both languages, on a quiet day and on a day with alerts; the next digest does not; a digest that was not delivered says it again.
- `Relay.send` sets `signed` on an unknown outcome only. The path check refuses a config whose sent record is another of its files. A journal with a digest item carrying `foreign` loads.

## Alternatives considered

- **Compare with ledger.json only.** It lacks Japanese replies, renewals and old digests, so each would read as theft.
- **Compare by public key (the key the poster signs with).** Needs the secret in the signer, which today never touches it, and misses a second relay-bot key the manifest names.
- **Date the baseline instead of listing ids** (judge only events dated after the record was made). A thief chooses `created_at`; a back-dated event would pass.
- **Baseline from the published checkpoint** (take as sent only what the last checkpoint this key signed lists). A checkpoint lists a window, not everything: old threads it skipped would read as foreign on the first run.
- **Stop signing while a foreign event is on the mirror.** A thief could then freeze every member at will; leaving the event out costs members nothing.
- **Say the line in every digest while the event is on the mirror.** A year of the same line; once per event tells the reader what happened and when.
- **Reply in the forged thread.** No reader shows it: the thread is not listed.

## Blast radius and rollback

Only the poster changes; no wire format, schema, manifest, ruleset or reader code. The checkpoint lists fewer events only when a relay-bot event is not in the record. The risk is the reverse of the feature: a real post taken for foreign is left out of checkpoints, and members do not get it until it is recorded. Criterion 4 and its tests are the guard; the summary token (`foreign=N`) shows it in the hourly log.

Rollback: revert the merge. An older poster ignores `<ledger>.sent.json`. It refuses a journal that holds a digest item with `foreign`, so going back needs the outbox free of such an item (the same as `dropped`, ai-tools-alerts#jsje); that item exists only between composing a digest and its acknowledgement.

## Limits, stated

- A lost or unreadable record takes a new baseline: a foreign event on the mirror at that moment is taken as sent. Losing the file needs access to the poster machine, where the checkpoint key is, so this gives a thief of the relay-bot key alone nothing. A stricter rule (treat everything unrecorded as foreign) would unlist every thread for good after an accident nobody is there to mend.
- Whoever holds the checkpoint key and the relay-bot key together is not stopped by this.
- A reader older than 0.1.6 knows no checkpoint and applies the forged event, as it applies anything the mirror serves.
- The poster's other reads of its mirror copy (the digest's list of withdrawn threads, the recompute's reader view, settling an unknown send by its text) still read a foreign event. A forged retraction can keep a real thread out of one digest. Filed as a follow-up; not in this branch.
- An event in a channel outside `spec/channels.json` (the catalog, the relay's other channels) is in no mirror file the poster reads and is not judged.

## Open questions

None that block. Assumes: one poster per relay-bot key set, as `signer.py` already requires of the checkpoint key.

## Review

One independent review (fresheyes) of this spec before the plan; findings and their disposition are recorded in the run manifest and, where they change the design, here.
