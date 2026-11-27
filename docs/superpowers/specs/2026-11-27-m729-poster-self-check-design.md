# The poster checks its own key (ai-tools-alerts#m729, finding D14, poster half)

## Problem

The relay-bot key signs every alert. Removing a stolen key from the manifest needs the trust root, and so a person; the 2026-11-23 ruling says nobody is watching. Today the poster vouches for a thief's event itself: the checkpoint it signs each run lists every event in its verified copy of the mirror whose key the manifest names (`signer.window`), and `signer.py` says so in its own header ("It does not vouch ... that the legitimate poster wrote an event signed by the bot key"). A reader applies an event only when a checkpoint lists it, so the poster's signature is what carries a forged relay-bot event to every member.

The checkpoint key is in a file on the poster machine and never on the relay VM. The relay-bot key is read on the poster machine too, but the relay VM still reads the same key for other channels (jibot-code#7z60). A key taken from the VM is therefore the case this closes: the thief can post to the relay, and cannot sign a checkpoint.

The member strike rule, the other half of D14, is ai-tools-alerts#cftg.

## Success criteria

1. A relay-bot event in the alert channels that this poster did not sign is in no checkpoint the poster signs, from the first run that sees it. When it is a root, no reply to it is listed either, on the mirror or still owed.
2. A member CLI that pulls a mirror serving that event, with the poster's checkpoint, shows no advisory from it (`pull.advisories`).
3. The first digest composed after the poster has seen the event carries one fixed line, in English and in the Japanese copy. The next digest does not repeat it for the same event.
4. Nothing the poster signed is ever taken for foreign: the id is on disk before a byte of the send is written, whatever happens to the send or the run afterwards.
5. A foreign event never stops the poster signing a checkpoint, and its copies do not pile up in the poster's store.
6. Losing the record never makes the poster vouch for an event it had left out.
7. `scripts/test-gate.sh` passes.

## Approach

### The sent record

A new file beside the ledger, `<ledger>.sent.json` (`Config.sent_state`), in a new module `aitools_alerts/poster/sent.py`. Every read-modify-write holds an exclusive lock on `<ledger>.sent.json.lock`, since one writer (the catalog pass) runs outside the ledger lock. Writes are atomic (`state.write_json`).

```
{"since": int | null, "ids": {event id: time}, "foreign": {event id: first seen}, "said": [event id]}
```

- `ids`: every event id this poster signed, or took as its own at the start (below). Never pruned: a thread's root can leave the poster's copy and come back with a new reply, and the ledger still sends into it. About 100 bytes a post.
- `since`: when the start was taken; null until then.
- `foreign`: the relay-bot events in the poster's mirror copy at the last check that `ids` does not hold.
- `said`: the foreign ids a delivered digest has reported.

Why not ledger.json, which the issue names: the ledger keeps no id of a Japanese reply or a renewal, and the journal keeps only the last digests' ids. The checkpoint state forgets an id once the mirror shows it. Neither is a list of what was signed.

### Recorded before the send

`transport.Relay` takes `on_signed`, a callable given the id of each event it has signed, called before the request is made. `relay_sender(config)` passes one that calls `sent.note(config.sent_state, id, now)` when `checkpoint_key_file` is set. When the callable raises, nothing is sent and the outcome is `failed` ("the sent record could not be written"): the caller tries again next hour, as after any failed send.

So an id is on disk before the relay can hold the event, for every kind of send (a post, a copy, a reply, a renewal, a Japanese reply, a digest, a catalog root) and whatever follows: an acknowledgement, no answer, a crash. No later step has to record it, and none is relied on.

`Run._owed` also notes the id it is given, beside `signer.record_sent` and with the same failure handling. For a send made by `Relay` this changes nothing. It covers a sender that is not `Relay` (the tests' fakes) and `resolve --delivered`, where a person names the event.

### Settling by id

`Run._delivery` finds an unknown send on the mirror by its text, channel, thread and claim. A thief can copy the text of a post and sign it again, so text is not proof of who signed.

`transport.SendResult` gains `signed`: the id of the event that send signed, set by `Relay.send` on the outcome `unknown` only. `Run.deliver` stores it in the journal item (`it["signed"]`, a list, one id per attempt; `inputs._item_ok` accepts the key). When an item has `signed`, `_delivery` takes only a mirror event whose id is in it. An item without the key (one journaled before this change, or sent by a sender that reports none) is matched by text as today; that remainder is stated under "Limits".

### The start

The first check with a verified checkpoint context (`signer.run_checkpoint`), while `since` is null, takes as sent:

- every id the checkpoint the mirror serves lists, when this poster's checkpoint key signed it (the poster's own last word on what it vouches for);
- every id of the checkpoint state's owed entries;
- every id the ledger records (roots, channel copies, replies), the journal's digest ids and the ids of journal items marked sent (`known`, passed in by the run).

It takes nothing because it is on the mirror. This is the same rule on the first run after the upgrade and after the record is lost or unreadable, so there is no lenient path to fall into: an event the poster had left out is in none of the three sources and stays out (criterion 6). One stderr line says the record was started and how many ids it took.

What that costs. On the first run after the upgrade the served checkpoint lists every event of every thread inside the window, so everything the poster vouched for an hour earlier is taken. After a loss, or when no checkpoint of this key is served, an old Japanese reply, renewal or digest that the last checkpoint did not list and the ledger does not record is read as foreign: it is left out, and the digest says the line once. A thread whose renewals are left out is left out by `lapsed` until the poster's next renewal of it, and keeps its level on every reader meanwhile. Nothing is applied that was not before.

### The check

`sent.check(path, events, m, now, adopt=None, channels=None) -> set` returns the foreign ids among `events`: events whose key has the role `relay-bot` in manifest `m`, bound to an alert channel (`pull._bound`), whose id `ids` does not hold.

- "Its own key" is every relay-bot key of the accepted manifest. One checkpoint key belongs to one poster with one ledger (`signer.py`), so a relay-bot event this poster did not sign is not its to vouch for, whichever relay-bot key signed it.
- While `since` is null: with `adopt` (the ids of "The start") the record is started; without it nothing is judged and nothing is written.
- It rewrites `foreign`, keeping each id's first time, and drops from `said` what is no longer foreign. A write that fails is said on stderr and the computed set is still returned.

Two callers:

1. `signer.run_checkpoint`, once the certificate and the served checkpoint are read and before anything is settled or listed, with `adopt`. From there it works on its copy without the foreign events: `settle_gone`, `settle_owed`, `_later`, `lapsed` and `window` get the filtered events. The foreign ids join `suppress`, so a thread whose root is foreign is left out whole, and an owed entry whose `root` is foreign is not listed (it stays owed until its time runs out). A foreign renewal cannot make a real one redundant, and a foreign level reply does not count in `lapsed`. A foreign event the mirror no longer serves is removed from the poster's stored copy in the same save as the events given up, so the store holds no more foreign events than the mirror's two capped files serve (criterion 5). The summary token gains `,foreign=N`.
2. `Run.digest`, after its own mirror pull (`_withdrawn`), with no `adopt`: a foreign event that arrived since the last run is said in today's digest, not tomorrow's. Any exception here is said on stderr and the digest goes on with what the record holds.

### The digest line

`sent.unsaid(path)`: the ids in `foreign` that are in neither `ids` nor `said`. When there are any, `compose.digest(..., foreign=True)` adds one line after the list (and after the withheld count), on a quiet day too:

- en: `Warning: an event signed with this service's key was not sent by this service. No checkpoint lists it, so the CLI does not apply it.`
- ja: `警告: このサービスの鍵で署名され、このサービスが送信していないイベントがあります。チェックポイントに載せていないため、CLI はこれを適用しません。`

The digest's journal item carries the ids it reported (`adv["foreign"]`, at most 200, each 64 hex; `inputs` validates the key as it does `dropped`). When the digest is recorded as sent (`Run._record`, not on a replay), `sent.mark_said` adds them. A write that fails there is said on stderr: the line is repeated in the next digest. The line states no id, count or text of the event.

### Files

| File | Change |
|---|---|
| `aitools_alerts/poster/sent.py` | new: `load`, `note`, `check`, `unsaid`, `mark_said`, the lock |
| `aitools_alerts/poster/transport.py` | `Relay(on_signed=)`, `SendResult.signed` |
| `aitools_alerts/poster/signer.py` | `run_checkpoint(known=)` calls the check and works on the filtered copy; header text |
| `aitools_alerts/poster/main.py` | `relay_sender` passes `on_signed`; `_owed` notes; `deliver` journals `signed`; `_delivery` by id; `digest` runs the check, passes `foreign`, journals the ids; `_record` marks them said; `run` passes `known` |
| `aitools_alerts/poster/ledger.py` | `Ledger.event_ids()` |
| `aitools_alerts/poster/inputs.py` | `Config.sent_state`, in the path checks; the item key `signed`; the digest item's `foreign` |
| `aitools_alerts/poster/compose.py` | the line, en and ja |
| `tests/poster/test_sent.py` and the existing poster tests | see "Tests" |
| `README.md`, `CHANGELOG.md` | what the poster now does, the summary token, the limits |

### Tests

- The record: the start takes `adopt` and nothing else; nothing is judged before it; a relay-bot event not in `ids` is foreign, a curator's and one outside the alert channels never; `note` ends it; the first-seen time is kept; `said` is dropped when the event is recorded or leaves the mirror; `ids` is never pruned; a damaged file and one of another shape start again from `adopt` only; a failed write returns the set; two writers under the lock lose no id.
- `Relay`: `on_signed` gets the id before the connection is made; when it raises, no connection is made and the outcome is `failed`; `signed` is set on `unknown` only.
- `run_checkpoint`: a foreign root is in no checkpoint and the token says `foreign=1`; a foreign reply in a real thread is left out and the thread is still listed; a curator reply to a foreign root is not listed, nor an owed reply to it; a foreign renewal does not keep a lapsed thread listed; the first run takes what the served checkpoint lists, and with no checkpoint of this key served it takes the ledger's and the owed ids only; after the record is deleted, a foreign event that had been left out is still left out (criterion 6); a foreign event the mirror stops serving leaves the stored copy; a foreign event never changes the token from `sent`.
- Acceptance, end to end: a member state pulls the mirror with that checkpoint, and `pull.advisories` holds the real alert and not the forged one.
- Settling: an unknown send whose item holds `signed` is settled by that id and never by a copy of its text under another id, with both on the mirror; the copy is foreign.
- A renewal with an unknown outcome that the mirror shows is not foreign. A run that dies after a send (before `_record`) has the id on disk.
- The digest carries the line once, in both languages, on a quiet day and on a day with alerts; the next digest does not; a digest that was not delivered says it again.
- The path check refuses a config whose sent record is another of its files. A journal with an item carrying `signed`, and a digest item carrying `foreign`, loads; a malformed one is refused.

## Alternatives considered

- **Compare with ledger.json only.** It lacks Japanese replies, renewals and old digests, so each would read as theft.
- **Record the id after the acknowledgement** (the first draft). A renewal is not journaled, so a crash or a failed write after the send loses its id for good.
- **Start from whatever is on the mirror** (the first draft). After a lost record it takes a forged event the poster had left out, and a reader that then applies it keeps it.
- **A marker that the record once existed**, to be lenient on the first run only. One more file or journal key to lose; the served checkpoint already is the poster's signed memory.
- **Compare by public key (the key the poster signs with).** Needs the secret in the signer, which never touches it today, and misses a second relay-bot key the manifest names.
- **Date the start instead of listing ids.** A thief chooses `created_at`; a back-dated event would pass.
- **Stop signing while a foreign event is on the mirror.** A thief could then freeze every member at will; leaving the event out costs members nothing.
- **Say the line in every digest while the event is on the mirror.** A year of the same line; once per event tells the reader what happened and when.

## Blast radius and rollback

Only the poster changes; no wire format, schema, manifest, ruleset or reader code. The checkpoint lists fewer events only when a relay-bot event is not in the record. The risk is the reverse of the feature: a real post taken for foreign is left out of checkpoints. Criterion 4 and the recording before the send are the guard; the summary token (`foreign=N`) shows it in the hourly log.

Rollback: revert the merge. An older poster ignores `<ledger>.sent.json`. It refuses a journal that holds an item with `signed` or a digest item with `foreign`: going back needs the outbox free of both (no send with an unknown outcome in flight, no digest waiting), the same kind of step as `dropped` (ai-tools-alerts#jsje).

## Limits, stated

- Whoever holds the checkpoint key and the relay-bot key together is not stopped by this.
- A reader older than 0.1.6 knows no checkpoint and applies the forged event, as it applies anything the mirror serves.
- A send with an unknown outcome that was journaled before the upgrade has no `signed` and is settled by text, as today: for the three days such an item can wait, a copy of its text under another id can be settled in its place. The copy says what the poster meant to say. No item made after the upgrade has this gap.
- A renewal sent in the last run before the upgrade whose outcome was unknown and that the mirror first shows after the first upgraded run is in none of the start's sources and reads as foreign: one redundant renewal left out, and one line in a digest. The window is the mirror's export lag after one run; installing between runs avoids it.
- A holder of the relay-bot key can still fill the mirror's capped channel files and push real events out of them. That is true today of any key that may post; it is not made worse, and the poster's own store no longer grows with it.
- The poster's other reads of its mirror copy (the digest's list of withdrawn threads, the recompute's reader view, the curator-translation pass, which would translate a curator's reply in a forged thread) still read a foreign event. A forged retraction can keep a real thread out of one digest. Filed as a follow-up; not in this branch.
- An event in a channel outside `spec/channels.json` is in no mirror file the poster reads and is not judged.

## Open questions

None that block. Assumes: one poster per relay-bot key set, as `signer.py` already requires of the checkpoint key.

## Review

Pass 1 (fresheyes, gpt-6.1-sol, commit 6d99ae2): four blockers, three substantive. Fixed here: settling by text could record a thief's copy as sent (now by id); ownership was recorded after the send (now before it, in the transport); a lost record took a new baseline from the mirror (now from the served checkpoint, the ledger and the owed list only); foreign events could fill the poster's store (now removed once the mirror stops serving them); pruning by age could disown a returning root (no pruning); an owed reply to a foreign root was listed (now left out). Rebutted: the pre-upgrade unknown renewal (see "Limits": a one-run window at install, one redundant event, no member effect).
