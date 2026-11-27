# The poster's other reads of its mirror copy leave out foreign relay-bot events (ai-tools-alerts#9cch)

Follow-up of ai-tools-alerts#m729 (design review finding D14, poster half).

## Problem

Since m729 the poster keeps a record of every event id it signed
(`aitools_alerts/poster/sent.py`). A relay-bot event in its copy of the mirror that
the record does not hold is foreign: evidence that the relay-bot key was used
elsewhere. `signer.run_checkpoint` works on the copy without those events, so no
member applies one.

Four other reads in `aitools_alerts/poster/main.py` still take the whole copy:

| Read | Used by | What a foreign event does there today |
|---|---|---|
| `Run._mirror` | `settle` | Nothing: `_delivery` already settles only by a recorded id. |
| `Run._withdrawn` | `digest`, `copies` (the recompute's last step, 3t4p) | A forged root that a curator retracts adds its id to the returned roots. No ledger thread has that id, so no digest or copy changes. See "Where the issue text is ahead of the code". |
| `Run.curator_events`, `posted` | `translate_curator` | A forged `lang: ja` reply to a curator's root or amendment marks it as translated. The poster then never sends its own translation. |
| `Run.curator_events`, the amendment branch | `translate_curator` | A curator's reply in a forged thread is translated and sent, one model call from the daily 20, and the reply is owed to a thread no checkpoint lists. A forged relay-bot reply in a real relay-bot thread changes the advisory text that a curator's amendment is translated from. |

### Where the issue text is ahead of the code

The issue says a forged retraction or expiry keeps a real thread out of one
digest. In the code as landed that cannot happen: `pull.threads_from` gives the
relay bot no retraction (a reply whose first line is `retract` is ignored whole),
drops `expires_at` from every relay-bot root and block, and a relay bot's
withdrawal (y484) hides a thread only when a member's own check confirms it, which
`_withdrawn` never asks (`pull.standing(t, now)` with no check). The landed code
wins. The read is filtered all the same: the rules of `threads_from` have changed
with several recent issues (c1g2, y484, swfe, tavj), and a read that never sees a
foreign event cannot start depending on one.

## Success criteria

1. One helper returns the copy's events without `sent.check`'s foreign ids. Each
   of the four reads uses it; none reads `st.events` or `st.events_for(root)` any
   other way for what it decides.
2. A test per read, each with a forged relay-bot event, in `tests/poster/test_sent.py`:
   - `_mirror`: the forged event is not among the events `settle` is given.
   - `_withdrawn`: a forged root a curator retracted is not in the returned roots;
     a forged `retract` reply and a forged withdrawal reply in a real relay-bot
     thread leave the digest listing that thread (true before and after: the test
     pins what the issue text feared).
   - `copies`: with those forged replies on the mirror the missing copy still posts.
   - curator translation: a forged `lang: ja` reply to a curator root, and one
     naming a curator's amendment (`of:`), do not stop the poster translating
     them; a curator's reply in a forged thread is not translated, costs no call
     and is not owed; a curator's amendment in a real relay-bot thread that holds
     a forged block is translated from the advisory without that block (the model
     input and the reply sent carry nothing of it); with the record not started
     (first run, and after the record is lost) the pass translates nothing and
     says `translate=no-record`, and the next run translates.
   Each test that asserts a changed behaviour fails with the helper turned off.
3. Without a checkpoint key (`checkpoint_key_file` is None) every read is as
   before: there is no record to judge by.
4. `scripts/test-gate.sh` passes.

## Approach

`sent.own(path, events, m, now) -> dict`: `events` is `{id: event}`, the copy as
stored. It runs `sent.check` on all of them (no `adopt`: the record starts only in
the signer, as m729 decided) and returns the mapping without the foreign ids; the
same object when there are none.

`Run._own(events, m) -> dict` in `main.py` wraps it: the copy unchanged when there
is no checkpoint key or no manifest; one stderr line and the copy unchanged when
the check raises something `sent.check` does not already answer (it answers every
OSError itself).

The four reads call `self._own(...)` right after their pull:

- `_mirror`: before the relay-bot filter of its return value.
- `_withdrawn`: before `pull.threads_from`.
- `curator_events`: `evs = self._own(st.events, m)`. `self.mirror_ids`, which only
  bounds the translate state's `done` map by what the mirror holds, keeps the ids
  of the whole copy.
- `_foreign` (the digest's own check, m729) stays as it is: it reads the record,
  not the events.

A curator's reply in a forged thread then finds no root among the events
(`ref in evs` is false) and is passed over each run without a call, like any reply
whose root the mirror does not hold. It is not marked done: should the root turn
out to be the poster's (a person's `resolve --delivered`), the next run translates it.

### What the record's state means for these reads

`sent.check` without `adopt` judges nothing while the record is not started
(`since` is None): in the first run after the upgrade, and after a lost record in
the part of a run before the signer, a read sees the whole copy.

For `_mirror` and `_withdrawn` that is today's behaviour and changes nothing
(`_delivery` settles nothing from an unstarted record; no relay-bot event moves
`_withdrawn`).

For the curator-translation pass it would matter: the pass runs before the signer,
and a forged relay-bot block in a real thread could shape the text a curator's
amendment is translated from. That translation would be sent, recorded as the
poster's own and never made again. So with a checkpoint key the pass does not run
while the record is not started (`sent.started`): `translate_curator` returns
`no-record`, reads nothing and calls nothing. The signer starts the record at the
end of the same run, and the next run translates. Nothing waits for a person: a
poster whose signer can never start the record (no certificate, no mirror) signs
no checkpoint either, and its summary says so every run.

Each call to `sent.check` brings the record's `foreign` and `said` up to date from
the events it is handed. Every caller hands it the whole copy, so the calls agree.

## Alternatives considered

- Filter inside `pull.fetch` or `State` so no caller can forget: that is reader
  code shared with members, who have no sent record. ai-tools-alerts#pdag is the
  issue for a pull-level hook; out of scope here.
- Compute the foreign set once per run and reuse it: each read makes its own pull,
  so the copy can differ between them; a set from an earlier pull would let a
  forged event that arrived since through. One check per read costs one small
  file read under a lock.
- Let the translation pass run on the whole copy while the record is not started,
  as the other reads do: the one read where a forged event leaves something
  behind for good (review finding, spec pass).
- Start the record from these reads (`adopt`): m729 ruled that the record starts
  only where the poster's own served checkpoint has been verified, in the signer.
- Fail closed when the check raises (hold the digest, skip the pass): the check
  answers every OSError itself, so what is left is a programming error, and a
  digest held for one waits for a person. The ruling of 2026-11-23 says nothing
  may wait for a person.
- Drop only `_withdrawn` from the list since nothing changes there today: the
  issue asks for each read, and the filter is what keeps it true.

## Blast radius and rollback

Poster only; no reader, wire or state-format change; no new file. With no
checkpoint key the code path is the old one. The record gains nothing new: the
same `sent.check` the digest already runs, called from three more places in a run.
Rollback: revert the commit. No install step beyond the next release
(ai-tools-alerts#5fry carries m729's note; this adds none).

## Open questions

None.
