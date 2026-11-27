# The checkpoint is dated when it is signed (ai-tools-alerts#p93w)

Split from ai-tools-alerts#gtw9: item 2 of the review note ai-tools-alerts#r0ra left there, and one case gtw9's own spec left open (its line 90).

## Problem

1. **The date.** `poster.main.run` takes one time, the start of the run, and passes it to `signer.run_checkpoint`, which dates the checkpoint with it. The posts of the run are stamped by the sender's clock when each is sent (`transport.Relay.send`), after that time, and the checkpoint lists them as owed ids. So every checkpoint of a run that posted lists events dated after it. The reader cannot treat such an event as a fault. It holds the event's claim back and does not judge the thread until the next checkpoint (ai-tools-alerts#r0ra, second decided comment).
2. **The reader's rule** for an event dated after its checkpoint was left to be decided once the poster no longer produces one.
3. **A level reply forgotten with the checkpoint state.** A reader counts a relay-bot reply that names a level as a renewal of its own date. The signer therefore never gives such a reply up: when the mirror hides it, the thread is left out of checkpoints until the poster's copy holds that reply or a renewal at least as late (`signer.settle_owed`). The memory of it is one file, the checkpoint state. When that file is lost, gtw9 sends a renewal for every enrolled thread, and a renewal that could not confirm carries the old `confirmed_at`: it is no later than the level reply's date in one of the two times a reader counts, so it does not replace it. After the 72-hour hold the thread is listed again without the hidden reply.

## Success criteria

1. A checkpoint signed by a run that posted lists those posts and is dated no earlier than any of them, when the machine's clock did not move back during the run.
2. Everything `run_checkpoint` judged by the run's start is judged by the signing time, with one exception: the hold after a lost state file, the mirror pull, the certificate, `settle_gone`, the 72 hours of `settle_owed`, `lapsed`, the window's cutoff and its "not dated after" filter, `next_seq`, and the checkpoint's `created_at` and `valid_until`. The exception: an owed post is settled as before, only when the copy holds it dated at or before the run's start, so a post of this run stays on the must-list of this run's checkpoint.
3. `spec/wire.md` states what a reader does with an event dated after the checkpoint that lists it, and `tests/test_wire_compat.py` runs that case on v0.1.8, v0.2.0, v0.2.1, v0.3.0 and this reader.
4. After a lost checkpoint state, a thread whose root carries a claim and whose level changed before the loss is left out of checkpoints until the poster's copy of the mirror holds, under that root, the level reply itself (or a later one), or a renewal confirmed after the change. A test covers it at the signer and through `main.run`.
5. `scripts/test-gate.sh` passes. No wire format, schema, manifest, ruleset or state file shape changes.

## Approach

### 1. The signing time

`signer.run_checkpoint(config, now, *, clock=None, ...)`. At entry: `now = max(int(now), int(clock()))` when a clock is given. Everything in the function then uses that one time. It is read once, before the mirror pull, so the filter "not dated after" and the checkpoint's date are the same number; the pull is bounded at 120 seconds, so the checkpoint is dated at most that long before its signature is made.

`main.run(now, config, ..., clock=None)` passes `clock` through. `main.main` passes `time.time`, the clock `transport.Relay` stamps posts with. Every send of alert channels happens before `run_checkpoint` is called (the journal, the renewals, the Japanese replies); the catalog pass runs after it and no catalog event is ever listed. So with a clock that does not move back, each post of the run is dated at or before the time read at entry.

`clock=None` keeps the run's `now`: a caller that drives the poster with one fixed time (every existing test) gets the dates it gave. `Run` keeps its own `now` for everything else it does (claims, the journal, the ledger): a claim's `checked_at` is the run's time and the event that carries it is dated later, as before.

What each use of the time does with the later value:

| Use | With the signing time |
|---|---|
| `load_owed`, the hold | The hold ends by the same clock that dates the checkpoint. |
| `pull.fetch(now=)` | An event dated up to 10 minutes past the signing time is stored, as before relative to the run's start. |
| `cert_problem`, `_choose_cert` | The certificate is valid when the checkpoint is dated. |
| `settle_gone` | An event missing from the mirror is given up 72 hours after it was first missed, by this clock. |
| `settle_owed` | Its 72 hours run by the signing time. **What counts as held does not move:** an owed post is settled only when the copy holds it dated at or before the run's start, and an owed renewal is made redundant only by renewals on events dated at or before the run's start, as today. A post of this run therefore stays owed, and on the must-list, in this run's checkpoint even when the mirror already shows it. Settled at once it would be an ordinary thread, which `window` leaves out when it does not fit whole: a crowded checkpoint would be signed without the alert the run just posted, where today the signer answers `too-large` and signs nothing. (Found by the spec review.) |
| `lapsed` | A thread is judged as a reader holding this checkpoint judges it. |
| `window` | The retention cutoff moves by the length of the run. Events dated after the signing time are not listed from the copy. |
| `next_seq` | The number is the signing time or one more than the highest used. It still never repeats. |
| `build_checkpoint` | `created_at` is the signing time; `valid_until` is 24 hours after it. |

**A clock that moves back.** The date is not raised to the date of the newest post. The other choice, dating the checkpoint at the newest post, dates it ahead of the true time by the size of the step whenever the clock was set back after a send.

What a clock set back between a send and the signing leads to, by the comparison each check makes. These are the reader's existing checks; none is added or changed here.

- **The post is dated after the checkpoint** (the post's date is later than both the run's start and the clock read at the signing): the checkpoint lists it, and a reader holds that event's claim back until a checkpoint dated at or after it (section 2).
- **The checkpoint is dated before the one a reader holds:** the reader refuses it (`checkpoint.checkpoint_order`), whatever its number. The feed reads stale to that reader until the poster's clock passes the held checkpoint's date.
- **The post is dated more than 10 minutes after the reader's own clock**, and the reader does not hold it yet: the reader does not admit it (`pull._filter`), and the pull whose checkpoint lists it fails as `mirror incomplete`. A checkpoint dated more than 10 minutes after the reader's clock is refused (`checkpoint.checkpoint_problem`); the run's start can be such a date when the clock was set back by more.

So the first success criterion holds for a clock that did not move back; a post dated after its checkpoint costs one claim until a later checkpoint; and dates far ahead of the true time make the feed read stale until the clock catches up, as they do today. The same holds for an owed post of an earlier run. Tests of those reader checks exist (`tests/test_checkpoint_pull.py::test_an_older_or_conflicting_checkpoint_is_refused`, `tests/test_expiry.py::test_an_event_dated_ten_years_ahead_is_refused_and_the_stale_check_still_fires`).

### 2. What the reader does: no refusal

Decided: a reader does not refuse a checkpoint that lists an event dated after it. It keeps what readers 0.1.8 to 0.3.0 do: the event is admitted and applied; its claim, and its date when its block names a level, count toward the thread's life only under a checkpoint dated at or after the event; while a thread has such an event it is not judged and keeps its level. No reader code changes.

Why not refuse, as ai-tools-alerts#r0ra first asked:

- It stops no attacker. Only the holder of the checkpoint key can list an event, and that holder can date the checkpoint as late as it likes. The honest signer lists an event from the mirror only when it is dated at or before the signing time, and its own posts by id.
- It turns the smallest clock fault on the poster (a step back of seconds during a run) into a refused checkpoint for every member, where holding back costs one claim one run.
- A reader that refuses cannot read a mirror whose poster still runs 0.3.0, after any run that posted, until the next run signs.
- It cannot be taken back. A released reader is never changed; a refusal shipped now binds every later poster. Not refusing leaves both choices open.

`spec/wire.md` says so, and names the two dates a poster may give: at the start of its run (to 0.3.0) and at the signing (after).

### 3. Level changes from before a lost state file

The ledger records two times for a thread's last level change, where the loss of the checkpoint state does not take them (gtw9, and before it):

- `Entry.changed[-1]`, called `t` here: the start of the run that first attempted the reply. The reply is stamped when it is sent, so it is dated at or after `t`: later in that run, or in a later run when the first send's outcome was unknown and the reply was sent again (`Run.settle` keeps the first attempt's time).
- `Entry.last_change`, called `u` here: the start of the run that recorded a reply of the thread last. The level reply is recorded in the run that sent it or a later one, and never dated after the end of the run that recorded it. So a claim confirmed after `u` comes from a run that began after the level reply was sent.

Neither is the reply's date `d`. A reply's own claim is confirmed at the start of the run that sent it, so a renewal that repeats that confirmation, or one made by the run that sent the reply again, is confirmed before `d` (both found by the spec reviews). The rule therefore asks for the reply itself, or for a confirmation later than `u`.

- `Run.level_changes()` (new): empty unless the checkpoint is configured and the state record carries a loss (`hold_until > 0`; the loss was at `hold_until - OWED_S`, as `Run._renew` already reads it). Else, for every ledger entry with a standing claim and `t` at or before the loss: `(root, t, u)` for the thread's root in each channel.
- `main.run` calls it inside the checkpoint's own `try`, with the ledger still open, and passes it as `run_checkpoint(..., changes=...)`. A ledger that cannot be read there means no checkpoint is signed in that run (`checkpoint=error`), never one signed without the rule.
- `run_checkpoint` leaves out (`suppress`) each such root that its copy holds unless `signer.answered(root, t, u, events, m)`: among the copy's events not dated after the signing time, a relay-bot reply to that root that either
  - names a level in its block (what `renewals_of` counts by the event's date) and is dated at or after `t`, or
  - carries a claim a reader takes as a renewal (`pull._renewal`) whose `confirmed_at` is after `u`.

No earlier level reply of the thread is dated at or after `t`: while a level reply is in flight the thread takes no other work (`Run.busy`), so each is sent before the next is attempted. There is no allowance for a reply dated before `t` by a clock set back: such a reply is not recognised and the thread stays out of checkpoints until a confirmation or the next level change. That is the safe side. A later ordinary reply moves `u` forward and so asks for a later confirmation; safe as well.

This is stricter than the rule for an owed renewal whose record is intact (`settle_owed` takes any pair no earlier than the run's time), which is left as it is.

The rule cannot put the reply back on the must-list (that needs its id), which matches an owed renewal past 72 hours: off the must-list, its thread left out.

What ends it: the mirror serves the level reply (the usual case: the first checkpoint after the hold lists the thread); a confirming renewal is served; a later level reply is recorded, which moves the ledger's last change past the loss, and that reply is owed in the new record. A step down is such a reply, so a thread whose source never answers is left out for at most its level's life from the change. A thread at notice with a hidden pre-loss change and no confirmation stays out of checkpoints: it keeps its level on readers that hold it, which is the safe side, as for any renewal the mirror hides.

The rule is computed from the ledger on every run after a loss and keeps no state of its own. `Run.renew`'s forced renewal after a loss is unchanged.

Not covered, and stated: a hidden raise is still not shown to a reader that never received it (the thread is left out; nothing can deliver an event the mirror will not serve). A ledger lost together with the checkpoint state knows no thread; `signer.lapsed` still leaves out every root whose events no longer hold its level.

## Alternatives considered

- **Date the checkpoint at the newest listed event.** Needs each post's date in the send result and the owed record (a record an older poster reads as malformed, which starts a 72-hour hold on a rollback), and dates checkpoints ahead of the clock after a step back. Rejected for the reason in section 1.
- **Leave an owed post dated after the signing time out of the checkpoint.** The post would wait a run. Its root may be in the same run; a reply listed without its root, or a root listed without the level reply that followed it, are the cases the must-list exists to prevent. Rejected.
- **Read the clock just before signing, after the pull.** The filter and the date would be two numbers, or the pull's filter would run before its limit is known. One reading at entry is simpler and at most 120 seconds earlier.
- **A reader that refuses**, or one that skips the late event and accepts the rest: section 2. Skipping needs new reader state for a case the honest signer does not produce (ai-tools-alerts#r0ra, first decided comment).
- **Keep each level reply's id and date in the ledger and put it back on the owed list after a loss.** A new ledger key makes the ledger unreadable to the released poster (`Entry(**e)`). The id would buy 72 hours of "mirror incomplete" on readers, during which the poster signs nothing anyway (the hold).
- **Leave out every thread whose level, as a reader of the poster's copy shows it, differs from the ledger's**, loss or not. Wider than the issue: it would also leave a thread out for the run in which its level reply was sent and is not yet on the mirror, and it changes when a hidden raise is given up with the state file intact. Not built.

## Blast radius and rollback

Poster only: `aitools_alerts/poster/signer.py`, `aitools_alerts/poster/main.py`. Reader code changes in comments and docstrings only. A checkpoint dated a few minutes later is one every released reader accepts (it is not dated ahead of the true clock). The state record and the ledger keep their shape, so the released poster reads what this one writes: rollback is installing the earlier poster. No install, signing or release is part of this issue.

On the live poster, once installed: checkpoints are dated at the signing; after a lost state file, a thread with a hidden level reply stays out of checkpoints.

## Tests

- `tests/poster/test_signer.py`: a run whose clock reads later than its start dates the checkpoint, numbers it and bounds its validity by that reading, and lists a post dated between the two, which stays owed; with the window full of threads that must be listed, a post of this run that the mirror already shows makes the signer answer `too-large`, never a checkpoint without it; a clock that reads earlier than the run's start changes nothing; no clock, the run's time (the existing tests). `main.main` passes `time.time`. A root with a claim and a level change before a loss is left out while the copy lacks the level reply, while it holds only a renewal confirmed at or before the run that recorded the reply (`u`), checked later or not, and while it holds only a level reply dated before the change; it is listed when the copy holds a level reply dated at or after the change, and when it holds a renewal confirmed after `u`; a root the copy does not hold adds nothing to `threads_suppressed`.
- `tests/poster/test_renew.py`, through `main.run`: after the state file is lost, the run passes the roots and the two times of a thread's pre-loss level change, the first attempt's and the recording run's when the reply was sent again by a later run; a thread with no level change, one changed after the loss, and one whose root carries no claim pass nothing.
- `tests/test_wire_compat.py`: `CLAIM_READERS` gains `v0.3.0`. New test on v0.1.8 to v0.3.0 and this reader: a claimed critical root 20 days old and a renewal dated after the checkpoint that lists both. The pull is accepted; under that checkpoint the thread shows critical (not judged), although the root's claim alone would give high; under the next checkpoint, dated after the renewal, it shows critical with the renewal counted. The same root with no renewal shows high, so the first result is the hold and not a reader that computes nothing.

## Open questions

None that block. The step-back cases in section 1 are where the first success criterion is conditional.
