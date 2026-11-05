# One line per advisory in check, plan and notify (ai-tools-alerts#54p7)

## Problem

A critical advisory is posted as two roots: one to #security-critical and a
copy to #security-feed. The reader builds one `Thread` per root, so both
copies are current threads with the same advisory id. `check` prints two
lines, `plan` prints the block twice, `run`/`notify` sends two desktop
notifications, and on jibot-code#gs18 the member's agent reported "one
advisory posted twice".

## Success criteria

1. `check` text: a critical with two roots (critical + feed copy, same id,
   same poster role) prints one match line; the line names both threads
   (`threads <a>, <b>`). The count line counts advisories, not roots.
2. `check --json`: one object for it; `thread` is still one root id (the one
   `plan` and the skills already read), and a new `threads` list carries
   every root id of the advisory.
3. `plan <id>` prints the block once, whether given the advisory id or
   either root id.
4. `notify` and `run` send one notification for it; on acceptance every root
   id of the advisory is marked seen; an advisory any of whose roots is
   already seen is not sent again (state written by the old code, which saw
   only the first copy, does not re-alert). `run --json`'s `unseen_critical`
   lists every root id of a pending advisory; exit 2 is unchanged.
5. Two different advisory ids still list twice; the same id from two poster
   roles (curator and relay-bot) still lists twice.
6. A high with one root reads exactly as before (text and JSON, except the
   added `threads: [<its id>]`).
7. When the copies of one advisory differ (an update one root has not had
   yet), they are NOT merged: each distinct copy lists as before, and stderr
   says `copies of <id> differ; listing each` once per command. Stdout (the
   JSON) is unchanged by the warning. (Amended after review, see below.)
8. "One line" means one line per (advisory, match): an advisory that matches
   two installations or two ranges still prints one line per match, as
   `check.match` already does; what goes is the per-channel duplicate.

## Approach

`cli._matches` groups `pull.active(...)` threads by
`(adv.id.casefold(), adv.posted_by)` before matching, into an `Entry`
(frozen dataclass in cli.py: `root_id` of the shown copy, `root_ids` of every
copy in reader order, `adv` of the shown copy). Matching runs on one
advisory per entry, so check, plan, notify and run all see one item per
advisory; the existing code reads `t.root_id` and `t.adv` and keeps working.
The seen test and the seen write use `root_ids`. `pull.py` is unchanged: the
reader's thread model stays one thread per root.

Only copies with equal advisories merge; within a group the first root in
reader order is `thread`. `plan` accepts any root id of the entry, so which
root is shown is not a contract.

Amended after the spec+plan review (fresheyes, gpt-6-astra) and Stage 1:
the draft picked one copy by (level, posted_at) and matched only that copy,
and called an advisory seen when any root was seen. With copies that differ,
that drops a match the other copy makes (a patch that reached one root
only, or a same-role re-post with other ranges) and lets a seen copy hide an
unseen, different one. The brief's "the highest level and the latest
posted_at win" is therefore not implemented; differing copies list apart and
the warning says so. The motivating case (identical copies) is fixed.

## Alternatives

- Group in `pull.advisories`: changes the thread model the curator path and
  tests rely on, and a retraction reply targets one root. Rejected.
- Dedupe only the printed lines: notify and the seen state would still see
  two. Rejected.
- Key by id alone: a curator advisory and a relay-bot advisory with the same
  id are different posts with different trust; the issue asks for the role
  in the key. Rejected.

## Blast radius / rollback

`aitools_alerts/cli.py` and `tests/test_cli.py`. JSON gains one key.
`git revert`; the seen file only gains ids the old code would add on its next
send, so no migration either way.

## Assumes / open questions

- Assumes the poster always posts the same block to both channels (the
  warning reports when it does not).
- A curator retraction reply targets one root; retracting only one copy
  leaves the other current, as before this change (not in scope; the
  manifest `retracted` list covers both, by id).
- The skills read `thread` and pass it to `plan`; they stay correct, so no
  skill edit.
