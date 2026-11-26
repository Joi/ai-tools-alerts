# The recompute posts the copy a thread's level lacks (ai-tools-alerts#3t4p)

## Problem

A thread has a root in each channel of its level: `CHANNELS_FOR` in `aitools_alerts/poster/main.py` gives `critical` and `feed` for a critical, `feed` for a high. Two paths keep that true today. `plan_new` posts a critical's root in `critical` and its copy in `feed`. `plan_known` posts a copy in every channel of the level the thread lacks, when a candidate for the advisory is sighted.

The recompute (`Run.recompute`) raises a thread with `Run._level_items`: a level-only reply in each channel the thread already has a root in. A thread posted at high has a root in `feed` only. Raised to critical by the recompute, it is critical in `feed` and absent from `critical`. A member who reads only that channel never sees it.

Since ai-tools-alerts#3qyq the recompute raises on advisory fields (a malware advisory, a KEV listing dated before the watermark), with no candidate. Measured on main at 8f91677: a thread posted at high from `GHSA-abcd-efgh-ijkl`, whose advisory then reads `type: malware`, gets one send in the next run, `Level is now critical.` in `feed`, and its ledger entry holds `channel_ids` of `feed` alone.

A second way to the same state exists since ai-tools-alerts#jsje: a copy the relay refuses is dropped after three days and "its advisory planned anew". That holds for a copy `plan_known` planned, whose candidate was deferred. A copy with no candidate behind it would be gone for good.

## Success criteria

1. A feed-only thread the recompute raises to critical has a root in the critical channel after that run, with no new input record. (Issue acceptance.)
2. A raise on a thread that has both channels sends what it sends today: one level-only reply per channel, no copy. (Issue acceptance.)
3. A copy whose send fails stays in the journal and is sent by the next run's drain. (Issue acceptance.)
4. The copy's block is the thread's advisory as the ledger holds it after the raise, key for key. Its body is the five lines a root has. It gets the Japanese reply a copy has.
5. A copy the relay refused and `expire_withheld` dropped is planned again by a later run, with no input record.
6. A thread with work in flight gets no copy until that work is settled. A synthetic thread gets none. A retracted or expired advisory gets none, and no copy is planned in a run that cannot read the mirror.
7. A copy whose send has an unknown outcome is settled from the mirror with no person: recorded when the mirror shows it, sent again after 24 hours when a fresh mirror does not, and after 72 hours whatever the mirror says.
8. `scripts/test-gate.sh` passes.

## Approach

One rule, applied at the end of `Run.recompute`, after the raises and lowerings of the run are sent: **every thread whose level has a channel the thread has no root in gets a copy there.**

`Run.recompute` ends by calling a new `Run.copies()`:

- It reads the ledger's entries as they are then. A raise sent earlier in the run is recorded, so the thread is critical in the ledger and lacks `critical`.
- It skips a synthetic thread (a synthetic thread takes no update from any input), a thread whose product the scope file no longer has under its name or a former name (`Run._scope_named`, over `catalog._scope`, which resolves the stored display name; a former name several entries share yields a scope with no package; `rules.scope_of` matches identities and returns nothing for Codex, Cursor or Hermes), and a thread that is busy (`Run.busy`: journaled or withheld work, or a send with an unknown outcome).
- When some thread is left, it pulls the mirror once (`Run._withdrawn`, as the digest does) and skips a thread whose id the manifest retracts, whose thread is retracted, or that has expired: a withdrawn advisory is never announced again. When the pull fails it plans no copy in this run and says so on stderr; the next run tries again.
- For each other thread with `missing = [ch for ch in CHANNELS_FOR[e.level] if ch not in e.channel_ids]`, it composes one text and journals one `copy` item per missing channel through `Run.enqueue`, with `root` set to the thread's root. The item's key is `copy:<scope>:<advisory id>:<channel>`, the key `plan_known` gives a copy.
- A `ValueError` from compose withholds that thread's copy for this run (`withheld` is counted) and the loop goes on. The next run tries again.

Why at the end and from the ledger, not inside the raise: the copy then follows the level the ledger records. A raise whose reply the relay refuses leaves the thread at high, and no copy goes to `critical` for a level the thread does not have. A raise whose reply fails stops the run (`_Stop`); the next run's drain sends the reply and its recompute posts the copy. One code path covers the raise, the dropped copy and a compose refusal that later passes.

### Composing from the ledger

`compose.root_post` takes a candidate and builds the block's title from the candidate's flags. The recompute has no candidate, and the level-only reply does not change the title, so a copy built by `root_post` could state another title than the thread holds.

A new `compose.copy_post(adv, scope, *, title=None, exploited=False)` renders a root from a validated `schema.Advisory`:

- The block is `adv`, unchanged. After rendering, `schema.parse_post(text) == adv` must hold, else `ValueError`.
- The body is `root_post`'s lines, built by one shared helper so the two cannot drift: the headline (`title`, the ledger's `source_title`, else the block title without its id), `Affected:`, `Do:`, `Covers`, `Source:`. The head's `unverified` mark is set when the block's title is the template's unverified form.
- Refused with `ValueError`: an unresolved scope entry; an id that is not a CVE or GHSA id; no product, or a product named otherwise than the scope; no source; a critical with no complete action (no fixed version and no `stop_using` for the product, the rule of ai-tools-alerts#9kgk that `deliver` also applies).
- `_guard` checks the text as for every post.

The ledger keeps the schema's form of the range and the fix, not the raw text of a range or fix the schema cannot express. So where the root said "affected versions: see the source", the copy says "versions not stated", and where a high's root said "upgrade to the fixed release the source names", the copy gives the workaround line. No critical is affected: a critical has a schema fix or stop_using. The block is the same.

No model wording (ai-tools-alerts#c6ak) for this copy: the ledger keeps no source prose to word from. The headline is the source title.

The Japanese body is `compose.root_post_ja(adv, reason, False, title, exploited=..., package=compose.package_of(scope))`, as `plan_known` builds a copy's.

### What a copy means on the wire

Nothing new. A copy is a root in a second channel, which `plan_new` and `plan_known` post today. `Run._record` adds the channel to the thread (`Ledger.add_channel`); later replies go to both. No schema, manifest, tag or reader change. On a thread that has had a lowering, spec/wire.md rule 2 governs replies; a copy is a root at the thread's level and no reader refuses it.

## Alternatives considered

- **Copy items inside the raise, before the level reply (as `plan_known` orders them).** Rejected: the copy would post at critical in `critical` while the feed reply can still be refused, leaving a critical root for a thread the ledger holds at high; and it leaves the dropped copy (criterion 5) and a refused compose with no second try.
- **Build a candidate from the ledger entry and call `root_post`.** Rejected: the title, the unverified mark and the action are derived from candidate flags the ledger does not keep; a wrong guess changes the block.
- **Only threads raised in this run.** Rejected: a run that stops after the raise is recorded, a refused copy dropped three days later, and a compose refusal would each leave the critical channel without the alert until a person noticed. Standing ruling: nothing waits for a person.
- **Only threads whose level changed in the last seven days.** Rejected: `plan_known` applies no such bound to the copies it posts, and a thread left without its channel stays wrong.

## Blast radius and rollback

Poster only: `aitools_alerts/poster/compose.py` (`copy_post` and `title_reason` added, `root_post`'s body lines moved to `_root_lines` with no change in output) and `aitools_alerts/poster/main.py` (`Run.copies`, one call). No state file gains a key. A copy item has the shape `plan_known`'s has, so an older poster drains it.

On the first run after an update, any thread already standing at critical with no root in `critical` gets its copy. On main that state arises only from a recompute raise or a dropped copy, both unreleased, so none is expected on the live ledger. If one exists, the copy is what `plan_known` would post at the next sighting.

Each run composes at most one copy text per such thread. A run with a copy to plan pulls the mirror once (at most 120 seconds, under the ledger lock, as the digest's pull); a run with none pulls nothing. A retracted thread that lacks a channel of its level costs that pull every run. A relay that refuses a copy every time yields one withheld item per three days per thread, counted in the digest as jsje counts dropped posts.

Rollback: revert the commit. Journaled copies drain under the old code.

Nothing here installs or releases. The release session needs no step beyond updating the poster.

## Assumes

- A thread's stored `scope` name, or a former name of an entry, is the product the copy names; the copy keeps the name the thread was posted under, as `Run._former` does for a reply.
- `Entry.exploited` is enough for the `Do:` line's "exploited in the wild" wording, which only a post with no fix and no stop_using uses.

## Open questions

None.

## Review dispositions (spec and plan, one independent pass at b8cd081)

1. BLOCKER, fixed: the scope check used `rules.scope_of` on the ledger's display name, which is None for Codex, Cursor, Hermes and others. `Run.copies` now resolves the name with `catalog._scope`, former names included. Tests: `test_a_thread_is_found_by_the_name_it_was_posted_under` (Cursor, and a former name). The recompute's own judging has the same lookup and is not this issue: filed as ai-tools-alerts#zmg2.
2. BLOCKER, fixed in part and rebutted in part: the ledger scan could post a new root for a retracted advisory. Fixed at planning: the mirror is pulled and a retracted id, a retracted thread and an expired one get no copy; a failed pull plans none (`test_a_withdrawn_advisory_gets_no_copy`, `test_no_copy_is_planned_while_the_mirror_cannot_be_read`). Rebutted for a copy already journaled when the retraction arrives: `Run.drain` sends every journaled root, copy, reply and digest as it was planned, and a check at drain time for all kinds is ai-tools-alerts#n1fc, which now names this case.
3. BLOCKER, fixed: the unknown-copy test proved only that no second copy is planned. Added `test_an_unknown_copy_the_mirror_shows_is_recorded_and_not_sent_again` and `test_an_unknown_copy_the_mirror_never_shows_is_sent_again` (24 hours with a fresh mirror, 72 hours with a stale one).
4. SUBSTANTIVE, rebutted: the message of the review snapshot commit. The snapshot is a dangling commit made for the reviewer and never lands; the branch's commits name the behaviour and the issue.

Medium takes no delta pass on the spec; the whole-branch review sees the fixes.

## Review dispositions (code, whole branch at e5984e7)

Independent pass (gpt-6.1-sol, high): 0 BLOCKER, 1 SUBSTANTIVE. Same-model pass beside it: 1 BLOCKER (the same finding), 3 SUBSTANTIVE, 3 COSMETIC.

1. SUBSTANTIVE (the same-model pass: BLOCKER), fixed: `catalog._scope` resolves a former name to the first entry that lists it, and seven MCP entries share "MCP servers and clients", so a copy for a thread under that name said `Affected: mcp-server-git ... (PyPI)` whatever server it was about. `Run._scope_named` drops the package when more than one entry carries the former name; the copy then names the thread's own name and no registry. Test: `test_a_thread_is_found_by_the_name_it_was_posted_under` now holds the English and the Japanese affected line. A text change in a post, not a change in which threads get a copy.
2. SUBSTANTIVE, fixed: only the manifest's retracted id was tested. Added `test_a_retracted_thread_and_an_expired_advisory_get_no_copy`.
3. SUBSTANTIVE, fixed: the lowered-thread test could not fail (its thread had both channels). Replaced by `test_a_thread_lowered_while_its_copy_was_missing_gets_none`.
4. SUBSTANTIVE, rebutted: a thread posted as unverified and later raised on the advisory's fields gets a critical copy whose head says unverified. The level-only reply leaves the thread's title as it is, so every channel and every reader already shows this thread under the unverified title; a copy whose head dropped the mark would disagree with its own block. Changing the title on a recompute raise is a change to the raise (and on a lowered thread spec/wire.md rule 2 forbids it), not to the copy.
5. COSMETIC, not changed: `root_post` no longer writes a `Who:` line for a wording with an empty `who`; `wording.parse` never returns one. The same-model pass compared 45,360 inputs of `root_post` on main and on the branch and found no other difference.
6. COSMETIC, fixed: a leftover assertion in the compose-refusal test; the plan's test names and signature; "one function added"; the changelog's headline sentence; the `Do:` line's wording loss, now stated above.

No BLOCKER fix changed behaviour after the independent pass, so no delta pass runs (Review Cycle). The rung stays medium.
