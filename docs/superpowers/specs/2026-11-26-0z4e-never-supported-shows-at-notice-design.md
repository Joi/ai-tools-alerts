# An alert the member's source never supported shows at notice (ai-tools-alerts#0z4e)

Finding D8 of the design review (comments on ai-tools-alerts#h29n), the row "`contradicted`, the source never supported it", and the paragraph under the table: "The source supported it earlier and no longer does" is not fabrication. ai-tools-alerts#fv4g built the source check; ai-tools-alerts#tavj applied the rows about a lowering and an unverified raise and split this row off.

## Problem

A relay-bot alert whose product the member's own read of the source does not support is flagged (`source check: the source does not support <id> for <product>`) and nothing else. A critical for Claude Code that rests on a CVE the CISA catalog lists for another vendor's product still shows as critical, sets exit 2 and sends a notification (as one of the two unverified interrupts its poster key has per 24 hours). Whoever holds the relay-bot key can interrupt every member twice a day with alerts each member's own machine has already found false.

The same flag is printed the moment a source stops supporting an alert it supported before, although the poster follows such a change within its own 24-hour wait and nothing was fabricated.

## Success criteria

Each is a test in `tests/test_never_supported_cli.py`, through `cli.main`.

1. A relay-bot critical for a product the KEV catalog lists under another vendor: once this machine has read the catalog, `check` shows the match at `NOTICE`, `run` exits 0 and sends no notification, `run --json` names it in neither `unseen_critical` nor `held_critical`, and `check` prints the flag line.
2. A critical whose source supported it yesterday and does not today keeps `critical`; no flag is printed until this machine's reads have found no support for more than 48 hours, and then one line says so. The level is still kept.
3. A failed read changes nothing: an alert shown at notice stays at notice, an alert at its published level stays there, and no flag appears or disappears.
4. `scripts/test-gate.sh` passes; `tests/test_wire_compat.py` is untouched.

## Approach

Almost all of it is in the member CLI (`aitools_alerts/cli.py`) and its state (`aitools_alerts/state.py`). `verify.py` changes in one place (an incomplete read reports the support it did read, section 1). `pull.py` and the wire are not changed. Nothing waits for a person.

### 1. A memory of support, per thread and product

`unverified.json` gains `supported`: `{"ruleset": <digest or null>, "threads": {root event id: {product name: [last, gone, seen]}}}`.

- `last`: this machine's time of the last read whose result for that product named a level above `none` from a source that may set one (the result's `source` is `notice`, `high` or `critical`). None: never.
- `gone`: the time of the first read, not before `last`, whose result was `contradicted`, why `unsupported` (every source read whole, every one an authority, none supports the product). None: no such read since the last support.
- `seen`: the time of the latest such read (`gone` when there was one only).

The rules, for one result read at `at`:

- support: `last = max(last, at)`; when `gone` is set and `at >= gone`, `gone` and `seen` are cleared. A support read older than `gone` (a command that started earlier and reports late) clears nothing.
- `unsupported`: ignored when `at < last`; else `gone = seen = at` when `gone` is None, and `seen = max(seen, at)` otherwise.
- `confirmed` with nothing supported (a withdrawn advisory at notice, why `withdrawn`): `gone` and `seen` are cleared when `at >= gone`, as by support. The source and the alert as it stands agree, so an alert whose lowering to notice was accepted is not flagged for the level it had before.
- anything else (`unread` with nothing read, `unauthoritative` with nothing supported, `no-source`, `off`): nothing. That is criterion 3: a failed read is `unread` at once in `verify.json`, and the memory does not move on it.
- every time is cut to this machine's clock before it is used or stored (`min(t, now)`), the result's own `at` too. A time written while the clock was ahead becomes "now" at the next command and counts from there, so no entry is stuck in the future.
- `ruleset` is the digest the entries were judged under. When it differs from this CLI's, every `gone` and `seen` is dropped (a finding of "no support" under other rules or another scope file is not reused; `last` is kept, which is the high side) and the digest is replaced. Nothing shows at notice on a record whose digest is not this CLI's.

**An incomplete read reports the support it read** (`verify.judge`). Today a thread one of whose reads failed is `unread` with `source` None, even when a body that arrived whole supports the product. It stays `unread` (nothing is confirmed), and `source` now carries that level: a lower bound, as `below-source` already rests on. So support read beside a failing alias still ends a demotion. The cache version goes to 4.

Two more places in `verify.run` follow from "a failed read changes nothing". When a run's request budget ends partway through a thread, what it did read is stored (as `unread` with that lower bound), where until now a made-up `unread` with nothing was. And an old result is no longer kept with a new time in that case when it was `unsupported`, or when this run read support: kept so, an old "no support" would count as found again today with no whole read behind it. Last, a run that read its sources and cannot write `verify.json` raises `verify.Unsaved`, which carries the results: the CLI says the source check failed, as before, and still hands the results to the memory for that command.

**Copies.** The CLI shows roots whose advisories are equal as one entry. Equal advisories can have different histories (one root held an alias and dropped it). Such roots are asked about different states, so they are no longer merged: each is judged on its own.

The memory is not in `verify.json`, which is dropped whole when damaged (and whenever the ruleset changes).

**Which state is asked.** The result that feeds the memory is the one for the thread's widest state (`pull.widest`: every alias it has held, every product name, the first fixed version) at the level it stands at. A thread's aliases are the relay bot's to replace, and for a CVE first id support can come only through an alias the thread lists. Judging the current state would let a reply that drops the supporting alias turn a true critical into "never supported". `_source_check` asks the sources about that state too whenever it differs from the alert as shown. A thread a curator posted, one a curator's hold is in force on (`Thread.curated`) and one the manifest retracts are not judged: a curator's word is not the relay bot's.

**When it is written.** Two places, one function (`_note_support`), always under the state lock and against the record as it is on disk then:

- `run` and `verify` hand the results of their own source check to it (`verify.run` returns them), so every read a command completed reaches the memory even when a concurrent command then writes its own view of `verify.json` over it. The rules above order by the reads' times, not by who writes last.
- `_matches`, which every command that reads the feed calls, applies the results on disk: a read whose command died before the hand-over is not lost.

Entries of roots no longer stored are dropped, by the stored events as they are read under the lock, not by this command's earlier view: a thread another command pulled meanwhile keeps what that command recorded. A state directory that cannot be written: the command uses what it computed and saves nothing.

**What is read again.** `verify.run` reads a confirmed state again only when asked (`recheck`). Today that is lowered states and critical matches. Every relay-bot match on this machine is added, at any level, so a `high` whose source drops its support is seen within a day. An alert that matches nothing here is not read again once confirmed; it interrupts nobody here.

A CLI that verifies nothing (`verify = "off"`, a CLI the trust root calls too old, a ruleset out of date or damaged) neither writes the memory nor acts on it: every alert is as posted, as today.

### 2. Never supported: shown at notice

A product of a thread is **never supported** when its memory has `gone` and no `last`, the record's digest is this CLI's, and the record was not rebuilt after damage in the last 48 hours (`State.reset_at`; what it held is unknown, and too high is the safe side).

- A match whose product is never supported is shown at `notice`: `check` prints it as `NOTICE: ... (id <id>, thread <ref>; published at <level>)`, `--json` gives `"level": "notice"` and the new key `"published_level"` (null on every other match), and its `source_check` is `contradicted`, `unsupported`, `none` whatever the cache holds now. It is not a critical match, so it takes no slot, sets no exit 2, sends no notification and is not held. `plan` shows it the same way.
- A thread every product of which is never supported is shown at notice in the list of all advisories too (it leaves "Critical advisories not installed here").
- Per match, not per thread: an alert that names a supported product beside the unsupported one (a real exploited CVE of another in-scope tool, with Claude Code added) must not carry the unsupported match at critical.
- The existing flag line is printed for it, unchanged, from the memory: it stays through failed reads.
- It ends when a read supports the product (then `last` is set and `gone` cleared), at once and for the same run: `run` matches again after its source check and notifies a critical that has just become one.

`run` notifies before it reads a source (tavj: a critical never waits for a source). So an alert this machine has not yet read still interrupts once, as unverified, inside the cap of two per poster key; from the first whole read it shows at notice. The session-start hook's `run --json` reads no source and applies the memory.

### 3. Supported earlier: the level is kept, flagged past 48 hours

A product whose memory has `last` and `gone` keeps its published level and interrupts as before. The existing "does not support" line is not printed for it. Once `seen - gone` is more than 48 hours (`verify.FRESH_S`), that is once a whole read more than 48 hours after the first still found no support, `check` prints `source check: the source has not supported <id> for <product> for more than 48 hours`. The level is still kept: the design review asks for a flag, and this machine has read real support for that product under that thread, so nothing was fabricated. The line comes from the memory alone, so a failed read neither brings it nor removes it; a read that supports the product again clears it.

The times are this machine's clock, like the results' own: no signed time says when this machine read a source.

### 4. `above-source` stays at its published level (decided)

A critical the source supports at `high` or `notice` keeps `critical`, is flagged by the existing line (`... is published at critical for <product>; the source supports <level>`) and stays unverified: it interrupts only inside the two slots of its poster key and its notification says `Not verified from this machine`. Not shown at the source's level, because the source does confirm the vulnerability for the product, so a wrong demotion costs a missed true critical while a false critical costs attention inside a cap; and because a rule "supported at this level earlier" would need the memory per level. One directive reverses this.

### 5. What the issue's fourth bullet already has

A withdrawn advisory published at notice reads `confirmed`, why `withdrawn` (tavj): never "never supported". The KEV catalog not listing a CVE is `unknown` for a standing alert, so it never demotes one. The catalog's silence counts only for a claimed lowered state (`verify.claimed`), which the poster's own lowering reply brings; that path is tavj's and is not changed. `verify.claimed` of a thread at its own level is true of any thread (no level above it was stated), so it is not used here.

### 6. The record

- `State.supported`, loaded, saved and re-read under the lock with the rest of `unverified.json`. The loader accepts the record without the key (written before this change) as empty, so an upgrade does not read as damage.
- Shape checked on load: `ruleset` is null or 64 hex characters; root ids are event ids, a product name is a string of 1 to 200 characters, each value is a list of three, each None or a time, `last` or `gone` set, `seen` set exactly when `gone` is and not before it. At most `MAX_UNVERIFIED_ENTRIES` roots and as many names per root. Roots are cut to the stored threads and names are scope product names (a product outside the scope file is never judged), so nothing the CLI writes is refused when read back.
- `_mend` (a damaged record) empties it with the rest and sets `reset_at`; for 48 hours from then nothing shows at notice.

## Alternatives considered

- **Demote from the cached result alone, no memory.** A failed read (the result becomes `unread`) would put the alert back at critical and interrupt; and the first read after a source withdrew would demote a real alert at once. Both are ruled out by the issue.
- **Memory per thread, not per product.** A fabricated product beside a supported one would count as "supported earlier" and keep critical for good.
- **Memory per advisory id, not per thread root.** The issue says per thread; results are shared by threads with one published state anyway, so copies of a supported alert each record the support.
- **Demote in `pull.standing`.** It would put the member's evidence into the reader that the poster, the exporter and the curator share. The CLI is where the D8 rows about interrupts live.
- **Measure the 48 hours from the last support read.** A machine that was off for a week would flag at its first read. `gone` is the first read without support.
- **Use the claim to read the catalog's silence for a standing alert.** See 5: `claimed` is vacuous at the thread's own level.

## Blast radius and rollback

Members' CLIs only; the poster, the mirror and the wire are untouched. One new key in `unverified.json` and a new cache version of `verify.json` (read again from the sources); a CLI from before this change that meets a record with the key reads it as damaged and starts it again (tavj's `_mend`; both are unreleased). Rollback is a revert of the pull request. Nothing is installed, signed or released here.

What a holder of the relay-bot key gains: no way to lower a true alert. Demotion rests only on whole reads of authorities by this machine about the widest state, and replies cannot narrow that state. It can still keep a fabricated alert from being judged at all (Known limits), which leaves that alert as it is today. What a source's owner gains: an advisory's author who empties it before a member's first read has the alert shown at notice on that machine; the poster's own recompute lowers such a thread anyway.

## Known limits

- A machine whose first read of a thread comes after the source dropped its support has no memory of the support and shows the alert at notice at once. The poster lowers such a thread within its own wait.
- The first interrupt of a new fabricated critical happens before its source is read, inside the unverified cap.
- A post can make itself unjudgeable, as before this change, and then it is never shown at notice: it stays what it is today, unverified, inside the two interrupts per poster key. Three ways: more than three aliases beside a CVE (`verify.MAX_ALIASES`), an alias whose read always fails, and a product spelled otherwise than the scope file spells it (`check.match` matches `claude code`; `verify.judge` judges only `Claude Code`). They are gaps of the source check itself (ai-tools-alerts#fv4g), not of this rule; the follow-up issue filed from this run carries them.
- An alert that matches nothing on this machine is not read again once confirmed.
- The strike against the key is ai-tools-alerts#m729: it can count `gone` entries with no `last`, by the root's poster key.

## Existing tests this changes

- `tests/test_unverified_cli.py::test_an_alert_the_source_contradicts_is_unverified_and_says_so`: an alert already read as unsupported interrupted as unverified. It is criterion 1 now: it shows at notice and does not interrupt.
- `tests/test_unverified_cli.py::test_a_copy_of_a_post_confirmed_earlier_is_not_confirmed_with_it`: its last line expects the "does not support" line at the first read after a withdrawal. That is "supported earlier": no line until 48 hours.
- `tests/test_unchecked_lowering.py::test_a_damaged_record_is_flagged_and_never_an_error`: the saved record's keys gain `supported`.
- `tests/test_verify.py::test_judge`: the row for an incomplete read beside support expects `source` None; it is the level read.

- `tests/test_verify_cli.py::test_an_alert_the_source_does_not_support_is_flagged_per_product`: it counted the substring `source check:`, which the heading "After the source check:" also holds. The match is now listed again, at notice, after the read; the count is of lines.

Any other failing test is a defect of the change. One was found that way: an alert whose advisory was withdrawn, and whose lowering to notice was then accepted, kept the "does not support" line for the level it had before (`tests/test_unverified_cli.py::test_the_source_withdraws_and_the_lowering_is_accepted`). Fixed by the `confirmed` rule of section 1.

## Review dispositions (plan, fresheyes gpt-6.1-sol high, snapshot c566f55)

Four findings, each rated major. All fixed in the code and here.

1. The first copy's widest state stood for every root of an entry. Fixed: roots with different judged states are not merged (section 1, Copies); `test_copies_with_one_content_and_another_history_are_each_judged_on_their_own`.
2. The record was cut to this command's own list of threads, also under the lock. Fixed: it is cut to the stored events as read under the lock; `test_the_memory_of_a_thread_this_command_did_not_see_is_kept`.
3. When the request budget ran out, support already read was discarded, and an old "unsupported" was kept with a new time. Fixed in `verify.run`; `test_support_read_before_the_request_budget_ran_out_ends_the_demotion`, `test_an_old_unsupported_is_not_kept_as_found_again_when_the_budget_runs_out`.
4. A read whose cache could not be written never reached the memory. Fixed: `verify.Unsaved`; `test_a_read_whose_cache_cannot_be_written_still_ends_the_demotion_for_that_command`.

## Review dispositions (spec, fresheyes gpt-6.1-sol high, snapshot 7099395)

Eight findings, each rated major by the reviewer.

1. Aliases the relay bot chooses can make a thread unreadable, so a fabricated alert is never demoted; and support read beside a failing alias was discarded, so a demotion could outlive real support. Second half fixed: an incomplete read reports the support it read (section 1). First half not fixed here: it is how the source check reads aliases (fv4g), it leaves the alert exactly as it is today, and the fix belongs with the next finding; Known limits and the follow-up issue.
2. A product spelled otherwise than the scope file matches an installation and is never judged. Not fixed here, same reason: the source check has judged only exact scope names since fv4g, for every row of the table. Known limits and the follow-up issue.
3. A "no support" finding outlived the ruleset it was made under. Fixed: the record carries the digest; another digest drops every `gone`.
4. A concurrent command could write its view of `verify.json` over a completed read before the memory saw it. Fixed: a command hands its own results to the memory under the lock, and the rules order by read time.
5. A `gone` dated ahead of the clock had no way back. Fixed: every time is cut to the clock on use.
6. A confirmed `high` was never read again, so its lost support was never seen. Fixed: every relay-bot match on this machine is read again daily.
7. A failed read removed the 48-hour line. Fixed: the line comes from the memory (`seen - gone`), not from the cache.
8. Existing tests contradict the design. Fixed: the section above names each.

## Assumes

- "Shown at notice" applies to any published level above notice, not only critical.
- No release, install or signing step: a comment on ai-tools-alerts#fa5a is not needed.
