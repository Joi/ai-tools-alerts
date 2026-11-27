# A `fixed` the advisory does not state is flagged and gives no upgrade version (ai-tools-alerts#53fy)

Split from ai-tools-alerts#swfe (its decision 2 names this follow-up). The level's half of the same rule is ai-tools-alerts#0z4e.

## Problem

A relay-bot reply that widens a product entry is joined at once (`pull._apply_patch`, `_join`): a widening is a raise, and a raise fails open. One widening is not harmless. A reply that raises `fixed` on a thread that already stated one (root `fixed: 2.0`, reply `fixed: 9.9`) replaces the entry. Every member on 2.0 or later is told they are affected, and `check.plan` builds the upgrade from the new `fixed`: `plan` prints `npm install -g <package>@9.9`, the notification says `upgrade ... to 9.9 or later`. A stolen relay-bot key can use it to send members to a version the vendor never named as the fix. swfe refuses such a `fixed` only when it arrives in a narrowing.

## Success criteria

Each is a test.

1. A relay-bot reply that raises `fixed` past the advisory's, on a thread that stated the advisory's, is shown with a flag and no upgrade version: `check`, `plan`, `verify` and `run` print the flag line; `plan` prints no `command:` for the upgrade; the notification text names no version; `check --json` and `run --json` carry `fixed_contradicted: true`. The alert still matches at its level and still interrupts.
2. A reply that raises `fixed` to what the advisory now states shows the version: no flag, `plan` prints the command.
3. With the fetch failing nothing changes: no flag, the version is shown as today. The same with `verify = "off"`, a CLI the trust root calls too old, and one whose ruleset is out of date.
4. A released reader is unaffected: nothing on the wire changes, and `tests/test_wire_compat.py` shows the widened entry on v0.1.7 to v0.2.1 and on this reader alike (same level, same `fixed`, same match).
5. Starting with no cached result, `run` notifies with the raised version (a critical never waits), reads the source, and in the same run sends one correction without it; a later `run` sends none. With `lang = "ja"` neither the correction nor `plan` shows the translation's version.
6. A whole read whose cache cannot be written still flags the entry in that command.

## Approach

### The question (`verify.fixed_stated`)

New function in `aitools_alerts/verify.py`, from the cache only, no request:

`fixed_stated(adv, product, cache) -> bool | None`. `adv` is the thread state as shown, `product` one of its entries.

- `None` (nothing known) when: `cache` is None; `adv` is not a relay-bot post; `product.fixed` is None; the product is no scope product (`scope_of`); the state has no result, or its result has no `ranges`, or its reads were not whole (`whole` is not True); the result holds no range for the scope product; or one of its ranges is one this reader cannot compare (a None item: an OSV entry, an unreadable GitHub range).
- Otherwise `True` when some range states a first patched version equal to `product.fixed` (`versions.parse` of both, as `verify._states` compares them), else `False`.

`ranges` is what swfe added: per scope product, the `[range, first patched]` pairs of every counted authority that supports the product and may lower. The result is keyed by the published state, and `fixed` is part of the key (`_Target.key`), so a reply that changes `fixed` is a state with no result until this machine reads its sources again.

`None` also when the sources support the product at no level (the product's result names no source level): a withdrawn advisory still lists its ranges, and an alert the source does not support is 0z4e's question. (Found in execution: an existing 0z4e test read a withdrawn advisory and gained the flag.)

Only `False` acts. It needs a whole read: with an alias unread, another advisory of the thread could state that version. No age limit: a result is read again daily for every relay-bot match (0z4e), and a failed read leaves the entry with `whole` False, which is `None` here.

The rule is about the entry the thread shows, not about how it got there. A root posted with a `fixed` no advisory range states is flagged like a reply that raised it. The motivating case (the reply) is the test.

### What a flag changes (`check.Match.fixed_contradicted`)

`check.Match` gains `fixed_contradicted: bool = False`. `cli._matches` sets it on each (entry, match) pair, after `_shown`, when `verify.fixed_stated(t.adv, m.product, cache) is False`; `cache` is `_results(a, st, s)`: None with `verify = "off"`, for a CLI the trust root calls too old or out of date, and without settings. Never for an entry shown at notice by 0z4e (`t.published`): no source supports its product, so no range is counted for it, and `t.adv` then carries a level nobody published.

With the field set:

- `check.plan` gives the upgrade action no value (`value=None`), so it is never ready for auto-apply and `upgrade_command` returns None. (A relay-bot post never auto-applies anyway; `plan` re-checks.)
- `check.describe(action, fixed_contradicted=False)`: an upgrade with no value reads `upgrade <target> (the fixed version given is not the advisory's)` when the flag is set, in place of `(no fixed version given)`.
- `cmd_plan` prints `      the fixed version given is not the advisory's: notify only, no command` under that upgrade.
- `notify.format_text` leaves `(fixed in X)` out of the `Affected:` line and describes the action with the flag.
- `_match_json` adds `"fixed_contradicted": <bool>`. `product` stays as published: it is the range the match was made with.

What does not change: the match itself, its reason, its level, the interrupt (0z4e decides the level; a flagged alert keeps its slot rules), the entry in `product`.

### The line

`FIXED_LINE = "source check: the fixed version {id} gives for {name} is not the advisory's: no upgrade version is shown"`, printed by `_source_lines` (so by `check`, `plan`, `verify` and `run`) once per id and scope product, for every thread it is given whose shown entries include a flagged one. Printed: the id as `verify.norm_id` returned it and a scope product name, as every other source-check line. Not the version: the line states nothing the signer chose.

### Translations and the title

Code review, BLOCKER: the English title is the signer's prose as much as a translation is ("Upgrade Claude Code to 50.0.0" is a valid title, and the reply that raises `fixed` can set it). For an entry with a flagged match the id stands for the title, `advisory <id>`, wherever the CLI prints one for that entry: the `check` listing and its held line, `plan`, the notification and the correction. The JSON keeps the post as published with the flag; the skill texts tell the agent, before its first report, to name such an advisory by its id and say no version (code review, SUBSTANTIVE).


A translation is the signer's prose and can name the version (the shipped Japanese template writes `<fixed> 以降に更新してください`). A translation belongs to the entry, not to one match. So for an entry any of whose matches on this machine is flagged, no translation is used for any of its matches: the notification is the English text, and `plan` prints the English title and no quoted translation (an unflagged Codex match of the same thread would otherwise quote the body that names the flagged Claude Code version). `notify.format_text` also ignores a translation for a flagged match on its own. `check`'s one-line listing keeps the translated title: it is a title, and the flag line follows it.

### This command's own read counts

`_source_check` returns the results it read, also when the cache could not be written (`verify.Unsaved`). The flag is computed from those results when a command has them, else from the cache on disk: `run` and `verify` mark their pairs again after the source check (`_flag(pairs, cache)`), and `_source_lines` takes the same results (`fresh=`). So a whole read that contradicts `fixed` flags it in that command whether or not `verify.json` was written. The command's own results are used only where the cache on disk would be (`_results` is not None): a CLI the trust root calls too old still reads sources (`_source_check` does not look at `min_cli`), and it flags and corrects nothing.

### When a member sees it: the first notification, and the correction

`run` notifies before it reads a source (a critical never waits for one), and a reply that changes `fixed` is a new state with no result. So the first notification of a critical whose `fixed` was just raised names the raised version, as today, and marks the alert seen. Left there, the only notification a member gets is the one with the version the advisory contradicts.

So a flag found after the notification is sent as a correction, once:

- A correction is due for a pair (entry, match) when the entry is critical, the match is not `may apply`, the alert is seen, the match is flagged, and no correction for this root, product and `fixed` was sent.
- `run` sends due corrections after its source check, with the results that check returned (`run --json` reads no source: from the cache on disk); `notify` sends them from the cache on disk. The text is `Correction: the fixed version this alert gave is not the advisory's; no upgrade version is shown`, then `notify.format_text` of the flagged match (English, no version). The line claims nothing about what an earlier notification said: a notification describes one match of an entry, and which one is not recorded.
- What was sent is remembered in `seen.json` beside the root ids, as a key no event id can equal: the SHA-256 of `fixed-correction`, the root id, the product key and the `fixed` (as `pull.narrow_key` sits beside root ids in `State.refused`). `seen.json` is a list of strings to every released reader, which only test membership of root ids.
- An accepted notification of an entry records the key of every match of that entry flagged at that moment, whichever match the text described: the alert was sent with no translation and, for the match described, no version, so nothing is left to correct. A critical matching Claude Code and Codex with both flagged is one notification and no correction.
- A correction takes no slot, sets no exit 2 and is not an interrupt of its own: the alert already interrupted. One that no channel accepted is tried again by the next `run` or `notify`; `run`'s status is then 1, as for any failed send.
- A member whose CLI is upgraded while it holds a seen critical with a flagged `fixed` gets one correction for it.

With the fetch failing no correction is due (nothing is flagged): nothing changes. `run --json` (the session-start hook) reads no source; it reports the flag, and sends a due correction, from the cache an earlier `run` wrote.

### Files

- `aitools_alerts/verify.py`: `fixed_stated`, `__all__`, module docstring.
- `aitools_alerts/check.py`: `Match.fixed_contradicted`, `plan`, `describe`.
- `aitools_alerts/cli.py`: `FIXED_LINE`, `CORRECTION_LINE`, `_flag`, the marking in `_matches`, `_source_lines(fresh=)`, `cmd_plan`, `_match_json`, `_corrections` and `_correct`, `_notify`, `cmd_notify`, `cmd_run`, `cmd_verify`.
- `aitools_alerts/notify.py`: `format_text`.
- `tests/test_fixed_stated_cli.py` (new), `tests/test_verify_narrowing.py` or a new `tests/test_fixed_stated.py` for the function, `tests/test_check.py`, `tests/test_wire_compat.py`.
- `README.md`, `CHANGELOG.md` (Unreleased), `spec/wire.md` (one paragraph: nothing on the wire), the three skill files that quote `plan`'s upgrade lines and the JSON keys.

No wire, schema, manifest, ruleset or state-file change. The cache format is unchanged (`VERSION` stays 5).

## Alternatives considered

- **Refuse the widening (keep the old entry).** Rejected: the issue says the alert is not narrowed, and a raise must fail open. A vendor that moves the fix to a later release (a bad first patch) is a true widening, and the advisory will come to state it.
- **Fall back to the advisory's first patched version in the upgrade.** Rejected: an advisory can state several (one per release line or package), and choosing one is a judgement this reader does not make; "no version, as for an alert with no known fix" is what the issue asks.
- **A memory of the flag (as 0z4e keeps for support), so a failed read after a whole one keeps it.** Rejected for now: the acceptance says a failing fetch changes nothing, a relay-bot match is read again daily, and a stolen key does not control a member's reads of GitHub. Cost of not having it: after a whole read flagged an entry, a later failed read shows the version again until the next whole read.
- **Hold the first notification until the source is read.** Rejected: a critical never waits for a source (tavj), and with the fetch failing it would change what is sent.
- **Leave the version out of every unverified relay-bot notification.** Rejected: with the fetch failing that changes what every member is sent.
- **Flag on a partial read.** Rejected: an unread alias may state the version; the flag would be wrong for a correct post.
- **Decide in `check.match` from the cache.** Rejected: `check` is the pure matcher (no state, no cache); the CLI already layers 0z4e's demotion on its pairs.

## Blast radius and rollback

Member CLI only. A flag removes a version from an upgrade suggestion and adds a line; it hides, lowers and executes nothing. Wrong flag (a correct `fixed` the advisory states in a form this reader misreads): the member sees the upgrade without a version and the source link. Rollback: revert the commit; no stored state depends on it.

Existing tests whose fixture posts a `fixed` other than the advisory's (the default `99.0.0` against an advisory stating `9.9.9`) will gain the line where they read the source whole; their expectations are updated only where the new line is true of the fixture.

## Open questions

None blocking. Whether a flagged `fixed` should also give the relay-bot key a strike is ai-tools-alerts#m729's subject (as for 0z4e), not built here.
