# Plan: a `fixed` the advisory does not state is flagged and gives no upgrade version (ai-tools-alerts#53fy)

Spec: `docs/superpowers/specs/2026-11-27-53fy-widened-fixed-flagged-design.md`. One chunk, one commit series on branch `53fy-self-correct-53fy`. Expected size: about 150 changed lines of code, 350 of tests, 40 of documents.

Rules for every task: tests use the `home` fixture through `test_verify_cli.env` (never the real HOME, ai-tools-alerts#3h9j); run a test file with `python3 -m pytest tests/<file> -q`; the whole suite only through `scripts/test-gate.sh` at the end.

## Chunk 1: the flag, the plan without a version, the correction

### Task 1: `verify.fixed_stated`

- [ ] `tests/test_fixed_stated.py` (new), unit tests over a hand-built cache (as `tests/test_verify_narrowing.py` builds one with `verify.run` and `Net`):
  - a `fixed` equal to a stated first patched version: True, also when written another way `versions.parse` reads as equal (`9.9.9` and `9.9.9.0` only if `parse` equates them; else skip that case);
  - a `fixed` no range states: False; a range with no first patched version and an entry with a `fixed`: False;
  - two ranges for the product, the entry states the second's: True;
  - None for: `cache` None; a curator's post; `fixed` None; a product that is no scope product; no result for the state; a result with `whole` False (an alias the first id names fails to read); no range for the product (a KEV-only thread); a None item among the ranges (an unreadable GitHub range, an OSV entry).
- [ ] `aitools_alerts/verify.py`, after `narrowing` (line 678): `fixed_stated(adv, product, cache) -> bool | None` as the spec's "The question" states it; add to `__all__` (line 44) and one sentence to the module docstring (line 17).

Acceptance: the new file passes; `tests/test_verify.py` and `tests/test_verify_narrowing.py` still pass.

### Task 2: `check` and `notify`

- [ ] `tests/test_check.py`: a Match with `fixed_contradicted=True` plans its upgrade with `value` None, in `prepare`, never in `auto_apply` (a curator post with the verb opted in, to show the flag alone is enough); `describe(action, True)` reads `upgrade <target> (the fixed version given is not the advisory's)`; `describe` of other verbs and of an upgrade with a value is unchanged by the argument.
- [ ] `tests/test_cli.py` (beside the `format_text` tests, line 78): `format_text` of a flagged match has no `(fixed in`, no version in `Action:`, and with a translation passed returns the English text.
- [ ] `aitools_alerts/check.py`: `Match.fixed_contradicted: bool = False` (line 66); `plan` line 229: `fixed = p.fixed if p is not None and not m.fixed_contradicted else None`; `describe(action, fixed_contradicted: bool = False)` (line 242).
- [ ] `aitools_alerts/notify.py` `format_text` (line 41): when `m is not None and m.fixed_contradicted`: ignore `translation`, leave `fixed` out of `Affected:`, and pass the flag to `check.describe`.

Acceptance: both test files pass.

### Task 3: the CLI marks, prints and reports the flag

- [ ] `tests/test_fixed_stated_cli.py` (new), on `test_verify_cli.feed`, `test_curator_hold_cli.serve`, `test_verify.Net`/`ghsa`, `test_unverified_cli.sent`. The thread: `bot(id=G1, level="critical")` with products and actions at the advisory's `<9.9.9` / `9.9.9` (the root states the advisory's), installed Claude Code inside the range; the reply: a relay-bot patch whose `products` is the entry with `affected="<50.0.0", fixed="50.0.0"` (a widening: it stands for the root's entry).
  - acceptance 1 (`test_a_reply_that_raises_fixed_past_the_advisory_is_flagged_and_gives_no_upgrade_version`): after `run`, `check --json` gives `fixed_contradicted` true, `product.fixed` `50.0.0`, level critical; `check`, `plan`, `verify`, `run` print `FIXED_LINE`; `plan` prints no `command:` and prints the "not the advisory's: notify only, no command" line; the alert still set exit 2 on its first `run`.
  - acceptance 2 (`..._to_what_the_advisory_now_states_shows_the_version`): the advisory served with `first_patched_version` `50.0.0` and range `< 50.0.0`: no flag, `plan` prints `command: npm install -g @anthropic-ai/claude-code@50.0.0`, `fixed_contradicted` false.
  - acceptance 3 (`test_with_the_fetch_failing_nothing_changes`), parametrized over 404, a timeout (`OSError`), and `verify = "off"`: no flag line, `plan` prints the command with `50.0.0`, the notification text names it, no correction is sent, `seen.json` holds only root ids.
  - a too-old CLI (`min_cli`) and an out-of-date ruleset (`ruleset_pin`, as `test_verify_cli._pin`) with a flagged result on disk: no flag, the version shown.
  - a partial read (the thread's first id names an alias that fails): no flag.
  - a root posted with a `fixed` the advisory does not state (the default `bot()` fixture, `99.0.0`) is flagged the same way.
  - an entry shown at notice by 0z4e (`published`) is not flagged.
  - the cache cannot be written (`verify.write_json` raising `OSError`, as `test_a_read_whose_cache_cannot_be_written_still_ends_the_demotion_for_that_command` does): `run` still prints `FIXED_LINE` in that command.
- [ ] `aitools_alerts/cli.py`:
  - constants beside `LOST_LINE` (line 68): `FIXED_LINE`, `CORRECTION_LINE`.
  - `_flag(a, st, pairs, fresh=None) -> list`: each pair with `m.fixed_contradicted` set to `not t.published and m.product is not None and verify.fixed_stated(t.adv, m.product, cache) is False` (`dataclasses.replace`). `cache`: None when `_results(a, st, s)` is None (the eligibility guard: `verify = "off"`, a too-old CLI, an out-of-date ruleset, no settings), else `fresh or` that disk cache. `cache` None flags nothing. (Plan review, BLOCKER 1: `fresh` never bypasses the guard.)
  - `_flagged(pairs) -> dict`: {root id of an entry: the correction keys of its flagged matches}, over every root of the entry. An entry in it uses no translation anywhere.
  - `_matches` (line 321): `threads, pairs = _shown(...)`, then return `threads, _flag(a, st, pairs, _results(a, st, s))` with `s = getattr(a, "settings", None)`; without settings, `cache` is None.
  - `_source_lines(a, st, s, threads, fresh=None)` (line 726): after the `cache is None` return, for each thread that is not `published` and each entry `p` of `t.adv.products`, when `verify.fixed_stated(t.adv, p, fresh or cache) is False` and its scope name is in `scope`: `FIXED_LINE.format(id=ident, name=name)`. Deduplicated by the existing `dict.fromkeys`. `_results`-style guard: the function already returns early for a too-old or out-of-date CLI.
  - `cmd_plan` (line 1233): `check.describe(x, m.fixed_contradicted)`; under an upgrade with no value print the "not the advisory's" line when flagged, else the existing one; for a flagged match print `t.adv.title` and no quoted translation.
  - `_match_json` (line 827): `"fixed_contradicted": m.fixed_contradicted`.
  - `cmd_verify` (line 804) and `cmd_run` (line 1276): after the source check, `pairs = _flag(a, st, pairs, got)` (after any re-run of `_matches`), and pass `fresh=got` to `_source_lines`, which uses it only past its own too-old and out-of-date return.
  - `cmd_plan`: the translation (title and quoted body) is left out for every match of an entry in `_flagged(pairs)`, flagged or not (plan review, BLOCKER 3).

Acceptance: the new file's tests above pass.

### Task 4: the correction

- [ ] `tests/test_fixed_stated_cli.py`:
  - success criterion 5: no cached result; `run` exits 2 and sends one text naming `50.0.0`, then in the same run one text starting with `CORRECTION_LINE` and naming no `50.0.0`; a second `run` sends nothing; `seen.json` holds the roots and one correction key.
  - the source fails in the first `run` and answers in the second: the correction is sent by the second.
  - a correction no channel accepts (`sent["accept"] = False`) is sent again by the next `notify`, and `run` returns 1.
  - a thread first notified when the flag was already known: one text, without the version, and no correction after.
  - `lang = "ja"` with a translation reply that names `50.0.0`: neither the correction nor `plan` output contains the translation's body.
  - two matched products (Claude Code and Codex installed, both entries flagged, results on disk before the first notification): one notification, no version, no correction after, both keys in `seen.json`.
  - mixed (Claude Code flagged, Codex's `fixed` the advisory's), `lang = "ja"`: `plan` quotes no translation under either match, and the notification carries none whichever match it describes.
  - a too-old CLI's complete `run` from no cache (the source answers, the entry would be flagged): one notification with the version, no correction, no key in `seen.json`, no flag in `check --json`.
  - a high (not critical) flagged alert, and a `may apply` match: no correction.
  - `run --json` with a flagged result on disk and a seen critical: sends the correction, prints one JSON object only.
- [ ] `aitools_alerts/cli.py`:
  - `_correction_key(root_id, product, fixed) -> str`: `hashlib.sha256(json.dumps(["fixed-correction", root_id, verify.pkey(product), fixed]).encode()).hexdigest()`.
  - `_corrections(st, pairs) -> list`: the pairs with `t.published or t.adv.level` critical... precisely: `t.adv.level == "critical"`, `m.reason != check.MAY_APPLY`, `_seen(t, st)`, `m.fixed_contradicted`, and no key of `t.root_ids` for `m.product` in `st.seen`; one per (entry, product).
  - `_correct(st, s, due) -> int`: under `st.locked()`, re-read as `_notify` does (skip a key already in `st.seen`); text `CORRECTION_LINE + "\n" + notify.format_text(t.adv, m)`; on acceptance add the keys of every root of the entry and `st.save_seen()`; no channel configured: return 0 silently (the alert's own notification already reported that); returns 1 when a send was not accepted.
  - `_notify(st, s, pending, loose, flagged=None)` (line 1166): `flagged` is `_flagged(pairs)` of all the command's pairs. For an entry in it the text is built with no translation, whichever match is sent; on acceptance every key of the entry in `flagged` is added to `st.seen` with the roots (plan review, BLOCKERs 2 and 3: the keys of every flagged match of the entry, not only the one the text described).
  - `CORRECTION_LINE` claims nothing about an earlier notice: `Correction: the fixed version this alert gave is not the advisory's; no upgrade version is shown`.
  - `cmd_notify`: after `_notify`, `_correct(st, s, _corrections(st, pairs))` with the pairs of `_matches`; status is the `or` of both. (`_interrupts(a, st, s)` computes its own pairs today; pass the same pairs to both.)
  - `cmd_run`: after the source-check block (and for `--json` after the first `send`), `status = correct(_corrections(st, pairs)) or status` with stdout redirected as `send` does when `--quiet` or `--json`. It never changes `EXIT_UNSEEN_CRITICAL`.

Acceptance: the tests above pass; `tests/test_cli.py`, `tests/test_unverified_cli.py` pass.

### Task 5: the released readers, existing tests, documents

- [ ] `tests/test_wire_compat.py`: `test_a_relay_bot_widening_of_fixed_shows_the_same_on_every_reader`, parametrized over `("v0.1.7", "v0.1.8", "v0.2.0", "v0.2.1")`: a root with `fixed` 2.0-shaped entry inside which the installed version is not, a relay-bot reply that raises `fixed`; `released(...)` and `this_reader(...)` show the same level, the raised `fixed` and the match. (Nothing on the wire changed: this pins it.)
- [ ] Run `scripts/test-gate.sh`. For each existing test that fails because its fixture's `fixed` (`99.0.0`) is not the advisory's (`9.9.9`) and the source was read whole: update the expectation where the new line or the missing version is true of the fixture; where the test is about something else and exact output matters, leave the fixture and assert the line. List each changed test in the run manifest.
- [ ] `README.md` (the source-check list near line 154): one bullet. `CHANGELOG.md`: an `Unreleased` section at the top, and the "What stays open" sentence of 0.3.0 is left as history. `spec/wire.md` (after line 102): one paragraph, nothing added to the wire. `skills/claude-code/aitools-alerts/SKILL.md`, `skills/hermes/aitools-alerts/SKILL.md`, `snippets/AGENTS.md`: the third line `plan` can print under an upgrade, and `fixed_contradicted` among the keys of a match; keep the three texts in step (`tests/test_templates.py`).
- [ ] `scripts/public-scan.sh` passes (part of the gate).

Acceptance (the chunk): `scripts/test-gate.sh` exits 0; the six success criteria of the spec are each a named passing test.

## Verification

`scripts/test-gate.sh` (public scan, then `python3 -m pytest -q`). There is no repoman registry row for this repository (no `.repoman-managed` marker): this is the project's ordinary verification, run once on the combined result.

## Rollback

Revert the commits. `seen.json` may then hold correction keys: 64-hex strings no root id equals, ignored by every reader (they test membership of root ids).

## Order and dependencies

Task 1, then 2, then 3, then 4, then 5. Tasks 1 and 2 are independent of each other.
