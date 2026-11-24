# Plan: the curator override, checked and held for 14 days (c1g2)

Spec: `docs/superpowers/specs/2026-11-24-c1g2-curator-override-time-boxed-design.md`. Tests are written with each chunk and run with `python3 -m pytest -q <file>`; the whole gate is `scripts/test-gate.sh`.

## Chunk 1: the reader (`aitools_alerts/pull.py`)

- [ ] Constants: `CURATOR_HOLD_S = 14 * 86400`, `NONE = "none"`; export `standing`, `asks`, `CURATOR_HOLD_S`.
- [ ] `Thread` gains `wide: Advisory | None`, `held_until: int | None`, `offered: str | None`, `held_aliases: tuple`, `held_fixed: tuple`, `refused: str | None`. All default to nothing, so a curator's own thread and every existing constructor call are unchanged.
- [ ] `_bot_patch(adv, patch, dropped)`: the relay bot's rules for one block, moved out of the loop of `threads_from` without change: `_apply_patch` as a non-curator; when that refuses, count `bad-patch` and join only `products`, `actions`, `sources`. Returns `(advisory or None, the block as applied)`.
- [ ] `threads_from`: per relay-bot root a `_Hold` (`wide`, `until`, `offered`, `aliases`, `fixed`). In the reply loop, for such a thread:
  - a curator's reply dated after `until` first lapses the hold (`adv = wide`, not retracted, not curated, `until = None`); a relay-bot reply never does;
  - renewals are collected even while retracted;
  - a relay-bot reply: a level-only lowering against `wide.level` sets `offered` (and raises the held level when it is above it) and stops; any other block goes to `wide` through `_bot_patch`; with no hold in force `adv` is `wide`; with one in force only a higher named level reaches `adv`, and not on a retracted thread; a named level at or above `wide.level` clears `offered`;
  - a curator reply: `retract` retracts, sets `offered = none`, renews the hold (also on a thread already retracted); a `level:` line at or below the current level lowers or renews and sets `offered`; a block applies to `adv` under the curator's rules (as today) and to `wide` through `_bot_patch` with no counter, and a level it names sets `offered` when below `wide.level` and clears it otherwise (tests: a lowering in a block; a raise that takes a lowering back); each action sets `until = created_at + CURATOR_HOLD_S` and `curated`;
  - a curator's own thread takes the loop exactly as before (`_Hold` is None).
  - The manifest's `retracted` list: the thread is built with `wide = None`, so nothing can lapse it.
- [ ] `widest(t)`: the advisory a check is asked about (every alias held; the first stated `fixed` where an entry has none).
- [ ] `asks(t, now=None) -> list[str]`: the levels a member's check is asked about for this thread: the held level (or `none`) while a hold is in force, and `offered`.
- [ ] `standing(t, now=None, check=None) -> Thread`: the table of spec section 4. A lapsed or refused view drops the translations when its advisory differs from the held one.
- [ ] `active(threads, now, listed, check=None)`: `standing` first (the hold's clock is `now` only when the checkpoint lists the root), then the existing rules.
- [ ] Tests, `tests/test_curator_hold.py` (new) and the two existing tests the rule changes (`tests/test_pull.py::test_relay_bot_cannot_undo_a_curator_amendment`, `tests/test_expiry.py::test_a_curated_thread_and_a_thread_without_a_claim_do_not_decay`): hold and lapse by the checkpoint's clock; a renewal; a raise at once and another change after the hold; a raise does not undo a retraction; a later curator action does not bring back a lapsed lowering; a curator's own thread unchanged, relay-bot replies 15 days later included; a manifest-listed thread never lapses; `offered` set and cleared; decay resumes after a lapse with renewals counted; order independence of the widest state.

Acceptance: `python3 -m pytest -q tests/test_curator_hold.py tests/test_pull.py tests/test_expiry.py tests/test_bot_patch.py tests/test_attacks.py`.

## Chunk 2: the member's check (`aitools_alerts/verify.py`, `aitools_alerts/cli.py`)

- [ ] `verify.at_level(adv, level)`: the state asked about; `verify.lowering(adv, level, cache, now) -> True | False | None` (spec section 4: `match` only, not below `reading_cap`, at most `FRESH_S` old); `verify.run(..., recheck=)` reads an asked state again daily; `verify.judge` at level `none`.
- [ ] `cli.main` puts the settings on the namespace (`a.settings`), so every caller of `_matches(a, st)` (`check`, `verify`, `plan`, `notify`, both passes of `run`) has them without a signature change. `cli._matches`: build the threads once (`pull.advisories`), keep them (`a.raw`) and the asked states (`a.asked`) on the namespace, pass `check` to `pull.active`. `check` is None with `verify = "off"` and with a CLI below `min_cli`.
- [ ] `cli._source_check(st, s, threads, pairs, asked)`: add the asked states to `current` and to `wanted` (`all`: every one; `matched`: those whose widest state matches this machine) and pass them as `recheck=`. In `verify.run`, a rechecked state whose turn the budget cut short is stored `unread`, never its old result with a new time. Tests: the budget case; a confirmed lowering read again a day later through `cli.main`.
- [ ] `cli._source_lines`: the two refused-lowering lines, computed from the kept threads with the cache as it is after the source check.
- [ ] `cli.cmd_run`: when a lowering was asked about, build the matches again after the source check and notify a critical that only now shows; exit 2 as for any unseen critical.
- [ ] `cli.Entry` gains `refused`, filled by `_entries` from the threads it groups (copies merge by equal advisories as before; a refusal on any copy is reported); `cli._match_json`: `"lowering_refused"`, asserted for `check --json` and `run --json`.
- [ ] Tests, `tests/test_curator_hold_cli.py` (new): the three acceptance cases of the issue end to end through `cli.main`; the four attack cases of spec criterion 2a; the same-run notification (2b); a bot lowering unread or contradicted keeps the level; `verify = "off"` and a too-old CLI apply none; `matched` asks only for a matching thread; no source is read by `run --json`; a curator-amended relay-bot thread is never auto-applied; nothing but fixed words, ids and level words is printed.

Acceptance: `python3 -m pytest -q tests/test_curator_hold_cli.py tests/test_verify.py tests/test_verify_cli.py tests/test_cli.py`.

## Chunk 3: the curator command and the other readers

- [ ] `curator.find_threads`, `_present`, `_replayed`: the thread as it stands at the command's clock (`pull.standing(t, now)`).
- [ ] `curator.renew_event` and the `renew` subcommand; `cmd_curator` prints when the hold of a relay-bot thread ends.
- [ ] `mirror/export_mirror.py::_threads` and `poster/main.py::_withdrawn`: `pull.standing(t, now)`.
- [ ] Tests in `tests/test_curator.py`: renew a lowering, a retraction and a narrowing; nothing to renew; an amendment after a lapse is written against the widest state; the hold note. One test each for the exporter page and `_withdrawn` after a lapse.

Acceptance: `python3 -m pytest -q tests/test_curator.py tests/mirror tests/poster`.

## Chunk 4: documents

- [ ] `README.md` (trust section, curator command), `docs/design.md` (reply rules), `spec/wire.md` (expiry list, the released-reader promise and its exception), `CHANGELOG.md` (Unreleased).
- [ ] `tests/test_wire_compat.py`: the existing cases unchanged, and one new case: a relay-bot thread a curator lowered is at the curator's level on a released reader for good, and on this reader until the hold lapses.

Acceptance: `scripts/test-gate.sh` (in a single-branch clone if the shared clone's scan fails on other branches' objects).

## Landing

Merge `origin/main`, gate, one independent review of `git diff origin/main...HEAD`, pull request, merge with the no-reply author address, check `git log -1 --format=%ae origin/main`, close the issue on the merge commit. Follow-ups filed: what remains of ai-tools-alerts#r98k as a `rollout:` issue; the Atom feed's withdrawal entry after a lapse; a note on ai-tools-alerts#tavj.

## Rollback

Revert the merge commit. No state file, wire format or manifest changes.
