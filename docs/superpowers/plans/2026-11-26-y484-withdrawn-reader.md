# The withdrawn state, member's half: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A relay-bot reply whose block is exactly `{"level":"withdrawn"}` hides its thread on the current reader while the member's own source check confirms the withdrawal, is a lowering to notice otherwise, and is refused by every released reader.

**Architecture:** The reader keeps the withdrawal as the thread's published offer (`Thread.offered == "withdrawn"`), never applied in replay. `pull._level_standing` decides with the member's check; `verify.lowering` answers for the level word `withdrawn`; the CLI's refusal memory asks through one function, `pull.offer_said`.

**Tech Stack:** Python 3 standard library, pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-26-y484-withdrawn-reader-design.md`

## Global Constraints

- `withdrawn` is not a level: `schema.LEVELS`, `wire.LEVELS`, `pull._RANK`, `spec/advisory.schema.json` do not change.
- Released readers v0.1.4 to v0.2.1 must still show the alert at its level (the review lens).
- A withdrawal never hides a thread unchecked. `lowering(adv, "none", ...)` stays never True.
- No poster file changes (`aitools_alerts/poster/`): that is ai-tools-alerts#kk2q.
- `verify.json` keeps its version; no state file changes shape.
- No host, tailnet, VM or home-path name and no personal email in any file or commit.

## Review Focus

1. A check run cut short: the withdrawal contradicted, notice unread. Expected: the level stays past 72 hours and the root is remembered as refused (Task 2 and Task 4 tests).
2. A withdrawal on a thread already at notice. Expected: nothing to lower, no wait reported, no "lowering to notice refused" line (Task 2).
3. A curator's hold in force. Expected: the curator's state shows; the withdrawal is judged after the hold (Task 2).
4. A hostile block near the word: `{"level":"withdrawn","title":"x"}`, `{"level":"Withdrawn"}`, `{"level":["withdrawn"]}`. Expected: no withdrawal, counted `bad-patch`, the thread unchanged (Task 1).
5. A hidden claimed thread whose claims run out. Expected: gone, as any decayed thread (Task 2).

---

### Task 1: the wire word and the reader's replay

**Files:**
- Modify: `aitools_alerts/wire.py` (after `is_lowering`), `aitools_alerts/pull.py` (`_bot_reply`, `asks`, `offers`, `__all__`)
- Test: `tests/test_withdrawn.py` (new), `tests/test_wire.py`

**Interfaces:**
- Produces: `wire.WITHDRAWN = "withdrawn"`; `wire.is_withdrawal(patch) -> bool` (True only for a dict equal to `{"level": "withdrawn"}`); `pull.WITHDRAWN` (the same word); `pull.unchecked_level(t: Thread) -> str | None` (`"notice"` for a withdrawal, else `t.offered`); `Thread.offered == "withdrawn"` with `offered_by` the first withdrawal reply's id.

- [ ] Tests in `tests/test_withdrawn.py`, with the helpers of `tests/test_curator_hold.py` (`bot_root`, `thread`, `says`, `AT`) and a local `withdraw(m, root, at=AT, first=None)` that posts `"Withdrawn by its source.\n\n```aitools-alert\n{\"level\":\"withdrawn\"}\n```\n"` as the relay bot:
  - `test_a_withdrawal_is_published_and_not_applied`: `(t.offered, t.offered_by) == ("withdrawn", reply id)`, `t.adv.level == "critical"`, `not t.retracted`, `t.stated` has only the root's entry, `t.renewals` unchanged by it.
  - `test_sent_again_it_keeps_the_first_reply`.
  - `test_a_level_reply_ends_it`: at the widest level and above it `offered is None`; below it `offered == "high"` and `offered_by` is that reply.
  - `test_a_lowering_then_a_withdrawal`: `offered` goes `"notice"` then `"withdrawn"`, `offered_by` the withdrawal.
  - `test_near_misses_are_no_withdrawal` (parametrized over the Review Focus 4 blocks, and a first line `retract` above the exact block): `offered is None`.
  - `test_a_root_that_names_withdrawn_is_no_advisory`.
  - `test_asks_and_the_record`: `pull.asks(t) == ["withdrawn", "notice"]`; on a notice root `["withdrawn"]`; `pull.offers([t], {}, now, listed) == {reply id: now}`; `pull.unchecked_level(t) == "notice"`.
  - on a curator's own thread a relay-bot withdrawal is discussion: `offered is None`.
- [ ] Run: `python3 -m pytest tests/test_withdrawn.py -q`; expected: the new tests fail.
- [ ] Implement. `_bot_reply` handles `wire.is_withdrawal(p)` first: set `offered_by` to the reply unless the offer already is a relay bot's withdrawal, set `offered`, return. `asks`: after the published offer, add `"notice"` for a withdrawal whose `wide.level` is above notice. `offers` needs no change beyond its docstring (`"withdrawn"` is not in `(None, NONE)`); the test pins it.
- [ ] Run the file and `tests/test_wire.py tests/test_unchecked_lowering.py tests/test_curator_hold.py`; expected: pass.

### Task 2: standing

**Files:**
- Modify: `aitools_alerts/pull.py` (`_level_standing`, new `offer_said`, docstrings of `standing`, `active`, `Thread`)
- Test: `tests/test_withdrawn.py`

**Interfaces:**
- Produces: `pull.offer_said(t: Thread, check) -> bool | None` as the spec defines it (`check` None gives None; a thread with no relay-bot offer gives None).

- [ ] Tests, with a check stub `by(withdrawn=..., notice=...)` that answers per level asked:
  - `test_hidden_only_while_the_check_confirms`: `by(True, True)` gives no active thread; `by(None, None)` at `AT + 900 days` with no record gives critical.
  - `test_unconfirmed_it_is_a_lowering_to_notice`: `by(None, True)` notice; `by(None, None)` with `since` gives `("critical", waiting "notice")` before 72 hours and notice at 72 hours, never hidden; `by(None, False)` gives `refused == "withdrawn"`.
  - `test_a_contradicted_withdrawal_stops_the_unchecked_notice` (4a): `by(False, None)` past 72 hours with `since` stays critical, `refused == "withdrawn"`, `waiting is None`; `by(False, True)` gives notice, no refusal.
  - `test_support_above_notice_overrides_an_older_confirmation`: `by(True, False)` is shown at critical with `refused == "withdrawn"`, and `offer_said` is False.
  - `test_on_a_notice_thread_there_is_nothing_to_lower`: `by(None)` gives notice, no waiting, no refusal; `by(False)` gives `refused == "withdrawn"`; `by(True)` hidden; the check is asked `withdrawn` only.
  - `test_a_curator_s_hold_governs` (both orders of a curator title amendment and the withdrawal): shown under `by(True, True)` inside the hold, hidden after `held_until`.
  - `test_a_curator_s_retraction_is_unchanged`: after its hold, with a stub that says True only for `"withdrawn"`, the thread is back at critical.
  - `test_expiry_is_not_changed`: a claimed root (`tests/test_expiry.py` helpers), withdrawn and confirmed: hidden; unconfirmed before the claims run out: shown; after: absent whatever the check says.
  - `test_offer_said` table.
- [ ] Implement `offer_said`, then `_level_standing` after the held branch: for a withdrawal, hidden (`replace(base(), retracted=True)`) only when `check(widest, "withdrawn", stated)` is True and `offer_said` is not False (the notice answer does not contradict); when `wide.level` is notice return `base("withdrawn" if that answer is False else None)`; else go on with `low = "notice"`, `said = offer_said(t, check)` and `refused` named `"withdrawn"`. A lowering keeps its path with `low = t.offered`.
- [ ] Run `tests/test_withdrawn.py tests/test_curator_hold.py tests/test_unchecked_lowering.py tests/test_expiry.py tests/test_pull.py`; expected: pass.

### Task 3: the check

**Files:**
- Modify: `aitools_alerts/verify.py` (`at_level`, `claimed`, `lowering`)
- Test: `tests/test_withdrawn.py` (with the `lowering` helper and tables of `tests/test_unchecked_lowering.py`)

- [ ] Tests:
  - `claimed(adv, "withdrawn", stated)`: True for `(("critical", MALWARE),)` and for `(("critical", MALWARE), ("notice", claim at notice))`; False when any statement lacks its claim, a notice one too; `"none"` still False.
  - `at_level(a, "withdrawn").level == "none"`, and its `_Target` key equals that of `at_level(a, "none", same claimed)`.
  - `lowering(a, "withdrawn")` over a withdrawn malware advisory: True claimed; None unclaimed; False when the source gives high, and still False after a failed read; None when the advisory names another package (silent: `unauthoritative`); None at `NOW + FRESH_S + 1`; None with `whole=True` unclaimed. `"none"` keeps what it has today in every row: False where the source supports more (a kept contradiction after a failed read too), None elsewhere, never True.
  - Incomplete reads: a confirmed withdrawal followed by a failed refresh a day later is None (the result is `unread`); a withdrawn first advisory that names a second id whose read fails is None; an advisory with two products of which the withdrawn source names one is None.
- [ ] Implement: `at_level` maps the word to `ruleset.NONE`; `claimed` reads `withdrawn` as rank below every level (every statement must be claimed) and keeps False for `none`; `lowering` for the word: `below-source` False; True only when claimed, the held result is within `FRESH_S` and every product is `confirmed` / `match`; else None.
- [ ] Run `tests/test_withdrawn.py tests/test_verify.py tests/test_unchecked_lowering.py`; expected: pass.

### Task 4: the CLI and the documents

**Files:**
- Modify: `aitools_alerts/cli.py` (`_note_offers.step`, the refusal line in `_source_lines`, the count line in `cmd_verify`), `spec/wire.md`, `README.md`, `CHANGELOG.md`
- Test: `tests/test_withdrawn.py` or `tests/test_unverified_cli.py` (its harness), `tests/test_wire_compat.py`

- [ ] CLI tests through the harness `tests/test_unverified_cli.py` uses: (a) a claimed thread whose advisory is withdrawn, the withdrawal reply listed: after `verify`, `check --json` has no match and exit status says clear; the source returns the advisory: after the next source check the alert is back at critical and stderr or the verify output says `a withdrawal of <id> is not applied`. (b) 4a end to end: the withdrawn state read with support, the notice state unread, then reads failing and a checkpoint 73 hours later: still critical, root in `State.refused`.
- [ ] `tests/test_wire_compat.py`: `test_a_relay_bot_withdrawal_is_refused_by_every_released_reader`, parametrized over `RELEASED + CLAIM_READERS`: a relay-bot critical and the withdrawal reply; the released reader shows `["critical", ["99.0.0"], True]` now and (for readers before 0.1.8) a month on; this reader shows the same unchecked, nothing under a check that confirms, and notice after 72 hours of the record.
- [ ] A CLI test of the refusal line for a notice-derived refusal: the notice state read with support, the withdrawn state unread; `verify` prints `a withdrawal of <id> is not applied: the source supports critical for Claude Code` and `check --json` has `lowering_refused == "withdrawn"`. And one through the real cache for the older confirmation: both states confirmed, then the source returns and a run reads only the notice state; the alert shows at critical.
- [ ] Implement: `step` uses `pull.offer_said(t, check)` for `said` and `check.whole(widest, pull.unchecked_level(t), stated)`; the refusal line names a withdrawal and takes its `below-source` products from both asked states of the thread (`withdrawn` and `notice`), each line once; the count line says `lowerings, withdrawals or retractions`, and the assertion on that line in `tests/test_curator_hold_cli.py` (line 119) is updated with it.
- [ ] Documents: `spec/wire.md` gets a section "A withdrawal" (the block, the table row for released readers, what this reader does, that it is no renewal, that nothing sends it until kk2q) and a row in the table at the top; `README.md` the member-facing sentences beside the lowering paragraph; `CHANGELOG.md` an entry under Unreleased.
- [ ] Run the whole suite: `python3 -m pytest -q -x`; expected: pass. Then the gate in a single-branch clone (the shared clone's public scan reads other sessions' refs).
- [ ] Commit (signed, no-reply author): `git add` the files above and the spec, plan and run record.

## Amendment after the code review (2026-11-26)

The code review found the two-question design unsafe: the results for `withdrawn` and for `notice` are cached apart, and a run that refreshes one leaves the other standing, in both directions. The design is now one question (spec 4a). What changed against the tasks above: `pull.offer_said` is gone; `pull.asks` returns `withdrawn` alone; `_level_standing` decides from `check(widest, "withdrawn", stated)`; `verify.lowering` for the word is False only for support above notice, and answers `whole`; `cli._note_offers` and the refusal line are as they were before this change, apart from the word "withdrawal". The tests named in Tasks 2 to 4 for the two-answer table are replaced by the one-question tests in `tests/test_withdrawn.py`.

## Acceptance

Every success criterion of the spec has a test named above; the full suite and `scripts/test-gate.sh` pass.

## Rollback

Revert the commit. No state migrates.
