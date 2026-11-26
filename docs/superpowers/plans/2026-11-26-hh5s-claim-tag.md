# Claim tag on sent events: implementation plan (ai-tools-alerts#hh5s)

> **For agentic workers:** this plan is executed by the /do-it pipeline in one session, task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the poster signs one `claim` event tag on every level change it sends, and on every root and copy once `main.ROOT_CLAIMS` is on; the journal, the owed byte count and the settle step carry it.

**Architecture:** the transport takes an optional claim tag and refuses anything `wire.claim_tag` would not write. A journal item keeps the tag's text under the optional key `claim`. One function, `rules.claim_text`, picks and builds the claim from the readings a level rested on; `recompute.support` hands back the readings it counted.

**Tech stack:** Python 3 standard library, pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-26-hh5s-claim-tag-design.md`

## Global constraints

- Nothing may wait for a person to act.
- `main.ROOT_CLAIMS = False` as shipped: no root or copy carries a claim. Tests of the root path turn it on with `monkeypatch.setattr(main, "ROOT_CLAIMS", True)`.
- A state file written before this change loads; an item without the key `claim` sends as before, with a three-argument `send`.
- `wire.MAX_CLAIM_BYTES` stays 2048. A claim over it is not sent, not trimmed, not replaced.
- `spec/advisory.schema.json`, the manifest and `signer.ENVELOPE` (600) do not change.
- No host, tailnet, VM or home-path name and no personal email in any file, commit or PR text.
- Stay inside this issue: no renewal, no step down, no signer change beyond the byte count.

## Review focus

1. A claim whose `checked_at` is after the event's `created_at` (the sender's clock stepped back): the reader takes no renewal from it. Test in task 4 that the claim's times are the run's `now` and the event is dated at or after it by the fake clock.
2. A journal item whose `claim` text is not a canonical claim tag (a damaged state file): `inputs._item_ok` refuses the state, as for any malformed item. Test in task 2.
3. A level change whose only reading is for an id the thread does not carry: no claim. Test in task 3.
4. A thread key with a slug (`GHSA-...:claude-code`) as first id: the claim's id still matches it. Test in task 3.
5. A sender that takes three arguments (the catalog pass, an older fake) and a post with no claim: called with three. Test in task 2.

---

## File map

| File | Change |
|---|---|
| `aitools_alerts/wire.py` | `tag_bytes(tag) -> int` |
| `aitools_alerts/poster/transport.py` | `claim=None` on `check_send`, `message_event`, `Relay.send` |
| `aitools_alerts/poster/inputs.py` | `_item_ok` accepts `claim` |
| `aitools_alerts/poster/rules.py` | `claim_text(readings, ids, product, now)` |
| `aitools_alerts/poster/recompute.py` | `support(..., counted=None)`; `judge` fills `info["readings"]` |
| `aitools_alerts/poster/main.py` | `ROOT_CLAIMS`, `_item(claim=)`, `deliver`, `_owe`, `_delivery`, `plan_new`, `plan_known`, `_level_items`, `_judge`, `recompute` |
| `spec/wire.md`, `CHANGELOG.md` | what the poster sends now |
| `tests/test_wire.py`, `tests/poster/test_transport.py`, `test_inputs.py`, `test_rules.py`, `test_advisory_recompute.py`, `test_main.py`, `test_settle.py`, `tests/poster/test_claims.py` (new), `tests/test_wire_compat.py` | below |

### Task 1: the transport signs a claim tag

**Files:** `aitools_alerts/wire.py`, `aitools_alerts/poster/transport.py`; tests `tests/test_wire.py`, `tests/poster/test_transport.py`.

**Interfaces, produces:**
- `wire.tag_bytes(tag: list) -> int`: `len(json.dumps(tag, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1` (the comma before it in the event's `tags`).
- `transport.check_send(channel_id, content, reply_to=None, claim=None) -> None`: ValueError unless `claim is None` or `claim == wire.claim_tag(wire.claim_of({"tags": [claim]}))` (a `None` from `claim_of` is a ValueError too; nothing here may raise another type).
- `transport.message_event(channel_id, content, reply_to, *, created_at, claim=None) -> dict`: tags `h`, then `e` for a reply, then the claim.
- `transport.Relay.send(channel_id, content, reply_to=None, claim=None) -> SendResult`.

- [ ] **Step 1: failing tests.** `test_wire.py::test_tag_bytes_is_what_the_tag_adds_to_an_event`: for a claim vector of `spec/claim-vectors.json` and for a 2048-byte claim with a quote and a backslash in a field, `signer._size(event with the tag) - signer._size(the same event without) == wire.tag_bytes(tag)`. `test_transport.py::test_message_event_carries_one_claim_tag_last`: tags equal `[["h", ch], ["e", root, "", "reply"], tag]`, and without `claim` the event is byte for byte what it was. `::test_check_send_refuses_what_claim_tag_would_not_write`: parametrized over `["claim"]`, `["claim", "{}", "x"]`, `["claim", '{"b":1, "a":2}']` (not canonical), `["claim", "[]"]`, `["other", "{}"]`, a 2049-byte one, `"claim"` (a string), `[["claim", "{}"]]`: each ValueError. `::test_relay_send_signs_the_claim`: with the test's fake connection, the POSTed event verifies (`nostr.verify_event`) and `wire.claim_of(event)` is the object.
- [ ] **Step 2:** run `python3 -m pytest tests/test_wire.py tests/poster/test_transport.py -q`; the new tests fail.
- [ ] **Step 3:** implement the three signatures and `tag_bytes`; add `tag_bytes` to `wire.__all__`.
- [ ] **Step 4:** run the same command; all pass.

### Task 2: the journal carries the claim

**Files:** `aitools_alerts/poster/inputs.py:444-470`, `aitools_alerts/poster/main.py` (`_item`, `deliver`, `_owe`, `_delivery`); tests `tests/poster/test_inputs.py`, `tests/poster/test_main.py` (FakeRelay), `tests/poster/test_settle.py`, new `tests/poster/test_claims.py`.

**Interfaces:**
- Consumes task 1.
- Produces: journal item key `claim` (optional, the tag's text). `Run._item(..., claim: str | None = None)` adds `{"claim": claim}` only when given. `inputs._item_ok`: `claim` allowed only for kinds `root`, `copy`, `reply`, and only when `wire.claim_tag(wire.claim_of({"tags": [["claim", text]]}))[1] == text`.
- `Run.deliver`: `tag = ["claim", it["claim"]] if it.get("claim") else None`; `transport.check_send(..., reply_to, tag)`; `self.send(ch, text, reply_to, tag)` with a claim, `self.send(ch, text, reply_to)` without.
- `Run._owe`: `text_bytes = len(text utf-8) + (wire.tag_bytes(tag) if tag else 0)`.
- `Run._delivery`: an event is a hit only when `[t for t in e["tags"] if isinstance(t, list) and t and t[0] == wire.CLAIM_TAG] == ([["claim", it["claim"]]] if it.get("claim") else [])`.
- `tests/poster/test_main.py::FakeRelay.__call__(self, channel_id, text, reply_to=None, claim=None)`: calls `transport.check_send(channel_id, text, reply_to, claim)`, appends the claim to `self.claims` (a list parallel to `self.calls`; None when none). `tests/poster/test_settle.py`'s mirror builder puts the recorded claim tag on the event it serves.

- [ ] **Step 1: failing tests** in `tests/poster/test_claims.py`, each building a `Run` or calling `main.run` through the `env` fixture of `test_main`:
  - `test_a_journaled_claim_is_sent_and_a_replay_sends_the_same`: put one reply item with a claim in the state file of a thread the ledger holds; the first run's relay answers `fail`, the second run's `ok`; each relay's `claims` equals `[tag]`.
  - `test_an_item_without_a_claim_calls_send_with_three_arguments`: a sender `lambda ch, text, reply_to: ...` (three positional) posts a root with no readings.
  - `test_the_owed_bytes_cover_the_claim`: with a checkpoint key configured, after a claimed reply is sent, the owed entry's `bytes == len(text) + wire.tag_bytes(tag) + signer.ENVELOPE`.
  - `test_a_state_file_item_with_a_bad_claim_is_refused`: `inputs._item_ok` False for `claim` on a `ja` or `digest` item, for non-canonical text, for `""`, for a 2049-byte text; True with a vector's canonical text on a reply; True with no key (an item written before this change).
  - In `tests/poster/test_settle.py`: `test_a_mirror_event_with_another_claim_is_not_the_items_send` (same text and thread, no claim tag or a different one: not settled, sent again after `PENDING_EXPIRY` under a fresh mirror) and `test_a_mirror_event_with_the_items_claim_settles_it`.
- [ ] **Step 2:** run `python3 -m pytest tests/poster/test_claims.py tests/poster/test_settle.py tests/poster/test_inputs.py -q`; new tests fail.
- [ ] **Step 3:** implement; update FakeRelay and the settle mirror builder.
- [ ] **Step 4:** run `python3 -m pytest tests/poster -q`; all pass.

### Task 3: which claim, and the recompute's readings

**Files:** `aitools_alerts/poster/rules.py` (after `claims_for`), `aitools_alerts/poster/recompute.py` (`support`, `judge`); tests `tests/poster/test_rules.py`, `tests/poster/test_advisory_recompute.py`.

**Interfaces, produces:**
- `rules.claim_text(readings, ids, product: str, now: int) -> str | None`. `readings`: iterable of `(source, fields dict)`. `ids`: the post's ids, first id first. Rule (spec "Which claim a post carries"): keep readings with `verify.norm_id(ruleset._id_of(source, fields))` in `{verify.norm_id(i) for i in ids} - {None}`; sort by (rank of `rs.level([(source, fields)], product)` descending with `none` lowest, id is the first id's first, source, id); build `rs.claim(source, fields, product, now, now)`; return `wire.claim_tag(claim)[1]`. Any `RulesetError`, `ValueError`, `TypeError`, `KeyError` gives None. Only the first in order is tried.
- `recompute.support(entry, scope, copy, rs, read=None, counted: list | None = None)`: return value unchanged; appends `(r.source, r.fields)` for each advisory response that was read, tied and may lower (`own[1]` or `r.lowers`), whatever level it supports, and `("kev", {"cve_id": i, "name": "<vendor> <product>"})` for each KEV entry it read as this product's at a level other than `none`.
- `recompute.judge(..., info)`: `info["readings"]` is that list.

- [ ] **Step 1: failing tests.** `test_rules.py`: `test_claim_text_takes_the_highest_reading_of_the_threads_ids` (a `ghsa` reading at high and a `kev` reading at critical for an alias: the KEV claim; `ruleset.check_claim(json.loads(text), "Claude Code") == "ok"`); `test_claim_text_prefers_the_first_id_on_a_tie`; `test_claim_text_ignores_a_reading_of_an_id_the_thread_does_not_carry` (None); `test_claim_text_reads_a_thread_key` (`"GHSA-ABCD-efgh-ijkl:claude-code"` as first id matches the reading of `GHSA-abcd-efgh-ijkl`); `test_claim_text_gives_none_for_a_reading_too_large` (a `ghsa` reading with 40 packages: None, and with 2 packages the text is at most 2048 bytes); `test_claim_text_states_a_withdrawal` (a withdrawn reading: level `none`, `check_claim` ok). `test_advisory_recompute.py`: `test_support_hands_back_the_readings_it_counted` (first GHSA read: one `ghsa` reading equal to `read(G).fields`; CVE first with KEV listing: the `kev` reading with the catalog's name; an unread, an untied and an unreviewed non-vendor response: none) and `test_judge_gives_the_readings_in_info`.
- [ ] **Step 2:** run `python3 -m pytest tests/poster/test_rules.py tests/poster/test_advisory_recompute.py -q`; new tests fail.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run the same; all pass, the existing `support` tuple assertions included. One existing assertion changes with the interface: `test_a_raise_needs_no_complete_read_and_ends_a_wait` compares `info` whole and becomes `{"known": False, "listed": set(), "readings": []}` (an unread source gives no reading).

### Task 4: roots, copies and level changes carry it

**Files:** `aitools_alerts/poster/main.py` (`ROOT_CLAIMS`, `plan_new`, `plan_known`, `_level_items`, `_judge`, `recompute`); tests `tests/poster/test_claims.py`.

**Interfaces:**
- Consumes `rules.claim_text`, `info["readings"]`, `_item(claim=)`.
- `main.ROOT_CLAIMS = False` with the comment: on only once the poster renews (ai-tools-alerts#gtw9); a thread whose root carries a claim decays on readers 0.1.8 and later.
- `Run._claim(readings, ids, scope_name) -> str | None`: `rules.claim_text(readings, ids, scope_name, self.now)`; when the readings hold one for the thread's ids and the result is None, `_say(f"{ids[0]}: no claim sent (larger than {wire.MAX_CLAIM_BYTES} bytes or not a claim)")`.
- `plan_new`: `claim = self._claim(rules._readings(c), [adv.id, *adv.aliases], scope.name) if ROOT_CLAIMS else None`, on the root and every copy.
- `plan_known`: each event's claim is chosen among the ids that event leaves the thread with, by a local `claim_for(adv) = self._claim(rules._readings(c), [adv.id, *adv.aliases], scope.name)`: a copy (only under `ROOT_CLAIMS`) with `new`, which states every id; the level-only reply of a lowered thread with `prev`, the thread as published, since `_level_items` publishes no new alias and the reply that would is often not sent; a shared reply, only when `"level" in changes` at the time it is composed, with `merged`.
- `_level_items(self, entry, level, claim=None)`: every item carries it.
- `_judge`: `self.readings[root] = info.get("readings") or []` (reset in `observe` beside `self.verdicts`); `recompute`: `self._level_items(e, level, self._claim(self.readings.get(e.root_event_id, []), [e.advisory["id"], *(e.advisory.get("aliases") or [])], e.scope))`.

- [ ] **Step 1: failing tests** in `tests/poster/test_claims.py` (the `env` fixture; `relay.claims` from task 2; `ok(claim)` asserts `wire.claim_of`, `ruleset.check_claim(obj, "Claude Code") == "ok"`, `obj["confirmed_at"] == obj["checked_at"] == now`):
  - `test_as_shipped_a_root_and_its_copy_carry_no_claim`: `kev_fixed(env)`, one run: two sends (critical, feed), `relay.claims == [None, None]`.
  - `test_with_root_claims_on_a_root_and_its_copy_carry_one_claim`: the same with the constant on: both carry the same tag, `ok`, its id is the post's first id, level critical.
  - `test_a_raise_in_a_reply_carries_the_claim`: a high GHSA thread, then KEV lists its CVE with the fix at the root: the reply that raises carries one `ok` claim; a later reply that only adds a fix carries none.
  - `test_the_recomputes_raise_carries_the_reading_it_rested_on`: a thread at high whose advisory response later supports critical (as `test_advisory_recompute` builds one): the level-only reply's claim fields equal that run's `Api` reading.
  - `test_the_recomputes_lowering_carries_the_lower_reading`: after `DWELL` and the quiet week the level-only lowering carries a claim whose level is the lower one; `test_a_lowering_that_rests_on_an_absence_carries_none`: a KEV-only thread whose CVE left the catalog.
  - `test_a_level_change_on_a_lowered_thread_travels_alone_with_its_claim`: `plan_known` on a lowered thread: the level-only reply has the claim, the following fix reply has none.
  - `test_a_level_only_raise_claims_no_id_the_thread_has_not_published`: a lowered thread, a candidate whose only reading above the thread's level is for an alias the thread has not published, and nothing else new: the level-only reply is sent with no claim for that alias (its claim, if any, names a published id).
  - `test_a_reading_too_large_posts_without_a_claim`: constant on, a GHSA response with 40 packages: the root is sent, `relay.claims == [None]`, stderr names the id.
  - `test_with_root_claims_on_a_copy_added_without_a_level_change_carries_one`: a thread recorded at critical with a feed root only, a candidate at the same level: the critical-channel copy carries the claim; with the constant off, none.
  - Review focus 1: in the root test, `relay` dates are not available from the fake, so assert through `transport.Relay` with a fake connection and `clock=lambda: now + 5`: `claim["checked_at"] <= event["created_at"]`.
- [ ] **Step 2:** run `python3 -m pytest tests/poster/test_claims.py -q`; they fail.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run `python3 -m pytest tests/poster -q`; all pass. Where an existing test compared `relay.calls` tuples nothing changes (claims are a separate list).

### Task 5: released readers, the wire spec, the changelog

**Files:** `tests/test_wire_compat.py`, `spec/wire.md` ("The claim"), `CHANGELOG.md` (Unreleased), the poster module docstrings that describe a send (`main.py` head, `transport.py` head).

- [ ] **Step 1: tests** in `tests/test_wire_compat.py`. `ALL = RELEASED + ("v0.1.8", "v0.2.0", "v0.2.1")`. A helper `poster_event(m, text, at, reply_to=None, claim=None)` signs `transport.message_event(channel, text, reply_to, created_at=at, claim=claim)` with the mirror's bot key and adds it to the mirror's files (through the mirror helper's `post`, asserting the stored event's tags equal `message_event`'s). Claims come from `rules.claim_text` over a `kev` reading for a CVE id thread about Claude Code.
  - `test_the_posters_events_as_shipped_show_the_same_or_higher_on_every_reader` (parametrized over `ALL`): an unclaimed root at high, then a raise to critical with a fix in one reply carrying the claim. Every reader and this one show the thread now and a month on, matched, at critical; none has decayed.
  - `test_why_root_claims_are_off_a_claimed_root_decays_where_claims_are_read` (parametrized over `ALL`): a claimed critical root. Now: critical everywhere. A month on with no renewal: critical on v0.1.4 to v0.1.7, lower than critical on v0.1.8 and later and on this reader.
- [ ] **Step 2:** run `python3 -m pytest tests/test_wire_compat.py -q`; pass (they test code from tasks 1 and 3).
- [ ] **Step 3:** `spec/wire.md` "The claim": add what the poster sends (a level change always when a reading of the thread's ids exists; a root and its copies only once the poster renews; the choice rule; too large means none). `CHANGELOG.md`: one Unreleased paragraph. Docstrings.
- [ ] **Step 4:** `scripts/test-gate.sh` in a clone that holds this branch alone (the shared clone's scan fails on other sessions' refs); exit 0.

## Acceptance

Spec success criteria 1 to 8. Rollback: revert the merge commit, with the precondition the spec states.
