# Plan: expiry against a signed head (ai-tools-alerts#r0ra)

Spec: `docs/superpowers/specs/2026-11-24-r0ra-expiry-against-signed-head-design.md`. One chunk, one commit, under 600 changed lines outside `docs/superpowers/`. Tests are written first and seen to fail.

## Chunk: reader

### 1. `aitools_alerts/ruleset.py`

- [ ] `UNCONFIRMED_DAYS = 45`, exported, beside `VERSION`.
- [ ] `Ruleset.stands_until(level, confirmed_at, checked_at) -> int`: `ttl = ttl_days[level] * 86400`; `max(confirmed_at + ttl, min(checked_at + ttl, confirmed_at + UNCONFIRMED_DAYS * 86400))`.
- [ ] `Ruleset.level_at(level, renewals, now) -> str`: for `level`, then `"notice"` (once when `level` is notice): return it when any `(confirmed_at, checked_at)` of `renewals` has `stands_until(...) >= now`; else `NONE`.
- [ ] Module text: one sentence on the two functions.

### 2. `aitools_alerts/pull.py`

- [ ] Import `ruleset` and `wire`. Export `head_clock`.
- [ ] `Thread`: add `renewals: tuple = ()` (each `(confirmed_at, checked_at, created_at)`), `enrolled: bool = False`, `curated: bool = False`.
- [ ] `_renewal(ev, role)`: None unless `role == "relay-bot"`; `ruleset.parse_claim(wire.claim_of(ev))` inside `try/except Exception` (a hostile claim never stops the other threads); None when the level is `ruleset.NONE` or `checked_at > ev["created_at"]`; else `(id.casefold(), confirmed_at, checked_at, created_at)`.
- [ ] `threads_from`, roots: `expires_at=None` in the `replace(...)` when `role != "curator"`, counted in `dropped["bot-expiry"]` when the block had one. Two more list items per root: the renewal candidates (replies' only) and the root's own candidate or None.
- [ ] `threads_from`, replies: directly after the `t is None or t[1]` check and before the discussion rule, append the reply's `_renewal` when it is not None.
- [ ] `threads_from`, output: `ok = ids | {a.id, *a.aliases}` case-folded. `enrolled` is "the root's candidate is not None and its id is in `ok`". `renewals` is the sorted tuple of the candidates (the root's and the replies') whose id is in `ok`, empty when not enrolled. `curated` is `t[3]`.
- [ ] `head_clock(state) -> tuple[int | None, frozenset | None]`: the checkpoint of `state.manifest_root`; `(None, None)` when there is none or when `not cp.events <= set(state.events)`.
- [ ] `active(threads, now=None, listed=None)` as section 4 of the spec. `ruleset.load()` is called at most once, only when a thread needs it; if it raises, no thread decays (a damaged spec file must not end alerts). A decayed thread is returned as `replace(t, adv=replace(t.adv, level=...))`.
- [ ] `_retain(kept, now, res)` keeps its signature; `_fetch` passes a retention clock: `rnow = min(now, old_cp.created_at) if check and old_cp is not None else now` for the early manifest save and for every `settle` before a head is accepted; the final `settle(fetched, None, keep=applied)` passes `min(now, cp.created_at)`. `settle` gains a keyword `at` defaulting to `rnow`; its size-limit fallback, after which the fetched head is not accepted, always uses `rnow`. The writer's path passes `now`.
- [ ] Module text and the `advisories` and `_retain` docstrings: the expiry rule and the retention clock, a few sentences.

No change to the pull's admission rules: section 5 of the spec bounds a claim's date in `active`.

### 3. `aitools_alerts/cli.py`

- [ ] `_matches`: `pull.active(pull.advisories(st), *pull.head_clock(st))`.

### 4. Tests

New file `tests/test_expiry.py` (helpers from `tests/mirror_helpers.py`; a claim is built by hand as `{"id": "CVE-2098-0001", "source": "kev", "fields": {"cve_id": "CVE-2098-0001", "name": None}, "ruleset": 1, "level": ..., "confirmed_at": ..., "checked_at": ...}` through `wire.claim_tag`; advisories use that id; a head is signed with `mirror.checkpoint(now=at)` and pulled with `now=at`; a head that must list an event dated after it is signed with explicit ids, `mirror.checkpoint(ids=mirror.honest_ids(<later>), now=at)`):

- [ ] `stands_until` and `level_at` at their bounds: the last second a level stands and the first it does not, for each level; an unconfirmed check extends to day 45 and no further; notice is not extended past 90 days; the maximum over two renewals wins in either order.
- [ ] What is a renewal: another id, a malformed claim, level `none`, a curator's event carrying a claim and `checked_at` after the event's date are not; a claim under an alias is; a refused lowering's claim is.
- [ ] Enrollment: a relay-bot root with no claim, then a reply with a claim confirmed at 0: `enrolled` is False, `renewals` is empty, and the thread is critical under a head a year on.
- [ ] A relay-bot `expires_at` is not read (`bot-expiry` counted) and a curator's ends its thread when the head passes it; `now=None` and a head that does not list the root expire nothing.
- [ ] A curated thread does not decay. A renewal dated after the head is not counted. A damaged ruleset expires nothing.
- [ ] Acceptance 1 (frozen 30 days), 2 (dropped renewal: `mirror incomplete`, the earlier head stays, critical; served whole: critical under the later head), 3 (short `expires_at`, a short-lived claim beside the root's), 4 (ten years ahead and listed: refused by the clock rule, not stored, `stale_since` fires; a renewal 50 seconds after its head, listed by explicit ids: stored after the pull, not counted under that head, counted under the next head that has reached its date), 5 (three threads whose root events are dated, and confirmed, 100, 20 and 0 days before the head, with no reply; pulls with the clock a year ahead and behind: the same shown set, and `State.load().events` still holds all three, the first being 465 days behind the fast clock), 6 (critical to notice one second after 14 days, gone one second after 90 days, each under a new head).
- [ ] The size limit: a stored thread 399 days behind the held head, then a pull whose head is two days later and whose events do not fit (`MAX_STORED_EVENTS` patched): `state limit reached`, the earlier head is still held and the old thread is still stored.
- [ ] The interrupted save: after a good pull, `break_write(monkeypatch, "events.json", 2)` on a pull whose head is past the TTL and lists a renewal; then `head_clock` is `(None, None)` and the alert is critical.
- [ ] `cli.main(["check"])` under a head past the TTL prints the alert as `NOTICE:`.

Existing tests that change, and why:

- [ ] `tests/test_wire_compat.py::test_what_the_format_avoids_an_expiry_in_a_relay_bot_block_ends_the_alert`: released readers still drop the alert a month on; this reader keeps it at critical. The docstring says so.
- [ ] Any other test that fails is read before it is changed, and named in the run record.

### 5. Text

- [ ] `spec/wire.md`, section "Level changes and expiry": how this reader computes expiry (enrollment, renewal, the formula, the head as clock, what a date ahead of the head can do).
- [ ] `CHANGELOG.md`, Unreleased: one paragraph.
- [ ] `README.md` only if it describes expiry (grep `expire`).

## Verification

- `python3 -m pytest tests/test_expiry.py -q` fails before step 1 and passes after step 3.
- `scripts/test-gate.sh` exits 0 (the public scan, then the whole suite; `tests/test_wire_compat.py` runs the four released readers).
- `git diff --stat origin/main -- . ':!docs/superpowers'` under 600 changed lines.

## Acceptance

The six cases of the issue pass as tests (case 4 with the deviation the spec's section 5 states); no released reader shows less than before (`tests/test_wire_compat.py` green); the gate is green; one independent review with every BLOCKER fixed and every SUBSTANTIVE finding fixed or rebutted.

## Rollback

`git revert` of the merge. No state or wire format changed; the previous reader reads this reader's state.

## After the code review

Changed from the steps above (the reasons are in the run record): `level_at` steps down through each lower level; `Thread.enrolled` is `enrolled_at`; a thread with a renewal dated after the head is not judged; a relay-bot raise is a renewal of its own date; the ids a claim may name include every alias the thread has held. `tests/test_wire_compat.py`'s fixture carries claims the reader takes.
