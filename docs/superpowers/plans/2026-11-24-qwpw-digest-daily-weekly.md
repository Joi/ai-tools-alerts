# Plan: digest daily short form and weekly summary (qwpw)

Spec: docs/superpowers/specs/2026-11-24-qwpw-digest-daily-weekly-design.md

One chunk. Expected size: about 150 lines of code, 200 of tests and docs.

## Chunk 1 — daily short form and weekly summary

- [ ] `aitools_alerts/poster/ledger.py`: `roots_since(t)` — entries whose `posted_at`
      is after `t`, oldest first. `entries_since` stays (no other caller after this:
      check with grep; remove if unused).
- [ ] `aitools_alerts/poster/compose.py`:
  - `_DIGEST` templates: `head` ("N new alert(s)"), `quiet(d, n, link)`, `quiet_bare(d)`,
    `level` word, weekly `w_head(n)`, `w_line(name, n)`, `w_more(k, n)`, `w_link(url)`;
    ja equivalents.
  - `digest(advs, date, lang, *, retracted, now, titles, held_count=0, link, weekly=None)`:
    filter as today; one line per (id, product), sorted by level rank desc then
    posted_at, id; `- LEVEL: ` prefix then `_single`'s text. No sections, no grouping.
    Empty → quiet line (bare when `weekly` is not None). `weekly`: a list of product
    names, one per notice, rendered as the summary (Counter, most first then name, 30
    lines max). Every line through `_guard(_inline(..))`; a refused line counts as
    withheld as today.
  - Remove `_group_key`, `_group_line`, `_LABEL`, the `release/one/cves/update/section`
    templates if no other caller (grep).
- [ ] `aitools_alerts/poster/inputs.py`: state key `weekly` (`YYYY-Www`, `iso_week`);
      `new_state` and `load_state` (older state) set the current Tokyo week; validation;
      digest item snapshot may carry `week` (str of that form).
- [ ] `aitools_alerts/poster/main.py` `Run.digest`:
  - led items from `self.led.roots_since(at - 1)` keyed `(posted_at, root)`, skipping
    `(at, root in done)` as today.
  - weekly due: `state["weekly"] < iso_week(today)`.
  - held: prune unlisted as today; a notice with a thread now, or `compose.withdrawn`,
    is retired (keys in `snap["held"]`, not counted) with any digest; when due, every
    remaining listable notice goes in the summary and its keys in `snap["held"]`.
  - quiet count: number of listable held notices.
  - link: `_mirror_link(config)`.
  - prefix halving applies to led items only; the summary is always whole (capped).
  - snapshot carries `week` when due.
- [ ] settle (`main.py` digest branch): `weekly = adv.get("week", state["weekly"])`.
- [ ] Tests (`tests/poster/test_compose.py`, `tests/poster/test_main.py`):
  - compose: one line per post, level prefix, no sections; quiet line with count and
    link; bare quiet with weekly; weekly counts sorted, capped at 30 with the rest;
    Japanese renders; guard withholds a bad line.
  - main: criteria 1–6 of the spec (new roots only; quiet line; listed once after a
    reply; Monday summary empties held into digested; missed Monday; fresh state
    waits for Monday; old journal item without `week` settles; old state without
    `weekly` loads; a retracted or expired notice is not counted and is retired; a
    notice that posted a thread is retired).
  - Update existing tests that assumed held notices in the daily digest (run them on
    Monday 2026-11-09 or assert the new lines), including
    `tests/poster/test_live_replay.py` and `tests/poster/test_catalog.py`.
- [ ] Docs: CHANGELOG Unreleased entry; README lines on the digest; docs/design.md
      digest lines and the catalog section's "held for the digest" wording.

### Verification

- `python3 -m pytest tests/poster -q` while working; `scripts/test-gate.sh` at the end.
- Mutation checks: drop the `posted_at` key (use `listed`) → the listed-once test
  fails; restrict the weekly predicate (`state["weekly"] < week`) to Mondays → the
  missed-Monday test fails; `Run._posted` with any id instead of every id → the held
  group test fails; `Run._posted` on the held scope only → the former-name test fails.

### Acceptance

Spec criteria 1–7.

### Rollback

`git revert` of the merge; on a host that ran it, the `jq` line in the spec on the
poster state (top-level `weekly` and journaled `adv.week`), named in the CHANGELOG.
