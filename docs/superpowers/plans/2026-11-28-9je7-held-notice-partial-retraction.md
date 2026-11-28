# Plan: 9je7 partial retraction of a held fix-group notice

Spec: docs/superpowers/specs/2026-11-28-9je7-held-notice-partial-retraction-design.md.
One chunk, on top of the z360 branch.

## Chunk 1: retire splits a struck held notice; the digest waits

- [ ] `aitools_alerts/poster/main.py`
  - `Run._survivors(adv: dict, bases) -> list[str]` (static): the notice's ids
    (`id`, then `aliases`) that match `candidates.BOT_ID`, are not synthetic and whose
    `_base` is not in `bases`; GHSA ids first, no repeats.
  - `Run.retire`: right after `bases` is computed, call `self._retire_held(bases)`
    inside `try/except Exception` (one `_say` line; the thread work goes on).
  - `Run._retire_held(bases)`:
    - `pending` = the `adv["held"]` key sets of every digest item in the outbox and in
      `_withheld_items()`.
    - struck = held notices with `_fold(ids) & self.gone`, whose `_notice_keys` no
      `pending` set covers, and that have a survivor or not (a struck notice with no
      survivor is dropped at once).
    - rotate the struck list by `(now // 3600) % len`; page cap `RETIRE_PAGES` counted
      from `len(self.pages)` at entry.
    - per notice: for each survivor not yet decided this pass, `self._judge_id(
      SimpleNamespace(scope=h["scope"], advisory=h["adv"], learned_sources=None), i,
      bases)`; None is undecided; a verdict covers `i` and every survivor whose base
      the page assigns; released verdicts give a pointer.
    - apply: pointers into `state["deferred"]` (replacing a row with the same
      `product_text` and id); released ids out of the notice; if no survivor is
      undecided: remove the notice, append its remaining `_notice_keys` to
      `state["digested"]` (cap `MAX_DIGESTED`); else rewrite `h["adv"]` with the
      remaining ids (lead: the old lead if it remains, else the first remaining id;
      the title's `(public id)` replaced as `hold` does for a fresh group).
    - one `self.save()` when anything changed; one `_say` line per notice changed.
  - `Run.digest`: first in the held loop, before `_posted` (spec review):
    `Run._part_retracted(h, gone)` (valid, withdrawn under `gone`, not withdrawn under
    no retraction, and `_survivors(h["adv"], bases of gone)` not empty): `continue`
    (it waits for `retire`).
  - `Run.hold`, the faxq branch where `ids != h["adv"]["aliases"]`: also set
    `sources` to `compose._sources([*old sources, *adv.sources])` as dicts.
  - `Run.hold`: skip a held notice `Run._struck(h)` in the join loop and in the test
    for "a held notice already has these ids" of the fresh-member branch.
  - `_retire_held`: within a notice, rotate the GHSA survivors and the CVE survivors by
    the hour (spec review: a failing page never starves the ids behind it).
- [ ] `tests/poster/test_main.py`, at the end: the tests of the spec's success
  criteria. Own helper `_strike` (publish the manifest, run the digest that pulls it):
  z360's `_retract` needs posted roots, and a held notice posts none (spec review).
- [ ] `CHANGELOG.md`: one entry under the unreleased heading, after z360's.

Verification: `python3 -m pytest -q tests/poster/test_main.py -k "held or notice or retract or surviv"`,
then `scripts/test-gate.sh`. Mutation checks, each failing at least one new test: no
digest wait; the wait after `_posted`; no source union; no `digested` write; `hold`
takes a struck notice; no rotation within a notice.

Acceptance: the spec's success criteria; no change to any existing test's expectation.

Rollback: revert the commit.
