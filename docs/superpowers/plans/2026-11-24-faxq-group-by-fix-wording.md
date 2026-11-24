# Plan: faxq group by fix and version 2 wording

Spec: docs/superpowers/specs/2026-11-24-faxq-group-by-fix-wording-design.md. One chunk; one commit plus review fixes.

## Chunk 1: grouping, wording, block, tests

- [ ] `aitools_alerts/schema.py` `render_post` (line ~353): `json.dumps(asdict(adv), ensure_ascii=False, separators=(",", ":"))`.
- [ ] `aitools_alerts/poster/compose.py`
  - `_OPS`: `<` before, `>` after.
  - `package_of(scope) -> (name, registry|None)`: from `scope.package` (`pypi` PyPI, `npm` npm, `cargo` crates.io, `go` Go, `gem` RubyGems, else the prefix), else `(scope.name, None)`.
  - `headline(head, name, title, fallback)`: prefix the name when the title lacks it (case-folded), cut the title to fit 90 characters at a word boundary with "…".
  - `covers(adv) -> (n, ids)`: public form of the id, then public aliases, case-folded unique; n = GHSA count or len.
  - `root_post`: new five lines (spec criterion 3); kind fallback without the id.
  - `root_post_ja(adv, ..., package=None)`: the Japanese five lines; 原題 line removed.
  - `_change_line`/`_change_line_ja`: `Do:` / `対応:` for actions; the title key prints nothing (filtered).
  - `reply_post`, `level_post`: compact patch block.
- [ ] `aitools_alerts/poster/ledger.py` `merge`: fix union key (`fix:` + schema fixed) for non-synthetic candidates with an expressible fix.
- [ ] `aitools_alerts/poster/main.py` (revised after the spec review: no cross-run join, follow-up btqg)
  - `merge(pairs, led, r.groups)`; `Run.defer` writes a fix group's members.
  - `Run.hold`: a matching held notice takes the new ids.
  - `plan_known`: a candidate's older fix never replaces the thread's.
  - `root_post_ja` calls pass `package=compose.package_of(scope)` and the source title.
- [ ] Tests
  - `tests/poster/test_compose.py`: update text assertions; new tests for headline cut, covers count, package line, Do lines (fix, unexpressed, stop, no fix, exploited), one-line block, Japanese root.
  - `tests/poster/test_ledger.py`: merge by fix; a different fix or no fix stays apart; a synthetic stays apart.
  - `tests/poster/test_main.py`: two advisories one release fixes are one post; a busy fix group is deferred as its members; a run never lowers a fix; a held notice takes the group's ids; update text assertions and give non-grouping fixtures distinct fixes.
  - `tests/poster/test_live_replay.py`: 11-18 posts one root covering five ids, equal to `tests/fixtures/poster/golden/11-18-root.txt` (the block line compared parsed).
  - `tests/poster/test_translate.py`, `tests/test_attacks.py`, `tests/mirror/test_export.py`: update only what the wording changes.

## Verification

`python3 -m pytest -q tests/poster tests/test_wire_compat.py`, then `scripts/test-gate.sh` after commit.

## Acceptance

Spec criteria 1 to 7.

## Rollback

Revert the merge commit.
