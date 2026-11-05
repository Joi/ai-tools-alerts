# Plan: scope.json not_match (ai-tools-alerts#3r9h)

Spec: `docs/superpowers/specs/2026-11-05-scope-not-match-design.md`.
One chunk; one commit plus the run artifacts.

## Chunk 1 — field, loader, matcher, lists, tests

- [ ] `aitools_alerts/schema.py`
  - `ScopeEntry`: add `not_match: tuple[str, ...] = ()` after `match_mode`.
  - `SCOPE_VERSION = 3`; `_scope_mode` accepts versions 2 and 3
    (`SCOPE_VERSIONS = (2, 3)`), refuses any other; returns the mode and the
    version so `load_scope` knows whether `not_match` is allowed.
  - `load_scope`: a version-3 entry may carry `not_match` (pop it before the
    `_obj` key check; validate with `_list(..., 1, 100)` and the same
    lowercase/trimmed check as `match`). In a version-1 or 2 file `not_match`
    is an unknown key and is refused by the existing check.
- [ ] `aitools_alerts/poster/rules.py` `scope_of`: an entry hits when a `match`
  pattern matches and no `not_match` pattern matches (same mode). Track whether
  any entry was excluded; when nothing hits and one was, append the text to
  `log`. Docstring updated. Nothing else in rules.py changes.
- [ ] `aitools_alerts/poster/main.py`: the deferred loop calls
  `scope_of(c.product_text, log=review)` (review pass 1). Test in
  `tests/poster/test_main.py`: a deferred candidate whose text is now excluded
  leaves the deferred list and lands in the ledger's review list.
- [ ] `tests/poster/test_rules.py` `test_scope_file_versions`: the refused
  version moves from 3 to 4 (review pass 1).
- [ ] `spec/scope.json`: version 3, description names the `not_match` rule,
  the lists from the spec table.
- [ ] Tests, `tests/poster/test_rules.py` (new section "not_match
  (ai-tools-alerts#3r9h)"):
  - the live KEV text is None and logged; runtime forms (`Node.js Node.js`,
    `nodejs/node`, `Node.js`, `NodeJS`) still hit Node.js;
  - the other lists: `Jenkins Git client Plugin`,
    `Example library for Golang`, `Example Chrome extension` are None;
    `Git Git`, `Docker Desktop`, `Docker Engine docker plugin install`, `golang/go`, `Google Chromium V8` still hit;
  - an excluded tier-1 entry does not stop a later entry from matching
    (constructed entries);
  - every `not_match` pattern, as text, does not resolve to its own entry;
  - end to end through `candidates.from_kev`: a synthetic KEV item
    (`CVE-2099-0031`, vendor `Npm package`, product
    `System Information Library for Node.JS`) yields a candidate whose
    `scope_of` is None; a sibling (`CVE-2099-0032`, `Node.js`/`Node.js`)
    yields tier 1 Node.js and `level_for` gives `critical`.
- [ ] Tests, `tests/poster/test_rules.py` beside x838's version tests (not
  test_schema.py, where no scope-version test lives): `load_scope` refuses `not_match` in a v2
  file, a non-list, an empty list, an uppercase or untrimmed pattern, version
  4; reads a v3 file without `not_match`; reads a v2 file (no `not_match`)
  unchanged.
- [ ] Synthetic ids: CVE-2099-0031/0032 — check `grep -rn "CVE-2099-003"`
  first so they collide with no fixture (E3's curator thread uses others).

## Verification

```
python3 -m pytest tests/poster/test_rules.py tests/test_schema.py -q
scripts/test-gate.sh
git diff origin/main --stat -- aitools_alerts spec tests   # under 200 lines; run artifacts not counted
git diff origin/main --stat -- trust   # empty
git diff origin/main | grep '^+' | grep -Ei 'host-a|host-b|host-d|host-e|host-f|host-c'   # docs aside: empty
```

## Acceptance

Spec success criteria 1–6. Red first: the KEV test fails on the current tree.

## Rollback

`git revert` the commit. No trust/ change, no state migration.
