# Plan: an advisory page that never parses reaches an end (ai-tools-alerts#psb5)

Spec: `docs/superpowers/specs/2026-11-28-psb5-unparsed-page-terminal-design.md`.
One chunk, one commit. About 330 changed lines, most of them tests.

## Chunk: terminal

### 1. `aitools_alerts/poster/rules.py`

- [x] `Evidence` (the dataclass near line 630): add `failed: bool = False`
      after `budget`; say so in the docstring.
- [x] New `_says(text, base, scope)` above `evidence`: the visible-text name
      test (`_lines`, `_names`) the site-page branch has inline. The site-page
      branch calls it; its behaviour does not change.
- [x] New `_sole(url, scope, entries=None)`: every scope entry (resolved to
      its component) for which `authoritative(url, entry)` holds has this
      scope's name. Uses `_default_index()` or `_index(entries)`.
- [x] `evidence(..., lapsed=False)`: in the repository branch, where the page
      did not parse or is another advisory's, `unparsed = True` stays. When
      `lapsed and rank == 0 and p is None and base == <the URL's GHSA id> and
      _sole(u, scope, entries) and _says(text, base, scope)`: `rank, found = 1,
      dict(url=u, ids={base})`. Then `continue` as before.
- [x] The returned `Evidence` sets `failed=retry and not found and not kev`.
- [x] Docstring: the `lapsed` paragraph with the four conditions.

### 2. `aitools_alerts/poster/main.py`

- [x] `Run.__init__`: `self.ended: set[str] = set()`.
- [x] `Run._lapsed(scope, cid)`: `self.saw(scope, cid)`; the `waiting` entry
      is missing or `RETRY_DAYS * 86400` old.
- [x] `Run.admit`: after the first `rules.evidence`, when `not ev.ok and
      ev.unparsed and not ev.failed and not ev.budget and self._lapsed(...)`:
      read `rules.evidence(..., lapsed=True)`; remember the end (the key into
      `self.ended`, with an entry `RETRY_DAYS` old written by `setdefault` when
      the map is under `inputs.MAX_WAITING` and the id is not synthetic); when
      still not ok, count "advisory page not parsed, dropped" and return None.
      Otherwise fall through to the existing code with the new evidence.
- [x] `run`: the prune of `state["waiting"]` keeps a key in `r.ended`.

### 3. Tests

- [x] `tests/poster/test_rules.py`: the cases the spec lists, before the
      "the page fetch" section.
- [x] `tests/poster/test_main.py`: rename the pinned test to
      `test_a_failed_fetch_defers_and_never_drops` without its 200 case; add
      the repeated-run tests the spec lists after it.

### Verification

```
python3 -m pytest -q tests/poster/test_rules.py tests/poster/test_main.py
scripts/test-gate.sh        # in a clone of this branch alone (the shared clone's
                            # public scan reads other sessions' refs)
```

Mutation checks, each of which a test must catch: drop `p is None`; drop the
URL-id condition; drop `_sole`; drop `_says`; drop `rank == 0`; `>` for `>=` in
`_lapsed`; drop `not ev.failed`; drop `k in r.ended` from the prune; defer
after the drop.

### Acceptance

- The acceptance test of the issue: repeated runs where a page never parses,
  the candidate at its end at `RETRY_DAYS`, the deferred list empty after, the
  pages fetched counted (`test_a_page_that_never_parses_ends_as_a_notice_after_retry_days`,
  `..._is_dropped_and_counted`, `test_many_pages_that_never_parse_...`).
- Nothing changes before `RETRY_DAYS`, for a failed fetch, a spent budget or a
  page that parses.
- The whole suite and the public scan pass.

### Rollback

Revert the commit. The state file's shape is unchanged; a `waiting` entry
older than `AGE_LIMIT` that no deferred candidate names is pruned by the older
code's next run.

### Order with ai-tools-alerts#vszx

vszx is in flight and edits `run` near the lines that build `pairs`. This
change touches `run` only in the prune. Merge `origin/main` before the review
and again before the merge.

### Rollout

None here. After the merge, a comment on ai-tools-alerts#g9bv: the change
reaches the poster with the next release; no state migration, no config.
