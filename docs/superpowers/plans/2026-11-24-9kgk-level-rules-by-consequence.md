# Plan: 9kgk levels by consequence; a critical needs a complete action

Spec: docs/superpowers/specs/2026-11-24-9kgk-level-rules-by-consequence-design.md
One chunk: the ruleset, the poster and the tests change together (a ruleset version the
poster does not follow fails the vector tests).

## Chunk 1: ruleset v3, poster level and action, replay

### Task 1: ruleset version 3 (`spec/ruleset.json`, `aitools_alerts/ruleset.py`)

- [ ] `spec/ruleset.json`: `version` 3; add `"action_cap": "high"`; delete the
      `severity_in` row; add `"stop_using": true` to the `ghsa-malware` channel row and
      the `ghsa-vendor` CWE-506 row; add CWE-22, CWE-59, CWE-693, CWE-862, CWE-863 to the
      two channel-scope high rows (not to the channel_if rows); description: drop
      `severity_in` from the condition list, describe `action_cap` and `stop_using`, the
      claim-versus-post sentence, and "Version 3 (9kgk ...) is the only version".
- [ ] `ruleset.py`: `VERSION = 3`; `_TOP_KEYS` gains `action_cap`; validate it is
      `notice` or `high`; `_RULE_WHEN` loses `severity_in` (and the `known` map entry);
      `_rule_row` accepts optional `stop_using` (must be `True`); `Support` gains
      `stop_using: bool = False`; `read` sets it from the matched row and "no package of
      this product has first_patched"; `_rule_matches` loses the severity clause.
- [ ] New `Ruleset.action_level(level, actions, product, fixed, readings=(), *, stop_using=None) -> str` (spec 1).
      Accept action entries as `(verb, target, value)` tuples or objects with
      `verb/target/value` attributes (`schema.Action`). Add to `__all__` nothing new
      (method). Module docstring: one sentence.
- [ ] `spec/claim-vectors.json`: `ruleset` 3; the "vendor advisory, severity high" level
      vector becomes notice (renamed "...severity high alone is a notice"); add an
      `actions` list of vectors `{name, product, level, readings, actions, fixed, want}`:
      kev critical with upgrade+version -> critical; kev critical with no action -> high;
      kev critical with stop_using -> high; malware critical with stop_using -> critical;
      high with no action -> high. Description gains one sentence on `actions`.

Verify: `python3 -m pytest tests/test_ruleset.py -q` (after Task 3's test edits).

### Task 2: poster (`aitools_alerts/poster/rules.py`, `compose.py`)

- [ ] `rules.py`: delete the severity-tier1 clause and `_HIGH_WORDS`; extend `_SEVERE`
      (spec 2); `level_for` docstring reasons: drop severity-tier1, add no-action and
      stop-using; after computing `(level, reason)`, build the would-be action and apply
      `rs.action_level(level, [action], scope.name, fixed, _readings(c))`; capped ->
      `("high"... i.e. rs.action_cap, "no-action")`; critical through stop_using ->
      reason `stop-using`. Module docstring: critical needs a complete action.
- [ ] `compose.root_post`: `actions` = upgrade when fixed; `stop_using` when level is
      critical, no fixed, and reason is `stop-using`; a critical with neither raises
      `ValueError("a critical needs a complete action")`. Body action line for
      stop_using: "Action: stop using <name> until a fixed release ships."
- [ ] `compose.root_post_ja`: when `adv.actions` holds stop_using, the line
      "対応: 修正版が出るまで <name> の使用を停止してください。"
- [ ] Check `main.py` callers of `root_post` catch `ValueError` per candidate (read
      lines 600-700, 1140-1180); if not, no change is needed because level_for never
      hands root_post a critical without an action; record which.

Verify: `python3 -m pytest tests/poster -q`.

### Task 3: tests

- [ ] `tests/test_ruleset.py`: version 3 assertions; refuse `action_cap: critical`,
      `stop_using: false`, a `severity_in` condition; `ttl_days["critical"] == 14`;
      vectors for `actions` run through `action_level`.
- [ ] `tests/poster/test_rules.py`, `test_ledger.py`, `test_compose.py`: severity-tier1
      cases become notice (severity word alone) or move to the prose reason they now
      take; kev-tier1 critical cases get a fixed version or expect `("high",
      "no-action")`; new cases: channel KEV no fix -> high no-action; same with fix ->
      critical kev-tier1 and an upgrade action in the root block; ghsa malware reading,
      no fix -> critical stop-using, root block carries stop_using, EN and JA lines;
      root_post refuses a critical without a fix and without stop-using; sandbox/approval
      prose -> high with a fix, notice without.
- [ ] `tests/poster/test_level_replay.py`: the 29-row table (spec 3) with expected
      levels; asserts no critical without a complete action, containerd and SDK items
      notice.
- [ ] Any other test the gate shows failing because of the version or the removed clause
      (`test_live_replay.py`, `test_end_to_end.py`, `test_main.py`): update the expected
      level with the reason in a comment.

Verify: `scripts/test-gate.sh` (public scan + whole suite).

## Acceptance

Spec success criteria 1-6. `git diff --stat origin/main` under about 600 lines excluding
`spec/claim-vectors.json`.

## Rollback

Revert the merge commit.

## After the chunk

- Note on ai-tools-alerts#fv4g: the member recompute applies `Ruleset.action_level`.
- Note on ai-tools-alerts#ny5g: the malware and CWE rows (incl. the new bypass CWEs) fire
  once the poster reads the API; the `stop_using` reply gap.
- Follow-up issue: a raise of an existing thread to critical through stop_using must
  carry the action or cap at high (labels repo:ai-tools-alerts, discovered-from:9kgk).
