# Inventory, matching and action planning Implementation Plan (Task A4, ai-tools-alerts#0xrc)

> **For agentic workers:** execute in order; each step has its verification.

**Goal:** `versions.py`, `inventory.py`, `check.py`, their tests and an invented
fixture home, per docs/superpowers/specs/2026-11-05-inventory-check-design.md.

**Tech stack:** Python >= 3.11 standard library (`subprocess`, `plistlib`,
`tomllib`, `json`, `re`, `dataclasses`); pytest.

## Chunk 1 (one chunk, one commit; target under 600 changed lines of code and tests)

### Files

| Path | Change |
|---|---|
| `aitools_alerts/versions.py` | new: `normalize`, `parse`, `check`, `affected` |
| `aitools_alerts/inventory.py` | new: `Installed`, `Inventory`, `default_runner`, tool table, collectors, `collect` |
| `aitools_alerts/check.py` | new: `Config`, `Match`, `Plan`, `match`, `plan`, `describe` |
| `tests/test_inventory.py` | new |
| `tests/test_check.py` | new |
| `tests/fixtures/inventory/probes.json` | new: argv string -> invented tool output |
| `tests/fixtures/inventory/home/.claude.json` | new: two invented MCP servers (one top-level, one under a project) |
| `tests/fixtures/inventory/home/.claude/skills/{example-notes,demo-formatter}/SKILL.md` | new: invented skills |
| `tests/fixtures/inventory/home/.claude/plugins/installed_plugins.json` | new: one invented plugin; a sibling `cache/` dir to prove directories are not read |
| `tests/fixtures/inventory/home/.codex/config.toml`, `.cursor/mcp.json` | new: one invented server each |
| `tests/fixtures/inventory/home/Applications/Cursor.app/Contents/Info.plist` | new: invented version |

### Steps

- [ ] **1. Fixtures and failing tests.**
  - `tests/test_inventory.py`: `test_collect_from_fixture_home` (fixture home,
    runner from probes.json, apps_dirs = fixture Applications: Claude Code,
    Codex, Node, OpenSSH `9.9p1`, Go from `go1.22.1`, macOS one-part, Cursor
    from the plist; skills = the two dirs plus the plugin key, not `cache`;
    MCP = the four invented names; every scope ecosystem key present, e.g.
    `hermes == []`); `test_runner_failures_return_none` (runner returning
    None/garbage for every argv -> tool lists empty, no raise);
    `test_collect_never_raises` (runner that raises, unreadable JSON files);
    `test_default_runner_fixed_argv_and_failures` (`subprocess.run`
    monkeypatched: missing binary, timeout, non-zero exit -> None; stderr
    fallback; output cap; every call a list argv, `timeout=5`, no `shell`,
    stdin DEVNULL; no real executable runs); `test_tool_table_is_constant` (every argv a tuple of literals).
  - `tests/test_check.py`, the plan's eight: `test_version_affected_ranges`,
    `test_match_claude_code_below_fixed`, `test_no_match_when_version_at_fixed`,
    `test_skill_match_by_name`, `test_relay_bot_post_never_auto_applies`,
    `test_curator_upgrade_auto_applies_when_opted_in`,
    `test_upgrade_without_fixed_is_notify_only`, `test_unknown_verb_is_notify_only`;
    plus `test_unparsable_version_notifies_without_actions`,
    `test_normalize_installed_strings` (`v22.1.0`, `claude-code/2.1.3`,
    `2.1.3 (Claude Code)`, `garbage` -> None),
    `test_suffix_ordering` (`9.9p1 > 9.9`, `1.0rc1 < 1.0`),
    `test_other_product_in_tool_ecosystem_does_not_match` (`undici`/node),
    `test_curator_upgrade_not_opted_in_is_prepared`,
    `test_upgrade_value_comes_from_product_fixed` (stale action value
    replaced, prepared and auto), `test_scope_component_patterns_are_not_the_tool`
    (containerd, moby, runc under docker), `test_destructive_verbs_need_their_own_ecosystem`
    (`remove_mcp_server codex` / `disable_skill codex` on a Codex CLI match),
    `test_match_constructs_with_the_plan_fields` (four-argument Match).
  - Verify: `python3 -m pytest tests/test_inventory.py tests/test_check.py -q` fails on missing modules.
- [ ] **2. `versions.py`.** Verify: `python3 -c "from aitools_alerts import versions; assert versions.affected('2.1.3', '<2.1.4', None)"`.
- [ ] **3. `inventory.py`.** Verify: `python3 -m pytest tests/test_inventory.py -q` passes, and the acceptance one-liner prints the ecosystem keys on this Mac.
- [ ] **4. `check.py`.** Verify: `python3 -m pytest tests/test_check.py -q` passes (test_check imports check, so it runs only once check.py exists).
- [ ] **5. Whole gate.** `scripts/test-gate.sh` passes. `git add -N aitools_alerts tests && git diff --stat origin/main` reports size.
- [ ] **6. Leak check.** grep the diff for the fleet host names and `nsec1`; prints nothing. Confirm no name in the fixtures appears in this Mac's real `~/.claude/skills` or MCP config (compare by script, print counts only).
- [ ] **7. Commit** `feat: local inventory, matching, action planning` with the run artifacts.

## Acceptance

- Spec success criteria 1-5.
- `grep -nE "subprocess|os\.system|Popen" aitools_alerts/check.py aitools_alerts/versions.py` prints nothing; the only `subprocess.run` is in `inventory.default_runner`, with `shell` absent and `timeout=5`.

## Rollback

`git revert` the commit.
