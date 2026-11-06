# Plan: mirror freshness (ai-tools-alerts#544a)

Spec: docs/superpowers/specs/2026-11-06-mirror-freshness-design.md.
Budget: under 200 changed lines excluding run artifacts
(`git diff --numstat origin/main -- . ':!docs/superpowers'`).

## Chunk 1 — pull freshness (aitools_alerts/pull.py, tests/test_pull.py)

- [ ] `pull.py` near the constants (~line 50): `STALE_EVENT_S = 3 * 86400`,
      `STALE_MANIFEST_S = 90 * 86400`; add `stale_since`, `freshness` and the
      two constants to `__all__`.
- [ ] After `effective_manifest` (~line 280):
      `freshness(state) -> tuple[int | None, int | None]`: `m =
      effective_manifest(state)`; None, None without one; else
      `(max((ev["created_at"] for ev in state.events.values() if
      manifest.role_of(m, ev["pubkey"]) is not None), default=None),
      m.event["created_at"])` (generator parenthesized). The manifest event's `created_at` equals its
      `issued_at` (manifest._parse_event enforces it).
- [ ] `stale_since(state, now=None) -> int | None`: no manifest -> None;
      `ref = newest if newest is not None else issued`; `ref < now -
      STALE_EVENT_S` -> ref; `issued < now - STALE_MANIFEST_S` -> issued;
      else None.
- [ ] `_fetch.record`: `last.update(zip(("newest_event_at",
      "manifest_issued_at"), freshness(state)))` on every record (ok or
      not). On the success path `record` runs after `state.accept`, so it
      sees the new manifest and events; on failure it sees the stored ones.
- [ ] Tests (tests/test_pull.py, end of file), using `Mirror` and `do_pull`
      (now = T0 + 1000):
      1. after a pull, `last_pull["newest_event_at"]` is the newest post's
         created_at and `manifest_issued_at` is the manifest's issued time;
         `stale_since(st, T0 + 1000)` is None.
      2. thresholds: `stale_since` at newest + 3 days is None, + 3 days + 1
         is the newest event's time; with a fresh event, manifest issued +
         90 days + 1 returns the issued time.
      3. an untrusted key's newer event does not count: after a pull, put
         a newer event signed by a key outside the manifest into the
         in-memory state (as a cached event after a bundled revocation);
         `freshness` and `stale_since` ignore it.
      4. no events: `stale_since` measures from the manifest's issued time.
      5. never pulled: `stale_since(State.load())` is None.
      6. a failed pull (bad manifest) still records both fields from the
         stored state.

## Chunk 2 — CLI and hook (aitools_alerts/cli.py, hooks/claude-code/session-start.sh, tests)

- [ ] `cli.py`: `_iso(ts)` = `time.strftime("%Y-%m-%dT%H:%M:%SZ",
      time.gmtime(ts))` (import time); in `cmd_check` after the "no
      successful pull" line: `since = pull.stale_since(st)`; when not None
      print `STALE_LINE.format(since=_iso(since))` with
      `STALE_LINE = "warning: alerts may be stale since {since}: no new signed post for over 3 days, or a trust manifest over 90 days old; the mirror may be frozen or replayed"`.
      Not printed in `--json` (a list stays a list). Exit stays 0.
- [ ] `cmd_run --json`: `out["stale_since"] = _iso(s) if (s :=
      pull.stale_since(st)) is not None else None`. Computed after the
      pull, under the same root check as `_matches`: when the stored state
      belongs to another root, `_matches` returns nothing; stale_since reads
      the same state, so guard it with `st.manifest_root == a.root`, else
      None.
- [ ] Hook: replace the invocation with
      `out=$(aitools-alerts run --json </dev/null 2>/dev/null)` directly
      followed by the existing `if [ "$?" -eq 2 ]` (an assignment's status is
      its command substitution's; no `rc=` line in between); then
      `case $out in *'"stale_since": "'*) printf '%s\n' "AITOOLS-ALERT: alerts may be stale (no new signed post for over 3 days, or a trust manifest over 90 days old); run aitools-alerts check" ;; esac`.
      Header comment: say why the match cannot be forged (JSON escapes `"`
      inside strings). Keep the PATH line untouched (ai-tools-alerts#fsmb).
- [ ] tests/test_cli.py: (a) pull the fixture mirror, monkeypatch
      `time.time` in `aitools_alerts.pull` to newest + 4 days; `check`
      prints the fixed line with the ISO time and returns 0; at newest + 1
      hour no line. Use `pull.time` patched via
      `monkeypatch.setattr(pull.time, "time", ...)` — patches the shared
      module, so restrict to this test. (b) `run --json` has
      `stale_since` null when fresh and the ISO string when stale.
- [ ] tests/test_templates.py: the stub accepts any args; expected args
      become `run --json`; the stub prints JSON lines to stdout; new
      parametrized cases: stub stdout `{"stale_since": "2099-01-01T00:00:00Z"}`
      with exit 0 -> stale line only; with exit 2 -> both lines (critical
      first); `"stale_since": null` -> nothing; a title value
      `"title": "\"stale_since\": \"x"` (JSON-escaped) -> nothing.

## Chunk 3 — docs (README.md, skills/*/SKILL.md, snippets/AGENTS.md)

- [ ] README hook section: the hook runs `run --json`; the second line and
      when it appears (3 days / 90 days); `check` prints a warning line.
- [ ] Both SKILL.md and snippets/AGENTS.md: one bullet under the JSON keys:
      `stale_since`: null, or a time: the newest trusted post when over 3
      days old, else the trust manifest's issue time when over 90 days
      old; tell the person the alerts may be stale and the mirror may
      be frozen. Keep the procedure anchors tests/test_templates.py checks.

## Verification

- `python3 -m pytest tests -q` (the repo's gate, as earlier tasks ran it;
  `scripts/test-gate.sh` if present).
- `scripts/public-scan.sh` (reads its terms from the external terms file,
  so no host name is written here) -> clean.
- Line count under 200.

## Acceptance

Spec success criteria 1-7.

## Rollback

`git revert` of the landed commits; nothing else to undo (state gains two
ignored keys).
