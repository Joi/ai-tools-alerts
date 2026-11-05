# Plan: pull, verify, state, notify and the member CLI (A5, ai-tools-alerts#z4hs)

Spec: docs/superpowers/specs/2026-11-05-pull-state-notify-cli-design.md.
Constraints (docs/plan.md Global Constraints): standard library only; the CLI
never executes a string from a post; auto-apply only from a curator post for
verbs the member opted into; nothing private leaves the machine.

## Chunk 1 — config, state, pull

Files: create `aitools_alerts/config.py`, `aitools_alerts/state.py`,
`aitools_alerts/pull.py`, `tests/test_pull.py`,
`tests/fixtures/mirror/{manifest.json,feed.json,critical.json,README.md}`;
modify `aitools_alerts/schema.py` (SPEC_DIR resolution),
`aitools_alerts/__init__.py` (TRUST_DIR).

- [ ] 1. `schema.SPEC_DIR`: `_HERE / "spec"` if it is a directory, else
  `_HERE.parent / "spec"`. `aitools_alerts.TRUST_DIR` the same for `trust`.
- [ ] 2. Fixtures: a throwaway generator in the scratchpad (not committed)
  mints a fixture root, a fixture curator and a fixture relay-bot with
  `nostr.keygen()`, signs `manifest.json` (v1, kind 30078, d tag) by the
  fixture root, and signs two root posts: a relay-bot critical for
  `claude-code` `<99.0.0`, fixed `99.0.0`, action `upgrade` (in both
  `critical.json` and `feed.json`, as the poster sends criticals to both), and
  a curator high for `git` (feed only). Secrets are discarded; README.md names
  the fixture root pubkey and says the secrets were never stored.
  `tests/test_pull.py` reads the root pubkey from the fixture manifest's
  `pubkey`. Tests that need their own events (bad signature, revoked key,
  replies, truncated files) mint keys at runtime and serve an in-memory mirror
  through the `fetch` callable.
- [ ] 3. `config.py` per spec (Settings, load, write_default, paths).
- [ ] 4. `state.py` per spec (State, load, save_pull, save_seen, atomic
  write helper, StateError).
- [ ] 5. `pull.py` per spec (fetch, default fetcher, PullResult, advisories,
  Thread, reply and patch rules).
- [ ] 6. Tests in `tests/test_pull.py` (HOME set to tmp_path by an autouse
  fixture):
  - `test_pull_verifies_and_stores_fixture_events` (file:// fixture mirror,
    default urllib fetcher, fixture root): two events stored, both new.
  - `test_pull_rejects_manifest_not_signed_by_root`: manifest signed by
    another key → error, state untouched.
  - `test_pull_drops_event_with_bad_signature`: tampered content →
    `dropped["bad-signature"] == 1`, not stored.
  - `test_revoked_poster_events_dropped` (Review Focus 3): pull with manifest
    v1 listing key K, event by K stored; pull v2 without K → event removed
    from state, `dropped["revoked"] == 1`, `advisories` empty.
  - `test_pull_truncated_json_keeps_previous_state` (Review Focus 2): good
    pull, then a mirror whose `feed.json` is cut mid-way → error starts with
    `mirror unreadable`, events, manifest and last good last_pull unchanged.
  - `test_posted_by_role_comes_from_manifest_not_block`: block says
    `curator`, key is relay-bot → advisory `posted_by == "relay-bot"`.
  - `test_curator_retract_reply_hides_root`: curator reply `retract` →
    thread retracted, not in the check list.
  - `test_relay_bot_reply_cannot_retract`: same from relay-bot → not
    retracted.
  - Extra (spec rules): an older-issued_at manifest is refused; a stored
    newer manifest refuses a replayed older one; `level: high` from curator
    lowers, from relay-bot does nothing; a patch with only `fixed` changed
    updates it and keeps the rest; an explicit null clears `expires_at`; a
    relay-bot patch on a curator root makes `posted_by` relay-bot; a patch
    that leaves the advisory invalid is ignored; a corrupt state file raises
    StateError; config loads defaults, intersects auto_apply with VERBS and
    rejects a bad type; the default fetcher refuses `http://`.

Verify: `python3 -m pytest -q tests/test_pull.py` then `scripts/test-gate.sh`.
Acceptance: all pass; commit `feat: pull, verify and state` and tick chunk 1.

## Chunk 2 — notify, cli, packaging

Files: create `aitools_alerts/notify.py`, `aitools_alerts/cli.py`,
`tests/test_cli.py`; modify `pyproject.toml`.

- [ ] 7. `notify.py` per spec (send, SendResult, format_text, the five
  transports, injected `run` and `post`).
- [ ] 8. `cli.py` per spec (init, keygen, pull, check, notify, plan, run;
  `AITOOLS_ALERTS_TRUST_ROOT` override with a warning; inventory and sender
  reached through module attributes so tests monkeypatch them).
- [ ] 9. `pyproject.toml`: `[project.scripts] aitools-alerts =
  "aitools_alerts.cli:main"`; packages add `aitools_alerts.spec` and
  `aitools_alerts.trust`; `package-dir` maps them to `spec` and `trust`;
  `package-data` `*.json`, `*.pub`.
- [ ] 10. Tests in `tests/test_cli.py` (HOME = tmp_path):
  - `test_run_exit_code_2_on_unseen_critical`: fixture mirror, inventory
    stub with claude-code 2.0.0, sender stub accepting → exit 2 first run,
    0 second run.
  - `test_notify_marks_seen_only_after_accepted`: sender returns not
    accepted → not seen, exit 1; then accepted → seen.
  - `test_notify_text_contains_level_title_action_source`.
  - `test_cli_init_writes_config_and_no_key_by_default`; plus `init
    --make-key` writes a 0600 key, prints an npub, never the nsec.
  - Extra: `plan` prints the npm command for claude-code from the template
    and executes nothing (subprocess.run patched to fail); desktop transport
    passes the text as one argv element outside the AppleScript;
    telegram refuses a group-readable token file; `check --json` parses.
- [ ] 11. Install check (scratchpad venv, temp HOME):
  `python3 -m venv $S/venv && $S/venv/bin/pip install .`, then the spec's
  acceptance line with `AITOOLS_ALERTS_TRUST_ROOT` set to the fixture root;
  `check` output contains the fixture critical's title. Record the output in
  the run manifest.
- [ ] 12. Leak grep: `git diff origin/main | grep -E
  'host-a|host-b|host-d|host-e|host-f|host-c|nsec1'` prints nothing.

Verify: `scripts/test-gate.sh`. Acceptance: gate green, install check prints
the critical; commit `feat: notify and the member CLI`, tick chunk 2.

## Review and ending

Spec and plan: one fresheyes pass (gpt-6-astra) on a snapshot. Code: one
whole-branch Stage 1 ∥ Stage 2 round after chunk 2; heavy delta only if a
BLOCKER fix changed behaviour (`--since <reviewed head>`). Then fetch, rebase,
gate, push, ff-merge to main from the primary checkout, close with evidence,
comment the interfaces on 83xn, gctv and h2gf, /finish-worktree.

Rollback: revert the two feature commits; nothing else depends on them yet.
