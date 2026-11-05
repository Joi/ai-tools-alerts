# Plan: B3 post composition and ledger (ai-tools-alerts#h2gf)

Spec: `docs/superpowers/specs/2026-11-05-poster-compose-ledger-design.md`.
One chunk; new files only.

## Chunk 1

Files:
- Create `aitools_alerts/poster/compose.py`
- Create `aitools_alerts/poster/ledger.py`
- Create `tests/poster/test_compose.py`
- Create `tests/poster/test_ledger.py`

Steps:
- [ ] 1. Write the tests first (red: modules missing).
  - `test_compose.py`: `test_root_post_body_has_four_lines_and_block` (four
    body lines, a blank line, the block; `schema.parse_post` returns the same
    Advisory; posted_by relay-bot; advisory_severity null),
    `test_unverified_body_says_unverified`,
    `test_body_never_contains_host_names` (candidate carries none;
    `socket.gethostname` monkeypatched to `host-alpha.example`; denylist of
    invented names plus a fleet-shaped regex, checked over root, reply and
    digest), `test_rule_inputs_never_reach_post_text` (a version in
    product_text and advisory_severity does not appear),
    `test_reply_only_carries_changed_fields` (block keys equal the changed set;
    `apply_patch` round-trips; empty patch and `id`/`posted_by`/unknown keys
    refused; null clears a nullable field and is refused on others),
    `test_digest_lists_every_item_once` (critical, high, notice order;
    duplicate id once), version-conversion cases.
  - `test_ledger.py`: `test_ledger_alias_merge` (KEV + heartbeat sharing a
    CVE under one scope merge and carry exploited; under another scope they do
    not; ledger entry carries exploited only for the same scope),
    `test_pending_blocks_resend` (pending on disk before return; same key or
    shared alias refused; clear allows; expire refused before 24 h or without a
    reason, allowed after, logged), lock held refuses a second Ledger,
    malformed file refused, atomic write leaves no temp file, review dedup,
    record_root refuses a known alias, record_reply updates.
- [ ] 2. Run `python3 -m pytest tests/poster -q`: FAIL (import errors).
- [ ] 3. Implement `compose.py` per the spec's tables and line templates.
- [ ] 4. Implement `ledger.py` per the spec.
- [ ] 5. Run `scripts/test-gate.sh`: PASS. Run
  `python3 -c "from aitools_alerts.poster import compose, ledger"`: exit 0.
- [ ] 6. Stage the four files (`git add` them by name), check `git diff --cached --name-only`
  lists all four, then the leak check on staged added lines:
  `git diff --cached origin/main -- aitools_alerts tests | grep '^+' | grep -E -i '<fleet-names>'`
  prints nothing (`candidates.FLEET_HOSTS` is not in this diff).
- [ ] 7. Commit `feat: post composition and ledger`.

Acceptance: spec success criteria 1-5.

Verification: `scripts/test-gate.sh`; the import one-liner; the leak grep;
`git diff --cached --stat origin/main -- aitools_alerts tests` (about 880 lines; see the spec's criterion 5).

Rollback: `git revert` of the chunk commit; no other file changes.
