# B4 plan: relay transport and the poster command (ai-tools-alerts#kfq6)

Spec: `docs/superpowers/specs/2026-11-05-poster-transport-main-design.md`.
Three chunks, three landings on `main` (decided: split by the 600-line rule).
Gate for each: `scripts/test-gate.sh` (the whole suite; the repo has no
repoman row). Every chunk: grep the chunk's new and changed lines for
`host-a|host-b|host-d|host-e|host-f|host-c` (only `candidates.FLEET_HOSTS`
and test denylists may hold them) and for `nsec|PRIVATE_KEY|\.buzz-keys|--private-key|--relay`
(only a test's denylist may). The repo-wide key path in `ops/vm/buzz-send`,
`ops/vm/README.md` and `docs/plan.md` is E1's wrapper and its docs, kept by
design: the poster's code must not hold it, and that is what the grep checks.

## Chunk 1: transport (landing 1)

Files: create `aitools_alerts/poster/transport.py`, `tests/poster/test_transport.py`.

- [ ] 1.1 Tests first, with a recording fake `ssh(argv, **kw) -> CompletedProcess`:
  - `test_argv_is_ssh_host_and_one_joined_remote_command` (exact argv; the
    remote string `shlex.split`s to the wrapper argv; content as `input`
    bytes; `timeout` and `capture_output` passed).
  - `test_reply_to_adds_flag`; `test_no_key_material_on_argv`.
  - `test_bad_arguments_raise_before_ssh` (non-UUID or uppercase channel, short
    or uppercase reply id, empty, NUL, bytes, oversize; no call recorded).
  - `test_success_parses_event_id`; `test_exit0_not_accepted_is_failed`;
    `test_exit0_garbage_is_unknown`.
  - `test_cli_exit_codes_are_failed` (1, 3, 4, 5, 126, 127).
  - `test_other_exits_are_unknown` (−9, −15, 6, 130, 137).
  - `test_exit2_delivery_unknown_is_unknown` (delivery unknown, empty, relay
    error 503, network error plus delivery unknown);
    `test_exit2_network_or_4xx_is_failed`.
  - `test_ssh_connect_failure_is_failed`; `test_ssh_drop_is_unknown`.
  - `test_timeout_is_unknown`; `test_oserror_is_failed`; `test_stderr_is_capped_and_decoded`.
- [ ] 1.2 Run `python3 -m pytest tests/poster/test_transport.py -q`: FAIL.
- [ ] 1.3 Implement per the spec's Transport section.
- [ ] 1.4 Run the file, then `scripts/test-gate.sh`: PASS.
- [ ] 1.5 Commit `feat: poster transport over the VM's buzz-send wrapper`.

Acceptance: transport tests green; gate green; greps clean.

## Chunk 2: inputs and the privacy guard (landing 2)

Files: create `aitools_alerts/poster/inputs.py`, `tests/poster/test_inputs.py`;
modify `aitools_alerts/poster/candidates.py` (`_PRIVATE`), `tests/poster/test_candidates.py`.

- [ ] 2.1 Tests:
  - Config: `test_load_config_defaults_and_expands`, `test_config_unknown_key_is_error`,
    `test_config_bad_types_are_errors` (digest_hour 24, bool, path not a string).
  - State: `test_state_fresh_has_backfill_floor`, `test_state_roundtrip_atomic`
    (no temp file left), `test_malformed_state_is_ledger_error` (bad JSON,
    missing key, wrong outbox item type).
  - KEV: `test_kev_fetch_not_modified_uses_cache` (304 + `If-Modified-Since`
    sent from the cached Last-Modified), `test_kev_200_writes_cache`,
    `test_kev_error_returns_none`, `test_kev_oversize_or_bad_shape_returns_none`,
    `test_kev_stalled_fetch_hits_deadline` (a fetch blocked on an Event;
    deadline patched to 0.2 s; returns None within 1 s).
  - Dirs: `test_heartbeat_dirs_after_watermark` (first run: newest only; after:
    every newer dir with run.json, oldest first, cap 48),
    `test_collector_newest_validated_only` (date-only dir ignored; validate not
    ok → None and counted; not newer than watermark → None).
  - Privacy: `test_source_with_volumes_path_is_dropped` in test_candidates.
- [ ] 2.2 Run: FAIL. 2.3 Implement `inputs.py` per the spec's Inputs section
  (`Config`, `ConfigError`, `load_config`, `new_state`, `load_state`,
  `save_state`, `load_channels`, `urllib_fetch`, `load_kev`, `heartbeat_dirs`,
  `collector_record`); widen `_PRIVATE`.
- [ ] 2.4 Run the files, then `scripts/test-gate.sh`: PASS.
- [ ] 2.5 Commit `feat: poster inputs: config, run state, KEV fetch, run dirs`.

Acceptance: tests green; gate green; greps clean.

## Chunk 3: the run (landing 3)

Files: create `aitools_alerts/poster/main.py`, `tests/poster/test_main.py`;
modify `aitools_alerts/poster/ledger.py` (`entries_since`),
`tests/poster/test_ledger.py`, `pyproject.toml` (console script
`aitools-alerts-poster = "aitools_alerts.poster.main:main"`).

- [ ] 3.1 Harness in `tests/poster/test_main.py`: `FakeSSH` (records
  `(channel, reply_to, text)`; answers from a queue: ok / fail (exit 5) /
  unknown (timeout)); `FakeKEV` (records request headers); a 200 source fetch;
  a config in `tmp_path`; collector and heartbeat dir writers; `now` at 06:20
  Tokyo unless a test says so.
- [ ] 3.2 The eight named tests, as in the spec's criteria:
  `test_send_failure_leaves_advisory_unposted` (exit 5: exit 1, no entry, no
  pending, the item stays; the next run posts it once; a third run sends
  nothing), `test_critical_posts_to_both_channels_in_order`,
  `test_high_posts_to_feed_only`, `test_notice_waits_for_digest` (held before
  09:00; one digest at 09:20 naming it; none again that day; not listed the
  next day), `test_duplicate_alias_becomes_reply`,
  `test_watermark_advances_only_on_success`, `test_kev_fetch_not_modified_uses_cache`
  (through `run`), `test_unknown_outcome_keeps_pending` (timeout: exit 1,
  pending and item kept; next run sends nothing and counts it busy; after
  `expire_pending` the item sends once, with no new input record).
- [ ] 3.3 Further tests:
  - `test_one_failure_stops_further_sends`: at 09:20 with two highs queued and a
    digest due, the first send fails; the call list is exactly that one send;
    watermarks unchanged.
  - `test_ledger_error_stops_sends`: `record_root` patched to raise LedgerError
    after a send; no later send; exit 1; the item keeps `sent`; the next run
    records it without sending.
  - `test_feed_failure_after_critical_completes_next_run`.
  - `test_partial_reply_retried_in_failed_channel_only`: a critical entry gets
    a change; the critical reply succeeds, the feed reply fails; the next run
    sends only the feed reply.
  - `test_busy_candidate_learns_ids` (A unknown; A/B seen; B alone stays
    busy).
  - `test_high_becoming_critical_under_another_id` (thread root A, critical
    candidate B with alias A: copy to critical titled with A and keeping the
    stored fix; feed reply; no ValueError).
  - `test_compose_value_error_sends_nothing` (the reply composer raises for a
    promotion: neither the copy nor the reply is journaled or sent).
  - `test_notice_dedup_is_per_scope` (one CVE under two scopes: both held).
  - `test_digest_includes_ledger_posts` (a high posted, then the digest lists it
    from the ledger even when `held` is empty).
  - `test_backfill_floor_drops_old_candidates`,
    `test_collector_record_skipped_unless_validate_ok`,
    `test_heartbeat_feeds_json_never_reaches_from_kev`,
    `test_malformed_state_refuses_to_send`, `test_config_unknown_key_exits_2`,
    `test_main_prints_one_summary_line`.
  - From the delta pass: `test_unknown_digest_is_journaled_once_and_acknowledges_its_snapshot`,
    `test_affected_range_correction_posts_a_reply`, `test_busy_candidate_holds_watermarks`,
    `test_finished_send_clears_pending_before_the_item_goes`.
  - In test_ledger: `test_entries_since_and_has_pending`.
- [ ] 3.4 Run: FAIL. 3.5 Implement `main.py` per the spec's Run section
  (`Run` with `drain`, `plan_new`, `plan_known`, `plan_digest`, `_record`;
  `gather`; `run(now, config, *, ssh, kev_fetch, http_status, channels)`;
  `main(argv)`); add `Ledger.entries_since(t)`; add the console script.
- [ ] 3.6 Run the files, then `scripts/test-gate.sh`: PASS;
  `python3 -m aitools_alerts.poster.main --help` prints usage.
- [ ] 3.7 Commit `feat: aitools-alerts-poster hourly run with a send journal`.

Acceptance: tests green; gate green; greps clean.

## Each landing

`git fetch origin`; rebase on `origin/main` if it moved; one whole-branch
fresheyes (`FRESHEYES_GPT_MODEL=gpt-6-astra`) of the landing's diff; every
BLOCKER fixed, every SUBSTANTIVE fixed or rebutted in one kata comment; one
delta pass only when a BLOCKER fix changed behaviour; gate; push the branch;
from `/path/to/repos/ai-tools-alerts`: `git checkout main && git pull
--ff-only && git merge --ff-only <branch> && git push origin main`; comment
the sha on kfq6. After landing 3: comment the config shape and the command
line on jibot-code#zhja (E2); comment the shas and interfaces on the issues
kfq6 blocks; file the `resolve` follow-up; close kfq6 with evidence.

## Rollback

Revert the landing commits; nothing is scheduled until E2.
