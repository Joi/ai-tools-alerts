# Plan: the reader enforces the checkpoint

Spec: `docs/superpowers/specs/2026-11-23-6whv-reader-checkpoint-design.md`. Kata: ai-tools-alerts#6whv. Branch `6whv-reader-checkpoint`, stacked on `zb8b-checkpoint-format`. Tests first in each chunk.

## Chunk 1: state and the pull

Files: `aitools_alerts/state.py`, `aitools_alerts/pull.py`, `aitools_alerts/poster/main.py` (two call sites), `aitools_alerts/curator.py`, `tests/mirror_helpers.py`, `tests/test_pull.py`, `tests/test_checkpoint.py` (remove `test_nothing_in_the_package_uses_the_module_yet`), `tests/fixtures/mirror/`.

- [ ] `tests/mirror_helpers.Mirror`: a checkpoint key (`ck_sec`, `ck`); `publish_cert(key=None, issued=None, days=120, signer=None)`; `checkpoint(ids=None, seq=None, now=None, sec=None, valid_s=86400)` returning and storing a signed checkpoint (default: what an honest signer lists: events that verify, are signed by a current manifest poster, are channel-bound and are not dated after the checkpoint; `seq` one higher than the last); `fetch` serves `checkpoint-key.json` and `checkpoint.json`: the stored one if a test set it, else a fresh automatic checkpoint dated at the newest event that is not more than a day after `T0` plus the tests' clock (so an event planted years ahead never dates it), never before the certificate. `raw[...]` overrides and `None` (file missing) work for the new names as for the old. A `second` dict (name to bytes) served under `SECOND = "https://second.example.invalid/trust/"`; a URL under it that is not in the dict raises `OSError`. `publish_manifest` issues a new certificate for the new manifest unless `cert=False`.
- [ ] `tests/fixtures/mirror/`: re-signed with new throwaway keys (the script of piece 1, extended), adding `checkpoint-key.json` and `checkpoint.json`; README updated.
- [ ] `state.py`: `State.trust: dict` (root -> `{"cert": event, "checkpoint": event | None, "applied": [ids]}`), read from `checkpoint.json` (missing: empty; malformed, wrong shape, or a document that does not load: `StateError`); `State.save_trust()`; `locked()` re-reads it. Accessors `cert_for(root)`, `checkpoint_for(root)`, `applied_for(root)` return parsed objects (`checkpoint.Cert`, `checkpoint.Checkpoint`, a frozenset or None when no checkpoint was ever accepted).
- [ ] `pull.py`:
  - `default_fetch(url, timeout=TIMEOUT)`; `SECOND_TIMEOUT = 5`.
  - `fetch(base_url, state, fetch=None, root_pubkey=..., now=None, second_origin=None, checkpoint=True)`.
  - `_manifest_step`: mirror and second-origin candidates, each loaded against the floor and verified; highest version, the second origin's on a tie; `last_pull["second_origin"]` is `None` (not configured), `"ok"`, or the fetch error kind.
  - `_cert_step`: candidates (mirror, second origin, bundled, stored) filtered by load, `verify_cert`, `cert_problem`; latest `issued_at`; `cert_order` against the stored one; saved at once with `state.save_trust()` when it differs from the stored one.
  - `_checkpoint_step`: load, `verify_checkpoint`, `checkpoint_problem` (dated ahead gets its own error), `checkpoint_order`.
  - completeness after `_filter`; `_retain` given the listed and applied ids to keep whole threads; the capacity rule (unlisted, unapplied events dropped newest-kept until the store fits).
  - step 0: `last_pull` written with `checkpoint_ok: false`, error `interrupted`, before any fetch; the final record sets `checkpoint_ok` true only at the end of a successful `checkpoint=True` pull; a `checkpoint=False` pull records false.
  - the applied set: new = old ∪ listed; ids not in the on-disk store are pruned at the start of the pull, never in the save that removes their events. `_retain` unchanged, after completeness.
  - save order: `save_trust()`, then events, then `last_pull`. `State.save_pull` is split so the order is explicit.
  - With `checkpoint=False` the function does what it does today and never reads or writes `state.trust`.
  - `advisories(state, dropped=None, checkpointed=True)`: applied set when one exists, else all stored bound events (legacy); `checkpointed=False` always all.
  - `unverified(state, now=None)` with the seven reasons, in the spec's order; `stale_since` as specified, with the no-manifest fallback (last pull attempt, else now).
- [ ] `poster/main.py`: `checkpoint=False` at both `pull.fetch` calls. `curator.py`: `checkpoint=False` at its pull; `checkpointed=False` at `find_threads`, `_replayed`, `_present`.
- [ ] Existing tests migrated, each keeping what it proves: the forged, revoked, unbound and future-dated event tests run against the honest automatic checkpoint; the 3-day and 90-day tests seed stored v0.1.4 state with no checkpoint; `test_live_feed_fixture_is_read_whole` pulls with `checkpoint=False`; the released-reader test fails when the tag is missing.
- [ ] Tests (`tests/test_pull.py`, new section), each named for what it shows:
  - the pull accepts a mirror with certificate and checkpoint, stores both, applies listed events; an unlisted event is stored and not applied, then applied after the next checkpoint lists it;
  - each new pull error, with state unchanged beyond what the spec allows: no certificate (all sources missing); certificate signed by a stranger, for another manifest, expired, dated ahead; no checkpoint; checkpoint by an uncertified key (the bot key, the root key); for another manifest; dated ahead (own error); older (replay of N after N+1); conflicting (two with one number);
  - the pull really verifies signatures: a certificate and a checkpoint each with a corrupted signature, an altered id, and altered content with a recomputed id, all claiming the right key, from the mirror and (certificate, manifest) from the second origin, with no valid fallback certificate available: refused;
  - the manifest and certificate survive a failed later step (revocation applies at once; certificate floor kept);
  - second origin: higher manifest wins; unreachable is not an error and is recorded; a second-origin manifest signed by a stranger is ignored; a lower one is ignored; the certificate comes from it when the mirror's is old;
  - the applied set: only grows; seeded with legacy events at the first checkpoint; an event of a revoked key leaves; retention drops a whole old thread but never one holding a listed event;
  - capacity: a flood of unlisted events with small `MAX_STORED_EVENTS` (monkeypatched) keeps every listed event; listed events that do not fit give `state limit reached` and no change;
  - interruption: `State.save_trust`, the events write and the final `last_pull` write each made to raise in turn, for a successful pull and for a refused pull that starts from a verified state; after reload, `unverified` gives the expected reason and no unlisted event is applied;
  - the interrupted-pruning case: a thread with its retraction ages out, the save is interrupted between the two files, reload, then a pull whose checkpoint (signed with the checkpoint key at a higher number) lists only the root: the thread is retracted or absent, never shown active;
  - an aged-out thread listed by a checkpoint is not shown (retention is not overridden by listing);
  - member pull refused, curator-mode pull of the same mirror succeeds, member `unverified` still reports (writer pulls never set `checkpoint_ok`);
  - `checkpoint.json` state: round trip; malformed JSON, wrong shapes, an unloadable certificate or checkpoint, a certificate not signed by its root: `StateError`; absent applied set versus empty; two roots kept apart; a `State` loaded before another process saved a newer certificate does not overwrite it (the lock re-reads);
  - `unverified`: one test per reason, including the clock set back behind the stored checkpoint and `last_pull.ok` false after a network error; `stale_since` non-null exactly when unverified or stale, in both the checkpoint and the legacy case;
  - `checkpoint=False`: stores every verified event, leaves `state.trust` untouched, works against a mirror with no certificate;
  - the curator path (`tests/test_curator.py`): accept a checkpoint, publish a thread no checkpoint lists, amend and retract it through `cli.main(["curator", ...])`, while the member's `advisories` still excludes it; and the future-event replay path of piece 1 through `checkpointed=False`.
- [ ] Verify: `python3 -m pytest -q tests/test_pull.py tests/test_checkpoint.py tests/test_curator.py tests/poster`.

Acceptance: every listed test fails on the parent branch and passes; existing member-path tests still run with `checkpoint=True`.

## Chunk 2: CLI, config, hook, skills

Files: `aitools_alerts/cli.py`, `aitools_alerts/config.py`, `hooks/claude-code/session-start.sh`, `skills/*/aitools-alerts/SKILL.md`, `snippets/AGENTS.md`, `tests/test_cli.py`, `tests/test_templates.py`.

- [ ] `config.py`: `second_origin` (default the repository's raw `trust/` URL; `""` off; else `https://.../`); `write_default` documents it.
- [ ] `cli.py`: `_pull` passes `second_origin` (skipped under a test-root override unless the config sets it); `cmd_pull` prints the checkpoint's number and count; `cmd_check` prints the unverified line (in place of the stale line when both apply); `cmd_plan` prints it and moves every auto-apply action to prepare; `run --json` gains `unverified`.
- [ ] Hook: the second line's wording. Skills and snippet: `stale_since` and `unverified` described.
- [ ] Tests: `check`, `plan` (an opted-in curator upgrade is listed under auto-apply when verified and under prepare when unverified, for each of: last pull failed, no checkpoint, out of date), `run --json`; config parsing of `second_origin` (default, off, http refused, no trailing slash refused); the hook prints its line for real unverified `run --json` output and for v0.1.4-shaped stale output, and nothing for a verified one (`tests/test_templates.py` already drives the hook with a fake CLI).
- [ ] Verify: `python3 -m pytest -q tests/test_cli.py tests/test_templates.py`.

## Chunk 3: the four attacks and compatibility

File: `tests/test_attacks.py` (new), one test per attack form in the spec's "The four attacks, as tests" (1; 2a, 2b, 2c with both a stale and a stolen-key checkpoint; 3 with and without the second origin, and the key rotation; 4), each going through `cli.main` where the outcome is something a member sees (`plan` output, `run --json`). Plus `test_released_reader_ignores_the_new_files`: the v0.1.4 reader (from the tag, as in piece 1) pulls and checks the re-signed fixture mirror, which now also holds the two new files; and `test_released_reader_reads_state_this_reader_wrote`: this reader pulls into a home (a completed pull; a certificate-only state after a refused checkpoint; a save interrupted after the checkpoint file), then v0.1.4 runs `check` on that home: exit 0, the advisories listed, no traceback. A fresh install whose first pull fails before any manifest: `run --json` has a non-null `stale_since`, and the hook prints its line.

- [ ] `README.md` ("Whom you are trusting": what the checkpoint and the second origin add and what they do not), `CHANGELOG.md` (Unreleased), `docs/design.md` pointer if it describes the pull.
- [ ] Verify: `python3 -m pytest -q` (the gate's public scan currently stops on a commit already on main; see the run manifest).

Acceptance: the tests of new enforcement (attacks 1, 2a, 2b, 3, the rotation) fail on the parent branch because the parent accepts the mirror; the tests of attack 4 and 2c are regression tests of behaviour the parent has, run through the new path, and are named so in their docstrings.

## Rollback

Revert the merge commit. The previous reader ignores `checkpoint.json` in the state directory.
