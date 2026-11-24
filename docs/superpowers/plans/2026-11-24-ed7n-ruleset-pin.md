# Plan: the ruleset pin in the checkpoint key certificate (ai-tools-alerts#ed7n)

Spec: `docs/superpowers/specs/2026-11-24-ed7n-ruleset-pin-design.md`. Three chunks, built in order; each ends with its tests green. Tests are written first in each chunk and seen to fail.

Run a test file with `python3 -m pytest -q tests/<file>`. The whole gate is `scripts/test-gate.sh`, run once at the end in a clone that holds only this branch and the tags (the shared clone's public scan trips on other sessions' refs).

## Chunk 1: the pin in the certificate

Files: `aitools_alerts/ruleset.py` (after `parse_pin`, about line 604, and `check_claim`, line 622), `aitools_alerts/checkpoint.py` (`Cert` line 74, `_parse_cert` line 199, `verify_cert` line 243, `build_cert` line 275, module docstring line 11), `scripts/sign-checkpoint-key.py` (docstring, argparse block line 94, the `previous` block line 117, `build_cert` call line 133), `tests/mirror_helpers.py` (`publish_cert` line 63, `mirror_now` line 177), `tests/test_ruleset.py`, `tests/test_checkpoint.py`.

- [ ] `tests/test_ruleset.py`: `outdated(pin, rs)` is True below `min_version` and at the pinned version with another digest; False at the pinned version and digest, between `min_version` and the pinned version, and above the pinned version. `check_claim` returns `outdated` in the two True cases (the existing s6mt tests keep passing unchanged).
- [ ] `ruleset.outdated(pin: Pin, rs: Ruleset | None = None) -> bool`, added to `__all__`; `check_claim` calls it.
- [ ] `tests/test_checkpoint.py`, beside the `min_cli` tests (line 536 on), using the same `w` and `script` fixtures:
  - first, the existing `test_unknown_content_keys_are_ignored` (line 372) signs `"ruleset": {"n": 1}` as its unknown key: change that example to `"later": {"n": 1}`, keeping the assertion;
  - no key by default: `w.cert.ruleset is None` and `"ruleset"` not in the content;
  - `build_cert(..., ruleset_pin=Pin(...))` writes exactly `{"version", "sha256", "min_version"}`; `load_cert` gives the same `Pin`; `verify_cert` is True;
  - `verify_cert` is False for `replace(cert, ruleset=<another pin>)`, `replace(cert, ruleset=None)` and `replace(w.cert, ruleset=<a pin>)`;
  - each malformed pin (a list, `{}`, a missing key, an extra key, `min_version` above `version`, `min_version` 0, a 63-character digest, upper-case hex, `version` True) raises `CheckpointError` matching `ruleset` from `load_cert` on a re-signed event; `build_cert` refuses a `ruleset_pin` that is not a `Pin` or fails `parse_pin`;
  - `"ruleset": null` reads as no pin;
  - a certificate with both `min_cli` and a pin carries both.
  - the script: `--ruleset-min-version 1` signs a pin equal to `Pin(ruleset.load().version, ruleset.load().digest, 1)`; `0`, a non-integer and `version + 1` exit before the root key is read (the fixture's reader counts calls, as the `min_cli` test does); replacing a certificate that had a pin without the option prints the warning and signs no pin; replacing with a lower `min_version` prints the lowering warning and signs.
- [ ] `checkpoint.py`: `from . import nostr, ruleset`; `Cert.ruleset: ruleset.Pin | None = None` with a comment like `min_cli`'s; `_parse_cert` reads the key (None when absent or null; `ruleset.parse_pin` otherwise, `RulesetError` re-raised as `CheckpointError(f"certificate: ruleset: {e}")`) and returns it last in the tuple; `verify_cert` compares it; `build_cert(..., min_cli=None, ruleset_pin=None)` checks `isinstance(ruleset_pin, ruleset.Pin)` and writes `{"version", "sha256", "min_version"}`; the closing `_parse_cert(ev)` catches anything else. The docstring's content line names the two optional keys.
- [ ] `scripts/sign-checkpoint-key.py`: `--ruleset-min-version` with an argparse type that accepts an integer of at least 1; after the manifest checks and before `read_root_secret`, build `pin` (refuse `N > rs.version` with `_die`); in the `previous` block warn on a dropped pin and on a lower `version` or `min_version`; pass `pin` to `build_cert`. Docstring: what the option does, that the digest is the checkout's, so sign from the verified release checkout, and that it must be passed again on each later certificate.
- [ ] `tests/mirror_helpers.py`: `publish_cert(..., min_cli=None, ruleset_pin=None)`; `mirror_now(min_cli=None, ruleset_pin=None)`.

Verify: `python3 -m pytest -q tests/test_ruleset.py tests/test_checkpoint.py tests/test_checkpoint_pull.py tests/test_pull.py` (the stored-state tests are in the last two).
Acceptance: spec criteria 1, 2, 3.

## Chunk 2: the CLI

Files: `aitools_alerts/pull.py` (`active`, line 1055), `aitools_alerts/cli.py` (`UPGRADE_LINE` line 39, `_matches` line 230, `_cache` line 256, `_source_check` line 261, `cmd_verify` line 301, `_min_cli` line 332, `cmd_run` JSON line 477, `main` finally line 542), `tests/test_cli.py`, `tests/test_verify_cli.py`, `tests/test_expiry.py` (which holds the `active` decay tests).

- [ ] `tests/test_cli.py`, after the `min_cli` tests, with a helper `_mirror_with_pin(tmp_path, monkeypatch, pin)` shaped like `_mirror_with_min_cli`:
  - a pin with `min_version` 99: no line before the first pull; then exactly one `aitools-alerts: out of date:` line on `pull`, `check`, `check --json`, `plan`, `run`, `notify`, `run --quiet`, `verify` and a failing `plan`, each with its own exit status; `run --json` has `ruleset_outdated == {"have": V, "pinned": 99, "min_version": 99}` and still lists the match;
  - same version, another digest (`"0" * 64`): the line, and `ruleset_outdated` names the same version twice;
  - parametrized no-line cases: no pin; the reader's own version and digest with `min_version` 1 and with `min_version` = version; a pin above the reader whose `min_version` the reader meets; `ruleset_outdated` is null in each;
  - the pin is read under the current root only (as the `min_cli` test);
  - both `min_cli` and an out-of-date pin: both lines, once each;
  - no computed expiry while out of date: a relay-bot thread with a claim, under a checkpoint dated past its TTL, shows `critical` with the out-of-date pin and the decayed level with a matching pin.
- [ ] `tests/test_verify_cli.py`: with an out-of-date pin, `run` makes no request (the `Net` double records none), prints no `source check:` line about a source, `check --json` and `run --json` give `source_check: null`, and `verify` prints `source check: not run (this aitools-alerts is out of date)`. With a pin the CLI meets and `verify = "off"`, `source_check` is still `{"result": "unknown", "why": "off", "source_level": null}`. The `feed` fixture gains `ruleset_pin=None`.
- [ ] `tests/test_expiry.py`: `active(..., decay=False)` keeps the level of a claim thread past its TTL and still ends a curator thread past its `expires_at`; default unchanged.
- [ ] `pull.active(threads, now=None, listed=None, *, decay=True)`: the `elif` branch requires `decay`. Docstring sentence.
- [ ] `cli.py`: `OUTDATED_LINE`; `_ruleset_outdated(a, st)` (pin from `st.cert_for(a.root)`; `ruleset.load()` in a `try` that returns None on `Exception`; computed once per run and kept on `a`, like `warned`); `_matches` passes `decay=_ruleset_outdated(a, st) is None`; `_cache(a, st, s)` returns None when out of date, and its four callers pass `a`; `_check_json(t, m, cache, judged=True)` returns None when not `judged`, and `_match_json` passes it on from `cmd_check` and `cmd_run` (`judged = _ruleset_outdated(a, st) is None`), because `verify.result_for(adv, None)` answers "unknown, off" and not null; `_source_check(a, st, s, ...)` returns first when out of date; `cmd_verify` prints the not-run line and returns 0; `cmd_run` adds the JSON key; `main`'s `finally` prints the line after the upgrade line under the same `OSError` guard.

Verify: `python3 -m pytest -q tests/test_cli.py tests/test_verify_cli.py tests/test_expiry.py tests/test_pull.py`.
Acceptance: spec criteria 4, 5.

## Chunk 3: released readers and documents

Files: `tests/test_wire_compat.py` (`feed` line 76, a new test after the manifest control), `spec/wire.md` (after the `min_cli` section, line 57), `README.md` (line 91), `CHANGELOG.md` (top of Unreleased; line 28), `docs/superpowers/runs/2026-11-24-ed7n-ruleset-pin.md`.

- [ ] `feed()`: `mirror_now(min_cli="99.0.0", ruleset_pin=Pin(rs.version, rs.digest, 1))`; the docstring and the module docstring name the pin. The existing assertions hold unchanged: this reader is not out of date, so it still decays a month on.
- [ ] New test, parametrized over `v0.1.6` and `v0.1.7`: a mirror whose certificate pins `Pin(99, "0" * 64, 99)` and one relay-bot critical. The released reader's pull is checked (`; checkpoint ` in stdout, no `unverified`) and shows the alert as critical and matched. This reader pulls it without error, `State.cert_for(root).ruleset.min_version == 99`, and `ruleset.outdated` is True for it.
- [ ] `spec/wire.md`: section "The ruleset pin": the key, its three members, what a reader does when out of date, that the pin object takes exactly three keys so a later addition is a new content key beside it, that v0.1.6 and v0.1.7 ignore it. Update the last sentence of the `min_cli` section, which names the pin as future.
- [ ] `README.md`: one paragraph after the `upgrade:` one for the `out of date:` line and the `ruleset_outdated` key.
- [ ] `CHANGELOG.md`: an entry at the top of Unreleased (what the root can now pin; what an out-of-date CLI does and does not do; released readers ignore the key, and why it is not in the manifest; no certificate carries it yet; the signing option). The s6mt paragraph's "does not yet pin the ruleset" clause points at this entry.
- [ ] File the rollout issue: "rollout: sign a checkpoint key certificate that carries the ruleset pin", labels `repo:ai-tools-alerts`, `discovered-from:ed7n`, priority 2. Leave a note on ai-tools-alerts#tavj (what it can call) and on the sibling issues whose files this touches (`cli.py`: 0xq6, c1g2, faxq).

Verify: `python3 -m pytest -q tests/test_wire_compat.py`, then the whole gate in a single-branch clone.
Acceptance: spec criteria 6, 7, 8.

## Review and landing

- [ ] Merge `origin/main` before the review. One whole-branch round: fresheyes on `git diff origin/main...HEAD` and one same-model reviewer in parallel. Every BLOCKER fixed, every SUBSTANTIVE finding fixed or rebutted in one kata comment; one delta only after a behaviour-changing BLOCKER fix.
- [ ] Gate in a single-branch clone at the final head. Close-out comment with head SHAs, test result and the review line. Pull request; merge with `gh pr merge <n> --merge --author-email` and the no-reply address; check `git log -1 --format=%ae origin/main`; close the issue on the merge commit; `/finish-worktree`.

## Rollback

Revert the pull request. No certificate carries the key until the rollout issue is done, and a certificate that does is ignored by v0.1.6 and v0.1.7 and read as pin-less by a reverted reader.
