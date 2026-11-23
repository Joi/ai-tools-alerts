# Plan: the self-correcting wire format (ai-tools-alerts#t8jr)

Spec: `docs/superpowers/specs/2026-11-24-t8jr-wire-format-design.md` (as revised after its review). Three chunks, one commit each, in this order. Budget: under 600 changed lines outside `docs/superpowers/` and tests.

Every test run: `python3 -m pytest -q <files>` from the repository root, with no `GIT_*` variable set (tests/git_env.py clears them; never export one). In-process tests run at the tests' reader clock (`conftest.reader_clock`, the year 2099), so they use `Mirror()` as it is; only the released readers, run as subprocesses at the real clock, need `mirror_now()`.

## Chunk 1: the claim tag and the level-only reply

Files:
- `aitools_alerts/wire.py` (new, about 80 lines)
- `aitools_alerts/poster/compose.py`: `level_post` after `reply_post`; a guard inside `reply_post` before `merged = apply_patch(prev, patch)`
- `tests/test_wire.py` (new); `tests/poster/test_compose.py` (four tests migrated)

Steps:
- [ ] `wire.py`: `CLAIM_TAG`, `MAX_CLAIM_BYTES = 2048`, `LEVELS`, `claim_tag(obj)`, `claim_of(event)`, `is_lowering(patch, level)`. `claim_tag` uses `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`; raises `ValueError` for a non-dict, an unserializable value, more than `MAX_CLAIM_BYTES` UTF-8 bytes, or an object that does not read back equal (a non-string key). `claim_of` returns None unless the event is a dict whose `tags` list holds exactly one list starting with `"claim"`, of length 2, with a `str` value within the limit that parses (`schema._no_duplicates`, `schema._reject_constant`) to a dict; it catches `ValueError` and `RecursionError`.
- [ ] `is_lowering(patch, level)`: True when `patch` is a dict whose `level` is a known level ranked below `level`. Ranks are a copy of `pull._RANK` in `wire` (so `wire` imports `schema` only); a test checks the two are equal.
- [ ] `compose.level_post(prev, level)`: raises `ValueError` unless `level` is a string in `wire.LEVELS` other than `prev.level`; text is `Level is now <level>.`, a blank line, the fenced block `{"level": "<level>"}`; passes `_guard`; checks the reply parses back to the merged advisory and the block to exactly that one key.
- [ ] `compose.reply_post`: `if wire.is_lowering(patch, prev.level): raise ValueError("reply: a lowering travels alone (level_post)")`; and before it, `if "expires_at" in patch: raise ValueError("reply: a relay-bot reply carries no expires_at")` (rule 3; `test_reply_only_carries_changed_fields` drops the expiry it sent and checks the refusal).
- [ ] Migrate the four tests in `tests/poster/test_compose.py` that build a reply with `reply_post(adv, c, {"level": "high"})` on a critical: each uses a high thread raised to critical instead and keeps its assertions (host names never appear, rule inputs never reach the text, the unverified line leads a level change, one SYNTHETIC mark). Where the text of a lowering was the subject, `level_post(adv, "high")` is checked as well. `test_reply_is_held_to_root_publication_rules` gains the refusal.
- [ ] `tests/test_wire.py`: round trip of `claim_tag`/`claim_of`; `claim_of` is None for no tag, two tags, a one- or three-element tag, a non-string value, a non-object, duplicate keys, `NaN`, an oversize value, deep nesting, a lone surrogate, a non-dict event, `tags` not a list; `claim_tag` refuses a non-dict, a non-string key, `NaN`, an unserializable value, oversize in bytes; `level_post` in both directions gives a one-key block and refuses no change and unknown levels; `reply_post` refuses a lowering alone and with `products`, and still posts the fix alone; the current reader (`pull.threads_from`) keeps the higher level for a bot `level_post` and reads an event with a claim tag as it reads one without.

Verify: `python3 -m pytest -q tests/test_wire.py tests/poster` passes.
Acceptance: success criteria 1 (carrier) and 2 of the spec.

## Chunk 2: `min_cli`

Files:
- `aitools_alerts/checkpoint.py`: `Cert`, `_parse_cert`, the tuple in `verify_cert`, `build_cert`
- `scripts/sign-checkpoint-key.py`: `--min-cli`
- `aitools_alerts/cli.py`: `UPGRADE_LINE`, `_min_cli(a, st)`, the `finally` in `main`, the key in `cmd_run`'s JSON
- `tests/mirror_helpers.py`: `publish_cert(min_cli=None)`, `Mirror.write(dir)`
- `tests/test_checkpoint.py`, `tests/test_cli.py`: new tests

Steps:
- [ ] `checkpoint._MIN_CLI = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")`. `_parse_cert` returns a sixth element: `c.get("min_cli")`, which must be absent, null, or a `str` fully matching, else `CheckpointError`. `Cert.min_cli: str | None = None` (last field, default None, so `Cert(ev, *fields)` holds). `verify_cert` compares the six-tuple, so the object's `min_cli` is bound to what the root signed. `build_cert(..., min_cli=None)` validates and adds the key only when given.
- [ ] Check every `Cert(`, `_parse_cert(` and `build_cert(` use (`grep -n "Cert(\|_parse_cert\|build_cert" -r aitools_alerts scripts tests mirror`): the other callers pass five arguments and are unchanged.
- [ ] `sign-checkpoint-key.py`: `--min-cli`, an argparse type using `checkpoint._MIN_CLI` (so a bad value exits 2 before the root key is read), passed to `build_cert`; the docstring says what it is for, why it is here and not in the manifest, and that it must be passed again on each later certificate.
- [ ] `cli._min_cli(a, st)`: `st.cert_for(a.root)` (verified under that root by `State.load`); its `min_cli` when `versions.parse(__version__) < versions.parse(min_cli)` and both parse, else None. `main`: the five state commands run inside `try`, and `finally` prints `UPGRADE_LINE` on stderr when `_min_cli` is not None; the command's return value or exception passes through. The state object is the one the command used (a pull updates `st.trust` in place). `cmd_run` JSON: `"min_cli": _min_cli(a, st)`.
- [ ] Tests in `tests/test_checkpoint.py`: a certificate with `min_cli` loads, verifies, and equals `cert_from_event` of itself (the state path); `dataclasses.replace(cert, min_cli=other)` does not verify, in either direction; malformed values are refused by `build_cert` and by `load_cert`; null reads as absent; the signing script writes the value and exits 2 on a bad one with no key read.
- [ ] Tests in `tests/test_cli.py` (a `Mirror` written to a directory, the test root in the environment): before any pull, no line; then each of `pull`, `check`, `check --json`, `plan`, `run`, `notify`, `run --quiet` and a failing `plan` prints the line exactly once and returns its own status; `run --json` carries `"min_cli": "99.0.0"` and still lists the match; `min_cli` absent, lower, or equal gives no line and `null`; a certificate signed by another key, or issued before the stored one, does not set it, and a later one from the root does and is in the reloaded state; the line survives a failed pull (bad event file, missing manifest); versions compare as numbers (`0.9.0` < `0.10.0`, `0.2.0rc1` < `0.2.0`, an unreadable own version says nothing); state stored under another root says nothing.

Verify: `python3 -m pytest -q tests/test_checkpoint.py tests/test_cli.py tests/test_checkpoint_pull.py tests/test_trust_root.py` passes.
Acceptance: success criterion 4.

## Chunk 3: the compatibility test, the changelog, `spec/wire.md`

Files:
- `tests/mirror_helpers.py`: `mirror_now(min_cli=None)`; `released_reader(...)`'s `run` gains `run.py(code, *args, root=...)`
- `tests/test_wire_compat.py` (new)
- `spec/wire.md` (new), `CHANGELOG.md` (an "Unreleased" section at the top), `README.md` (one sentence where upgrading is described)

Steps:
- [ ] `run.py(code, *args)`: runs `code` in the released tree with the same home redirect, cwd and environment as `run`.
- [ ] `DUMP`, the script run in each released tree: for `at` in (clock, clock + 30 days), `pull.active(pull.advisories(State.load()), at)`, and per active thread `[level, sorted fixed versions, matched]` where `matched` is `check.match` against `Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", ...)]})`. `shown()` computes the same for this reader.
- [ ] The feed (events dated `now - 3600` on; `mirror_now(min_cli="99.0.0")`): 0001 bot critical with a claim tag; 0002 bot high, then one reply raising to critical with a fix and a claim (never lowered: may share); 0003 bot critical, then `level_post` to notice, then `level_post` to high, then a reply with the fix, each with a claim; 0004 curator critical; 0005 a bot root whose block has an extra key. Every bot root has `expires_at` null and no bot reply names it.
- [ ] `this_reader(m, now, tmp_path)`: this reader's pull of the same mirror, in process, with the real timestamp passed explicitly (`pull.fetch(..., fetch=m.fetch, root_pubkey=m.root, now=now)`), because the tests' default reader clock is the year 2099 and a certificate dated today would read as expired there. It asserts `res.error is None` before anything is compared, then returns `shown()` at `now` and `now + 30 days`.
- [ ] `test_every_alert_still_appears...`, parametrized over the four tags: the pull exits 0 (on v0.1.6 and v0.1.7 a checked pull, no "unverified"); at both times the active ids are 0001 to 0004 on both readers; each released level ranks at or above this reader's; each matches; 0003 is critical with the fix on both; 0002 is critical with the fix.
- [ ] Controls: a lowering with a fix, and a raise with a fix after a lowering, each leave v0.1.4 without the fix; a bot root with `expires_at` a week out and a bot renewal reply is active now and gone thirty days on, on all four tags and this reader; a manifest with `min_cli` in its content is "bad manifest" on v0.1.4, v0.1.7 and this reader.
- [ ] Schema lock: `git show v0.1.4:spec/advisory.schema.json` equals the working tree's file byte for byte (a clone without the tag fails), and the field names of `Advisory`, `Product`, `Action`, `Source` equal the released tree's (read through `run.py`).
- [ ] `spec/wire.md`: the table of what released readers do with each place a new field could go; the claim tag; the three rules of the level-only reply and `expires_at`; where `min_cli` lives; and the rule for the next slice ("a new signed thing goes where the table says released readers ignore it; add it to the feed in tests/test_wire_compat.py first").
- [ ] `CHANGELOG.md` Unreleased: what was added; that readers at 0.1.7 and earlier keep the higher level after a bot lowering and never print the upgrade line; that nothing on the wire changes yet.

Verify: `python3 -m pytest -q tests/test_wire_compat.py` passes; then the gate.
Acceptance: success criteria 1 (schema lock), 3, 5 (changelog half) and 6.

## The gate

`scripts/test-gate.sh` is the public scan, then the whole suite. The scan reads every object reachable from every ref of the clone it runs in, and the working clone is shared with other sessions' local branches. If the scan fails on objects this branch does not reach (`scripts/public-scan.sh --hit-ids` against `git rev-list --objects HEAD`: no id in common), run the gate again in a fresh clone that holds only this branch and the tags, and record both results. A hit this branch reaches is fixed, never listed.

## After the chunks

- [ ] Post the correction on ai-tools-alerts#9mx8 and notes on ai-tools-alerts#wa6n, #q03f, #0xq6, #9kgk, #ny5g, #fv4g, #r0ra (criterion 5, the issue half).
- [ ] File `rollout: confirm the relay keeps an unknown event tag before the first claim is posted` and `rollout: sign a certificate with min_cli when a release must be required`, labelled `discovered-from:t8jr`, `repo:ai-tools-alerts`, priority 2.
- [ ] `git fetch origin`, merge `origin/main`, gate, one whole-branch independent review (`git diff origin/main...HEAD`), fix or rebut, push, pull request, merge with the no-reply author address, check `git log -1 --format=%ae origin/main`, close the issue on the merge commit.

## Rollback

Revert the merge commit. No stored state, event or signed document depends on the change: a certificate signed with `min_cli` is read by the reverted code as v0.1.7 reads it.
