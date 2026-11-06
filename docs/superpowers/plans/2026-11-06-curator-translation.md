# Curator translation — plan

Spec: docs/superpowers/specs/2026-11-06-curator-translation-design.md
Kata: ai-tools-alerts#bq8v. Budget: under 400 changed lines in code, tests,
README and design.md (run artifacts excluded, as earlier runs counted).

## Chunk 1 — translate.py (new file, ~150 lines)

- [ ] `aitools_alerts/poster/translate.py`: constants (`MODEL`, `TIMEOUT`,
  `DAILY_CALLS`, `API_URL`, `MARK`, `KEY_NAME = "ANTHROPIC_API_KEY"`),
  `SYSTEM`, `AuthError`, `CallError`, `tokens`, `translate`, `read_key`,
  `api_call` exactly as the spec's "translate.py" section.
- [ ] `read_key` copies sign-manifest.py's `read_root_secret` safeguards
  (root refusal, 0o500 cache dir, write probe, `_DROP_ENV`, old key removed,
  empty-after check, `shutil.rmtree` in `finally`); no `_die`: every failure
  is `CallError` with a fixed message.
- [ ] `api_call` uses `urllib.request.Request(..., method="POST")` through
  an opener that refuses every redirect (`_NoRedirect`), inside
  `translate.bounded(…, TIMEOUT)`; reads at most 1 MiB; HTTP protocol
  errors are `CallError("unreachable")`; never puts the key or the body in an
  exception. `opener=` is injectable for tests.

Tests `tests/poster/test_translate.py` (fake `call`, no network):
- [ ] success: tokens kept → translation returned.
- [ ] mismatch: a URL, a version and a CVE id each dropped or altered → None.
- [ ] `tokens` finds URL (trailing period stripped), CVE, GHSA, `USN-1234-1`,
  `1.2.3`, `v2.0.1-rc1`.
- [ ] `api_call`: 401 and 403 → AuthError; 500 → CallError; refusal
  stop_reason → `""` (untranslated, never retried); request body has no
  `temperature`, model and headers as spec (fake opener).
- [ ] `read_key` with a fake runner: returns the one line; the runner's env
  has `SECRETS_CACHE_DIR`, no old key, the key never in argv; a non-zero
  exit → CallError without output in its message.

Verify: `python3 -m pytest tests/poster/test_translate.py -q`.

## Chunk 2 — poster wiring (~150 lines)

- [ ] `poster/inputs.py` Config: `translate_curator: bool = False`,
  `translate_mirror_url: str = config.DEFAULT_MIRROR_URL`, `secrets_helper:
  Path | None = None`; `load_config` type checks (bool; mirror via
  `config.check_mirror_url`; helper absolute path); `translate_curator`
  without `secrets_helper` → ConfigError. Properties `translate_state`
  (`<ledger>.translate.json`) and `mirror_dir` (`<ledger>.mirror`).
- [ ] `poster/main.py`:
  - `_journal_ja(key, scope, channel, text, target)` split out of
    `_queue_ja` (the backlog bound and the append); `_queue_ja` calls it.
  - `Run.translate_curator(fetch=None, call=None, read_key=translate.read_key)`
    per spec steps 1–6; `_load_tr`/`_save_tr` for the translate file
    (malformed → `translate=state-error`, nothing written).
  - `run()` calls it after `r.save()` and before `r.drain_ja()`, only when
    `english_ok`, inside `try/except Exception` (counted, never the exit
    code). `run()` gains `mirror_fetch=None, translate_call=None` for tests.
  - SUMMARY gains `untranslated`, `translate_failed`, then
    `translate=<status>`, all before `inputs=`, which stays last.
  - `translate-clear-hold` subcommand under the ledger lock.
- [ ] `pull.py` threads_from: the discussion gate passes `lang:` replies
  (`if role != "curator" and t[3] and not first.startswith("lang:")`, with
  `first` computed before the gate).

Tests `tests/poster/test_curator_translation.py` (a fake mirror built from
signed events with test keys and a test manifest, as tests/test_pull.py does;
fake `call`; fake `read_key`):
- [ ] config off: no fetch, no call, no ja item, `translate=off`.
- [ ] success: curator root → one ja item to the root, text `lang: ja`,
  blank, translation, MARK; amendment → `of: <amendment id>`; a second run
  makes no call (cache).
- [ ] mismatch skip: `untranslated=1`, no ja item, cached, not retried.
- [ ] auth hold: fake call raises AuthError → `translate=held`, later runs
  make no call and read no key; `translate-clear-hold` clears it.
- [ ] budget: 21 curator events → 20 calls the first day, the 21st the next
  UTC day.
- [ ] relay-bot events and retractions are never translated.
- [ ] an exception in the pass leaves the exit code 0 and the English post
  sent.
- [ ] `tests/test_pull.py`: a relay-bot `lang:` reply on a curator thread is
  the thread's translation; a curator's still wins; a relay-bot patch on a
  curator thread stays discussion (existing test unchanged).

- [ ] Review fixes (spec pass 1): no redirects (`_NoRedirect` opener),
  `translate.bounded` wall-clock deadlines (call 30 s, mirror 120 s, pass
  300 s), whole-version tokens, refusal → `""`, `MAX_TRIES` 3, the journal
  key reconciled before a call, `done` pruned to mirror ids, amendment source
  plus the whole amended advisory, `check_paths` covers the new files.
  Tests: retry cap, reconcile, redirect handler, path collision, amendment
  that changes only `fixed`.
- [ ] Update the tests the change contradicts: test_main.py summary
  assertions (translate= goes before inputs=, so `endswith(inputs=…)` holds),
  test_pull.py `test_relay_bot_cannot_translate_a_curator_thread` → the bot
  translation counts and a bot patch stays discussion,
  tests/mirror/test_export.py `test_ja_atom_translation_rules_match_the_cli`.
  Also `test_digest_id_recorded_and_printed`, which fails on origin/main when
  its preset ids collide with FakeSSH's shared counter: preset ids moved to
  `1 << 252`.

Verify: `scripts/test-gate.sh` (public scan, then the suite) — the repo gate.

## Chunk 3 — docs (~20 lines)

- [ ] README: one paragraph after the rd8t paragraph (what is translated,
  the mark, the check, the budget, the hold and how to clear it, off by
  default, the config keys).
- [ ] docs/design.md "Post format" translations paragraph: one sentence on
  the curator machine translation and the reader rule change.
- [ ] Config template if the repo ships one for the poster (check
  `templates/`): commented `translate_curator`, `secrets_helper`.

## Acceptance

Spec S1–S11; `scripts/test-gate.sh` green; size counted as added lines in
aitools_alerts/, tests/, README.md and docs/design.md (run artifacts
excluded, as earlier runs on this repo counted), target under 400, reported
with a `decided:` comment if review fixes push it over; the fleet host-name
grep from the brief over added lines in aitools_alerts/, tests/ and README.md
empty (the plan and brief that name the pattern are excluded).

## Rollback

To stop translating: `translate_curator = false`. To downgrade, in this
order: remove `translate_curator`, `translate_mirror_url` and
`secrets_helper` from the deployed config (the old `load_config` refuses
unknown keys and would stop all posting), then reinstall the old version.
`<ledger>.translate.json` and `<ledger>.mirror/` may then be deleted. In the
repo: revert the branch commits.
