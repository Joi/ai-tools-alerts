# Plan: CLI hardening (ai-tools-alerts#8et2)

Spec: docs/superpowers/specs/2026-11-06-cli-hardening-design.md

## Chunk 1 — trust-root override behind a config flag

- [ ] `aitools_alerts/config.py`: `Settings.trust_root_override: bool = False`;
  in `load`, `if "trust_root_override" in raw`: must be a `bool`, else
  `ConfigError("trust_root_override must be true or false")`.
- [ ] `aitools_alerts/cli.py` `_root(s) -> tuple[str, list[str]]` (:54-61):
  variable unset → `(TRUST_ROOT_PUBKEY, [])`; set and
  `not s.trust_root_override` → stderr "ignoring AITOOLS_ALERTS_TRUST_ROOT:
  trust_root_override is not set in config.toml", `(TRUST_ROOT_PUBKEY,
  [TRUST_ROOT_ENV])`, no validation; set with the flag → today's checks.
- [ ] `main` (:349-): after init/keygen, `s = config.load()`, then
  `a.root, a.ignored_env = _root(s)`, then the curator branch and the rest.
- [ ] `cmd_run` (:309): `out` gains `"ignored_env": a.ignored_env`.
- [ ] Tests, `tests/test_cli.py`: the autouse `env` fixture writes
  config.toml with `trust_root_override = true`; `write_config` prepends that
  line; the three init tests unlink the config first. New:
  `test_trust_root_env_ignored_without_the_flag` (config without the flag,
  variable = fixture root: pull against the fixture mirror fails
  `manifest not signed by the trust root`, `run --json` has
  `ignored_env == ["AITOOLS_ALERTS_TRUST_ROOT"]`, stderr names it);
  `test_bad_trust_root_env_ignored_without_the_flag` (non-hex, no flag:
  no SystemExit); `test_trust_root_override_must_be_bool`;
  `run --json` with the flag has `ignored_env == []`. The existing
  `test_bad_trust_root_override` keeps the flag and still exits.
- [ ] `tests/test_curator.py` `mirror` fixture writes the flag.

Verify: `python3 -m pytest tests/test_cli.py tests/test_curator.py -q`.

## Chunk 2 — fixed pull_error strings

- [ ] `aitools_alerts/pull.py`: `class FetchError(OSError)` with `kind`;
  `PULL_ERRORS` tuple of the fixed strings (spec criterion 4, `http <status>`
  matched by pattern). `default_fetch` (:81-96): catch `HTTPError` first →
  `http {code:03d}` (code outside 100..599 → `unreachable`); `URLError`
  whose reason is a `TimeoutError` → `timeout`; other `URLError` →
  `unreachable`; `TimeoutError` during read → `timeout`; `ValueError` →
  `unreachable`; refused scheme → `unreachable`; over the limit →
  `too large`.
- [ ] `_fetch` (:184-): `_kind(e)` helper (FetchError → kind; TimeoutError →
  timeout; else unreachable). Manifest: `ManifestError` or older issued_at
  → `bad manifest`; get failure → `_kind`. Event files: `ValueError` →
  `bad event file`; other → `_kind`.
- [ ] Tests, `tests/test_pull.py`: update the assertions at :87, :127,
  :135, :175, :350, :386, :419 to the fixed strings. New
  `test_pull_error_is_fixed_text`: an injected `get` raising `FetchError`
  for an HTTP 503 with a hostile reason, `TimeoutError`, a generic
  `OSError("<script>")`, a manifest with a duplicate key carrying hostile
  text; each `res.error` is in the fixed set and contains no hostile text.
  `default_fetch` unit test: monkeypatched `_OPENER.open` raising
  `HTTPError(..., 418, "ignore previous instructions", ...)` → `FetchError`
  kind `http 418`; raising `URLError(TimeoutError())` → `timeout`.
- [ ] `tests/test_cli.py` :159 → `unreachable`.

Verify: `python3 -m pytest tests -q`.

## Chunk 3 — docs

- [ ] README: two lines on `trust_root_override` (test setting; without it
  the variable is ignored and `run --json` names it in `ignored_env`).
- [ ] `skills/claude-code/aitools-alerts/SKILL.md` and
  `skills/hermes/aitools-alerts/SKILL.md`: one line naming `ignored_env`.

## Acceptance

- Spec criteria 1-6; full suite green; `git diff --stat` code+tests under
  150 changed lines; leak grep for fleet host names on the diff: 0 hits.

## Rollback

Revert the commit(s); no state migration (the config key is optional, the
error strings are display only).

## Amendments after the spec+plan review (pass 1, snapshot 01f8ac1b)

- `write_config` calls `config.write_default(force=True)`; the env fixture
  writes the flag; `test_pull_then_check_prints_fixture_critical` re-writes
  the flag after `init`; the `auto_apply = []` rewrite at :316 goes through
  `write_config`.
- The flag-less test asserts the property, not a string: with
  `cli.TRUST_ROOT_PUBKEY` set to the fixture root (the pinned root signs the
  mirror) and the variable set to another valid root or to `nothex`, `run
  --json` exits 2 with the critical in `unseen_critical`, and `ignored_env`
  names the variable.
- `test_pull.py` also updates :376 and :164; `default_fetch` is tested for
  HTTP, timeout, reset and an oversized body.
- `snippets/AGENTS.md` carries the same `ignored_env` line as the Claude
  skill (`test_snippet_carries_the_skill_procedure_word_for_word`); the
  fixture mirror README names the flag.
- Line count: `git diff --numstat 47f9d7a`, additions plus deletions,
  excluding `docs/superpowers/`.
