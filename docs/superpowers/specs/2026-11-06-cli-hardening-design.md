# Spec: CLI hardening: trust-root override behind a config flag; fixed pull_error strings (ai-tools-alerts#8et2)

## Problem

From the independent security read of the public repo (2026-11-06), parent
epic jibot-code#gr5b.

(a) `aitools_alerts/cli.py` `_root()` accepts `AITOOLS_ALERTS_TRUST_ROOT`
with only a stderr warning. The Claude Code SessionStart hook
(`hooks/claude-code/session-start.sh`) discards the CLI's stderr. A cloned
project's `.claude/settings.json` can set environment variables for the
session, so a hostile project can point the CLI at another trust root. The
CLI then refuses the stored state ("pulled under another trust root",
`_matches`), and the pull against the pinned mirror fails the signature
check: alerts are silently suppressed. An invalid value is worse: `_root()`
raises SystemExit, so the hook exits early and also says nothing.

(b) `pull._fetch` puts exception text into `PullResult.error`
(`mirror unreadable: {name}: {e}`, `manifest unreadable: {e}`,
`manifest refused: {e}`). `default_fetch` turns a urllib error into
`OSError(str(e.reason))`, which for an HTTP error is the server's reason
phrase; a `ManifestError` can quote a key from the served manifest. `run
--json` reports this as `pull_error`, and the skill tells the agent to relay
it: server-controlled text reaches the agent.

## Success criteria

1. `config.Settings` has `trust_root_override: bool = False`; `config.load`
   reads `trust_root_override` from config.toml and refuses a non-boolean
   value with a ConfigError naming the key.
2. With `AITOOLS_ALERTS_TRUST_ROOT` set and `trust_root_override` absent or
   false, every command except `init`/`keygen` uses the pinned
   `TRUST_ROOT_PUBKEY`, whatever the variable holds (a non-hex value is
   ignored too, never a SystemExit). stderr says the variable was ignored.
   `run --json` carries `"ignored_env": ["AITOOLS_ALERTS_TRUST_ROOT"]`.
3. With `trust_root_override = true`, behaviour is today's: a 64-hex value
   is used with the stderr warning; a malformed value exits with the existing
   message. `run --json` carries `"ignored_env": []`; so does every run with
   the variable unset.
4. `PullResult.error` (and `last_pull.error`, and so `pull_error`) is `None`
   or one of a fixed set: `http <status>` (three digits), `timeout`,
   `unreachable`, `too large`, `bad manifest`, `bad event file`,
   `manifest not signed by the trust root`,
   `state limit reached: new events not stored`. No exception or server text
   is ever part of it. `pull.PULL_ERRORS` lists the fixed strings.
5. Tests: `tests/test_cli.py` covers criteria 2 and 3 (pinned root used,
   bad hex ignored, `ignored_env` in `run --json`, override honoured with
   the flag); `tests/test_pull.py` covers criterion 4 for an HTTP error with
   a hostile reason phrase, a timeout, an unreachable host, an oversized
   body, a manifest whose error would quote served text, and a bad event
   file.
6. README: two lines documenting `trust_root_override` as a test setting.
   Both SKILL.md files name `ignored_env`. Under 150 changed lines of code
   and tests (run artifacts excluded).

## Approach

(a) `main` loads the config before choosing the root, for every command
except `init`/`keygen` (curator now loads it too; a broken config.toml
fails curator with the usual ConfigError, exit 1). `_root(s)` returns
`(root, ignored)`: the variable is read only when `s.trust_root_override`;
otherwise it is not validated, stderr names it, and `ignored` is
`[TRUST_ROOT_ENV]`. `a.ignored_env` carries it to `cmd_run`.
`check --json` stays a list (its contract); only `run --json`, the one
object the skill reads, gains the key.

(b) `default_fetch` raises `FetchError(OSError)` with a fixed `kind`:
`urllib.error.HTTPError` → `http <code>`; a timeout (`TimeoutError` /
`socket.timeout`, directly or as a URLError reason) → `timeout`; any other
URLError, refused scheme, refused redirect or malformed URL →
`unreachable`; a body over the limit → `too large`. `_fetch` maps: a
fetch failure → its kind (`FetchError.kind`; another `TimeoutError` →
`timeout`; any other exception from `get` → `unreachable`); a
`ManifestError` or an `issued_at` older than the floor → `bad manifest`; a
`ValueError` from an event file → `bad event file`. The two existing fixed
strings stay.

## Alternatives considered

- Drop the env override entirely and have tests monkeypatch
  `TRUST_ROOT_PUBKEY`: rejected; the fixture mirror README and the
  acceptance scripts run the installed CLI against a fixture root, which
  needs a runtime switch. The issue specifies the config flag.
- Keep detail after the fixed string (`http 404: Not Found`): rejected;
  the detail is the attacker-controlled part.
- Add `ignored_env` to `check --json`: rejected; it prints a list that the
  skill and tests rely on.

## Blast radius / rollback

`cli.py`, `config.py`, `pull.py`, two test files, README, two SKILL.md.
A member whose config lacks the flag and who set the variable deliberately
now gets the pinned root: that is the intent. Error strings in stderr and
`last_pull` get shorter. Rollback: revert the commit.

## Assumes

- The threat is a project-level environment block; a project that can
  change config.toml in the member's home is out of scope.
- Other variables a hostile project could set for the hook (HOME, PATH)
  are out of scope for this issue.
