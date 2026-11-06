# Home from the password database, bounded hook PATH (ai-tools-alerts#fsmb)

## Problem

Claude Code applies a project's `.claude/settings.json` `env` block to the
session, and the SessionStart hook inherits that environment. Today:

- `aitools_alerts/config.py` builds the config, key and state paths from
  `Path.home()`, which reads `HOME`. A project that sets `HOME` into its
  checkout supplies its own `config.toml` (with `trust_root_override = true`,
  which 8et2 made the gate on `AITOOLS_ALERTS_TRUST_ROOT`; or broken, so the
  CLI exits 1 and the hook prints nothing) and its own `state/`, where
  every alert can already read as seen.
- `inventory.collect` reads skills and MCP config from `Path.home()`, so the
  same `HOME` hides installed skills and servers from matching.
- `hooks/claude-code/session-start.sh` sets
  `PATH="$HOME/.local/bin:$PATH:/opt/homebrew/bin:/usr/local/bin"`: the
  project chooses `HOME` (so `~/.local/bin`) and `PATH`, so it chooses which
  `aitools-alerts` binary runs, and which `claude`, `node`, ... the
  inventory probes see.

## Success criteria

1. `config.config_dir()`, `config.key_path()`, `config.state_dir()`, the
   default `telegram_token_file`, a `~`-relative `telegram_token_file`, and
   `inventory.collect()`'s default home all come from the password database
   entry of the real uid (`pwd.getpwuid(os.getuid()).pw_dir`), not `HOME`.
   A CLI test sets `HOME` elsewhere and shows the paths unchanged.
2. The hook sets `HOME` from the password database and runs the CLI with
   exactly `PATH=$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`
   (the launchd template's PATH), the session's `PATH` not appended. A hook
   test points `HOME` and `PATH` into a temp project holding a stub
   `aitools-alerts`; the stub does not run.
3. README and the hook header state the rule. Under 200 changed lines
   (code, tests, README; run artifacts excluded).
4. The full test suite passes (`scripts/test-gate.sh`).

## Approach

**CLI.** One function, `config.home() -> Path`:
`Path(pwd.getpwuid(os.getuid()).pw_dir)`; on `KeyError` (no passwd entry,
as in some containers) or an empty `pw_dir`, fall back to `Path.home()`.
`config_dir`, `state_dir` use it; `_token_default` follows through
`config_dir`; a configured `telegram_token_file` starting with `~/` (or
equal to `~`) is expanded against `home()` instead of `os.path.expanduser`
(`~user/` forms keep `expanduser`, which reads the password database
already). `inventory.collect` defaults `home` to `config.home()`;
`inventory` cannot import `config` without a cycle check — `config` imports
`check`, not `inventory`, so the import is safe.

Tests: the `home` fixture in `tests/conftest.py` already sets `HOME`; it
also monkeypatches `config.home` to return the temp home, so every existing
test keeps its isolation. New tests call the real resolver with `HOME`
pointed at a temp dir and assert the paths equal the passwd home's.

**Hook.** Before anything else:

```sh
u=$(/usr/bin/id -un 2>/dev/null) || exit 0
case $u in ''|-*|*[!A-Za-z0-9._-]*) exit 0 ;; esac
eval "HOME=~$u"
case $HOME in /*) ;; *) exit 0 ;; esac
export HOME
PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
```

`id` by absolute path (the session `PATH` is untrusted); the username is
checked against a portable-name pattern before `eval`, so `eval` sees only
`HOME=~name`; tilde expansion of `~name` reads the password database in
every POSIX `sh`. An unresolvable user, or an expansion that is not an
absolute path (an unknown user leaves `~name` literal), exits 0 silently —
the hook's contract is to never fail a session. The CLI receives the
resolved `HOME`, and resolves it again itself, so either alone suffices.

Tests: the hook's home block is delimited by marker comments. The existing
behaviour tests (exit codes, silence, stdin) run a copy of the hook with
that block replaced by `HOME=<tmp home>`, the stub in `<tmp home>/.local/bin`.
The new tests run the real hook: (a) `HOME` and `PATH` into a temp project,
each holding a stub that writes a marker; no marker appears and stdout is
empty unless a real CLI is installed for the user (skipped then); (b) the
block alone, run under `sh` with `HOME` set to a temp dir, prints the
passwd home.

## Alternatives considered

- **Session PATH appended after the fixed dirs** (the issue's "ahead of"):
  rejected; when the CLI is not in a fixed dir, the project's binary runs,
  and the CLI's own probes (`claude --version`) would find a project stub
  that reports a patched version, silencing a match. The bounded PATH is the
  launchd job's PATH, so the hook sees what the hourly job sees.
- **Honour `HOME` in the CLI and fix only the hook:** rejected; the CLI is
  also run by the skill inside the session, which inherits the same env.
- **An env var to override the home for tests:** rejected; it is the same
  hole under another name. Tests monkeypatch in-process and rewrite the hook
  copy instead.
- **`getent passwd` / `dscl` in the hook:** not portable across macOS and
  Linux; `~name` is.

## Blast radius / rollback

Member CLI and hook only; the poster (its own paths, runs on a VM) is not
touched. A user whose `HOME` intentionally differs from their passwd home
(rare) now gets config and state under the passwd home: README says so.
Inventory probes in the hook lose binaries outside the bounded dirs (an
nvm-only `node`, an npm prefix elsewhere); the hourly launchd job already
had that limit. Rollback: revert the commit; the coordinator reinstalls.

## Assumes

- Threat: a project's `env` block (HOME, PATH, other variables). A project
  that can write the user's real home or `/opt/homebrew/bin` is out of scope.
- `id` lives at `/usr/bin/id` on macOS and Linux.

## Amendments after the spec review (fresheyes gpt-6-astra, snapshot bbbd991)

- No HOME fallback: with no passwd entry or a non-absolute `pw_dir`,
  `config.home()` raises `ConfigError` (CLI exit 1); tests cover both.
- The hook runs the CLI under `/usr/bin/env -i` with only HOME, PATH, USER
  and LOGNAME, so PYTHONPATH, PYTHONHOME, NODE_OPTIONS, the trust-root
  variable and the rest of a project's env block never reach the CLI or its
  probes. The real-hook test sets PYTHONPATH and the trust-root variable and
  checks the CLI's environment holds only those names (plus what sh adds).
- All-digit user names exit 0 before `eval` (bash reads `~0` as the
  directory stack).
- README registers the hook by absolute path: a `~` in the hook command
  expands against the session's HOME.
- Tests: an autouse fixture in tests/conftest.py resolves `config.home`
  from HOME for every test (two mirror tests set HOME by hand); resolver
  tests live in tests/test_home.py, which restores the real resolver; the
  real-hook test swaps only the CLI call for a probe, so an installed CLI
  never runs from the suite.
- Not addressed (rebutted): LD_PRELOAD / DYLD_* set by the project reach
  `/bin/sh` before the hook's first line; the hook cannot defend against
  them, and they reach every process Claude Code starts. The skill running
  the CLI inside the session inherits the session's env; HOME no longer
  redirects it, and the hook is the unattended path this issue covers.

## Open questions

None.
