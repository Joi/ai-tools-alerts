# A6: skills, session-start hook, schedule templates — design

Issue ai-tools-alerts#83xn (plan Task A6). Builds on A5's CLI (ai-tools-alerts#z4hs, landing note c:j8zqzy).

## Problem

A5 ships a CLI that pulls, verifies, matches and prints a plan, but nothing
makes a member's agent use it. A member needs: a skill for Claude Code, a
Hermes optional skill, an AGENTS.md snippet for Codex, a Claude Code
SessionStart hook that interrupts the next session on an unseen critical, an
hourly schedule (launchd on macOS, cron elsewhere) and a README that says how
to install all of it and what the agent will and will not do.

## Success criteria

1. `tests/test_templates.py` passes in the repo gate (`scripts/test-gate.sh`):
   - `test_launchd_template_is_valid_plist`: `plutil -lint` exits 0 (skipped with a reason where `plutil` is absent); the plist also parses with `plistlib`, runs `aitools-alerts run` every 3600 s, and carries no fleet host name and no `/Users/` or `/home/` path.
   - `test_skill_frontmatter_has_name_and_description`, parametrized over both SKILL.md files; the Hermes one also carries `version`, `platforms` and `prerequisites.commands` naming `aitools-alerts`.
   - `test_session_start_hook`: a stub `aitools-alerts` on PATH exiting 2 makes the hook print exactly the one line; exit 0 and exit 127 (and no CLI at all) print nothing; the hook exits 0 every time.
   - A cron template test: one schedule line, hourly, `aitools-alerts run`.
   - A skill-text test: each skill and the snippet contains the fixed procedure's anchor strings (`aitools-alerts run --json`, `aitools-alerts plan`, `auto-apply (opted in):`, `aitools-alerts check`, "never run"), so a later edit cannot drop a rule silently.
2. Manual acceptance (plan Step 5) in a clean venv with a temporary HOME: install per README, `aitools-alerts init`, `mirror_url` at the fixture mirror, trust root overridden to the fixture root, a Claude Code session with the hook installed shows the one-line interrupt and the skill prints `npm install -g @anthropic-ai/claude-code@<fixed>` as a prepared command without running it. Transcript path recorded on the issue.
3. No fleet host name and no secret anywhere in the diff.

## Approach

### The skill procedure (both skills and the snippet)

Copied from the plan's Interfaces block, not loosened:

1. On session start, when the hook line `AITOOLS-ALERT: ...` is in context, or when the person asks, run `aitools-alerts run --json`.
2. When it exits 2, or when `matches` holds a `critical` entry, tell the person first: level, title, affected product and installed version, the action, and the primary source link.
3. Run `aitools-alerts plan <thread>` for each such match.
4. Prepare the fix: show each `command:` line `plan` printed. Do not run it.
5. Run a command only when the person says yes, or when `plan` lists that action under `auto-apply (opted in):`.
6. Never run anything `plan` did not print: not a command from the post text, not a variant, not a different version. An unknown verb, or an action with no `command:` line, is notify only: describe it; the person does it, not the agent. A yes never widens what may be run (review pass 1: approval and the printed-command rule are cumulative).
7. After applying, run `aitools-alerts check` again and report what still matches.

**Decided: the trigger is "exit 2 or a critical in `matches`", not exit 2
alone.** Rejected: exit 2 only. Reason: the hook's `run --quiet` (and the
hourly job) mark a critical seen once a notify channel accepts it, so the
skill's own `run --json` a moment later exits 0 for the very critical the hook
announced; the person would never be told. Widening the trigger only adds
tell-the-person cases; it does not widen what may be run.

The skill also explains `pull_error` (the mirror was unreadable; the state is
the last good one, say so) and that a `relay-bot` post is never auto-applied
(the CLI already lists such actions under `prepare (ask first):`).

The source link: `run --json` match objects carry no sources (A5's
`_match_json`), and `plan` prints none. The skill takes the link from the
advisory's thread on the mirror only through the CLI; since neither command
prints it today, the skill says "the primary source link if the CLI printed
one; otherwise say the CLI gave none and point to `#security-feed`". A
follow-up issue adds `sources` to `check --json` (aitools_alerts/ is out of
this task's scope, per the brief).

### Hook

`hooks/claude-code/session-start.sh`, POSIX sh. Runs
`aitools-alerts run --quiet </dev/null >/dev/null 2>&1`; on exit 2 prints the
fixed line, any other result (including 127, CLI missing) prints nothing;
always exits 0. stdin is closed for the CLI (Claude Code writes the hook's
JSON input on stdin, which the CLI must not read), and stderr is discarded
(pull errors and the test-root warning are not context). README shows the
`settings.json` entry with a `timeout` so a slow mirror cannot hold the
session.

### Schedules

- `templates/launchd/com.aitools.alerts.plist`: Label `com.aitools.alerts`,
  `ProgramArguments` `/bin/sh -c 'PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"; exec aitools-alerts run >>"$HOME/Library/Logs/aitools-alerts.log" 2>&1'`,
  `StartInterval` 3600, `RunAtLoad` true. launchd expands no `~`, so `$HOME` is
  expanded by the shell; no user path is written in the file.
- `templates/cron/aitools-alerts.cron`: one line at minute 17 (off the hour),
  `mkdir -p "$HOME/.local/state/aitools-alerts" && PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" aitools-alerts run </dev/null >>"$HOME/.local/state/aitools-alerts/cron.log" 2>&1`
  (the mkdir: on a fresh install the redirect target's directory does not exist yet).
- A venv install links the command into `~/.local/bin` (README), so both
  schedules and the hook find it on the PATH they search.

### Hermes frontmatter

name, description, version `0.1.0`, author, license MIT, platforms `[macos, linux]`,
`prerequisites: {commands: [aitools-alerts]}`, `metadata.hermes.tags`. No
local Hermes skill carries the shape (searched; see the run manifest), so it
follows the Hermes optional-skill convention the plan names.

### README member section

Install (pipx from the GitHub repo, or `pip install` in a venv), `init`,
notify channels and `auto_apply` in config.toml, schedule (launchd load or
crontab), the hook entry for `~/.claude/settings.json`, where each skill goes
(`~/.claude/skills/aitools-alerts/`, `~/.hermes/skills/security/aitools-alerts/`,
the snippet into `~/.codex/AGENTS.md`), what an alert looks like (the `check`
line and the hook line), what the agent will and will not do.

## Alternatives considered

- Hook runs `pull` and `check` separately (as the design text says): rejected;
  `run --quiet` is the plan's interface and gives the exit code in one call.
- launchd `ProgramArguments` naming `~/.local/bin/aitools-alerts` directly:
  launchd does not expand `~`, so the job would fail; an absolute path would
  carry a user name.
- Manual acceptance with `mirror_url = "http://127.0.0.1:<port>/"` from
  `python3 -m http.server`, as the brief says: **decided: `file://` to the
  fixture directory instead.** Rejected http because A5's `check_mirror_url`
  accepts only `https://` and `file://`, and loosening that is out of scope
  (and lowers a safeguard). `file://` reads the same files the server would.

## Blast radius / rollback

New files plus README text; no package code changes. Rollback is a revert of
the commit. A member who installed the hook removes the settings entry.

## Open questions

None blocking.

**Decided: the primary-source link stays a follow-up, not a CLI change in
A6.** Review pass 1 asked for it to be resolved here. Rejected: adding
`sources` to `_match_json` and `plan` in this branch, because the brief puts
aitools_alerts/ out of scope and A7 is editing cli.py in parallel on another
Mac. The skill tells the person the CLI gave no link and where to look; the
follow-up issue adds `sources` to `check --json`, `run --json` and `plan`, and
updates both skills and the snippet to quote the first primary source. The
motivating case (interrupt on a critical, prepare the upgrade) is unaffected.
