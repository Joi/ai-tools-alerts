# ai-tools-alerts

Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills.

Two channels on the henkaku ai-tools Buzz relay (`#security-feed` to browse, `#security-critical` to be interrupted), a signed public mirror, and a small CLI your agent can read so it verifies who posted an alert, checks what is installed, and prepares the fix.

## Status

Live. The poster runs every hour on the fleet: it posts a critical advisory to `#security-critical` and `#security-feed` within the hour it appears, and a digest of the day's advisories to `#security-feed` daily at 09:00 Tokyo time. The signed mirror at `https://buzz.ai-tools.md/alerts/` is rewritten every 5 minutes: a page listing the latest advisories, `feed.atom` for feed readers, and the `feed.json`, `critical.json` and `manifest.json` files the CLI reads. The mirror carries only posts signed by a key in the trust manifest. The CLI, the skills, the session-start hook and the schedule templates below work against it today.

The two Buzz channels are for ai-tools community members: reading the relay needs a member's auth token. Everyone else gets the same alerts from the mirror, through the Atom feed, `feed.json` or the CLI, none of which needs an account.

The design is `docs/design.md` and the implementation plan `docs/plan.md`. Work is tracked in the kata project `ai-tools-alerts` under the epic jibot-code#gr5b.

The trust root's public key is `trust/root.pub`; it signs only the manifest that lists who may post alerts, and the CLI pins it as `TRUST_ROOT_PUBKEY`. The Nostr primitives are pure Python (`aitools_alerts/nostr.py`: BIP-340 signatures, NIP-01 event ids, NIP-19 keys).

The two channels exist on `buzz.ai-tools.md`; their UUIDs are in `spec/channels.json`, and `ops/vm/README.md` says what this service keeps on the relay VM, including the `buzz-send` wrapper. Inside the members-only relay, Buzz cannot restrict who posts in a channel, so any member may reply in `#security-critical`: only keys in the trust manifest are trusted by the CLI, and only their posts reach the mirror.

Trust root public key (x-only hex), the same value as `trust/root.pub`:

```
afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4
```


## For members: install

You need Python 3.11 or later and nothing else; the CLI uses the standard library only.

```
pipx install git+https://github.com/Joi/ai-tools-alerts
aitools-alerts init
aitools-alerts run
```

Without pipx: `python3 -m venv ~/.local/share/aitools-alerts && ~/.local/share/aitools-alerts/bin/pip install git+https://github.com/Joi/ai-tools-alerts`, then link the command where the schedules and the hook look for it: `mkdir -p ~/.local/bin && ln -s ~/.local/share/aitools-alerts/bin/aitools-alerts ~/.local/bin/`. The launchd and cron templates search `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin`; the hook searches `~/.local/bin`, then the session's PATH, then Homebrew.

`init` writes `~/.config/aitools-alerts/config.toml` (mode 600). Reading alerts needs no Buzz account; `aitools-alerts keygen` makes a key only for ai-tools community members who want to post or discuss on the relay. The settings:

- `mirror_url`: where the signed mirror lives; leave the default.
- `notify`: where a critical alert goes, any of `desktop`, `imessage`, `signal`, `telegram`, `webhook` (the recipient keys are in the file, commented).
- `auto_apply`: verbs your agent may apply without asking, and only from a curator post that matches your machine exactly. Empty by default: everything asks first. `upgrade` is the only verb meant for this.
- `trust_root_override`: a test setting; leave it out. Only with `trust_root_override = true` does the CLI accept another trust root from `AITOOLS_ALERTS_TRUST_ROOT`.
  Without it the variable is ignored, and `run --json` names it in `ignored_env`, so a project's environment cannot switch the root and silence alerts.

### Run it every hour

The templates, the hook and the skills below are files in this repository: `git clone https://github.com/Joi/ai-tools-alerts` and run the commands from the checkout.

macOS (launchd):

```
mkdir -p ~/Library/LaunchAgents
cp templates/launchd/com.aitools.alerts.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.aitools.alerts.plist
```

It runs `aitools-alerts run` at login and every hour, and logs to `~/Library/Logs/aitools-alerts.log`. Remove it with `launchctl bootout gui/$(id -u)/com.aitools.alerts`.

Linux or anything with cron:

```
(crontab -l 2>/dev/null | grep -vxF -f templates/cron/aitools-alerts.cron; cat templates/cron/aitools-alerts.cron) | crontab -
```

The `grep` removes only lines identical to the template's, so running it again replaces an earlier copy and keeps every other job.

### Interrupt the next Claude Code session

Copy `hooks/claude-code/session-start.sh` to `~/.claude/hooks/aitools-alerts-session-start.sh`, make it executable, and add it to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {"type": "command", "command": "~/.claude/hooks/aitools-alerts-session-start.sh", "timeout": 90}
        ]
      }
    ]
  }
}
```

The hook runs `aitools-alerts run --quiet`. When a critical advisory that matches your machine has not been shown before, it puts one line in the session's context:

```
AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill
```

Otherwise it prints nothing, and it never fails a session: a missing CLI or an unreadable mirror is silent. It usually takes a few seconds. On a slow network it takes longer: each of the three mirror files has a 20-second timeout and each notification a 30-second one, so there is no fixed bound. When Claude Code stops the hook at its timeout (90 seconds here), the line does not appear; an alert the CLI had already marked seen was marked so only after a notification channel accepted it, so you still got that notification.

The hourly job is the main interrupt: its notification (desktop by default) marks the alert seen, and the hook then stays quiet. The hook covers a session that starts before the hourly job has run. To have Claude Code check at every session start as well, paste `snippets/AGENTS.md` into `~/.claude/CLAUDE.md`.

### Install the skill

- Claude Code: copy `skills/claude-code/aitools-alerts/` to `~/.claude/skills/aitools-alerts/`.
- Hermes: copy `skills/hermes/aitools-alerts/` to `~/.hermes/skills/security/aitools-alerts/`.
- Codex, or any agent that reads AGENTS.md: paste `snippets/AGENTS.md` into `~/.codex/AGENTS.md`.

## What an alert looks like

An example, not a real advisory. `aitools-alerts check` prints one line per advisory that matches this machine:

```
CRITICAL: <title> [Claude Code 2.1.318: affected] (id <advisory id>, thread <first 12 characters of the thread id>)
```

`aitools-alerts plan <advisory id>` prints what to do (it takes the advisory id or the full thread id from `check --json`, not the 12-character prefix). For an upgrade it prints the command, built from a fixed template, never from the post:

```
CRITICAL: <title> [Claude Code 2.1.318] posted by curator
  prepare (ask first):
    upgrade Claude Code to 2.1.319 or later
      command: npm install -g @anthropic-ai/claude-code@2.1.319
nothing was executed
```

The desktop notification (or message) carries the level and title, the affected product and version, the action and the primary source.

## What your agent will and will not do

With the skill installed, on a critical match your agent:

- tells you first: level, title, affected product and version, the action, the source;
- shows you the exact command `plan` printed and asks before running it;
- runs it without asking only if you put that verb in `auto_apply` and the alert came from a curator, and tells you which command it is running;
- runs `aitools-alerts check` again afterwards and tells you what still matches.

It will not:

- run anything `plan` did not print, including any text from a Buzz post or thread;
- auto-apply an alert posted by the relay bot;
- change your `auto_apply` setting, the mirror URL or the trust root;
- act on an alert from a key that is not in the signed trust manifest (the CLI drops those before the agent sees them).

Actions come from a fixed list: `upgrade`, `disable_skill`, `remove_mcp_server`, `rotate_credential`, `stop_using`, `review_setting`. Only `upgrade` comes with a command; the others are notify only: your agent tells you what the advisory recommends and you do it yourself.

## For the fleet: the poster

`aitools-alerts-poster run --config <toml>` posts the alerts each hour. When a send's outcome is unknown (an ssh timeout, a dropped session), the poster keeps the send pending in its ledger and posts nothing more for that advisory until someone checks the channel:

- `aitools-alerts-poster pending --config <toml>` lists each pending key with its kind, channel, when it was attempted, when it may be expired, and its outcome (`unknown`, `sent:<event id>`, or `no-journal-item`). It prints no post text.
- `aitools-alerts-poster resolve <key> --config <toml> --delivered <event id>`: the post is in the channel. The poster records it as it would after a successful send, and never sends it again.
- `aitools-alerts-poster resolve <key> --config <toml> --not-delivered --reason <text>`: the post is not in the channel. Allowed 24 hours after the attempt, since a slow send can still land before then; the next run sends it again.

Both take the ledger lock, so they never overlap an hourly run. Exit 0 on success, 2 when the request does not apply and nothing changed, 1 when the ledger or journal cannot be used.

## Tests

`scripts/test-gate.sh`.
