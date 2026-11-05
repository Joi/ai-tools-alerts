# ai-tools-alerts

Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills.

Two channels on the henkaku ai-tools Buzz relay (`#security-feed` to browse, `#security-critical` to be interrupted), a signed public mirror, and a small CLI your agent can read so it verifies who posted an alert, checks what is installed, and prepares the fix.

## Status

The member CLI, the skills, the session-start hook and the schedule templates are in place; the fleet poster and the live mirror are still being built, so until the mirror at `https://buzz.ai-tools.md/alerts/` is up a pull reports "mirror unreadable". The design is `docs/design.md` and the implementation plan `docs/plan.md`. Work is tracked in the kata project `ai-tools-alerts`, one issue per plan task, under the epic jibot-code#gr5b.

Done: the pure-Python Nostr primitives (`aitools_alerts/nostr.py`: BIP-340 signatures, NIP-01 event ids, NIP-19 keys) and the trust root. The trust root's public key is `trust/root.pub`; it signs only the manifest that lists who may post alerts, and the CLI pins it as `TRUST_ROOT_PUBKEY`.

The two channels exist on `buzz.ai-tools.md`; their UUIDs are in `spec/channels.json`, and `ops/vm/README.md` says what this service keeps on the relay VM, including the `buzz-send` wrapper. Buzz cannot restrict who posts in an open channel, so `#security-critical` is open: only keys in the trust manifest are trusted by the CLI, and anyone may reply.

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

Without pipx: `python3 -m venv ~/.local/share/aitools-alerts && ~/.local/share/aitools-alerts/bin/pip install git+https://github.com/Joi/ai-tools-alerts`, then link the command where the schedules and the hook look for it: `mkdir -p ~/.local/bin && ln -s ~/.local/share/aitools-alerts/bin/aitools-alerts ~/.local/bin/`. The launchd and cron templates search `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin`.

`init` writes `~/.config/aitools-alerts/config.toml` (mode 600). Reading alerts needs no Buzz account; `aitools-alerts keygen` makes a key only if you want to post or discuss on the relay. The settings:

- `mirror_url`: where the signed mirror lives; leave the default.
- `notify`: where a critical alert goes, any of `desktop`, `imessage`, `signal`, `telegram`, `webhook` (the recipient keys are in the file, commented).
- `auto_apply`: verbs your agent may apply without asking, and only from a curator post that matches your machine exactly. Empty by default: everything asks first. `upgrade` is the only verb meant for this.

### Run it every hour

The templates, the hook and the skills below are files in this repository: `git clone https://github.com/Joi/ai-tools-alerts` and run the commands from the checkout.

macOS (launchd):

```
cp templates/launchd/com.aitools.alerts.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.aitools.alerts.plist
```

It runs `aitools-alerts run` at login and every hour, and logs to `~/Library/Logs/aitools-alerts.log`. Remove it with `launchctl bootout gui/$(id -u)/com.aitools.alerts`.

Linux or anything with cron:

```
(crontab -l 2>/dev/null; cat templates/cron/aitools-alerts.cron) | crontab -
```

### Interrupt the next Claude Code session

Copy `hooks/claude-code/session-start.sh` to `~/.claude/hooks/aitools-alerts-session-start.sh`, make it executable, and add it to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {"type": "command", "command": "~/.claude/hooks/aitools-alerts-session-start.sh", "timeout": 30}
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

Otherwise it prints nothing, and it never blocks a session: a missing CLI or an unreadable mirror is silent.

### Install the skill

- Claude Code: copy `skills/claude-code/aitools-alerts/` to `~/.claude/skills/aitools-alerts/`.
- Hermes: copy `skills/hermes/aitools-alerts/` to `~/.hermes/skills/security/aitools-alerts/`.
- Codex, or any agent that reads AGENTS.md: paste `snippets/AGENTS.md` into `~/.codex/AGENTS.md`.

## What an alert looks like

An example, not a real advisory. `aitools-alerts check` prints one line per advisory that matches this machine:

```
CRITICAL: <title> [Claude Code 2.1.318: affected] (id <advisory id>, thread <thread id>)
```

`aitools-alerts plan <thread>` prints what to do. For an upgrade it prints the command, built from a fixed template, never from the post:

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
- runs it without asking only if you put that verb in `auto_apply` and the alert came from a curator;
- runs `aitools-alerts check` again afterwards and tells you what still matches.

It will not:

- run anything `plan` did not print, including any text from a Buzz post or thread;
- auto-apply an alert posted by the relay bot;
- change your `auto_apply` setting, the mirror URL or the trust root;
- act on an alert from a key that is not in the signed trust manifest (the CLI drops those before the agent sees them).

Actions come from a fixed list: `upgrade`, `disable_skill`, `remove_mcp_server`, `rotate_credential`, `stop_using`, `review_setting`. Only `upgrade` comes with a command; the others are notify only: your agent tells you what the advisory recommends and you do it yourself.

## Tests

`scripts/test-gate.sh`.
