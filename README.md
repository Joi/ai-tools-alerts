# ai-tools-alerts

Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills.

Two channels on the henkaku ai-tools Buzz relay (`#security-feed` to browse, `#security-critical` to be interrupted), a signed public mirror, and a small CLI your agent can read so it verifies who posted an alert, checks what is installed, and prepares the fix.

## Who this is for

Two audiences get the same alerts.

- **Members of the henkaku ai-tools community** read and discuss them on the Buzz relay at `buzz.ai-tools.md`: `#security-feed` carries every advisory and the daily digest, with discussion under each thread, and `#security-critical` carries critical advisories only, for interruption. The relay is members-only: reading it needs a member's auth token, and membership is handled in the community, not in this repository.
- **Everyone else** gets the same posts from the public mirror at `https://buzz.ai-tools.md/alerts/`, with no account: `feed.atom` (Japanese: `feed.ja.atom`) for a feed reader, `feed.json` for anything that reads signed events, and the CLI below, which verifies every post and checks it against what is installed on your machine. The mirror carries only the posts signed by keys in the trust manifest; members' discussion stays on the relay.

The CLI is the product for your agent and needs nothing else. The Buzz channels are where people talk about an alert, and where a member hears about a critical one at once instead of at the next hourly run.

## Status

Live. The poster runs every hour on the fleet: it posts a critical advisory to `#security-critical` and `#security-feed` within the hour it appears, and a digest of the day's advisories to `#security-feed` daily at 09:00 Tokyo time. The signed mirror at `https://buzz.ai-tools.md/alerts/` is rewritten every 5 minutes: a page listing the latest advisories, `feed.atom` for feed readers, and the `feed.json`, `critical.json` and `manifest.json` files the CLI reads. The mirror carries only posts signed by a key in the trust manifest. The CLI, the skills, the session-start hook and the schedule templates below work against it today.

The design is `docs/design.md` and the implementation plan `docs/plan.md`. Work is tracked in the kata project `ai-tools-alerts` under the epic jibot-code#gr5b.

The trust root's public key is `trust/root.pub`; it signs only the manifest that lists who may post alerts, and the CLI pins it as `TRUST_ROOT_PUBKEY`. The Nostr primitives are pure Python (`aitools_alerts/nostr.py`: BIP-340 signatures, NIP-01 event ids, NIP-19 keys).

The two channels exist on `buzz.ai-tools.md`; their UUIDs are in `spec/channels.json`, and `ops/vm/README.md` says what this service keeps on the relay VM, including the `buzz-send` wrapper. Inside the members-only relay, Buzz cannot restrict who posts in a channel, so any member may reply in `#security-critical`: only keys in the trust manifest are trusted by the CLI, and only their posts reach the mirror.

Trust root public key (x-only hex), the same value as `trust/root.pub`:

```
afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4
```

Check it on two different hosts: `trust/root.pub` at the release tag on GitHub (`https://github.com/Joi/ai-tools-alerts/blob/v0.1.2/trust/root.pub`) and the copy the mirror on the relay VM publishes, `https://buzz.ai-tools.md/alerts/root.pub`. The VM's copy comes from a release deployed earlier, so agreement shows the root was not changed on GitHub alone since then. All three must show the same 64 characters. If they differ, do not install, and tell the ai-tools community; if the mirror's copy is missing, that is not a pass: wait for it.


## Install

You need Python 3.11 or later and nothing else; the CLI uses the standard library only.

### Verify the release

From v0.1.1 on, release tags are signed with an SSH key on Joi's GitHub account; v0.1.0 is unsigned. Check the tag before you install anything:

```
git clone https://github.com/Joi/ai-tools-alerts && cd ai-tools-alerts && git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.2
```

It passes only if it exits 0 and prints `Good "git" signature for 19930+Joi@users.noreply.github.com with ED25519 key SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA`. `No principal matched` or `no signature found` is a failure: do not install.

`trust/allowed_signers` comes from the same repository as the tag, so the check alone shows only that the two agree. Compare the full fingerprint with the copy on the mirror page, `https://buzz.ai-tools.md/alerts/`, which the relay VM serves, not GitHub; a missing copy is not a pass: wait for it. GitHub's tags page shows the tag as Verified, and `https://github.com/Joi.keys` lists the key; both depend on the GitHub account alone.

Only after both checks pass, install the commit the tag names from this checkout (`--force` replaces an earlier install such as 0.1.0; `init` is for a first install):

```
git checkout --detach 'refs/tags/v0.1.2^{commit}' && pipx install --force .
aitools-alerts init
aitools-alerts run
```

Run the hook, template and skill commands below from this checkout.

The current release is v0.1.2, a signed tag; verify it as above, then install from the verified checkout or pin the tag:

```
pipx install git+https://github.com/Joi/ai-tools-alerts@v0.1.2
aitools-alerts init
aitools-alerts run
```

Without pipx: `python3 -m venv ~/.local/share/aitools-alerts && ~/.local/share/aitools-alerts/bin/pip install .` from the verified checkout (for v0.1.0, `git+https://github.com/Joi/ai-tools-alerts@v0.1.2` in place of `.`), then link the command where the schedules and the hook look for it: `mkdir -p ~/.local/bin && ln -s ~/.local/share/aitools-alerts/bin/aitools-alerts ~/.local/bin/`. The launchd and cron templates search `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin`; the hook searches the same directories and nothing else.

Install from a release tag, as above, not from the default branch: the trust root is pinned in the code you install, so the tag is what fixes it. `CHANGELOG.md` lists each release. A PyPI package (`aitools-alerts`) is coming; until it ships, install from the tag.

`init` writes `~/.config/aitools-alerts/config.toml` (mode 600). Reading alerts needs no Buzz account; `aitools-alerts keygen` makes a key only for ai-tools community members who want to post or discuss on the relay. The settings:

- `mirror_url`: where the signed mirror lives; leave the default.
- `notify`: where a critical alert goes, any of `desktop`, `imessage`, `signal`, `telegram`, `webhook` (the recipient keys are in the file, commented).
- `auto_apply`: verbs your agent may apply without asking, and only from a curator post that matches your machine exactly. Empty by default: everything asks first. `upgrade` is the only verb meant for this.
- `trust_root_override`: a test setting; leave it out. Only with `trust_root_override = true` does the CLI accept another trust root from `AITOOLS_ALERTS_TRUST_ROOT`.
  Without it the variable is ignored, and `run --json` names it in `ignored_env`, so a project's environment cannot switch the root and silence alerts.

### Run it every hour

The templates, the hook and the skills below are files in this repository: run the commands from the checkout you verified above (with v0.1.0, `git clone https://github.com/Joi/ai-tools-alerts && cd ai-tools-alerts && git checkout --detach 'refs/tags/v0.1.0^{commit}'`).

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

Copy `hooks/claude-code/session-start.sh` to `~/.claude/hooks/aitools-alerts-session-start.sh`, make it executable, and add it to `~/.claude/settings.json` with `/Users/you` replaced by your home directory (`echo ~`). Write the path out in full, not with `~`: a project can change `HOME` for the session, and the command's `~` would then expand into the project.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {"type": "command", "command": "/Users/you/.claude/hooks/aitools-alerts-session-start.sh", "timeout": 90}
        ]
      }
    ]
  }
}
```

The hook runs `aitools-alerts run --json`. When a critical advisory that matches your machine has not been shown before, it puts one line in the session's context:

```
AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill
```

When no new signed post has arrived for over 3 days (the poster's daily digest is the heartbeat), or the trust manifest is over 90 days old, a frozen or replayed mirror is the likely cause, and the hook adds a second line; `aitools-alerts check` prints a warning line with the time:

```
AITOOLS-ALERT: alerts may be stale (no new signed post for over 3 days, or a trust manifest over 90 days old); run aitools-alerts check
```

Otherwise it prints nothing (neither line), and it never fails a session: a missing CLI or an unreadable mirror is silent. It usually takes a few seconds. On a slow network it takes longer: each of the three mirror files has a 20-second timeout and each notification a 30-second one, so there is no fixed bound. When Claude Code stops the hook at its timeout (90 seconds here), the line does not appear; an alert the CLI had already marked seen was marked so only after a notification channel accepted it, so you still got that notification.

A project's `.claude/settings.json` can set environment variables for the session, and the hook inherits them. So the hook and the CLI take your home directory from the password database, not from `HOME`, and the hook runs the CLI with the fixed PATH above and no other variable from the session: a project cannot choose the config, the key, the state, the `aitools-alerts` binary the hook runs or the Python code it loads. (Variables the dynamic loader reads, such as `LD_PRELOAD`, act before any script runs; the hook cannot stop them.) If you set `HOME` to something other than your account's home directory, the CLI still uses the account's; a user with no home directory in the password database gets an error.

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

Every post the poster makes (an alert, a change to it, the daily digest) gets a Japanese version as a reply in the same thread, in each channel the post went to. Its first line is `lang: ja`; a reply that translates a change adds `of: <event id>` naming it. It is built from fixed templates, with no model call: product names, ids, versions, links and the SYNTHETIC TEST and unverified marks stay as they are. It carries no alert block, so it never changes an alert. The Japanese reply is sent after every English post of the run; one that fails waits for the next hour and never holds an English post back (summary fields `ja` and `ja_failed`; its pending key ends in `:ja`, or `:ja:<event id>` for a change).

A curator's post or amendment is written by a person, so templates cannot translate it. With `translate_curator = true` in the config (off by default), the poster reads the curator's posts from the mirror (`translate_mirror_url`, default the public mirror) and translates each one with one Claude API call (`claude-sonnet-5-5`, a fixed prompt in `aitools_alerts/poster/translate.py`), at most 20 calls a UTC day. The key is the secrets helper's `ANTHROPIC_API_KEY` (`secrets_helper` names the helper's absolute path), read with `get_secret` into memory only, never argv, a file or a log. The translation posts as the thread's `lang: ja` reply, ending with the line `（機械翻訳）`, only when every link, id, version and number of the English appears in it unchanged; otherwise nothing posts and the summary counts it `untranslated`. Each event is translated once. If the API refuses the key (HTTP 401 or 403), translation stops (`translate=held` in the summary) until a person runs `aitools-alerts-poster translate-clear-hold --config <toml>`. The English posts never wait for any of this: it runs after them, and its failures never change the exit code. A curator's own `lang: ja` reply always takes precedence over the poster's. Before reinstalling a version older than this one, remove `translate_curator`, `translate_mirror_url` and `secrets_helper` from the config; older versions refuse unknown keys.

## Tests

`scripts/test-gate.sh`.

The gate starts with `scripts/public-scan.sh`, which fails when a tracked file names the maintainers' deployment. Its terms are not in this repo: the maintainers' machines carry them in a private file, `~/.config/aitools-alerts/public-scan.terms` (one regex fragment per line, `#` for comments). Without that file the scan exits 2 and the gate stops. A contributor runs the rest of the gate by pointing `PUBLIC_SCAN_TERMS` at a file whose fragments match nothing in the tree; `(?!)` matches no text at all: `printf '(?!)\n' > /tmp/terms && PUBLIC_SCAN_TERMS=/tmp/terms scripts/test-gate.sh`.
