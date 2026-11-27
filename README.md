# ai-tools-alerts

Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills.

Two channels on the henkaku ai-tools Buzz relay (`#security-feed` to browse, `#security-critical` to be interrupted), a signed public mirror, and a small CLI your agent can read so it verifies who posted an alert, checks what is installed, and prepares the fix.

## Who this is for

Two audiences get the same alerts.

- **Members of the henkaku ai-tools community** read and discuss them on the Buzz relay at `buzz.ai-tools.md`: `#security-feed` carries the high and critical advisories, a short daily digest and a weekly count of the notices, with discussion under each thread, and `#security-critical` carries critical advisories only, for interruption. The relay is members-only: reading it needs a member's auth token, and membership is handled in the community, not in this repository.
- **Everyone else** gets the same posts from the public mirror at `https://buzz.ai-tools.md/alerts/`, with no account: `feed.atom` (Japanese: `feed.ja.atom`) for a feed reader, `feed.json` for anything that reads signed events, and the CLI below, which verifies every post and checks it against what is installed on your machine. The mirror carries only the posts signed by keys in the trust manifest; members' discussion stays on the relay.

The CLI is the product for your agent and needs nothing else. The Buzz channels are where people talk about an alert, and where a member hears about a critical one at once instead of at the next hourly run.

## Whom you are trusting

Trusting this project means trusting Joi Ito. Everything an alert's authority rests on is his:

- The trust root key that signs the manifest is a key he holds. The manifest names who may post: jibot, the automated poster he runs. Since manifest version 4 it names no curator: the service runs with no person in the loop, and a curator is added back only by a new manifest the root key signs.
- The relay and the mirror run on a machine he operates. Every post is signed, and no key that may post (the curator's or the bot's) is kept on that machine: the bot signs on a separate poster machine and sends the signed post to the relay. So someone who takes the relay machine cannot sign an alert the CLI accepts. They can delay alerts, change what the mirror serves, including the copy of the trust root it publishes, and hide alerts from a CLI at 0.1.5 or older. Revoking a key is a manifest update only the root key can sign. From the release after 0.1.5, hiding one is noticed too: a second key, kept off that machine and named in a certificate the root signs, signs a checkpoint listing the posts that exist. The CLI admits a new post only when a checkpoint lists it, refuses a mirror that lacks a listed post, reads stale when no fresh checkpoint arrives for a day, and while any of that fails it applies nothing automatically. It also fetches the manifest from this repository, so a mirror that keeps serving a manifest from before a revocation is overruled. The poster also writes down the id of every post before it sends it, and its checkpoint leaves out any post signed with the bot's key that it did not send: a copy of that key, without the second key, gets no alert to a CLI at 0.1.6 or later, and the next daily digest the poster sends says that such a post was found. What this does not cover: whoever holds that second key and the mirror together can still withhold a post no member has seen.
- Release tags are signed with a key on his GitHub account, and the repository is his.
- What the bot posts comes from public sources (CISA's Known Exploited Vulnerabilities catalogue and vendor security releases), selected and ranked by the code in this repository, with no person reading each item before it posts. CISA's catalogue carries no version data, so an alert built from one of its entries may not name the fixed release even when the vendor has shipped one; such an alert says the source states no version and sends you to the vendor's advisory. A curator post is Joi writing by hand. A curator can also lower, narrow or retract one of the bot's alerts; your CLI holds that for 14 days at most unless your own check of the source agrees, and does not apply it at all when the source says more (see "Checking alerts against the source").

If you do not trust him, do not install this. What bounds the trust you extend: the CLI prepares fixes and executes nothing unless you opt in, action by action; the actions it can ever take are a fixed list in this repository (`spec/actions.json`), readable before you install; and a post from the bot is never applied automatically, whatever your settings.

## Status

Live. The poster runs every hour on the fleet: it posts a critical advisory to `#security-critical` and `#security-feed` within the hour it appears, and a digest to `#security-feed` daily at 09:00 Tokyo time: one line for each alert posted since the last digest, or one line saying there were none with the number of notices added to the catalog this week. The first digest of each week (Monday's) adds the week's notices counted by product. The signed mirror at `https://buzz.ai-tools.md/alerts/` is rewritten every 5 minutes: a page listing the latest advisories, `feed.atom` for feed readers, and the `feed.json`, `critical.json` and `manifest.json` files the CLI reads. The mirror carries only posts signed by a key in the trust manifest. The CLI, the skills, the session-start hook and the schedule templates below work against it today.

The design is `docs/design.md` and the implementation plan `docs/plan.md`. Work is tracked in the kata project `ai-tools-alerts` under the epic jibot-code#gr5b.

The trust root's public key is `trust/root.pub`; it signs only the manifest that lists who may post alerts, and the CLI pins it as `TRUST_ROOT_PUBKEY`. The Nostr primitives are pure Python (`aitools_alerts/nostr.py`: BIP-340 signatures, NIP-01 event ids, NIP-19 keys).

The two channels exist on `buzz.ai-tools.md`; their UUIDs are in `spec/channels.json`, and `ops/vm/README.md` says what this service keeps on the relay VM (the mirror exporter, and no poster key). Inside the members-only relay, Buzz cannot restrict who posts in a channel, so any member may reply in `#security-critical`: only keys in the trust manifest are trusted by the CLI, and only their posts reach the mirror.

Trust root public key (x-only hex), the same value as `trust/root.pub`:

```
afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4
```

Check it on two different hosts: `trust/root.pub` at the pinned release commit on GitHub (`https://github.com/Joi/ai-tools-alerts/blob/25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77/trust/root.pub`) and the copy the mirror on the relay VM publishes, `https://buzz.ai-tools.md/alerts/root.pub`. The VM's copy comes from a release deployed earlier, so agreement shows the root was not changed on GitHub alone since then. All three must show the same 64 characters. If they differ, do not install, and tell the ai-tools community; if the mirror's copy is missing, that is not a pass: wait for it.


## Quick install

The pinned release is `v0.3.0`, commit `25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77`. Paste this into your agent chat to set up ai-tools-alerts:

> Set up ai-tools-alerts release v0.3.0, commit 25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77. Clone https://github.com/Joi/ai-tools-alerts and, before you read any other file from it or install anything, run `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.3.0`, `git rev-parse 'v0.3.0^{commit}'` and `git tag --list 'v*' --sort=-v:refname` in the clone. Continue only if the tag check exits 0 and prints `Good "git" signature for 19930+Joi@users.noreply.github.com with ED25519 key SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA`, that fingerprint also appears on https://buzz.ai-tools.md/alerts/, the commit is exactly 25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77, and v0.3.0 is the first line of the tag list. If any check fails, stop, install nothing, and tell me what failed. Then, in that clone, run `git checkout --detach 25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77` and `pipx install --force .`; never clone again, and never check out or install any other commit, tag or branch. Run `aitools-alerts init`, then, from that checkout and as its README describes, enable the hourly monitoring schedule for this system and add the supported agent instructions for your harness without weakening their safety rules. Verify that monitoring runs, then tell me what you installed and any remaining manual steps or limitations.

## Detailed install

You need Python 3.11 or later and nothing else; the CLI uses the standard library only.

### Verify the release

The pinned release is `v0.3.0`, commit `25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77`. Release tags are signed with an SSH key on Joi's GitHub account. The README on the default branch pins the latest release; the README inside a release pins the one before it, because a commit cannot contain its own hash. Check the tag and the commit before you install anything:

```
git clone https://github.com/Joi/ai-tools-alerts && cd ai-tools-alerts
git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.3.0
git rev-parse 'v0.3.0^{commit}'
git tag --list 'v*' --sort=-v:refname
```

The tag check passes only if it exits 0 and prints `Good "git" signature for 19930+Joi@users.noreply.github.com with ED25519 key SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA`. `No principal matched` or `no signature found` is a failure: do not install. The commit check passes only if it prints exactly `25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77`; anything else means the tag is not the release this README pins: do not install. The tag list must start with `v0.3.0`: a newer tag means this README is out of date, so get the current one from the default branch; an older pin can be a downgrade to a release with known flaws.

`trust/allowed_signers` comes from the same repository as the tag, so the tag check alone shows only that the two agree. Compare the full fingerprint with the copy on the mirror page, `https://buzz.ai-tools.md/alerts/`, which the relay VM serves, not GitHub; a missing copy is not a pass: wait for it. GitHub's tags page shows the tag as Verified, and `https://github.com/Joi.keys` lists the key; both depend on the GitHub account alone.

Only after every check passes, check out the pinned commit:

```
git checkout --detach 25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77
```

Then install from this checkout (Install, below). You may instead install the same commit from GitHub, which pip fetches by hash, so a moved tag or a push to a branch cannot change what it installs: `pipx install git+https://github.com/Joi/ai-tools-alerts@25969f8fdfb9d7c81fcb3abb53c51b5b18ffff77`. Either way, check out the commit first: the template, hook and skill files below come from this checkout.

### Install

From the verified checkout (`--force` replaces an earlier install; `init` is for a first install):

```
pipx install --force .
aitools-alerts init
aitools-alerts run
```

Run the hook, template and skill commands below from this checkout.

When a command prints `aitools-alerts: upgrade: this aitools-alerts is X; the feed needs Y or later`, the trust root has said that releases older than Y cannot read everything the feed now carries. The CLI keeps working and shows what it can read; newer alerts may be missing, or shown at an older level. Verify and install the release this README pins, as above. `run --json` carries the same value as `min_cli` (null when this release is new enough). The 0.1.7 release and earlier cannot print the line.

When a command prints a line that starts `aitools-alerts: out of date:`, the rules this install uses to judge a level are not the ones the trust root has pinned: they are an older version, or the same version with different files, or the pin is in a form this release cannot read. The CLI still shows and notifies every alert as posted. Until it is upgraded it does not check alerts against their sources and does not age a relay-bot alert down or out, so an alert may show longer, or at a higher level, than on a current install. Upgrade the same way. `run --json` carries it as `ruleset_outdated` (null when the ruleset is current).

Without pipx: `python3 -m venv ~/.local/share/aitools-alerts && ~/.local/share/aitools-alerts/bin/pip install .` from the verified checkout, then link the command where the schedules and the hook look for it: `mkdir -p ~/.local/bin && ln -s ~/.local/share/aitools-alerts/bin/aitools-alerts ~/.local/bin/`. The launchd and cron templates search `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin`; the hook searches the same directories and nothing else.

Install a verified release commit, never a branch or a tag name alone: the trust root is pinned in the code you install, so the commit is what fixes it. `CHANGELOG.md` lists each release. No release of this project is published to PyPI, and none is planned. The name `aitools-alerts` there holds an empty placeholder that installs nothing, and PyPI refuses `ai-tools-alerts` as too similar to it: do not install from PyPI.

`init` writes `~/.config/aitools-alerts/config.toml` (mode 600). Reading alerts needs no Buzz account; `aitools-alerts keygen` makes a key only for ai-tools community members who want to post or discuss on the relay. The settings:

- `mirror_url`: where the signed mirror lives; leave the default.
- `notify`: where a critical alert goes, any of `desktop`, `imessage`, `signal`, `telegram`, `webhook` (the recipient keys are in the file, commented).
- `auto_apply`: verbs your agent may apply without asking, and only from a curator post that matches your machine exactly. Empty by default: everything asks first. `upgrade` is the only verb meant for this.
- `trust_root_override`: a test setting; leave it out. Only with `trust_root_override = true` does the CLI accept another trust root from `AITOOLS_ALERTS_TRUST_ROOT`.
  Without it the variable is ignored, and `run --json` names it in `ignored_env`, so a project's environment cannot switch the root and silence alerts.

### Run it every hour

The templates, the hook and the skills below are files in this repository: run the commands from the checkout you verified above, at the pinned commit.

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

### Checking alerts against the source

The relay bot's key signs every alert, so a stolen key could sign a false one. Once an hour, `aitools-alerts run` therefore reads the primary source itself and compares what it supports with what was posted. `aitools-alerts verify` does the same on demand. It reads three addresses and no other, whatever a post says:

- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` for a CVE id,
- `https://api.github.com/advisories/<GHSA id>`,
- `https://api.osv.dev/v1/vulns/<id>`.

The id comes from the alert's own id and aliases and is used only when it has the exact form of a CVE id, a GHSA id or an OSV malware id (`MAL-`). Which other ids are the same advisory is taken from the source, never from the post. No link in a post is ever opened. Each request is https with no redirect followed, at most 10 seconds, at most 8 MB for the CISA file and 256 KB for an advisory; a run makes at most 10 requests in at most 30 seconds. Nothing a source says is printed. What is stored from a response: its ETag, the ids it names, and the version ranges and first patched versions a GitHub advisory states for a product in scope, each only when it has the exact form of a version range.

Each product of each relay-bot alert gets one of three results:

- **confirmed**: the source supports the posted level for that product. An alert at notice whose advisory the source has withdrawn is confirmed too: the relay bot has no retraction, so a withdrawn advisory stands at notice.
- **contradicted**: the source supports more than was posted, or does not support the alert for that product. A known-exploited CVE that CISA lists for another vendor's product, posted as an alert about Claude Code, is contradicted. `check` prints one `source check:` line for each.
- **unknown**: the source could not be read (a timeout, a rate limit, a 404, a damaged body), or it is one anyone can write (an advisory GitHub has not reviewed), or CISA simply does not list the CVE, or the level rests on a reading of prose that no program can check. Unknown says nothing in either direction.

Beside a CVE, an alert may list GitHub or OSV advisories as aliases. One counts as support only when your CLI's own read of it is an advisory that has the say and names the CVE. An alias the source has no entry for (a 404) is an answer that supports nothing. At most eight aliases count: the first your CLI saw the alert list. The alert is `unknown` until each of them has answered, with one exception: an alias whose answer your CLI cannot use (an entry too large or of a form it does not read) stops counting 24 hours after the first incomplete read. An alias your machine cannot reach (a timeout, a rate limit) keeps the alert `unknown` for as long as that lasts, also when it answered before. A published lowering is held to the stricter rule: every listed alias, at most three, read whole in one run.

The check compares the product and the level. It does not compare the affected versions or the fixed version a post states with the source's.

A product is judged as the product your installation was matched as. `claude code`, `claude-code` and `@anthropic-ai/claude-code` under ecosystem `claude-code` are all Claude Code, and get its result. A posted product that is no product of `spec/scope.json` under its ecosystem (`Claude Code` posted as a skill, say), or an alert whose id names no source, can never be confirmed or contradicted. When the trust root pins the ruleset your CLI has, such a match does not interrupt: `check` lists the alert and says `names a product or an id this check cannot judge`.

The result is reported, and `check --json` and `run --json` carry it as `source_check` on each match. It changes what you are shown in three cases: a lowering, an interrupt, and an alert no source supports:

- The relay bot may publish a lower level for one of its alerts. Your CLI applies it at once when its own read of the source, no more than two days old, gives no more than that level. A lowering below `high` needs one thing more, because a `high` can rest on a reading of the advisory's text that no program can check: every higher level the alert has stated must carry a signed claim that names the source's own fields, which your CLI computes the same level from. Then a withdrawn advisory, or a CVE that CISA no longer lists, confirms a lowering to notice.
- A lowering your CLI cannot check (the source cannot be read, the result settles nothing, or `verify = "off"`) is not applied at first. `check` says it waits, and `--json` carries the level as `lowering_waits`. It applies once the signed checkpoints your CLI has accepted have listed it for 72 hours. Only checkpoint times count, never the date on the lowering and never your clock, so a frozen mirror keeps the higher level.
- The relay bot may publish that the source withdrew an advisory. Your CLI then stops showing the alert, and matches nothing against it, while its own read of the source, no more than two days old, says the advisory is withdrawn and every level the alert has stated carries such a signed claim. It is never hidden on the relay bot's word alone, however long the reply has stood. Until your CLI can confirm it, the reply counts as a lowering to notice that nobody has checked: it applies after the 72 hours of the rule above. When the source publishes the advisory again the alert comes back: at once on your machine when your CLI reads the source, with one line (`source check: a withdrawal of <id> is not applied: the source supports <level> for <product>`, and `lowering_refused` is `withdrawn` in `--json`), and for everyone when the relay bot posts its level again in the same thread. The relay bot cannot retract an alert.
- A relay-bot reply that narrows an alert's products (a shorter affected range, a fixed version, a product left out) is checked the same way. Your CLI compares the reply with the range and first patched version the GitHub advisory states. When they agree the alert shows the narrower entry, in the command that reads the source. When they do not, it keeps the wider entry and one line says so: `source check: a narrowing of <id> is not applied: its products are not what the source states`; `check --json` carries `narrowing_refused`. A `fixed` version is taken only when it is exactly the advisory's: a higher one would send an upgrade to a version the vendor did not name. A refused list stays refused however often it is sent again, until the source itself comes to state it, and after one refusal no other narrowing of that alert applies without a whole read of its source. When the source cannot be read or states no versions, `check` says the narrowing waits (`narrowing_waits`), and it applies after 72 hours of signed checkpoints, as a lowering does.
- A relay-bot reply that widens an entry is joined at once, as any raise is. One widening is checked afterwards: the `fixed` version, because the upgrade is sent to it. When your CLI has read the alert's sources whole and no version range of the GitHub advisory gives the alert's `fixed` as its first patched version, the alert stays as it is (it still matches, at its level, and still interrupts) and the upgrade is shown with no version: `plan` prints `the fixed version given is not the advisory's: notify only, no command`, the notification names no fixed version, `check --json` carries `"fixed_contradicted": true` (its `title`, `product` and `actions` stay as published), and one line says `source check: the fixed version <id> gives for <product> is not the advisory's: no upgrade version is shown`. The alert's title and translations are the signer's text and can name that version too, so `check`, `plan` and the notification show `advisory <id>` in place of the title and no translation for such an alert. A root posted with such a `fixed` is treated the same. `run` notifies before it reads a source, so the first notification of a critical can still name that version; when the read then contradicts it, your CLI sends one correction (`Correction: the fixed version this alert gave is not the advisory's; no upgrade version is shown`). When the source cannot be read, was read in part, or states no version your CLI can compare, nothing changes: the version is shown as published. When the advisory comes to state the version, the flag ends with the next read.
- A curator may lower, narrow or retract a relay-bot alert. That holds for 14 days and then lapses, unless the curator signs it again or your own check confirms the lowering. A relay-bot raise shows at once during those days; its other changes show after them.
- When the source supports more than a lowering or a retraction says, from either key, it is not applied on your machine and one line says so: `source check: a lowering of <id> to <level> is not applied: the source supports <level> for <product>`. `check --json` carries the refused level as `lowering_refused`. An alert whose lowering was refused keeps its level, whatever later replies change in it or offer again, until your CLI confirms it or reads the sources whole and finds no more than its level; its 72 hours start then.
- A relay-bot critical your CLI has not confirmed from the source still interrupts, and its notification ends `Not verified from this machine`. At most two such alerts from one poster key interrupt in 24 hours. A third is held: `check` lists it and says so, `run --json` names it in `held_critical`, and it sends no notification and sets no exit 2 until its source confirms it or a slot is free; a free slot goes to the alert held longest. A confirmation counts for two days and for one alert a day per advisory and product: a second post about a confirmed advisory is unverified. Whoever holds the relay bot's key can fill the queue with false alerts, and a true one you cannot verify then waits behind them; it is listed all the while. `check` also names, in one line, the relay-bot matches that are not verified.
- A relay-bot alert for a product that no source your CLI read has ever supported is shown at notice, whatever level it was published at. It needs whole reads of sources that have the say: a failed read, an advisory anyone can write and a CVE that CISA simply does not list all settle nothing. `check` prints the match as `NOTICE: ... (id <id>, thread <ref>; published at <level>)` with the line `source check: the source does not support <id> for <product>`, and `--json` carries `"level": "notice"` and the published level as `published_level` (null on every other match). Such a match sends no notification and sets no exit 2. It is decided per product: an alert that names a supported product beside an unsupported one keeps its level for the first. What is asked about is the alert with every alias it has ever listed, so a later reply cannot drop the support. It stays at notice through failed reads and through later replies, and returns to its published level in the run that reads a source supporting it. `run` notifies before it reads, so an alert that arrives unread can still interrupt once, as unverified; it shows at notice from the first read on.
- Two such alerts from one poster key within seven days put that key on probation on your machine for 30 days. An alert counts once your CLI's reads have found that no source ever supported one of its products; copies of one advisory count once, and an alert that is never read does not count. During the probation the key's alerts that your CLI has not confirmed do not interrupt: each is held (`held, not notified (not verified from this machine; its poster key is on probation here): ...`, and `held_critical` in `run --json`), whether or not a slot is free. One your CLI confirms from the source interrupts as always. The key's lowerings and narrowings, and its replies that lower or narrow another relay-bot key's alert, are not applied after 72 hours: only your CLI's own confirmation applies them, and one that had already applied unchecked stops applying. `check` says which key and until when (`probation: poster key <first 12 characters> is on probation on this machine until <time>: ...`). It ends by itself: the held alerts then take the free slots, the 72 hours of a lowering start at the first checkpoint issued after it ended, and a key that kept posting unsupported alerts goes straight back. Nothing is sent anywhere; the probation is your machine's own. With more than one relay-bot key in the manifest (there is one today), an alert counts against the key that started its thread, whoever changed it later.
- When a source supported the product on an earlier read and no longer does, nothing was made up: the relay bot follows its sources within a day or so. The alert keeps its level and nothing is printed, until reads more than 48 hours apart have both found no support. Then `check` prints `source check: the source has not supported <id> for <product> for more than 48 hours`, and the level is still kept. To notice this, `run` reads the source of every relay-bot alert that matches your machine again once a day.
- A critical that the source supports at a lower level keeps critical. It is flagged (`... is published at critical for <product>; the source supports <level>`) and counts as unverified.

With `verify = "off"` nothing is read, so every relay-bot alert is unverified: a relay-bot lowering or narrowing applies after its 72 hours, at most two relay-bot criticals interrupt in 24 hours, and a curator's lowering holds its 14 days. Nothing shows at notice for want of support, and what your CLI remembered about support is kept for when the check is on again. No alert is counted against a key while the check is off, and a probation that began before still runs. An alert a curator posted is not covered: a curator's word on its own alert stands. Neither is a relay-bot alert while a curator's change to it holds. A result of `unknown`, `unread` can carry a `source_level`: what the sources that could be read support, when another read the alert needs failed.

The waits, the refusals, the interrupts, what your CLI has read about support (per alert and product: the last read that found support, and since when reads have found none) and the probations (per poster key: its last two unsupported alerts, and since when it is on probation) are kept in `unverified.json` in the state directory. If that file is damaged the CLI starts it again and says so once: every wait starts over, for 24 hours no unverified alert interrupts, for 48 hours nothing is shown at notice for want of support and no alert is counted against a key, and a probation that was running is lost. What was found under one ruleset is not reused under another.

`verify` in `config.toml` chooses which alerts are read, and with that what other parties learn:

| Value | What is read | What it tells others |
|---|---|---|
| `"matched"` (default) | Alerts that match a tool on this machine | GitHub or OSV sees, from your address, requests for the advisories that apply to you. The CISA file is one request, the same for every member |
| `"all"` | Every alert, ten requests an hour | GitHub or OSV sees requests for every advisory on the feed, which does not show which apply to you. A new alert can wait some hours for its turn |
| `"off"` | Nothing | Nothing. No alert is verified |

GitHub allows 60 unauthenticated requests an hour from one address; the check uses at most 10 of them.

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

The hook runs `aitools-alerts run --json`. That form never reads a primary source (the hourly job's plain `run` does), so a session start makes no request to CISA, GitHub or OSV. If you write your own hook, keep `--json`. When a critical advisory that matches your machine has not been shown before, it puts one line in the session's context:

```
AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill
```

When the CLI cannot vouch that the alerts are complete and current (the last pull failed, the mirror lacks an event its signed checkpoint lists, or no fresh checkpoint has arrived for a day), a frozen, replayed or incomplete mirror is the likely cause, and the hook adds a second line; `aitools-alerts check` prints a warning line with the reason, and `plan` lists nothing under auto-apply until a pull succeeds:

```
AITOOLS-ALERT: alerts may be stale or unverified (no fresh signed checkpoint, or the last pull failed); run aitools-alerts check
```

Otherwise it prints nothing (neither line), and it never fails a session: a missing CLI or an unreadable mirror is silent. It usually takes a few seconds. On a slow network it takes longer: each of the five mirror files has a 20-second timeout, the two from the second origin 5 seconds and each notification a 30-second one, so there is no fixed bound. When Claude Code stops the hook at its timeout (90 seconds here), the line does not appear; an alert the CLI had already marked seen was marked so only after a notification channel accepted it, so you still got that notification.

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
- act on an alert from a key that is not in the signed trust manifest, or on anything such a key signed outside the two alert channels (the CLI drops those before the agent sees them).

Actions come from a fixed list: `upgrade`, `disable_skill`, `remove_mcp_server`, `rotate_credential`, `stop_using`, `review_setting`. Only `upgrade` comes with a command; the others are notify only: your agent tells you what the advisory recommends and you do it yourself.

## For the fleet: the poster

`aitools-alerts-poster run --config <toml>` posts the alerts each hour. It signs each post itself, with jibot's key read from the secrets helper (`secrets_helper` names the helper's absolute path, `relay_key_secret` the secret's name; read with `get_secret` into memory only, never argv, a file or a log), checks that the key is the trust manifest's relay-bot key, and sends the signed event to `relay_url` (default `https://buzz.ai-tools.md`) over HTTPS with a NIP-98 header signed by the same key. Each send has a 90-second limit. A config that still names `relay_send_wrapper`, the retired ssh send route, is refused. When a send's outcome is unknown (a timeout or a dropped connection after the request began, a 5xx from the relay), the poster keeps the send pending in its ledger and posts nothing more for that advisory until the send is settled. A later run settles it with no one involved (ai-tools-alerts#jsje). It pulls the mirror; an event there signed by the relay-bot key, with the same text, channel and thread, is the delivery, and the run records it. A send that a mirror generated within the last hour does not show 24 hours after the attempt is sent again, and so is one that no mirror has shown after 72 hours: at that point one possible duplicate post costs less than an alert thread that waits for a person. A send the relay refused waits three days in the state's `withheld` list; then a root, a copy or a digest is dropped and its advisory is composed again from its sources, and a reply is sent once more as it is and dropped only if the relay refuses it again (another channel may already have that change, and then nothing would compose it again). The next digest counts each dropped post in its "withheld by the publication check" line. A raise never waits behind an unsent lowering, or an unsent reply that only lists ids and sources, on its own thread: that work leaves the journal in the same write that journals the raise. It does wait while a send of that thread is unknown. A run that settled anything adds `settled=delivered:N,resent:N,dropped:N,superseded:N` to its summary line. An operator who is watching can still settle a send sooner:

- `aitools-alerts-poster pending --config <toml>` lists each pending key with its kind, channel, when it was attempted, when it may be expired, and its outcome (`unknown`, `sent:<event id>`, or `no-journal-item`). It prints no post text.
- `aitools-alerts-poster resolve <key> --config <toml> --delivered <event id>`: the post is in the channel. The poster records it as it would after a successful send, and never sends it again.
- `aitools-alerts-poster resolve <key> --config <toml> --not-delivered --reason <text>`: the post is not in the channel. Allowed 24 hours after the attempt, since a slow send can still land before then; the next run sends it again.
- `aitools-alerts-poster resolve <key> --config <toml> --requeue` or `--drop`: a refused post goes back to the journal (with `--text-file <path>`, under corrected text) or is discarded.

Both take the ledger lock, so they never overlap an hourly run. Exit 0 on success, 2 when the request does not apply and nothing changed, 1 when the ledger or journal cannot be used.

The poster also signs the feed checkpoint, at the end of every run, when its config names `checkpoint_key_file` (a secret key in a file on the poster machine, mode 600; `aitools-alerts-poster checkpoint-keygen --config <toml>` creates it and prints the npub), `relay_ssh_host` and `relay_put_wrapper` (the put-only ssh route and the storing command on the relay VM, `ops/vm/README.md`; the route carries the checkpoint and nothing else, and holds no key). The checkpoint lists the posts on the mirror and every post the relay acknowledged to this poster, until the mirror shows it; the run's summary line ends `checkpoint=` and one of `sent`, `failed` (not delivered), `no-mirror`, `no-certificate`, `too-large` (what must be listed does not fit: nothing is signed), `held` (the record of owed posts was lost: nothing is signed for 72 hours), `owed-unrecorded` or `error`, with `,owed_dropped=N` or `,gone_dropped=N` when posts were given up after 72 hours, and `,threads_suppressed=N` while a curator's reply is missing from the mirror and its thread is left out. One key belongs to one poster with one ledger.

With a checkpoint key set, the poster keeps a record of every event id it signed (`<ledger>.sent.json`, with a lock file beside it), written before the send. Each run it compares the relay-bot posts on the mirror with that record. A post that is not in it was not sent by this poster: it is left out of the checkpoint, with every reply when it starts a thread, the summary line shows `,foreign=N`, and the next daily digest carries one fixed line. The record starts from the checkpoint the mirror serves under this key, the ledger and the posts still owed, never from what happens to be on the mirror, and a lost record starts the same way. A send whose outcome is unknown is settled only by an id in the record, never by its text.

`scripts/sign-checkpoint-key.py <checkpoint public key as an npub>` signs, with the trust root, the certificate that names the key allowed to sign feed checkpoints; it is bound to the current manifest, so it is signed again after every new manifest. The format of the certificate and the checkpoint is in `aitools_alerts/checkpoint.py`. The certificate in force is `trust/checkpoint-key.json`, which the exporter serves as `checkpoint-key.json` beside the manifest; readers from 0.1.6 on carry it too, and refuse a pull without a valid certificate and a current checkpoint. It expires 120 days after signing, and past that every member reads unverified: sign it again before then.

Every post the poster makes (an alert, a change to it, the daily digest) gets a Japanese version as a reply in the same thread, in each channel the post went to. Its first line is `lang: ja`; a reply that translates a change adds `of: <event id>` naming it. It is built from fixed templates, with no model call: product names, ids, versions, links and the SYNTHETIC TEST and unverified marks stay as they are. It carries no alert block, so it never changes an alert. The Japanese reply is sent after every English post of the run; one that fails waits for the next hour and never holds an English post back (summary fields `ja` and `ja_failed`; its pending key ends in `:ja`, or `:ja:<event id>` for a change).

A curator's post or amendment is written by a person, so templates cannot translate it. With `translate_curator = true` in the config (off by default), the poster reads the curator's posts from the mirror (`translate_mirror_url`, default the public mirror) and translates each one with one Claude API call (`claude-sonnet-5-5`, a fixed prompt in `aitools_alerts/poster/translate.py`), at most 20 calls a UTC day. The key is the secrets helper's `ANTHROPIC_API_KEY` (`secrets_helper` names the helper's absolute path), read with `get_secret` into memory only, never argv, a file or a log. The translation posts as the thread's `lang: ja` reply, ending with the line `（機械翻訳）`, only when every link, id, version and number of the English appears in it unchanged; otherwise nothing posts and the summary counts it `untranslated`. Each event is translated once. If the API refuses the key (HTTP 401 or 403), translation stops (`translate=held` in the summary) until a person runs `aitools-alerts-poster translate-clear-hold --config <toml>`. The English posts never wait for any of this: it runs after them, and its failures never change the exit code. A curator's own `lang: ja` reply always takes precedence over the poster's. Before reinstalling a version older than this one, remove `translate_curator`, `translate_mirror_url` and `secrets_helper` from the config; older versions refuse unknown keys.

With `model_wording = true` (off by default; it needs `secrets_helper`), a model writes the first line of a high or critical alert and one sentence after it, `Who: …`, naming who is exposed. The call is the same as above (same key, model and helper) and reads the vendor's advisory text or the KEV entry's description; at most 4 calls a run, and no call starts after 30 of its 60 seconds are spent. A fixed check in `aitools_alerts/poster/wording.py` refuses a draft that is too long (90 and 200 characters), holds anything but letters, digits and plain punctuation, a URL, a command, an advisory id, an `@`-name, a capitalised word the advisory does not write, any word that is neither in the advisory, the product's name, nor the module's fixed word list, or a line that does not start with the product's name (the headline) or a subject and connector such as "Anyone who" or "Users of" (the `Who:` line). A refused draft, a model error or a missing key posts the source's own title and no `Who:` line, as before. Both lines are prose only: the alert block, which the CLI reads, is the same with or without them, and the Japanese reply takes the headline but not the `Who:` line. A 401 or 403 sets the same hold as translation, so no call is made until `translate-clear-hold`; posts go on meanwhile. The summary line ends with `wording=<worded>/<asked>` (or `held`, `key-error`, `error`) only when this is on. Before reinstalling an older version, remove `model_wording` from the config.

## Tests

`scripts/test-gate.sh`.

The gate starts with `scripts/public-scan.sh`, which fails when a tracked file names the maintainers' deployment. Its terms are not in this repo: the maintainers' machines carry them in a private file, `~/.config/aitools-alerts/public-scan.terms` (one regex fragment per line, `#` for comments). Without that file the scan exits 2 and the gate stops. A contributor runs the rest of the gate by pointing `PUBLIC_SCAN_TERMS` at a file whose fragments match nothing in the tree; `(?!)` matches no text at all: `printf '(?!)\n' > /tmp/terms && PUBLIC_SCAN_TERMS=/tmp/terms scripts/test-gate.sh`.
