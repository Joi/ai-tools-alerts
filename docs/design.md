# ai-tools security alerts: design

Date: 2026-11-05. Status: approved by Joi 2026-11-05 ("do all as you recommend"), trust root = a new dedicated key. Decided in chat with Joi on 2026-11-05; calls marked "builder's call" or "jibot's call" are not Joi's words.

## What this is and why

A security alert service for the henkaku ai-tools community: people running Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills on their own machines. Two channels on the existing Buzz relay at buzz.ai-tools.md, a public signed mirror, and a small CLI plus a skill so a member's agent can read the alerts, match them against what is installed, interrupt the person, and prepare the fix.

Why now: the six-hour fleet security watch (its runbook is in the jibot workspace, standing issue jibot-code#w3xq) already discovers and verifies advisories for Joi's own fleet, so the supply side exists. The ai-tools relay is up but dormant (25 member keys; 212 posts by 12 people in July 2026, 3 posts by 1 poster in November). A trusted alert channel gives members a reason to open the app. No public feed today is signed, curated for this stack, and tells an agent what to do: CISA KEV has a required action but no agent scope; OSV and GitHub advisories give fixed versions only; the Vulnerable MCP Project, Snyk's ToxicSkills work and Koi's malicious-skills list cover parts; OpenSSF Siren is an email list under TLP. The trojanized Claude Code builds in the Cursor marketplace on 2026-10-29 are the kind of item this service would have carried the same day.

## Goals

- A member can browse what matters in one channel and be interrupted only for fix-now items.
- A member's agent can consume the same alerts deterministically, verify who posted them, and act only within a fixed action vocabulary.
- Joi, and later other trusted people, can post; the trust boundary is a signed list of keys, not relay membership.
- Reading needs no account; posting and discussion need Buzz membership.
- The fleet watch produces the feed with hourly discovery and no increase in model cost per day.

## Non-goals

- Replacing CISA KEV, OSV or vendor advisories. The service curates and merges; it cites them.
- Scanning members' machines from the outside. The CLI runs locally and sends nothing back.
- Publishing Joi's fleet exposure evidence. Only the advisory and the action go out.
- A separate channel for agents. One set of channels serves humans and agents.

## Anti-goals (failures even if it runs)

- The channel becomes a supply-chain attack: an agent runs a command string from a post. Actions are verbs from a fixed list, never commands.
- The interrupt channel carries judgment calls and members mute it. Critical is rule-based.
- A member's agent silently patches something the member did not opt into.
- Alerts that cannot be verified: a post without a primary source does not post.

## Decisions

### Channels (Joi)

- `#security-feed`: the browse channel. Everything rated notice or higher, human readable. Daily digest post at a fixed hour (builder's call on the hour; jibot's suggestion 09:00 JST). Items rated high post in real time. Cross-posts from KEV, GitHub advisories, vendor security pages, the Vulnerable MCP Project and the malicious-skill lists, filtered by a scope list.
- `#security-critical`: the interrupt channel. Fix-immediately only. Every critical post also posts to the feed so the feed is complete.
- Critical posts do not wait for Joi (Joi, 2026-11-05). jibot's key posts the moment the rule fires. Joi receives the same item by the existing iMessage path and can reply in the thread to amend or retract.

### Severity and the critical rule

Levels: critical (fix now, interrupt), high (today, real-time feed post), notice (digest only). Advisory severity (CVSS, vendor rating) is recorded separately from the level the channel assigns.

Critical fires only by rule, jibot's call: the product is in scope tier 1 and at least one of: CISA KEV lists it as exploited; the vendor or a primary source confirms a trojanized, backdoored or malicious release or package; a verified prompt-injection-to-code-execution path in an agent, IDE or MCP client with a fix available. High: a vendor advisory with a fix and a plausible path to code execution, credential theft or data loss in scope, and every KEV entry for scope tier 2. Notice: everything else in scope.

Amended 2026-11-24 (ai-tools-alerts#s6mt): the level table is now `spec/ruleset.json`, computed from structured source fields by the poster and the CLI alike. The trojanized-release and injection-to-execution clauses below rest on a model's reading, so they post `high` and no longer `critical`; critical comes from a field (CISA KEV, a GitHub malware advisory, the vendor's own advisory stating embedded malicious code).

Who may fire each clause (jibot's call, following Joi's decision that critical posts do not wait for him): the KEV clause is mechanical and fires from the collector alone. The trojanized-release and injection-to-execution clauses need a reading of a source, so the model step may fire them, under two deterministic checks the poster enforces before signing: the cited primary source is on the allowlisted primary-domain list (vendor security pages, GitHub advisories, CISA, CERT/CC, OSV) and was fetched successfully, and the product resolves to a scope entry. A critical with no passing primary source posts as high in the feed with "unverified" in the body, never to the interrupt channel. A relay-bot post is therefore a model's reading in part, and the CLI treats it accordingly: the CLI never auto-applies any verb from a relay-bot post, only from a curator post. Members are interrupted on relay-bot criticals; nothing changes on their machine without them.

What the relay bot signs (ai-tools-alerts#h340, 2026-11-23; it narrows the paragraph above). An upstream record is a pointer: an id, a product, URLs. The poster signs only what an authoritative source states, and it reads that source itself.

- A product is resolved by exact identity (`spec/scope.json`, version 5): the whole product text, normalised, equals a listed name, repository slug, package key (`npm:@anthropic-ai/claude-code`) or CISA KEV "vendor product" pair. Nothing is matched by a word in free text, so a package named `claude-code-router` is not Claude Code.
- A source is authoritative for a product only when it is the CISA KEV catalog the poster fetched, or a page under the product's own `authority` prefixes in `spec/scope.json` (the vendor's repository or site, inside `spec/primary-domains.json`). The global GitHub advisory database, another repository and a distribution's tracker are authoritative for nobody else's product.
- A candidate posts, at any level, only when such a source confirms it. A repository advisory page confirms it when the candidate's id is that advisory's GHSA or CVE ID and one of its package blocks is the product. Any other vendor page confirms it when its visible text names the id and the product; that makes a notice, never more.
- The ids, the fixed version, the affected range, the title and the severity word of a post are read from the labelled fields of the vendor's advisory page (or are CISA's). The record's own values for them are never published. A record's severity text and model-read flags count only when the vendor's advisory page confirmed it and the record cites nothing else.
- A post names ids of the CVE or GHSA shape only, lists only the page that confirmed it (with CISA's sources for a KEV entry and the global page of the vendor's own GHSA), and has no action sentence when the fixed version cannot be expressed.
- A fetch that fails, or a vendor page the poster cannot parse, defers the candidate to the next run; nothing is posted and nothing is dropped for it.

### Scope list

Superseded on 2026-11-24 (ai-tools-alerts#wa6n, design ai-tools-alerts#9mx8 section 2): each entry of `spec/scope.json` is now channel, catalog or out, and an MCP server is named by its package. The file's own description is the current rule; the tiers below are the version 1 design.

A file in the repo, edited by pull request, in two tiers (jibot's call, to keep the interrupt channel from paging on every exploited WebKit or kernel entry the OS updater already handles).

Tier 1, interrupt-eligible: agents and IDEs (Claude Code, Codex, Cursor, Gemini CLI, Hermes, OpenClaw), MCP servers and clients, skill marketplaces (ClawHub, skills.sh), runtimes used by agents (Node, Python, Go, Rust toolchains), Docker and container runtimes, Tailscale, OpenSSH, git.

Tier 2, feed only: macOS, common Linux distributions, browsers. A KEV entry here posts as high in real time, never as critical.

Items outside both tiers do not post.

### Post format

One advisory is one thread, and advisories for one product that one release fixes, seen in one poster run, are one thread too (ai-tools-alerts#faxq): their ids are the root's `id` and `aliases`. The root post is the advisory; later news (fix shipped, now exploited, level raised) is a reply in the thread. The thread root event id is the stable advisory id for agents. Merging: CVE, GHSA and vendor ids are aliases of one advisory; a candidate matching an existing alias becomes a reply, never a new root.

Each root post has a human body on top and a fenced JSON block at the end:

```
id, aliases[], level (critical|high|notice), advisory_severity, title,
products[] {name, ecosystem, affected (version range), fixed (version)},
actions[] {verb, target, value}, sources[] {url, published_at},
posted_by (pubkey role: curator|relay-bot), posted_at, expires_at
```

Humans read the top; agents parse the block. Replies carry the same block with the changed fields. Final field names and the schema file are the builder's.

What a reply may change depends on who signed it (ai-tools-alerts#tyje, 2026-11-24, finding D1 of the design review on ai-tools-alerts#h29n). A curator's reply replaces each field it names, whole. A relay-bot reply never shrinks what a member sees: one that lowers `level` or sets `expires_at` is ignored whole, and its `products`, `actions` and `sources` are joined to the thread's, never put in their place: an entry that is wider than one the thread holds replaces it, a new one is added, and one that is left out, narrowed (a narrower `affected`, a lower `fixed`, a `fixed` where there was none) or weakened stays as it was. The three fields of a reply are joined even when the reply is ignored for its level or expiry. Each is therefore the widest state the thread's signed replies have given it, in whatever order they are read: the signer dates its own replies, so a rule that depended on their order could be undone with a reply dated earlier. The reader cannot tell a true narrowing from a forged one, so it applies neither; the member's own check against the source (ai-tools-alerts#h29n) is what will let a true one through. Readers at 0.1.6 and earlier apply a relay-bot narrowing whole.

The relay bot's root body (ai-tools-alerts#faxq, design section 6 of ai-tools-alerts#9mx8, replacing r7hr's): a headline, the level and what goes wrong in at most 90 characters with no id (the authoritative source's own title, after the product name when the title does not name it; never a title an upstream record supplies, ai-tools-alerts#h340; with no title, the product and the template kind); `Affected:` with the package, the range and the registry; `Do:` with one action sentence; `Covers N advisories:` with each public id; `Source:`. The block's `title` keeps the template title with the id, the advisory's identity, and the block is one line of JSON. The Japanese post has the same lines, its headline the same English title. A title never enters the block or the thread's identity, a title learned after the root posted gets no reply, and a digest line carries it after the id.

Translations (coordinator decision 2026-11-06, ai-tools-alerts#rd8t): a translation is a reply in the thread (e tag marked root) from a manifest key whose first line is `lang: ja`, an optional second line `of: <event id>` naming the event it translates (absent = the root), a blank line, then the Japanese body. It carries no aitools-alert block; a lang reply that carries one is ignored entirely by readers (never a patch). For one target the latest lang reply from a manifest key wins. A lang reply from a non-manifest key is discussion. A curator `retract` retracts the translations with the thread. The digest root gets a `lang: ja` reply too. A curator's post or amendment gets a machine translation from the relay-bot key (ai-tools-alerts#bq8v, one Claude API call, body ending `（機械翻訳）`); readers keep a relay-bot lang reply on a curator thread as its translation unless a curator's exists, and every other relay-bot reply there stays discussion.

### Trust manifest and action vocabulary

- A trust manifest in the repo lists trusted poster pubkeys with a role: curator (a human) or relay-bot (jibot's automated posts). The manifest is signed by a trust root key, so a compromised GitHub account cannot add a poster. The root is a new key minted only for this service (Joi, 2026-11-05), held in Kura and used only to sign manifests, so a rotation of the ops-room key never re-issues every member's trust root. The retired ai-tools key `ef4cf523…` and the shared relay-owner key `18eafd07…` are not used for this. Adding a person is a manifest update plus channel write access on the relay. Version 1 trusted posters: Joi (as curator, posting with his current relay identity) and jibot (relay-bot).
- Channel writes (jibot's call): `#security-critical` is writable by curators and the bot only; members read. `#security-feed` is writable by members too, so discussion of an alert happens in its thread. Buzz has no reply-only tier, so member-started threads in the feed are accepted as the cost of having discussion in one place; the CLI trusts manifest keys only, so chatter is never an agent input.
- Curator posts and amendments (jibot's call): the repo ships a `curator` subcommand that signs a conforming post, amendment or retraction with a curator's own nsec read from a mode-600 file, never from argv. For a curator typing in the Buzz app instead, the CLI also accepts a plain-text convention in a reply from a curator key: a first line of `retract`, or `level: high`, applies to that thread. Any other text from a curator key is discussion.
- Action verbs, fixed: `upgrade` (product, minimum version), `disable_skill` (name), `remove_mcp_server` (name), `rotate_credential` (which), `stop_using` (marketplace or package), `review_setting` (path). The CLI rejects any other verb, and the skill tells the agent to treat an unknown verb as "notify only".

### Distribution

- A public GitHub repo under Joi's account (name is the builder's; it also names the kata project). Contents: this design, the schema, the vocabulary, the scope list, the trust manifest, the CLI, the skill, a launchd and a cron template, and a README written for a member.
- A mirror at https://buzz.ai-tools.md/alerts/ serving both channels as raw signed Nostr events in JSON, plus an Atom rendering for feed readers, plus the current trust manifest. Agents verify the event signatures locally against the manifest. Hosting (jibot's call): the Caddy container that already fronts the relay on the buzz-aitools VM serves a static directory at that path; the poster writes the files after each post and copies them to the VM over the existing SSH route. This needs no DNS change, which matters because no Kura token can edit the ai-tools.md zone (jibot-code#zxrj). A hostname such as alerts.ai-tools.md on Cloudflare Pages is the alternative if the path ever needs to move off the relay, and it would cost Joi a one-time DNS step.
- The CLI, one small Python program with no network writes: `init` (optionally create a key and print the join steps), `pull` (fetch the mirror, verify signatures and the manifest, store state), `check` (match advisories against the local inventory: agent CLI versions, IDE versions, installed skills directories, MCP config files, runtimes), `notify` (desktop notification, iMessage, Signal, Telegram or a webhook, the member's choice), `plan` (print the actions for the agent). Hourly schedule by the provided templates. A Claude Code SessionStart hook runs `pull` and `check` so a critical item interrupts the next session even without the schedule.
- The skill (SKILL.md for Claude Code, a Hermes optional skill, an AGENTS.md snippet for Codex): on a critical match, tell the person first, then prepare the fix, then ask. Auto-apply is opt-in per verb in the CLI config; `upgrade` is the only verb expected to be automated. `disable_skill` and `rotate_credential` stay ask-first (jibot's call).

### Supply: the fleet watch becomes the producer

- Do not gate the first post on the collector (jibot's call). The poster consumes one normalized candidate shape behind two adapters: the live heartbeat's `run.json` and `feeds.json` in the jibot workspace's security-watch/runs/ today, and the d9aa run-record contract once that collector is rescued. The collector rescue (amplifier-bundle-joi#d9aa is closed expired-reopenable with five major findings open; #vy7y deployment has no host chosen) is its own slice and runs in parallel. Hourly discovery arrives with the rescued collector; until then real-time means the heartbeat's six-hour cadence, and the design says so to members.
- Runner and host (jibot's call): the poster Mac, always on, which already runs the Security desk. An hourly launchd job runs the deterministic collector; when it finds a new candidate it starts one model turn through the fleet's existing unattended launch path, inside the 25-minute budget. Model turns are capped at four a day in total, so daily model cost does not rise above today's four heartbeat runs; a fifth candidate in a day waits for the next day unless it is a KEV critical, which needs no model turn. The poster Mac holds the SSH route to the relay VM, so the poster and the mirror copy run there too.
- A new poster step takes the collector's run record, applies the scope list and the level rules, drafts the human body (templated for relay-bot posts), and posts to the relay with jibot's ai-tools key from the fleet's secrets store. The existing buzz-post is ops-room only and says so; the ai-tools relay has no machine poster today, so this step is new code, placed beside buzz-post in cell-fleet ops/buzz or in the new repo (builder's call).
- The daily digest is one post built from the day's feed items.
- The fleet exposure check, the iMessage to Joi and the kata finding issues continue as today. The channel receives the advisory and the action, never host names, versions observed or evidence files.

### Interrupt delivery

- Joi: the existing iMessage path from the watch, unchanged, plus the Buzz post.
- Members: their own agent via `notify`, and the Buzz app if it supports per-channel notification (builder to verify; a mention of every member on critical posts is a fallback to test for noise).

### Catalog channel (ai-tools-alerts#q03f, v2 design section 1)

Every in-scope advisory is also posted, whole, to a third channel, #security-catalog, which the mirror serves as `catalog.json`; machines read it, and the CLI matches it (ai-tools-alerts#8nb4). The channel posts stay as they are: only channel-class products at high or critical reach #security-feed, plus a catalog or out product's remote code execution at high where its scope entry has `channel_if`.

- **Switch.** `spec/catalog-channel.json`, `{"catalog": "<uuid>"}`. Absent, nothing changes anywhere. Malformed, or naming an alert channel: the catalog is off for that run in the poster and in the exporter, and alert work goes on. The channel and the file are added by ai-tools-alerts#q3fd.
- **What is catalogued.** Each ledger thread whose product is still in scope (under its current name, or an earlier name its scope entry lists in `formerly`) and starts at its level, and each notice held for the digest; never a synthetic check. A key is one advisory for one product (`<product>|<advisory id>`). The poster reads them in memory under the ledger lock, before the digest drops the notices it lists, and keeps them in `<ledger>.catalog-known.json`, which outlives the held list (newest first sight kept, at most 5,000 keys and 48 MiB as written). Each merge carries its run's time, so a pass that merges late never replaces a later run's advisory with its own older one.
- **What is posted.** A root per key whenever its advisory differs from the last one posted for that key: a two-line body and the whole block. No replies, no Japanese copy. A reader takes the newest root per advisory id and product; where the same advisory and product also has a thread in `feed.json` or `critical.json`, the alert thread governs, so a curator's correction or retraction there wins. A catalog-only advisory has no curator path yet.
- **When.** After the ledger lock is released and the checkpoint is signed, under the catalog's own lock (waited for at most 60 seconds), at most 20 attempts a run, refused ones included, and none after 120 seconds. A refused post is not tried again until its advisory changes; a failed or unknown one is sent again next run, and a duplicate root is harmless. Nothing in the lane reaches the exit code; the summary line ends `catalog=<sent>/<waiting>` (or `busy`, `error`, `off-bad-spec`, `off-bad-paths`) once the file exists.
- **Never in the checkpoint, never in the alert files.** The lane never records a debt for the checkpoint, and the checkpoint binds events to the two alert channels only: released readers v0.1.6 and v0.1.7 refuse a checkpoint that names an event outside `feed.json` and `critical.json`. The exporter binds `catalog.json` to the catalog id alone and the alert files to the two alert ids, writes `catalog.json` after everything else, starts it only in the first 150 seconds of a run, cuts it off after 75 seconds, refuses a catalog file that is not a regular file without blocking on it, and on any catalog failure keeps the previous file and changes nothing else. The mirror's withholding of a catalog entry is therefore not detected; a catalog checkpoint is a later slice (8nb4 names the limit).
- **Muting.** The Buzz app cannot leave a channel muted by default: a mute is each member's own flag, kept by their client. Members need not join #security-catalog; the CLI reads `catalog.json`.
- **Known gaps.** Notices digested before the lane is switched on are not catalogued, and a notice seen again after its digest does not update its entry (ai-tools-alerts#v46a). A notice digested in a run whose catalog pass found the lock busy for 60 seconds is not catalogued.

## Constraints

- Fleet rules apply: secrets from Kura by helper, never printed; repoman-managed repos land by handoff; no third-party messages beyond the two channels and the mirror; outward-facing changes (the public repo, the mirror domain) are class a and were approved in this design, nothing else is.
- Posts and fetched advisories are untrusted text. The poster never executes anything from a source; the CLI never executes anything from a post.
- The relay requires NIP-42 auth for reads, so the mirror is required for account-free consumption.
- Keep the first slice under 600 changed lines per issue; split by component (poster, mirror, CLI, skill, collector rescue).

## Existing tools this overlaps

| Tool | Decision |
|---|---|
| security watch heartbeat + collector d9aa + routing hht9 + rollout vy7y | kept; d9aa rescued and made hourly; vy7y absorbs the schedule change |
| cell-fleet ops/buzz/bin/buzz-post, buzz-notify | kept as ops-room posters; a new ai-tools poster is added beside them |
| cell-fleet's Buzz npub intake script | kept; it stays the member intake for the relay |
| amplifier-bundle-joi news_watch.py, upstream radar | kept; they are discovery inputs the collector may read |
| opsctl kata-buzz-bridge | kept, unrelated |
| morning Security desk | kept; reads the same watch output as today |

## Decided by Joi after the builder check

The trust root is a new dedicated key (2026-11-05). Minting it and storing it in Kura is the first step of the plan; the README's bootstrap pins its public key.

## Left to the builder

The repo name, the schema field names, the digest hour, the CLI language packaging (Python assumed), the hook wiring per harness, the test fixtures for hostile posts, and the order of slices.

## Acceptance

- A member on a fresh Mac installs from the README, runs `pull` and `check` with no account, and sees a mocked critical advisory interrupt a Claude Code session with the action prepared and not applied.
- A synthetic KEV entry in scope tier 1 posts to `#security-critical` and `#security-feed` under jibot's key within one collector cycle, and Joi receives the iMessage.
- A second trusted poster is added by manifest update and their test post verifies; a post from a non-listed key is ignored by the CLI.
- The daily digest posts once, with every feed item of the day.
- Daily model runs of the watch do not increase.
- A relay-bot critical with an opt-in `upgrade` configured does not apply; the same advisory re-signed by a curator key does.
