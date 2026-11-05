# ai-tools security alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two alert channels on the ai-tools Buzz relay, a signed public mirror, and a zero-dependency CLI plus skill that lets a member's agent verify, match and act on alerts, fed hourly by the fleet security watch.

**Architecture:** One public repo `ai-tools-alerts` holds the spec files (advisory schema, action verbs, scope tiers, primary domains, signed trust manifest), a Python package `aitools_alerts` with the member CLI and the fleet poster, the skills and the schedule templates. The poster runs hourly on the poster Mac, reads the heartbeat's run records and the CISA KEV JSON, applies the level rules, and posts through the Buzz CLI on the relay VM over SSH. A mirror exporter on the relay VM dumps the two channels' raw signed events to static files that Caddy serves at `https://buzz.ai-tools.md/alerts/`. The member CLI pulls those files, verifies BIP-340 signatures against the manifest, matches against the local inventory and notifies.

**Tech Stack:** Python 3.11+ standard library only for the member CLI (pure-Python BIP-340, bech32, tomllib, urllib); `websockets` as an optional extra for the curator subcommand; Buzz CLI (`~/buzz/target/release/buzz`) on the relay VM for posting; PostgreSQL (`buzz-prod-postgres-1`) and Caddy (`~/buzz/deploy/compose/Caddyfile.pair`) on the VM for the mirror; launchd on the poster Mac; systemd timer on the VM; pytest.

**Spec:** the jibot workspace's docs/plans/2026-11-05-ai-tools-security-alerts-design.md

## Global Constraints

- Levels are exactly `critical`, `high`, `notice`. Verbs are exactly `upgrade`, `disable_skill`, `remove_mcp_server`, `rotate_credential`, `stop_using`, `review_setting`. Any other verb is rejected by the CLI and treated as notify-only by the skill.
- The CLI never executes a string from a post, never auto-applies from a `relay-bot` post, and auto-applies from a `curator` post only for verbs the member opted into in config.
- Critical fires only by rule: product in scope tier 1 and (KEV exploited, or trojanized/malicious release confirmed by a primary source, or injection-to-execution with a fix). A critical whose cited primary source is not on the allowlist or did not fetch posts as `high` with the word "unverified" in the body.
- Scope tier 2 (macOS, Linux distributions, browsers) never posts critical.
- Trust root is a new dedicated key: vault line `AITOOLS_ALERTS_ROOT_NSEC` in Kura, used only to sign manifests. Public key pinned in the CLI as `TRUST_ROOT_PUBKEY` and in the README.
- Secrets come from Kura helpers or mode-600 files, never argv, never printed. jibot's relay key on the VM is `~/.buzz-keys/agent.nsec`; the Kura copy is `BUZZ_AITOOLS_AGENT_NSEC`.
- Relay: NIP-42 URL `wss://buzz.ai-tools.md`, HTTP API `https://buzz.ai-tools.md`, VM `<relay-vm>`, Buzz CLI `~/buzz/target/release/buzz`.
- Model turns for the watch stay at four a day; the 25-minute budget per run holds.
- Nothing private leaves the fleet: posts carry advisory, products, actions, sources; never host names, observed versions or evidence paths.
- Public repo creation is approved (class a, 2026-11-05). No other outward-facing change is.
- Slices land under 600 changed lines each. The new repo is Joi's and not repoman-managed; amplifier-bundle-joi and cell-fleet are repoman-managed (handoff, never push main).

## Review Focus

1. A post whose fenced block parses but whose `products[].fixed` is missing for an `upgrade` action: the CLI must refuse the action and still notify (Task A4 test `test_upgrade_without_fixed_is_notify_only`).
2. A mirror file served mid-write or truncated: `pull` must keep the last good state and report "mirror unreadable", never an empty feed (Task A5 test `test_pull_truncated_json_keeps_previous_state`).
3. An event signed by a key that was in the manifest but is absent from the current manifest: it must be dropped and counted, not trusted from cache (Task A5 test `test_revoked_poster_events_dropped`).
4. A KEV entry whose `vendorProject`/`product` string does not match the scope list exactly ("Anthropic" vs "Anthropic Claude Code"): the matcher must be case-insensitive substring on the scope entry's `match` patterns and must log unmatched tier-1-looking vendors for review (Task B2 test `test_scope_match_is_pattern_based`).
5. The poster's SSH to the VM succeeds but the Buzz CLI exits non-zero (exit 3 auth, 5 write conflict): the poster must not mark the advisory posted and must retry next hour, never duplicate (Task B4 test `test_send_failure_leaves_advisory_unposted`).

---

## Slice A: repo, trust root, spec files, member CLI (new repo `ai-tools-alerts`)

Kata: create project `ai-tools-alerts` after Task A1; file one issue per task below under it. Epic in jibot-code links everything.

### Task A1: Repo scaffold and trust root key

**Files:**
- Create: `README.md`, `pyproject.toml`, `LICENSE` (MIT), `docs/design.md` (copy of the spec), `docs/plan.md` (this file), `.gitignore`
- Create: `aitools_alerts/__init__.py`, `aitools_alerts/nostr.py`, `tests/test_nostr.py`
- Create: `trust/root.pub` (64 hex chars)

**Interfaces:**
- Produces: `nostr.keygen() -> tuple[str, str]` (sec hex, pub hex); `nostr.sign_event(sec_hex: str, event: dict) -> dict` (fills `id`, `pubkey`, `sig`); `nostr.verify_event(event: dict) -> bool`; `nostr.event_id(event: dict) -> str` (sha256 of the NIP-01 serialization `[0,pubkey,created_at,kind,tags,content]`); `nostr.npub(pub_hex) -> str`, `nostr.nsec_to_hex(nsec: str) -> str` (bech32, NIP-19).

- [ ] **Step 1: Write the failing tests** in `tests/test_nostr.py`: `test_bip340_vector_1` (the BIP-340 test vector 0: seckey 3, pubkey `F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9`, message 32 zero bytes, signature from the BIP vector table, expect verify True), `test_sign_then_verify_roundtrip`, `test_tampered_content_fails_verify`, `test_event_id_matches_known_event` (one real kind-1 event from the Nostr NIP-01 examples with its published id), `test_nsec_roundtrip` (hex -> nsec -> hex).
- [ ] **Step 2: Run** `pytest tests/test_nostr.py -v` — expect FAIL, module missing.
- [ ] **Step 3: Implement `aitools_alerts/nostr.py`** with pure-Python secp256k1 point arithmetic and BIP-340 sign/verify as in the BIP reference implementation, plus bech32 encode/decode for `npub`/`nsec`. No third-party imports.
- [ ] **Step 4: Run** the tests — expect PASS.
- [ ] **Step 5: Create the GitHub repo** `gh repo create Joi/ai-tools-alerts --public --description "Security alerts for people running AI agents: two Buzz channels, a signed mirror, and a CLI your agent can act on"` using the token from `get_github_token`. Push `main`.
- [ ] **Step 6: Mint the trust root on the poster Mac**: `python3 -c 'from aitools_alerts.nostr import keygen; ...'` writing the sec hex to a 0600 temp file, append `AITOOLS_ALERTS_ROOT_NSEC=<hex>` to the Kura vault through `the Kura edit helper` with `EDITOR` set to a one-shot append script (the script appends the line from the temp file and exits), wipe the temp file, verify with `get_secret AITOOLS_ALERTS_ROOT_NSEC | wc -c` (65). Commit only `trust/root.pub` with the pub hex.
- [ ] **Step 7: Commit** `git commit -m "feat: nostr primitives, trust root public key"`.

### Task A2: Spec files

**Files:**
- Create: `spec/advisory.schema.json`, `spec/actions.json`, `spec/scope.json`, `spec/primary-domains.json`
- Create: `aitools_alerts/schema.py`, `tests/test_schema.py`, `tests/fixtures/posts/*.md`

**Interfaces:**
- Produces: `schema.parse_post(content: str) -> Advisory | None` (finds the last fenced block with info string `aitools-alert`, validates, returns a dataclass); `schema.render_post(adv: Advisory, body: str) -> str` (body, blank line, fenced block); `Advisory` dataclass fields exactly: `id, aliases: list[str], level, advisory_severity: str|None, title, products: list[Product], actions: list[Action], sources: list[Source], posted_by: str` (role), `posted_at: int, expires_at: int|None`; `Product(name, ecosystem, affected: str|None, fixed: str|None)`; `Action(verb, target, value: str|None)`; `Source(url, published_at: str|None)`.
- Produces: `schema.VERBS`, `schema.LEVELS`, `schema.load_scope() -> list[ScopeEntry]` with `ScopeEntry(name, ecosystem, tier: int, match: list[str])`; `schema.is_primary(url) -> bool`.

- [ ] **Step 1: Write failing tests**: `test_parse_valid_post_fixture`, `test_parse_ignores_block_without_info_string`, `test_unknown_verb_rejected`, `test_unknown_level_rejected`, `test_render_then_parse_roundtrip`, `test_primary_domain_github_only_under_advisories_paths` (`https://github.com/anthropics/claude-code/security/advisories/GHSA-x` True, `https://github.com/foo/bar/issues/1` False), `test_scope_tiers_loaded` (Claude Code tier 1, macOS tier 2).
- [ ] **Step 2: Run** `pytest tests/test_schema.py -v` — FAIL.
- [ ] **Step 3: Write the spec files.** `actions.json`: the six verbs with a one-line meaning and the `target` kind each takes. `scope.json`: tier 1 entries for Claude Code (`claude-code`), Codex (`codex`), Cursor (`cursor`), Gemini CLI (`gemini-cli`), Hermes (`hermes`), OpenClaw (`openclaw`), MCP servers and clients (`mcp`), ClawHub and skills.sh (`skill`), Node (`node`), Python (`python`), Go (`go`), Rust (`rust`), Docker (`docker`), Tailscale (`tailscale`), OpenSSH (`openssh`), git (`git`); tier 2 for macOS (`macos`), Ubuntu/Debian/Fedora (`linux`), Chrome/Safari/Firefox (`browser`); each with `match` patterns (lowercase substrings, e.g. `["claude code", "@anthropic-ai/claude-code"]`). `primary-domains.json`: `cisa.gov`, `kb.cert.org`, `osv.dev`, `support.apple.com`, `nodejs.org`, `python.org`, `go.dev`, `ubuntu.com`, `debian.org`, `tailscale.com`, `openssh.com`, `docs.docker.com`, `cursor.com`, `openai.com`, `anthropic.com`, `blog.google`, `github.com` with path prefixes `/advisories/` and `*/security/advisories/`. `advisory.schema.json`: JSON Schema draft 2020-12 for the block.
- [ ] **Step 4: Implement `schema.py`** (hand-written validation; no jsonschema dependency; the schema file documents the contract and a test asserts the dataclass fields equal the schema's required keys).
- [ ] **Step 5: Run** tests — PASS. **Commit** `feat: advisory schema, verbs, scope tiers, primary domains`.

### Task A3: Trust manifest

**Files:**
- Create: `trust/manifest.json`, `aitools_alerts/manifest.py`, `scripts/sign-manifest.py`, `tests/test_manifest.py`

**Interfaces:**
- Produces: `manifest.load(path_or_bytes) -> Manifest` where the manifest is a signed Nostr event of kind `30078`, tag `["d","aitools-alerts-manifest"]`, `content` = JSON `{"version": int, "issued_at": iso, "posters": [{"pubkey": hex, "role": "curator"|"relay-bot", "name": str}]}`; `manifest.verify(m: Manifest, root_pubkey: str) -> bool`; `manifest.role_of(m, pubkey) -> str|None`; constant `TRUST_ROOT_PUBKEY` in `aitools_alerts/__init__.py` equal to `trust/root.pub`.
- `scripts/sign-manifest.py <content.json>`: reads the root nsec via `get_secret AITOOLS_ALERTS_ROOT_NSEC` (sourcing `the Kura secrets helper` in a subprocess), writes `trust/manifest.json`, prints the event id.

- [ ] **Step 1: Failing tests**: `test_manifest_signed_by_root_verifies`, `test_manifest_signed_by_other_key_rejected`, `test_manifest_version_must_increase` (loading v2 then v1 raises), `test_role_lookup`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Produce manifest v1 on the poster Mac** with posters: Joi's current relay identity (`18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29`, role curator, name "Joi") and jibot's ai-tools pubkey (`~/.buzz-keys/agent.pub.hex` on the VM, role relay-bot, name "jibot"). Commit `trust/manifest.json`.
- [ ] **Step 6: Commit** `feat: signed trust manifest v1`.

### Task A4: Inventory, matching and action planning

**Files:**
- Create: `aitools_alerts/inventory.py`, `aitools_alerts/check.py`, `aitools_alerts/versions.py`, `tests/test_inventory.py`, `tests/test_check.py`, `tests/fixtures/inventory/*.json`

**Interfaces:**
- Produces: `inventory.collect(home: Path = Path.home()) -> Inventory` with `Inventory.products: dict[ecosystem, list[Installed(name, version: str|None, path: str)]]`; collectors: `claude --version`, `codex --version`, `/Applications/Cursor.app/Contents/Info.plist` `CFBundleShortVersionString`, `gemini --version`, `~/.claude/skills/*` and `~/.claude/plugins/*` directory names (ecosystem `skill`), MCP servers from `~/.claude.json` (`mcpServers` keys), `~/.codex/config.toml` (`mcp_servers`), `~/.cursor/mcp.json`; `node --version`, `python3 --version`, `go version`, `rustc --version`, `docker --version`, `tailscale version`, `ssh -V`, `git --version`, `sw_vers -productVersion` (macos). Each collector is a function that returns `Installed|None` and swallows missing binaries; nothing executes with user-controlled arguments.
- Produces: `versions.affected(installed: str, affected: str|None, fixed: str|None) -> bool` (dotted-integer compare; `affected` is `<x.y.z` or `>=a,<b` or `*`); `check.match(advs: list[Advisory], inv: Inventory) -> list[Match(adv, installed, actions_allowed: list[Action], reason)]`; `check.plan(m: Match, config) -> Plan(notify: bool, auto_apply: list[Action], prepare: list[Action])` where `auto_apply` is non-empty only when `adv.posted_by == "curator"` and `config.auto_apply` contains the verb.

- [ ] **Step 1: Failing tests**: `test_collect_from_fixture_home` (fixture home with fake `~/.claude.json`, skills dir, Cursor plist), `test_version_affected_ranges`, `test_match_claude_code_below_fixed`, `test_no_match_when_version_at_fixed`, `test_skill_match_by_name`, `test_relay_bot_post_never_auto_applies`, `test_curator_upgrade_auto_applies_when_opted_in`, `test_upgrade_without_fixed_is_notify_only`, `test_unknown_verb_is_notify_only`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** the three modules. **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat: local inventory, matching, action planning`.

### Task A5: Pull, state and the CLI

**Files:**
- Create: `aitools_alerts/pull.py`, `aitools_alerts/state.py`, `aitools_alerts/config.py`, `aitools_alerts/notify.py`, `aitools_alerts/cli.py`, `tests/test_pull.py`, `tests/test_cli.py`, `tests/fixtures/mirror/{feed.json,critical.json,manifest.json}`
- Modify: `pyproject.toml` (console script `aitools-alerts = aitools_alerts.cli:main`)

**Interfaces:**
- Consumes: Tasks A1 to A4.
- Produces: `pull.fetch(base_url: str, state: State, fetch=urllib) -> PullResult(new_events: list[dict], dropped: Counter, manifest: Manifest, error: str|None)`; mirror layout `base_url/feed.json`, `critical.json`, `manifest.json`, each JSON `{"generated_at": iso, "channel": name, "events": [NIP-01 event dicts]}`; verification order: manifest signed by `TRUST_ROOT_PUBKEY`, event signature, event pubkey in current manifest, parse block; `Advisory.posted_by` is always set from the manifest role of the event's pubkey, never from the block (a block claiming `curator` under a relay-bot key is still relay-bot); replies (events with an `e` tag marked `reply`) are applied to their root in `created_at` order: a curator-key reply whose first line is `retract` hides the root from `check`, one whose first line is `level: high` lowers the level, and any reply with a block updates the block's fields; `state` at `~/.local/state/aitools-alerts/` with `events.json` (verified events by id), `seen.json` (notified ids), `last_pull.json`; config at `~/.config/aitools-alerts/config.toml` keys `mirror_url` (default `https://buzz.ai-tools.md/alerts/`), `notify = ["desktop"]` (choices `desktop`, `imessage`, `signal`, `telegram`, `webhook`), `auto_apply = []`, `imessage_to`, `signal_to`, `telegram_chat_id`, `webhook_url`.
- CLI commands: `init [--make-key]` (writes config; with `--make-key` writes `~/.config/aitools-alerts/key.nsec` 0600 and prints the npub and the Buzz pairing steps), `pull`, `check [--json]`, `notify` (sends for unseen critical matches, then marks seen), `plan <advisory-id>` (prints actions and the exact commands the agent should prepare, e.g. `npm install -g @anthropic-ai/claude-code@<fixed>`), `run` (= pull, check, notify; exit 2 when a critical match is unseen), `keygen` (same as init --make-key).
- `notify.send(channel, text, config) -> SendResult(accepted: bool, detail: str)`: desktop via `osascript -e 'display notification'` on macOS and `notify-send` on Linux; iMessage via `imsg` if present; Signal via `signal-cli` if present; Telegram via Bot API; webhook POST JSON. Every transport is a subprocess with a fixed argv list or a urllib POST; the alert text is passed as one argument.

- [ ] **Step 1: Failing tests**: `test_pull_verifies_and_stores_fixture_events`, `test_pull_rejects_manifest_not_signed_by_root`, `test_pull_drops_event_with_bad_signature`, `test_revoked_poster_events_dropped`, `test_pull_truncated_json_keeps_previous_state`, `test_run_exit_code_2_on_unseen_critical`, `test_posted_by_role_comes_from_manifest_not_block`, `test_curator_retract_reply_hides_root`, `test_relay_bot_reply_cannot_retract`, `test_notify_marks_seen_only_after_accepted`, `test_notify_text_contains_level_title_action_source`, `test_cli_init_writes_config_and_no_key_by_default`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Verify install**: `pipx install .` on a clean venv, `aitools-alerts init && aitools-alerts pull --mirror-url file://$PWD/tests/fixtures/mirror/ && aitools-alerts check` prints the fixture critical. **Commit** `feat: pull, verify, notify, CLI`.

### Task A6: Skills, hooks and schedule templates

**Files:**
- Create: `skills/claude-code/aitools-alerts/SKILL.md`, `skills/hermes/aitools-alerts/SKILL.md` (frontmatter in the Hermes optional-skill shape: name, description, version, platforms, prerequisites.commands `[aitools-alerts]`), `snippets/AGENTS.md`, `hooks/claude-code/session-start.sh`, `templates/launchd/com.aitools.alerts.plist` (hourly, `aitools-alerts run`), `templates/cron/aitools-alerts.cron`, `tests/test_templates.py`
- Modify: `README.md` (member install: pipx, init, schedule, skill install for each harness, what an alert looks like, what the agent will and will not do)

**Interfaces:**
- Consumes: CLI from A5 (`run` exit 2, `plan`).
- The SKILL.md procedure, fixed: on session start or when asked, run `aitools-alerts run --json`; if exit 2, tell the person the level, title, affected product and version, and the action, with the primary source link; run `aitools-alerts plan <id>`; prepare the fix (open the command, do not run) and ask; run only when the person says yes or `plan` says `auto_apply` for that verb; never run anything not printed by `plan`; after applying, run `aitools-alerts check` again and report.
- `hooks/claude-code/session-start.sh`: runs `aitools-alerts run --quiet`; on exit 2 prints one line `AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill` to stdout so it lands in context.

- [ ] **Step 1: Failing test** `test_launchd_template_is_valid_plist` (`plutil -lint`), `test_skill_frontmatter_has_name_and_description` for both skills.
- [ ] **Step 2: Run** — FAIL. **Step 3: Write the files.** **Step 4: Run** — PASS.
- [ ] **Step 5: Manual acceptance on a fresh macOS user or a clean venv**: install per README, point `mirror_url` at the fixture mirror served by `python3 -m http.server`, start a Claude Code session with the hook, confirm the one-line interrupt appears and the skill prepares `npm install -g @anthropic-ai/claude-code@<fixed>` without running it. Record the transcript path in the kata issue.
- [ ] **Step 6: Commit** `feat: skills, session-start hook, schedule templates, member README`.

### Task A7: Curator subcommand

**Files:**
- Create: `aitools_alerts/curator.py`, `aitools_alerts/relay.py`, `tests/test_curator.py`
- Modify: `aitools_alerts/cli.py`, `pyproject.toml` (extra `curator = ["websockets>=12"]`)

**Interfaces:**
- Consumes: `schema.render_post`, `nostr.sign_event`, manifest roles.
- Produces: `curator post --level --title --product ... --action verb:target[:value] --source url [--channel feed|critical]`, `curator amend <event-id> --level|--fixed|...`, `curator retract <event-id>`; key read from `~/.config/aitools-alerts/key.nsec`; `relay.send(event, relay_url="wss://buzz.ai-tools.md", key)` performs NIP-42 AUTH then `EVENT`, returns the relay's `OK` tuple. Channel ids read from `spec/channels.json` (written in Task E1). Amend and retract are kind-9 replies with `["e", root_id, "", "reply"]` whose content is the convention text (`level: high` or `retract`) plus a block.
- [ ] **Step 1: Failing tests**: `test_post_event_has_block_and_h_tag`, `test_retract_is_reply_with_convention_text`, `test_send_refuses_without_curator_role` (manifest lookup), fake websocket server fixture for `test_nip42_auth_then_event_ok`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: curator post/amend/retract over NIP-42`.

## Slice B: the fleet poster (same repo, `aitools_alerts/poster/`)

### Task B1: Candidate adapters

**Files:**
- Create: `aitools_alerts/poster/__init__.py`, `aitools_alerts/poster/candidates.py`, `tests/poster/test_candidates.py`, `tests/fixtures/heartbeat/{run.json,feeds.json}` (redacted copies of the jibot workspace's outputs/security-watch/runs/2026-11-04T175014Z/), `tests/fixtures/collector/run-record.json` (the d9aa schema_version=1 shape from amplifier-bundle-joi/bundles/security-watch/tests/fixtures/)

**Interfaces:**
- Produces: `Candidate(id, aliases, product_text: str, advisory_severity, local_level_hint: str|None, exploited: bool, trojanized: bool, injection_exec: bool, fixed: str|None, affected: str|None, sources: list[Source], observed_at)`; `candidates.from_heartbeat(run_dir: Path) -> list[Candidate]` (findings dict values, `source` to one Source, `local_severity` to the hint; drops `hosts`, `evidence`, `kata`); `candidates.from_kev(kev_json: dict, since_date: str) -> list[Candidate]` (`exploited=True`, product_text = `vendorProject + " " + product`, source = the KEV catalog URL plus `notes`/vendor URL when present); `candidates.from_collector(record: dict) -> list[Candidate]`.
- [ ] **Step 1: Failing tests**: one per adapter plus `test_heartbeat_adapter_never_emits_hosts_or_evidence` (serialize the candidate list and assert no host name from the fixture appears), `test_kev_adapter_filters_by_date_added`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: poster candidate adapters (heartbeat, KEV, collector)`.

### Task B2: Level rules and scope matching

**Files:**
- Create: `aitools_alerts/poster/rules.py`, `tests/poster/test_rules.py`

**Interfaces:**
- Produces: `rules.scope_of(product_text) -> ScopeEntry|None` (lowercase substring over `match`, first tier-1 hit wins over tier 2); `rules.level_for(c: Candidate, scope: ScopeEntry, source_ok: bool) -> tuple[level, str]` (reason) implementing the Global Constraints exactly: tier 1 and (`exploited` or (`trojanized` and source_ok) or (`injection_exec` and `fixed` and source_ok)) is `critical`; tier 1 with a fix and severity text matching code execution, credential or data loss, or any tier 2 `exploited`, is `high`; a would-be critical with `source_ok=False` is `high` with reason `unverified`; otherwise `notice`; `rules.source_ok(c, fetch) -> bool` (at least one source `schema.is_primary` and HTTP 200 on HEAD or GET within 10 s).
- [ ] **Step 1: Failing tests**: `test_kev_tier1_is_critical`, `test_kev_tier2_is_high`, `test_trojanized_without_primary_is_high_unverified`, `test_injection_exec_needs_fix`, `test_scope_match_is_pattern_based`, `test_out_of_scope_is_none`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: level rules`.

### Task B3: Post composition and advisory ledger

**Files:**
- Create: `aitools_alerts/poster/compose.py`, `aitools_alerts/poster/ledger.py`, `tests/poster/test_compose.py`, `tests/poster/test_ledger.py`

**Interfaces:**
- Produces: `compose.root_post(c, level, scope) -> tuple[str, Advisory]` (templated human body: one line level and title, one line affected and fixed, one line the action in plain words, one line the primary source; then the block via `schema.render_post`); `compose.reply_post(prev: Advisory, c, changes: dict) -> str`; `compose.digest(advs_today: list[Advisory], date) -> str`.
- `ledger.Ledger(path=~/.local/state/aitools-alerts-poster/ledger.json)`: `lookup(aliases) -> Entry|None` (`Entry(root_event_id, channel_ids: dict, level, aliases, posted_at, last_change)`), `record_root(...)`, `record_reply(...)`, `pending(...)` and `clear_pending` so a send whose outcome is unknown is never re-sent (mirror the dedup discipline of security_route.py: write pending before sending). Lock file beside the ledger.
- [ ] **Step 1: Failing tests**: `test_root_post_body_has_four_lines_and_block`, `test_body_never_contains_host_names` (candidate carries none; assert against a denylist of fleet host names in the fixture), `test_reply_only_carries_changed_fields`, `test_digest_lists_every_item_once`, `test_ledger_alias_merge`, `test_pending_blocks_resend`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: post composition and ledger`.

### Task B4: Relay transport and the `aitools-alerts-poster` command

**Files:**
- Create: `aitools_alerts/poster/transport.py`, `aitools_alerts/poster/main.py`, `tests/poster/test_transport.py`, `tests/poster/test_main.py`
- Modify: `pyproject.toml` (console script `aitools-alerts-poster = aitools_alerts.poster.main:main`)

**Interfaces:**
- Produces: `transport.send(channel_id: str, content: str, reply_to: str|None, ssh=subprocess) -> SendResult(ok, event_id: str|None, exit_code, stderr)` running `ssh <relay-vm> '<the remote command>'`, the remote command being `env BUZZ_RELAY_URL=https://buzz.ai-tools.md BUZZ_PRIVATE_KEY_FILE=$HOME/.buzz-keys/agent.nsec $HOME/buzz/target/release/buzz messages send --channel <id> --content - [--reply-to <id>]` (single-quoted, so the VM's shell expands `$HOME`; superseded by the wrapper at the configured absolute path) with content on stdin; the remote argv is built with `shlex.join`; the key is read by a tiny remote wrapper script installed in Task E1 (`~/bin/buzz-send`) so the nsec is never on argv; event id parsed from the CLI's JSON stdout (builder verifies the field name on the VM; fall back to `SELECT encode(id,'hex') FROM events WHERE pubkey=... ORDER BY created_at DESC LIMIT 1` through `docker exec buzz-prod-postgres-1 psql`).
- `main.run(now, config)`: load candidates (heartbeat run dirs newer than the watermark; KEV JSON fetched from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` with `If-Modified-Since`; collector records when present), scope, level, ledger lookup, compose, send to `critical` then `feed` for critical, `feed` for high, hold notice for the digest; at the digest hour (`09:00 Asia/Tokyo`) send the digest; write a watermark only after sends succeed; exit 0 with a one-line summary, exit 1 on any send failure.
- [ ] **Step 1: Failing tests**: `test_send_failure_leaves_advisory_unposted`, `test_critical_posts_to_both_channels_in_order`, `test_high_posts_to_feed_only`, `test_notice_waits_for_digest`, `test_duplicate_alias_becomes_reply`, `test_watermark_advances_only_on_success`, `test_kev_fetch_not_modified_uses_cache`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: poster transport and hourly run`.

## Slice C: the mirror (relay VM + cell-fleet overlay)

### Task C1: Mirror exporter

**Files (repo `ai-tools-alerts`):**
- Create: `mirror/export_mirror.py`, `mirror/aitools-alerts-mirror.service`, `mirror/aitools-alerts-mirror.timer` (every 5 min), `tests/mirror/test_export.py`

**Interfaces:**
- Produces: `export_mirror.py --channels spec/channels.json --out ~/alerts-mirror --manifest trust/manifest.json` reading events with `docker exec buzz-prod-postgres-1 psql -U buzz -d buzz -At -c "SELECT json_build_object('id',encode(id,'hex'),'pubkey',encode(pubkey,'hex'),'created_at',extract(epoch from created_at)::bigint,'kind',kind,'tags',tags,'content',content,'sig',encode(sig,'hex')) FROM events WHERE channel_id = '<uuid>' AND deleted_at IS NULL ORDER BY created_at"`, writing `feed.json`, `critical.json`, `feed.atom` (one entry per root post, title from the advisory title, content the human body), `manifest.json`, each to a temp file then `os.replace`. Re-verifies every exported event with `nostr.verify_event` and drops any that fail (a created_at rounding mismatch would show here).
- [ ] **Step 1: Failing tests**: `test_export_writes_atomically` (temp then replace), `test_exported_events_verify` (fixture rows), `test_atom_has_one_entry_per_root`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: mirror exporter and systemd timer`.

### Task C2: Caddy path and VM install (cell-fleet, repoman-managed)

**Files:**
- Modify: `cell-fleet/ops/buzz/compose-overlays/buzz-aitools/Caddyfile.pair` (add before the catch-all: `handle_path /alerts/* { root * /srv/alerts; file_server; header Cache-Control "max-age=60" }`), `compose.override.yml` (mount `~/alerts-mirror:/srv/alerts:ro` on the caddy service), `ops/buzz/README.md` (mirror section)
- Create: `ops/buzz/compose-overlays/buzz-aitools/install-mirror.sh` (copies the exporter, service and timer to the VM, `systemctl --user enable --now`, copies Caddyfile and override to `~/buzz/deploy/compose/`, `docker compose up -d --wait` from that directory, bare `docker compose` as the overlay header requires)
- [ ] **Step 1: Failing test** in cell-fleet's bats suite: `caddyfile has /alerts handle before catch-all` (grep order) and `override mounts alerts-mirror read-only`.
- [ ] **Step 2: Run** the repo's scoped gate via `~/repos/cell-fleet/ops/repoman/bin/repoman-gate <slug> --repo .` — FAIL on the new test.
- [ ] **Step 3: Edit the overlay files and write `install-mirror.sh`.** **Step 4: Gate** — PASS.
- [ ] **Step 5: Install on the VM** (ops step, read-only for the relay, approved as part of the mirror): run `install-mirror.sh`, then `curl -sI https://buzz.ai-tools.md/alerts/manifest.json` returns 200 and `curl -s https://buzz.ai-tools.md/pair` still answers (pairing untouched). Record both in the kata issue.
- [ ] **Step 6: Commit, push the branch, `repoman-submit`.**

## Slice D: collector rescue and hourly cadence (amplifier-bundle-joi, repoman-managed)

Reopen amplifier-bundle-joi#d9aa on branch `d9aa-security-collector-review-repairs` (base e7dea79b). The three open major findings from the last review are the tasks; nothing else changes on that branch.

### Task D1: Missing evidence never lowers a rating (F3)
- Modify: `bundles/security-watch/scripts/security_watch.py` around line 680 and `parse_probe()` lines 326–328: `service_running` becomes tri-state `True|False|None`; `None` for missing executable or Docker output; carry-forward suppression requires `False`.
- Test: `test_missing_docker_output_keeps_prior_high` and `test_observed_stopped_service_allows_downgrade` in `tests/test_security_watch.py`.

### Task D2: Whole-fetch deadline (F5)
- Modify: the HTTP read loop near line 813: run the fetch in a worker thread with `deadline = min(per_source, remaining_budget)` and abandon it (close the socket) on timeout; the elapsed check at 818 moves before and after the join.
- Test: `test_stalling_read_inside_body_hits_deadline` with a fixture server that sends one byte every 2 s forever; assert the fetch returns an error within `deadline + 1 s`.

### Task D3: Watchdog test executes the watchdog
- Modify: `tests/test_security_watch.py:782-791`: restore `sw.run_tree` before the launch and assert the child process is gone after the watchdog interval (`os.kill(pid, 0)` raises).

### Task D4: Review, gate, handoff
- One whole-branch independent review with `FRESHEYES_GPT_MODEL=gpt-6-astra` (security-shaped), BLOCKERs fixed, SUBSTANTIVE fixed or rebutted in one kata comment with the evidence line; scoped gate through `repoman-gate`; `repoman-submit -r <slug> -p amplifier-bundle-joi -i d9aa`.

### Task D5: Rollout at hourly cadence (amplifier-bundle-joi#vy7y)
- Host: the poster Mac. launchd `com.joi.security-watch-collect` hourly running the collector in read-only mode writing `<collector-state>/runs/<ts>/run-record.json`; a second step in the same job starts one model turn through `kata-dispatch` against jibot-code#w3xq only when the record carries a candidate with no prior ledger entry, and only while a counter file `<collector-state>/model-turns-<date>` is below 4; the heartbeat automation is retired by the cutover guard the vy7y brief already specifies (one runner active). The poster (Task B4) reads the new record path through `candidates.from_collector`.
- Acceptance: as written in vy7y, plus `aitools-alerts-poster run` consuming a scheduler-produced record.

## Slice E: channels, schedule, live acceptance

### Task E1: Create the channels and the VM send wrapper

- On the VM as jibot (`BUZZ_RELAY_URL=https://buzz.ai-tools.md`, key from `~/.buzz-keys/agent.nsec` via `BUZZ_PRIVATE_KEY=$(cat ...)` inside the SSH session only): `buzz channels create --name security-feed --type stream --visibility open --description "Security alerts for people running AI agents: daily digest, real-time highs. Agents: parse the aitools-alert block."` and `--name security-critical --description "Fix-now alerts only. Posts here also interrupt your agent."`. Add Joi's identity as owner of both (`buzz channels` role commands; builder checks the exact subcommand). Builder verifies whether Buzz can restrict writes on `security-critical` to owner/admin/bot; if it cannot, the channel stays open and the README states that only manifest keys are trusted.
- Write `~/bin/buzz-send` (reads the nsec from the key file, execs the Buzz CLI; mode 700) and commit a copy at `ops/buzz/compose-overlays/buzz-aitools/buzz-send` in cell-fleet.
- Write `spec/channels.json` in the repo: `{"feed": "<uuid>", "critical": "<uuid>"}`. Commit.

### Task E2: Poster schedule on the poster Mac
- Install `aitools-alerts` from the repo into `~/.local/pipx` on the poster Mac; launchd `com.joi.aitools-alerts-poster` hourly at :20 (`aitools-alerts-poster run`), logs under `~/Library/Logs/aitools-alerts-poster.log`, `ProcessType Standard` (Background QoS has timed out other lanes). Record the plist in dotfiles-private per the launchd skill.
- Verify: one scheduler-triggered run writes the summary line and posts nothing when there is nothing new.

### Task E3: Live acceptance (from the design's acceptance list)
- Synthetic KEV: run the poster with `--kev-file tests/fixtures/kev-synthetic.json` whose single entry is a scope tier 1 product; confirm posts in `#security-critical` and `#security-feed` under jibot's key, the body says `SYNTHETIC TEST`, and Joi's iMessage from the existing watch is not triggered (the poster never messages). Retract the test posts with `curator retract`.
- Second trusted poster: sign manifest v2 adding a test curator key, post with `curator post`, confirm `aitools-alerts pull` on a member machine accepts it; sign v3 removing it, confirm `test_revoked_poster_events_dropped` behaviour live.
- Fresh-machine install per Task A6 step 5 against the live mirror.
- Digest: force `--digest-now` once and confirm one post with every feed item of the day.
- Model-turn count for the day read from the counter file stays at or below 4.
- Post the evidence lines on the kata epic; close child issues with `--commit`/`--test` evidence.

## Kata and review

- Epic: jibot-code, title "ai-tools security alerts: two Buzz channels, signed mirror, member CLI (design 2026-11-05)", children per task group: A1–A3, A4–A5, A6, A7, B1–B2, B3–B4, C1, C2, D1–D4 (reopen d9aa), D5 (vy7y), E1–E3. Each child under 600 changed lines.
- The new repo gets a `.kata.toml` and a kata project `ai-tools-alerts`; a `scripts/test-gate.sh` that runs `pytest -q` is its gate. Every slice ends with one independent-model review; slices B, C and D are security-shaped (`gpt-6-astra`).
