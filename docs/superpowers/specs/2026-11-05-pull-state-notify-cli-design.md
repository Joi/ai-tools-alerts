# Pull, verify, state, notify and the member CLI (Task A5, ai-tools-alerts#z4hs)

## Problem

A1 to A4 gave the member package its parts: BIP-340 and NIP-01 (`nostr`), the
advisory block (`schema`), the signed poster list (`manifest`), and the local
inventory and action planner (`inventory`, `versions`, `check`). Nothing yet
fetches the mirror, decides which events to believe, remembers them, tells the
member, or gives the member a command to run. This task adds that, as a
standard-library-only CLI `aitools-alerts`.

The security property that matters: an event reaches `check` only when the
manifest that names its key is signed by the pinned trust root and is not
older than one already accepted, the event's own signature verifies, and its
key is in the CURRENT manifest. `posted_by` always comes from that manifest.
Nothing from a post is ever executed, and `plan` builds commands only from
fixed templates.

## Success criteria

1. The twelve plan tests pass, among them Review Focus items 2 and 3
   (`test_pull_truncated_json_keeps_previous_state`,
   `test_revoked_poster_events_dropped`); `scripts/test-gate.sh` passes.
2. In a clean venv under the scratchpad, with a temporary HOME:
   `$VENV/bin/pip install <copy of the repo>` (pipx's install path), then,
   with `HOME` a temp directory and `AITOOLS_ALERTS_TRUST_ROOT=<fixture root>`
   EXPORTED so it reaches every command:
   `$VENV/bin/aitools-alerts init && $VENV/bin/aitools-alerts pull
   --mirror-url file://$REPO/tests/fixtures/mirror/ &&
   $VENV/bin/aitools-alerts check` prints the fixture critical. The installed
   package finds `spec/` and `trust/` (package data). The exact script is in
   the run manifest Notes.
3. No test writes under the real `~/.config` or `~/.local`: every test sets
   HOME to a temp directory.
4. No subprocess argument comes from a post. Notify transports use a fixed
   argv with the text as one argument; `plan` prints commands from fixed
   templates keyed by `product.ecosystem`, and the CLI executes none of them.
5. The diff carries no real key, no fleet host name, no real phone number or
   chat id. Fixture keys are generated and their secrets discarded.

## Approach

### The fixture trust root (decided)

The mirror fixture cannot be signed by the real trust root (its secret is in
Kura and must never sign a test key) nor by the real posters. So the trust
root is a parameter: `pull.fetch(..., root_pubkey=TRUST_ROOT_PUBKEY)`, and the
CLI reads an override from the environment variable
`AITOOLS_ALERTS_TRUST_ROOT` (64 lowercase hex). When it is set the CLI prints
`warning: trust root overridden by AITOOLS_ALERTS_TRUST_ROOT` to stderr on
every command that reads state. It is not a config key, so `init` never
persists it. State is bound to its root: the accepted manifest is stored per
root, and `check`, `notify`, `plan` and `run` refuse to use state pulled
under a root other than the active one (they print "pulled under another
trust root; run pull"), so trust gained under an override ends when the
override is removed, and the pinned root's freshness floor survives a test
pull under another root. Rejected: signing a fixture manifest with the real root (it would
publish a trusted key whose secret is in the repo); a `--trust-root` flag (the
acceptance command line has none, and a flag is easier to leave in a hook).

### `config.py`

- Paths, computed at call time from `Path.home()`:
  `config_dir() = ~/.config/aitools-alerts`, `config_path()`, `key_path()`
  (`key.nsec`), `state_dir() = ~/.local/state/aitools-alerts`.
- `Settings(mirror_url, notify: tuple[str, ...], auto_apply: frozenset[str],
  imessage_to, signal_to, signal_account, telegram_chat_id, webhook_url,
  telegram_token_file)`, frozen; `Settings.check_config() -> check.Config`.
- `load(path=None) -> Settings`. A missing file gives the defaults
  (`mirror_url = "https://buzz.ai-tools.md/alerts/"`, `notify = ("desktop",)`,
  `auto_apply = frozenset()`, the rest None). Parsed with `tomllib`. A file
  that does not parse, or a key with the wrong type, raises `ConfigError` (a
  ValueError) naming the key. Unknown keys are ignored. `auto_apply`: a list of
  strings, intersected with `schema.VERBS` (unknown verbs ignored).
  `notify`: a list of strings, unknown channels ignored. `mirror_url` must
  start with `https://` or `file://`. Recipients (`imessage_to`, `signal_to`,
  `signal_account`) must match `[A-Za-z0-9+@._:-]{1,128}` and not start with
  `-`; `telegram_chat_id` (JSON, never argv) is a numeric id, negative for
  groups and channels, or `@channelname`; `webhook_url` must be
  https.
- `write_default(path, force=False)`: writes a commented TOML template with
  the defaults, mode 0600, directory 0700; refuses an existing file unless
  `force`.
- The Telegram bot token is a secret, so it is not in config.toml: it is read
  from `telegram_token_file` (default `~/.config/aitools-alerts/telegram.token`),
  which must not be readable by group or others; otherwise the send is refused.

### `state.py`

- Directory `~/.local/state/aitools-alerts/` (0700), files written atomically
  (temp file in the same directory, `os.replace`, mode 0600):
  `events.json` (`{"current": root, "roots": {root: {"manifest": manifest
  event, "events": {event id: event}}}}`: per trust root, the last accepted
  manifest and the events filtered under it, in ONE file so no reader and no
  crash ever pairs events with another generation's manifest, and a pull
  under one root never touches another root's events), `seen.json` (sorted
  list of advisory thread ids notified), `last_pull.json` (`{"at", "mirror_url", "ok",
    "error", "last_ok_at", "new", "dropped"}`: the last ATTEMPT, rewritten on
  a failed pull too, with `last_ok_at` carried from the last success), Stored events keep only the seven NIP-01 fields (an unsigned extra field
  never reaches state).
- `State(dir, roots: {root: [Manifest, events]}, manifest_root, seen,
  last_pull)`, with `manifest` and `events` the current root's; `State.locked()` takes an exclusive `flock` on `<dir>/.lock` and
  re-reads the files, and `pull.fetch` runs inside it, so two concurrent
  pulls decide one after the other on the latest saved floor (no rollback).
  `notify` holds the same lock while it sends, re-reads `seen` and skips a
  thread a concurrent run already sent, so no update is lost. `State.load(dir=None)`
  never raises on a missing file. A state file that does not parse, or has the
  wrong shape, raises `StateError` naming the file: the CLI reports it and
  stops rather than silently start from empty (an empty manifest record would
  drop the freshness floor to the bundled manifest; an empty seen list would
  re-notify). `save_pull(...)` writes events, manifest and last_pull;
  `save_seen()` writes seen.

### `pull.py`

`fetch(base_url, state, fetch=None, root_pubkey=TRUST_ROOT_PUBKEY, now=None)
-> PullResult(new_events: list[dict], dropped: Counter, manifest: Manifest |
None, error: str | None)`.

`fetch` is a callable `url -> bytes`; the default uses `urllib.request` with
a 20 s timeout, reads at most 8 MiB (more is an error), and refuses any URL
scheme but `https` and `file`. `base_url` gets a trailing `/` if it lacks
one.

Order. A failure in steps 1 and 2 returns `error` and changes nothing but
`last_pull`. A failure in step 3 also returns `error` (`mirror unreadable`)
and fetches nothing new, but the manifest verified in steps 1 and 2 IS
accepted and step 4 runs over the stored events alone: a revocation applies
at once, and the last good events of keys still trusted are kept.

1. Fetch and `manifest.load(bytes, previous=floor)`. `floor` is the stored
   manifest when it was accepted under the same root, and for the pinned root
   also the bundled `trust/manifest.json`; the higher version of the two is
   the floor. `load` refuses a lower version or a same version with a
   different id. Then refuse a manifest whose `issued_at` is older than the
   floor's. Errors: `manifest unreadable: ...`, `manifest refused: ...`.
2. `manifest.verify(m, root_pubkey)`, else `manifest not signed by the trust
   root`.
3. Fetch `feed.json` and `critical.json`. Each must be a JSON object with
   `generated_at` (string), `channel` (string) and `events` (list of at most
   10000 objects). A fetch failure, truncated JSON or wrong shape is
   `mirror unreadable: <file>: <why>`: never an empty feed.
4. Candidates are the stored events, then the fetched ones. Each is
   verified BEFORE it may claim its id (the first candidate with an id that
   verifies and is trusted wins; a forged copy of a genuine id never
   displaces it; stored events were verified when stored and are re-checked
   for role only); each is checked under the CURRENT manifest only: `nostr.verify_event`
   (else `dropped["bad-signature"]`), then `manifest.role_of` (else
   `dropped["revoked"]` when the key was in the previous manifest or the
   event was in state, else `dropped["unknown-poster"]`). The block is parsed
   later, when advisories are built. A stored event whose key left the
   manifest is removed from state: the cache never vouches for it.
   Retention: a whole thread (a root and every reply to it) is dropped
   (`aged-out`) when its newest event is older than 400 days; a thread is
   never split, so a retraction or amendment never outlives or predeceases
   it. Bound: when the result would exceed 20000 events, or the serialized
   state of ALL roots would exceed 32 MiB (half the 64 MiB load limit), the
   fetched events are refused
   (`state limit reached: new events not stored`) and the stored ones are
   filtered under the new manifest alone, so state always stays loadable and
   a revoking manifest always lands.
5. Save the root's manifest and events (one file), then last_pull. `new_events` are the
   accepted events not in state before, in `created_at` order.

`advisories(state) -> list[Thread]` builds the current view from the stored
events under the EFFECTIVE manifest: the stored one, or the bundled
`trust/manifest.json` when the current root is the pinned root and the
bundle is newer, so a revocation shipped in the package governs the cache
even while the mirror replays an old manifest (`Thread(root_id, adv, retracted, updated_at)`):

- A root is an event with no `e` tag marked `reply` or `root`, and whose last
  `aitools-alert` block parses (`schema.parse_post`); the advisory's
  `posted_by` is replaced by the manifest role of the event's pubkey.
- A reply is an event with an `e` tag marked `root` (its target), or else
  `reply`. Replies to a known root are applied in `(created_at, id)` order:
  - first line (stripped) exactly `retract`, from a curator key: the thread is
    retracted (hidden from `check`, `notify`, `plan`); later replies change
    nothing;
  - first line `level: high` or `level: notice`, from a curator key, lowers
    the level when it is lower than the current one (never raises);
  - a reply whose last `aitools-alert` block decodes is a PATCH, applied
    after any `level:` line in the same reply (A7's amend sends both).
  Once a curator has posted or amended a thread, a relay-bot reply to it is
  discussion, so the bot cannot suppress, expire, re-scope or undo a
  curator's word. A patch that fails validation or raises is counted
  (`bad-patch`) and skipped; it never stops the other threads.
  Plain-text replies from a relay-bot key, and any other text, are discussion.
- Patch contract (for B3 compose.reply_post and A7 curator): the block is a
  JSON object whose keys are a subset of the advisory fields. An omitted field
  is unchanged; a field present with a value replaces it whole (lists are
  replaced, not merged); an explicit `null` clears a nullable field
  (`advisory_severity`, `expires_at`; also `products[].affected` and `fixed`
  through the whole-list replace). `id` must equal the root's id or be
  omitted; `posted_by` in a patch is ignored, and the thread's `posted_by` is
  always its ROOT's manifest role (a curator patch on a relay-bot thread does
  not make it curator; a curator re-posts as a new root for that). Each field is validated with
  schema's validators by validating the merged object with `schema.validate`,
  so a patch that leaves the advisory invalid is dropped whole
  (`dropped["bad-patch"]`, counted in the view). A relay-bot patch (on its
  own thread) that lowers `level` or carries `expires_at` is dropped whole:
  only a curator may lower or expire an alert.
- Expired advisories (`expires_at` before now) are left out of `check`.

### `notify.py`

`send(channel, text, settings, run=subprocess.run, post=None, platform=None)
-> SendResult(accepted: bool, detail: str)`; never raises.

- `desktop`: on macOS `["osascript", "-e", SCRIPT, text]` where SCRIPT is the
  fixed `on run argv / display notification (item 1 of argv) with title
  "ai-tools alert" / end run`: the text is an argument, never part of the
  AppleScript. On Linux `["notify-send", "--", "ai-tools alert", text]`.
- `imessage`: `["imsg", "send", "--to", imessage_to, "--text", text]` when
  `imsg` is on PATH.
- `signal`: `["signal-cli", ("-a", account,) "send", "-m", text, signal_to]`
  when `signal-cli` is on PATH.
- `telegram`: urllib POST of JSON `{"chat_id", "text"}` to
  `https://api.telegram.org/bot<token>/sendMessage`; accepted only on HTTP
  200 with `"ok": true`. The token never appears in `detail`.
- `webhook`: urllib POST of JSON `{"text": text}`; accepted on HTTP 2xx.
  Redirects are refused (urllib would turn the POST into a bodiless GET and
  a login page's 200 would mark the alert seen).
- Subprocesses: `shell=False`, `timeout=30`, stdin closed, accepted on exit 0.
- `format_text(thread, match) -> str`: four lines: `CRITICAL: <title>`,
  `Affected: <product> <installed version> (fixed in <fixed>)`,
  `Action: <check.describe(action)>` (one line per action, or `Action: see
  the advisory`), `Source: <first source url>`.

### `cli.py`

`main(argv=None) -> int`, console script `aitools-alerts =
aitools_alerts.cli:main`.

- `init [--make-key] [--force]`: write the default config (refuse an existing
  one without `--force`, but with `--make-key` an existing config is kept and
  only the key is made). No key is written without `--make-key`.
- `--make-key` / `keygen`: write `key.nsec` (bech32 nsec) with
  `os.open(O_CREAT|O_EXCL|O_WRONLY, 0o600)`, refuse if it exists, print the
  npub and the Buzz pairing steps; the nsec is never printed.
- `pull [--mirror-url URL]`: one summary line; exit 1 with the error on
  stderr when the pull fails.
- `check [--json]`: matches the current advisories against
  `inventory.collect()`; prints one line per match (level, title, installed
  version, reason, thread id), and every critical not matched here under
  "Critical advisories not installed here". `--json` prints a list of objects.
- `notify`: for every unseen critical match, sends to each configured
  channel; marks the thread seen only when at least one channel returned
  `accepted`; exit 1 if any unseen critical stayed unsent.
- `plan <id>` (thread root id or advisory id): for each match, `check.plan`
  under the member's `auto_apply`, then prints `auto-apply (opted in):` and
  `prepare (ask first):` sections with `check.describe(action)` and, for an
  `upgrade` in an ecosystem with a template, the command, built as an argv
  list and shown with `shlex.join`. Templates: `claude-code` ->
  `npm install -g @anthropic-ai/claude-code@<fixed>`, `codex` ->
  `npm install -g @openai/codex@<fixed>`, `gemini-cli` ->
  `npm install -g @google/gemini-cli@<fixed>`. `<fixed>` is the product's
  `fixed`, which schema already restricts to the version grammar. An
  upgrade with no `fixed` prints "no fixed version given: notify only, no
  command" (Review Focus 1). Other ecosystems print "no command template;
  upgrade with your package manager".
  Nothing is executed: A6 wires hooks.
- `run [--json | --quiet]`: pull (a failure warns on stderr and continues on
  the cached state), check, notify; exit 2 when at least one critical match
  was unseen when the run started, else the notify status. `--json` (A6's
  skill) prints one object `{"pull_error", "matches": [as check --json],
  "unseen_critical": [thread ids]}`; `--quiet` (A6's SessionStart hook)
  prints nothing on stdout. Exit codes are the same in all three modes.

### Packaging

`spec/` and `trust/` stay at the repo root. `pyproject.toml` maps them into
the package as `aitools_alerts.spec` and `aitools_alerts.trust` with
`package-dir` and `package-data = ["*.json", "*.pub"]`, so an installed
package has `aitools_alerts/spec/*.json`. `schema.SPEC_DIR` and a new
`TRUST_DIR` look beside the module first and fall back to the repo root.

## Alternatives considered

- Parsing patches with `schema.parse_post`: it needs a whole advisory, so a
  reply carrying only changed fields would be dropped. Patches use
  `schema._last_block` and the same JSON decoder settings instead.
- Keeping revoked events and filtering at read time: the plan says dropped
  and counted, not trusted from cache; removing them from state is simplest.
- Starting from empty on a corrupt state file: loses the freshness floor and
  the seen list; refusing is louder and safe.

## Blast radius and rollback

New modules and tests; two edits to existing code (`schema.SPEC_DIR`
resolution, `pyproject.toml`). Nothing runs on a schedule yet (A6). Rollback:
revert the commits.

## Size

About 1,300 changed lines including tests and fixtures, over the 600 line
guide. Decided: one landing in two chunk commits (pull+state+config, then
notify+cli), the only split the brief allows, reviewed as one branch;
splitting into two issues would add a second review and gate for a CLI that
is not usable until both halves land.

## Open questions

None blocking. The Buzz pairing steps printed by `init --make-key` are
generic (send the npub to the relay admin; import the nsec in the Buzz app)
until the relay's intake text is final.
