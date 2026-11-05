# Mirror exporter and systemd timer (Task C1) — design

Kata: ai-tools-alerts#xksk. Parent plan: docs/plan.md, Task C1. Epic jibot-code#gr5b.
Depends on A1 (zq90: `nostr.verify_event`), A2 (j153: `schema.parse_post`,
`spec/channels.json`), A3 (0exc: `manifest.load`, `manifest.verify`,
`manifest.role_of`, `trust/manifest.json`). Consumed by A5 (z4hs: `pull` reads
the JSON files) and C2 (jibot-code#8k6g: `install-mirror.sh` installs the files
on the relay VM and Caddy serves the output directory at `/alerts/`).

## Problem

The relay requires NIP-42 auth for reads, so members without an account read
the two alert channels from a static mirror. Something on the relay VM must
dump both channels' raw signed events to static files every few minutes,
without ever serving a half-written file, a forged event or an event whose
`created_at` did not survive the database round trip.

## Success criteria

1. `mirror/export_mirror.py`, standard library plus this repo's
   `aitools_alerts` only, with argparse options `--channels`, `--out`,
   `--manifest`, `--psql-cmd`, `--rows-from`, `--mirror-url`.
2. `python3 mirror/export_mirror.py --channels spec/channels.json --manifest
   trust/manifest.json --out <scratch> --rows-from <fixture>` exits 0 and writes
   `feed.json`, `critical.json`, `feed.atom`, `manifest.json`; `feed.json` loads
   with `json.load`; `feed.atom` parses with `xml.etree.ElementTree`.
3. `tests/mirror/test_export.py` holds the plan's three tests
   (`test_export_writes_atomically`, `test_exported_events_verify`,
   `test_atom_has_one_entry_per_root`) plus the edge cases in the plan, all
   with throwaway keys from `nostr.keygen`; no relay data, no host names.
4. `mirror/aitools-alerts-mirror.service` and `.timer`: a systemd user unit
   pair for relayuser, every 5 minutes, `Persistent=true`, run with
   `/usr/bin/python3`. Reviewed line by line against systemd.service(5),
   systemd.timer(5) and systemd.exec(5) (no `systemd-analyze` on macOS; the VM
   has systemd 255, and C2's install is where it is first loaded).
5. `scripts/test-gate.sh` passes.

## Approach

### Reading rows

For each `name, uuid` in `spec/channels.json` (today `feed`, `critical`) the
exporter runs the plan's query verbatim with the channel id substituted:

```
SELECT json_build_object('id',encode(id,'hex'),'pubkey',encode(pubkey,'hex'),'created_at',extract(epoch from created_at)::bigint,'kind',kind,'tags',tags,'content',content,'sig',encode(sig,'hex')) FROM events WHERE channel_id = '<uuid>' AND deleted_at IS NULL ORDER BY created_at
```

- The id is interpolated into SQL, so it must first parse as a UUID and equal
  its canonical lowercase form (`str(uuid.UUID(v)) == v`); otherwise exit 1
  before any command runs. The file must name exactly `feed` and `critical`
  (A5 reads exactly those files; any other name could collide with an output
  such as `manifest.json`).
- Default command: `docker exec buzz-prod-postgres-1 psql -U buzz -d buzz -At
  -c <query>`, run as an argv list (no shell). `--psql-cmd "<prefix>"` replaces
  the prefix (split with `shlex`); the query is appended as the last argument.
  Timeout 120 s per channel. A non-zero exit, a timeout or a missing binary is
  a read failure.
- `--rows-from <file>` replaces the command for tests and for the acceptance
  run: a JSON object `{"<channel name>": [row, ...]}` where each row is what
  one psql output line would decode to. A channel absent from the file is a
  read failure.
- psql `-At` prints one JSON object per line (JSON escapes newlines inside
  strings). Each non-empty line is decoded; a line that is not a JSON object
  is counted as `malformed` and dropped.

### Verification

Every row is reduced to exactly the seven NIP-01 keys (`id`, `pubkey`,
`created_at`, `kind`, `tags`, `content`, `sig`) and checked with
`nostr.verify_event`; failures are counted as `bad_sig` and dropped (a
`created_at` rounding mismatch shows up here). The exporter does not filter the
JSON files by manifest membership: the mirror is the raw channel, and A5
checks each pubkey against the manifest it verifies itself.

The manifest is loaded and checked before anything is written:
`manifest.load(path)` then `manifest.verify(m, TRUST_ROOT_PUBKEY)`. A manifest
that does not load or verify is a refusal (exit 1, nothing written), so the
mirror never publishes a manifest every member would reject. `manifest.json`
is then the verbatim bytes of the input file.

One summary line goes to stderr per run, counts only, never row content:
`export_mirror: feed kept=N malformed=M bad_sig=K; critical kept=... ; atom entries=E`.

### Writing

All four outputs are rendered in memory first; nothing is written unless every
channel read and the manifest check succeeded, so a failed read or check
leaves the previous files in place. The guarantee is per file, not per
generation: each file is always either the old or the new version, but a write
that fails part-way (disk full) can leave a new `manifest.json` beside an old
`feed.json`; the next run rewrites all four. Each file is written to a temp file created in the
output directory (`tempfile.mkstemp(dir=out, prefix=".<name>.")`), flushed,
`fsync`ed, `chmod 0644` (mkstemp creates 0600 and Caddy must read it), then
`os.replace`d onto the final name; on any error the temp file is removed.
Order: `manifest.json`, `critical.json`, `feed.json`, `feed.atom`, so a reader
never sees an event from a newly added poster before the manifest naming them.
`--out` must exist (the installer creates it, owned by relayuser); the exporter
does not create it.

JSON layout, exactly as A5 reads it:
`{"generated_at": "<UTC ISO 8601, seconds, Z>", "channel": "<name>", "events": [...]}`,
events in the query's `created_at` order, `ensure_ascii=False`, UTF-8.

### Atom

`feed.atom` is the reading aid for feed readers, which cannot verify
signatures, so it shows only what the CLI would trust:

- Source: the `feed` channel's verified events only (every critical also posts
  to the feed, design line 38; using both channels would duplicate entries).
- An entry per ROOT post: an event with no tag whose first element is `e`.
- Only events whose pubkey has a role in the verified manifest
  (`manifest.role_of`); others are left out of the Atom (they stay in the
  JSON).
- A root that a curator-role event retracts is left out, matching A5's rule
  that a retracted root is hidden. The retracting event is from a curator key,
  its content's first line (split on CommonMark line endings, as
  `parse_post` does) stripped is `retract`, and its target is the one root it
  replies to under NIP-10 marked tags: its `e` tag marked `root`, else its
  `e` tag marked `reply`. Unmarked `e` tags are mentions and retract nothing.
- An event whose `created_at` is beyond `schema.MAX_TIMESTAMP` (9999-12-31)
  has no Atom date: it stays in the JSON, unchanged, and gets no Atom entry.
- Title: `schema.parse_post(content).title` when the block parses; otherwise
  the first non-empty line of the content, cut to 200 characters, or
  `(untitled)`.
- Content (`type="text"`): when the block parses, the text before the opener
  of the last closed `aitools-alert` fence, found with the same fence
  tracking as `schema._last_block` (so a block quoted inside another fence is
  not mistaken for the real one), stripped; otherwise the whole content.
- `id`: `urn:nostr:event:<event id>`; `updated`/`published`: `created_at` as
  UTC ISO; `link rel="alternate"`: `<mirror-url>feed.json`; author: the
  manifest poster's name.
- Feed: `id` `<mirror-url>feed.atom`, `title` "ai-tools security alerts",
  `updated` the newest entry's time or `generated_at`, `link rel="self"`, one
  feed-level `author`. Newest entries first.
- Built with `xml.etree.ElementTree` (escaping), after removing characters
  XML 1.0 forbids (C0 controls except tab/LF/CR, U+FFFE/U+FFFF, lone
  surrogates).
- `--mirror-url` defaults to `https://buzz.ai-tools.md/alerts/` (the design's
  public URL; not a fleet host name).

### Install layout (the C2 contract)

The exporter imports `aitools_alerts` and reads `spec/channels.json` and
`trust/manifest.json`, so it runs from a checkout of this repo, not as a lone
script. It inserts the repo root (`Path(__file__).resolve().parents[1]`) at
the front of `sys.path`, so it works from any checkout without a package
install. The units assume the checkout at `/home/relay/ai-tools-alerts`
(`%h/ai-tools-alerts`):

```
ExecStart=/usr/bin/python3 -I %h/ai-tools-alerts/mirror/export_mirror.py --channels %h/ai-tools-alerts/spec/channels.json --manifest %h/ai-tools-alerts/trust/manifest.json --out %h/alerts-mirror
```

C2's `install-mirror.sh` today copies `export_mirror.py` alone to `~/bin`; it
must instead place the checkout's `aitools_alerts/`, `mirror/`, `spec/` and
`trust/` at `~/ai-tools-alerts` (and still install the two units). This goes
to jibot-code#8k6g as a comment; C2 is not edited here, and the live install
(an attended step after both land) depends on that C2 change. A test copies
those four directories into a fixture home and runs the service's own
`ExecStart` line with `%h` substituted, so the layout the unit assumes is
checked offline.

### Scale

The query has no history bound, and every run verifies every event: 3.4 ms
per `verify_event` on a 2026 Mac, so a 5-minute run covers tens of thousands
of events; both channels held 16 events on 2026-11-05. A bound (a verified-id
cache outside the served directory, or a time window) is a follow-up issue,
not this task.

### Units

Service: `Type=oneshot`, the `ExecStart` above, `UMask=0022`,
`NoNewPrivileges=yes`, `Nice=10`, `TimeoutStartSec=5min`. No `[Install]`: the
timer starts it.

Timer: `OnCalendar=*:0/5`, `Persistent=true`, `AccuracySec=30s`,
`[Install] WantedBy=timers.target`. `python3 -I` ignores `PYTHON*` variables
and the user site directory.

## Alternatives considered

- Vendor BIP-340 verification and the block parser into a single
  self-contained script so C2's `~/bin` copy works: rejected, it duplicates
  the crypto and the parser, which would drift from the copies members run.
- Filter the JSON files to manifest posters: rejected, the mirror is the raw
  channel and A5 owns trust decisions; filtering only the Atom covers readers
  that cannot verify.
- Atom from both channels deduplicated: rejected, a critical is two distinct
  events (one per channel), so dedup by id would not remove the duplicate.
- `OnUnitActiveSec=5min` instead of `OnCalendar`: rejected, `Persistent=` only
  applies to `OnCalendar=` timers and the plan asks for it.

## Blast radius and rollback

New files under `mirror/` and `tests/mirror/` only; nothing imports them. The
live VM is not touched (the install is the attended step after C2 lands).
Rollback: revert the commit; on the VM, `systemctl --user disable --now
aitools-alerts-mirror.timer` stops the export and the last files stay served.

## Assumes

- The Buzz channel tables keep the column names the design lists (confirmed
  read-only on 2026-11-05: the query runs and returns the seven keys).
- A5 hides a root on a curator reply whose first line is `retract` (plan A5
  interface); the Atom mirrors that rule and nothing else of A5's reply logic.

## Open questions

None blocking. If C2 prefers the lone-script layout, the alternative is a
`--repo` option, which still needs the package on the VM.
