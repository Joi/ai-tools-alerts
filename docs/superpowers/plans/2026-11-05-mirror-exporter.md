# Mirror exporter and systemd timer (Task C1) — plan

Spec: docs/superpowers/specs/2026-11-05-mirror-exporter-design.md. Kata: ai-tools-alerts#xksk.
One chunk, one commit (`feat: mirror exporter and systemd timer`). Target size:
exporter ~250 lines, tests ~250, units ~30 (under the 600-line rule; run docs
excluded, as in B1/B2).

## Chunk 1 — exporter, units, tests

### Files

- Create `mirror/export_mirror.py`
- Create `mirror/aitools-alerts-mirror.service`, `mirror/aitools-alerts-mirror.timer`
- Create `tests/mirror/test_export.py` (no `__init__.py`: tests/ uses rootdir
  imports; the module is loaded with `importlib.util.spec_from_file_location`
  so pytest never imports `mirror/` as a package)

### Step 1 — failing tests (`tests/mirror/test_export.py`)

Fixtures: `keygen()` twice per test session: a curator key and a relay-bot key,
and a stranger key. Tests that need a manifest build one signed by a throwaway
root key and monkeypatch the exporter's `TRUST_ROOT_PUBKEY` name to that root
(the exporter reads it at call time from its module global). One test also runs
against the real `trust/manifest.json` with the real root, unpatched, to prove
the shipped file passes the check. Helper `post(sec, title, body, tags=())`
renders a post with `schema.render_post` when a title is given (a valid
Advisory dict built inline and passed through `schema.validate` first:
`render_post` takes an `Advisory`, not a dict), or plain text otherwise, and
signs with `nostr.sign_event`.

Tests:
1. `test_export_writes_atomically` — monkeypatch `os.replace` in the module to
   record `(src, dst)`: every dst is one of the four names in `out`, every src
   is in the same directory and starts with `.`, src no longer exists after
   the run, the four files exist with mode 0644, and no `.*` temp files remain.
   Second case: a renderer raising mid-write (monkeypatch `json.dumps` for
   `feed` to raise after `critical.json` was written... simpler: make
   `os.replace` raise on the third call) leaves no temp files behind and the
   pre-existing `feed.json` content unchanged.
2. `test_exported_events_verify` — rows: two good events, one with
   `created_at` off by one (re-serialised, signature now wrong), one with a
   flipped sig, one line that is not JSON (psql path) / a non-dict row
   (rows-from path), one with an extra key (kept, reduced to the seven keys).
   Output `feed.json` holds exactly the good events, every one passes
   `verify_event`, layout is `{"generated_at", "channel": "feed", "events"}`,
   `generated_at` matches `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`; stderr summary
   reports `kept=3 malformed=1 bad_sig=2` for feed.
3. `test_atom_has_one_entry_per_root` — feed rows: root A (curator, parsing
   block, title "Alpha"), reply to A (`e` tag), root B (relay-bot, plain text
   "First line\nmore"), root C from a stranger key, root D retracted by a
   curator reply `retract`, root E retracted by a stranger reply `retract`
   (stays), and a relay-bot `retract` reply to B (B stays). Atom parses;
   entries are E, D, B, A by `updated`, newest first (C, the stranger's, is
   absent); D is a withdrawal: title "Retracted: to be retracted", content the
   retraction's text, `updated` the retraction's time, `published` D's own;
   A's title is "Alpha" and its content is the body without the fence; B's
   title is "First line"; ids are `urn:nostr:event:<id>`; link href
   `https://buzz.ai-tools.md/alerts/feed.json`. (Changed after the code
   review: a retracted root is published as a withdrawal, not omitted, and a
   withdrawal's `updated` is always later than its root's.)

Edge tests:
4. `test_psql_path_parses_lines` — `--psql-cmd` pointing at a fake runner:
   monkeypatch `subprocess.run` to return lines; assert argv is the prefix plus
   the exact query with the uuid, no shell, timeout set.
5. `test_read_failure_writes_nothing` — runner returns code 1 for `critical`:
   exit 1, previous files untouched, no temp files.
6. `test_bad_channel_id_refused` — channels file with `"feed": "x' OR 1=1"`:
   exit 1 before any runner call; also a bad name (`"../x"`) and a missing
   `critical` key.
7. `test_bad_manifest_refused` — manifest signed by a key that is not the root:
   exit 1, nothing written.
8. `test_manifest_copied_verbatim` — real `trust/manifest.json`, real root:
   output bytes equal input bytes.
9. `test_cli_rows_from_end_to_end` — `subprocess.run([sys.executable,
   "mirror/export_mirror.py", ...])` from the repo root with `--rows-from`
   built from signed fixture events and the real manifest, but none of them
   need manifest roles; asserts the four files, `json.load` and
   `ElementTree.parse` succeed. Proves the `sys.path` insertion works.
10. `test_atom_strips_xml_illegal_chars` — content with `\x01` and `\x1b`:
    atom parses.
11. `test_reserved_channel_name_refused` — a third channel `manifest`: exit 1
    before any write.
12. `test_retract_needs_marked_reply` — an unmarked `e` (mention) retracts
    nothing; an event with a `mention`-marked and a `root`-marked tag retracts
    only the root-marked target.
13. `test_atom_body_ignores_quoted_block` — a real post followed by a quoted
    `aitools-alert` example inside a four-backtick fence: title and body come
    from the real block.
14. `test_far_future_timestamp_kept_in_json_not_atom` — `created_at` past
    `schema.MAX_TIMESTAMP`: kept in feed.json, no Atom entry, the run succeeds.
15. `test_unit_execstart_runs_from_fresh_checkout` — copy `aitools_alerts/`,
    `mirror/`, `spec/`, `trust/` into a fixture home, run the service's
    `ExecStart` (with `%h` substituted, `--rows-from` appended): four files.

Run `python3 -m pytest tests/mirror -q` — FAIL (module missing).

### Step 2 — implement `mirror/export_mirror.py`

Structure (names are the interface the tests use):

- Header docstring: what it does, the install layout, exit codes.
- `REPO = Path(__file__).resolve().parents[1]`; `sys.path.insert(0, str(REPO))`
  then `from aitools_alerts import nostr, schema, manifest as mf` and
  `from aitools_alerts import TRUST_ROOT_PUBKEY`.
- `QUERY` = the plan's SQL with `{channel_id}`; `DEFAULT_PSQL = ["docker",
  "exec", "buzz-prod-postgres-1", "psql", "-U", "buzz", "-d", "buzz", "-At",
  "-c"]`; `NIP01_KEYS`; `DEFAULT_MIRROR_URL`; `PSQL_TIMEOUT = 120`.
- `class ExportError(Exception)`.
- `load_channels(path) -> dict[str, str]`: JSON object naming exactly `feed`
  and `critical`; ids canonical UUID.
- `psql_reader(prefix) -> Callable[[str, str], list]`: returns a function
  `(name, channel_id)` that runs `prefix + [QUERY.format(...)]` via
  `subprocess.run(capture_output=True, text=True, timeout=PSQL_TIMEOUT)`;
  raises ExportError on non-zero / timeout / OSError (message names the
  channel and exit code only, never stdout); returns decoded rows, with a
  non-JSON line returned as the sentinel `None` (so counting happens in one
  place).
- `file_reader(path)`: loads the JSON object once; returns `(name, id) ->
  list`; missing name or non-list raises ExportError.
- `clean(rows) -> (events, Counter)`: non-dict → malformed; reduce to
  NIP01_KEYS (missing key → bad_sig via verify failing); `verify_event` false
  → bad_sig.
- `check_manifest(path) -> (bytes, Manifest)`: read bytes, `mf.load(raw)`,
  `mf.verify(m, TRUST_ROOT_PUBKEY)` (module global looked up at call time);
  ExportError on failure.
- `channel_doc(name, events, generated_at) -> str`.
- `_xml_safe(s)`: regex remove `[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]`.
- `_lines(content)`: `schema._LINES.split` (the parser's line endings).
- `_body_before_block(content)`: the fence tracking of `schema._last_block`
  (`schema._FENCE_OPEN`, closers by char and length), recording the opener
  index of the last closed fence that is ours; join lines before it, strip.
- `_reply_target(ev)`: the `e` tag marked `root`, else the one marked `reply`;
  unmarked tags ignored.
- `atom_doc(events, m, generated_at, mirror_url) -> str`: roots = no `e` tag,
  role present, `created_at <= schema.MAX_TIMESTAMP`; retracted ids =
  `_reply_target` of events whose role is `curator` and whose first line
  stripped equals `retract`; entries
  sorted by (created_at, id) descending; ElementTree with default namespace
  `http://www.w3.org/2005/Atom` registered; `xml_declaration=True`,
  `encoding="unicode"` then encode UTF-8 at write.
- `write_atomic(out: Path, name: str, data: bytes)`: mkstemp in out, write,
  flush, fsync, `os.fchmod(fd, 0o644)`, close, `os.replace`; `except
  BaseException`: unlink temp, re-raise.
- `export(channels_path, manifest_path, out, reader, mirror_url, now=None) ->
  dict` (summary counts): validates `out` is a directory, checks manifest,
  reads all channels, renders all four, then writes manifest, critical (and any
  other channel), feed, atom.
- `main(argv=None) -> int`: argparse; `--rows-from` and `--psql-cmd` mutually
  exclusive; builds reader; calls export; prints summary to stderr; ExportError
  → `export_mirror: <message>` on stderr, return 1.
- `if __name__ == "__main__": sys.exit(main())`.

### Step 3 — units

`mirror/aitools-alerts-mirror.service`:
```
[Unit]
Description=Export the ai-tools alert channels to the static mirror
Documentation=https://github.com/Joi/ai-tools-alerts

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I %h/ai-tools-alerts/mirror/export_mirror.py --channels %h/ai-tools-alerts/spec/channels.json --manifest %h/ai-tools-alerts/trust/manifest.json --out %h/alerts-mirror
UMask=0022
NoNewPrivileges=yes
Nice=10
TimeoutStartSec=5min
```
`mirror/aitools-alerts-mirror.timer`:
```
[Unit]
Description=Export the ai-tools alert mirror every 5 minutes

[Timer]
OnCalendar=*:0/5
Persistent=true
AccuracySec=30s

[Install]
WantedBy=timers.target
```

### Step 4 — verify

- `python3 -m pytest tests/mirror -q` — PASS.
- `scripts/test-gate.sh` — PASS (whole suite).
- Acceptance one-liner: build a `--rows-from` fixture in the scratchpad from
  throwaway keys (a small script there), run the brief's command into a
  scratch dir, `python3 -c "import json;json.load(open('<scratch>/feed.json'))"`.
- `command -v systemd-analyze` (absent on macOS) → line-by-line review of the
  units against systemd.service(5)/timer(5)/exec(5) recorded in the landing
  comment.
- Real rows: only the brief's read-only `LIMIT 1` probe. (Removed after
  review: a full-export run against the relay exceeds the brief's
  authorization. It had already run once, read-only; see the run manifest.)
- Leak grep on the whole diff, docs included, with the pattern read from the
  brief's Gotchas line (the untracked TASK file) so no committed file carries
  the host-name literals: 0 hits.

### Step 5 — commit, then the C2 comment

Commit `feat: mirror exporter and systemd timer`. Post on jibot-code#8k6g the
install-layout difference (spec "Install layout").

## Acceptance

All of spec "Success criteria" 1–5.

## Rollback

`git revert` the commit. Nothing on the VM changes in this task.
