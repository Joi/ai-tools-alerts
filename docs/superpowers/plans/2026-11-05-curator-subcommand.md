# Curator subcommand (A7) — plan

Spec: docs/superpowers/specs/2026-11-05-curator-subcommand-design.md. Kata ai-tools-alerts#gctv.
Budget: the plan said under 600 changed lines; the review fixes took the code and tests to about 860 lines. Kept as one deliverable (decided on the issue): relay, curator and their tests are one interface and land together.

## Chunk 1 — relay, curator, CLI, tests (one commit: `feat: curator post/amend/retract over NIP-42`)

- [x] `pyproject.toml`: add `curator = ["websockets>=12"]` under
      `[project.optional-dependencies]`; `dependencies` stays `[]`.
- [x] `aitools_alerts/relay.py` (new, ~110 lines):
  - `RELAY_URL = "wss://buzz.ai-tools.md"`, `AUTH_KIND = 22242`, `MAX_MSG = 1 << 20`,
    `MAX_READS = 100`, `TIMEOUT = 20`.
  - `class RelayError(Exception)`, `class RelayUnavailable(RelayError)`.
  - `check_url(url)`: `wss://` any host, `ws://` only 127.0.0.1 / localhost / ::1.
  - `auth_event(sec, relay_url, challenge, now)`: kind 22242, tags
    `[["relay", relay_url], ["challenge", challenge]]`, content "".
  - `require_curator(event, sec, m, root_pubkey)`: m verifies under root,
    `role_of(m, pub) == "curator"`, `event["pubkey"] == pub`, `verify_event(event)`.
  - `send(event, relay_url=RELAY_URL, key=None, *, manifest, root_pubkey=TRUST_ROOT_PUBKEY,
    connect=None, timeout=TIMEOUT, now=None) -> tuple[str, bool, str]`: checks, then
    lazy `from websockets.sync.client import connect` (ImportError → RelayUnavailable);
    read until `AUTH` (ignore NOTICE etc.), send AUTH, read until `OK` for the auth id
    (false → RelayError with the relay's message), send EVENT, read until `OK` for the
    event id, return it. Deadline-based recv timeouts; a non-JSON or oversized frame
    → RelayError. Never include the key in any message.
- [x] `aitools_alerts/curator.py` (new, ~200 lines):
  - `KeyError_` text "cannot read the curator key at <path>: <reason>" with reasons from a
    fixed set (missing, not a regular file, readable by group or others, not a valid nsec).
  - `read_key(path=None)`: lstat; regular file; `mode & 0o077 == 0`; content stripped;
    `nsec1…` via `nostr.nsec_to_hex`, else 64 lowercase hex checked by range; errors
    re-raised `from None` with the fixed text.
  - `channels()`: `spec/channels.json` → dict with `feed`, `critical`.
  - `role_manifest(st, root)`: `pull.effective_manifest(st)` when `st.manifest_root == root`,
    else `pull.bundled_manifest()` when root is `TRUST_ROOT_PUBKEY`, else None.
  - `post_event(sec, m, *, level, title, product, ecosystem, affected, fixed, actions,
    sources, adv_id, aliases, severity, expires_at, channel, now)`: role from m (must be
    curator); `Advisory` → `schema.render_post(adv, body)`; body = level/title line,
    affected/fixed line, one line per action, `Source: <first url>`.
  - `_find(st, m, ref)`: thread from `pull.advisories(st)` by root id or advisory id
    (ambiguous advisory id refused); root event from `st.events`; channel = its `h` tag.
  - `amend_event(sec, m, thread, root_ev, *, level, fixed, title, sources, actions,
    expires_at, no_expiry, note, now)`: build `changes`; lower level → first line;
    higher level → patch; fixed → products (and the matching upgrade action's value);
    sources appended (dedup by url); actions replaced; expiry set or cleared. Patch =
    keys whose value differs from prev. `compose.apply_patch(prev, patch)` (ValueError →
    refuse); nothing changed → refuse. Content: `[level line]`, note or "Amended.", then
    the block when the patch is non-empty; check with `pull._apply_patch` +
    first-line rule that a reader reaches the same merged advisory.
  - `retract_event(sec, m, thread, root_ev, reason, now)`: content `retract` +
    optional reason lines.
  - `cmd_curator(a)`: load key (before network), state, manifest; build; `--dry-run`
    prints the JSON; else `relay.send`; prints `OK <id> accepted|rejected: <msg>`;
    exit 0 accepted, 1 otherwise; RelayUnavailable → install hint, exit 1.
- [x] `aitools_alerts/cli.py`: docstring lines; `curator` subparser with `post`,
      `amend`, `retract` sub-subparsers; `main` dispatches `a.cmd == "curator"` to
      `curator.cmd_curator(a)` after `a.root = _root()`. `curator.CuratorError` → exit 1.
- [x] `tests/test_curator.py` (new, ~200 lines): uses `mirror_helpers.Mirror` for a
      root-signed manifest with a curator key, writes the key file 0600 under the `home`
      fixture. Tests listed in the spec, plus: `test_post_round_trips_through_reader`,
      `test_amend_lower_uses_convention_line_and_reader_agrees`,
      `test_key_file_must_be_private_and_never_printed`, `test_dry_run_sends_nothing`,
      `test_missing_websockets_prints_install_hint`, `test_relay_rejects_auth`,
      `test_ws_url_must_be_wss_or_loopback`.

## Verification

- `python3 -m pytest -q` in the repo (stdlib only: the websockets test skips).
- The scratchpad venv with `websockets` installed runs `tests/test_curator.py`
  so the fake-server test runs for real.
- Leak grep over the files this task adds or changes (aitools_alerts/curator.py,
  aitools_alerts/relay.py, aitools_alerts/cli.py, tests/test_curator.py, pyproject.toml):
  the six fleet Mac names → 0 hits. The poster's denylist in poster/candidates.py and
  its fixtures name them on purpose and are out of scope. Key disclosure
  is tested with generated keys: no part of the nsec, the hex key or its upper case in
  stdout or stderr on any refusal or a dry run.

## Acceptance

All spec success criteria; full suite green; fake-server test passes with websockets.

## Rollback

`git revert` the feature commit; no state or live system is touched.

## Amendments after the spec/plan review (pass 1, 6cfa9f2f)

- `post_events` returns a list: a critical posts to critical then feed; at least one primary source.
- `find_threads(st, root, ref)`: every open thread of an advisory id; state from another root refused.
- `role_manifest`: newest of `st.accepted(root)` and the bundled manifest (pinned root only).
- `amend_event` / `retract_event` take the state: created_at after the thread's newest event;
  the signed reply is replayed through `pull.advisories` before it is returned.
- `relay.send` runs the exchange in a worker thread joined for timeout + GRACE.
- amend and retract pull first (`--no-pull` to skip).
- Tests added: both-channel critical and retract, primary source, ordering after a skewed
  reply, revocation across a root switch, foreign-root threads, tampered and mis-signed
  events, malformed keys, refused AUTH / malformed / reset / stalled write, CLI error path.
