# Curator subcommand (A7) — design

Kata: ai-tools-alerts#gctv. Plan task: docs/plan.md Task A7. Contract: the E1 note
(c:xyds9s, channel ids), the A5 landing note (c:dhz6ke, thread and patch rules the
readers enforce), directive 01M6MRNTMKYE93MC28Y687SYJZ (root-marked e tag), B3's
patch contract (ai-tools-alerts#kfq6 c:rncpsk, `poster.compose.apply_patch`).

## Problem

A curator (a human, today only Joi) needs to post a conforming advisory, amend
one, or retract one from the command line, signed with the curator's own key, so
that member CLIs trust it as a curator post (the only kind they may auto-apply
from). Today only the relay bot posts, through the Buzz CLI on the relay VM. The
reader rules are fixed by A5; this task writes events the readers accept, and
refuses locally what they would skip.

## Success criteria

1. `aitools-alerts curator post --level L --title T --product NAME --ecosystem E
   [--affected A] [--fixed V] --action verb:target[:value]... --source URL...
   [--id ID] [--alias X]... [--severity S] [--expires-at TS]
   [--channel feed|critical] [--dry-run]` builds a kind-9 event with tags
   `[["h", <channel id>]]` and no e tag, whose content is a short human body plus
   the block from `schema.render_post`, `posted_by` = the signing key's manifest
   role. A critical posts twice, to `critical` and then `feed` (the design: every
   critical also posts to the feed so the feed is complete); other levels post to
   `feed`; `--channel` names one channel only. At least one `--source` must pass
   `schema.is_primary` (the design: a post without a primary source does not post).
2. `curator amend <event-id|advisory-id> [--level L] [--fixed V | --fixed NAME=V]
   [--title T] [--source URL]... [--action ...]... [--expires-at TS | --no-expiry]
   [--note TEXT] [--no-pull] [--dry-run]` builds, for the root event id or for every
   open thread of the advisory id (a critical has one per channel), a kind-9 reply with tags
   `[["h", <root's channel>], ["e", <root id>, "", "root"]]`. A lower level
   becomes the first line `level: high` / `level: notice`; every other change
   (a higher level, fixed, title, sources, actions, expiry) goes in a trailing
   aitools-alert block holding only the changed fields. The merged advisory is
   built with `compose.apply_patch` and must pass `schema.validate`; then the
   signed reply is replayed through `pull.advisories` with the stored thread, and
   the amend is refused unless the readers reach exactly that advisory, unretracted.
   It is refused too when nothing changes. The first line is always the CLI's own
   (`level: ...` or `Amended: <title>`); `--note` is one line of at most 500
   characters with no code fence, placed after it. created_at is
   max(now, the newest stored event of the thread + 1), so readers, who sort replies
   by (created_at, id), apply it after every update the curator saw.
3. `curator retract <event-id|advisory-id> [--reason TEXT] [--no-pull] [--dry-run]`
   builds a reply per open thread with the same tags and ordering whose first line
   is `retract`, replayed to confirm the readers retract.
4. The key comes from `~/.config/aitools-alerts/key.nsec` (`config.key_path()`),
   nsec bech32 or 64 hex; the file must be a regular file with no group or other
   permission bits, or the command refuses. The key never appears on argv, in
   output, or in an error message (decode errors are replaced by a fixed text).
5. `relay.send(event, relay_url="wss://buzz.ai-tools.md", key, *, manifest,
   root_pubkey)`: refuses unless the manifest verifies under the root and
   `manifest.role_of(m, pubkey_of(key)) == "curator"` and the event's pubkey is
   the key's; then opens the websocket, waits for the relay's `["AUTH",
   challenge]`, answers with a signed kind-22242 event (tags `relay`,
   `challenge`), requires `["OK", auth_id, true, ...]`, sends `["EVENT", ev]`
   and returns the relay's `OK` as `(event_id, accepted, message)`. Only `wss://`
   URLs, plus `ws://` to a loopback host (the test server). Bounded: the whole
   exchange (connect, sends, reads, close) runs in a worker thread joined for the
   timeout plus a grace period; a stalled peer is cut off by closing the socket.
   At most 1 MiB per message, at most 100 messages read. Every failure (refused
   AUTH, closed or reset connection, malformed traffic, timeout) is a `RelayError`
   naming the cause by type only; the CLI prints one line and exits 1.
6. `websockets` is the optional extra `curator = ["websockets>=12"]`, imported
   only inside `relay.send`'s connect path. Without it the curator command prints
   `install the curator extra: pip install 'aitools-alerts[curator]'` and exits 1.
   The member package keeps `dependencies = []`.
7. `--dry-run` prints the signed event JSON and sends nothing (E3 can inspect an
   event before the live post). Without it the command prints the relay's OK and
   exits 0 only when accepted.
8. Amend and retract pull the mirror first (`--no-pull` skips it; a failed pull
   refuses), then read the root from the pulled state (`pull.advisories` for the
   current advisory, the stored root event's `h` tag for the channel); an unknown
   or retracted thread is refused with "run: aitools-alerts pull". Only state pulled
   under the requested trust root is used, and the role manifest is the newest one
   known for that root (`st.accepted(root)` or the bundled one under the pinned root),
   never another root's, so a test-root pull cannot roll back a revocation.
9. Tests: `test_post_event_has_block_and_h_tag`,
   `test_retract_is_reply_with_convention_text` (root-marked e tag),
   `test_amend_patch_validates_before_send`, `test_send_refuses_without_curator_role`,
   `test_nip42_auth_then_event_ok` against a fake websocket server under
   `pytest.importorskip("websockets")`, plus round-trip tests: every event the
   subcommand builds is read back by `pull.advisories` to the intended thread
   state (post, lowered level, patch, retract), and a key-leak test.

## Approach

- `aitools_alerts/relay.py` (stdlib at import): `RELAY_URL`, `RelayError`,
  `RelayUnavailable`, `auth_event(key, relay_url, challenge, now)`,
  `send(...)`. The websocket client is `websockets.sync.client.connect`, injected
  as `connect=` for tests.
- `aitools_alerts/curator.py`: `read_key(path) -> sec hex`, `channels()` from
  `spec/channels.json`, `role_manifest(state, root)` (the effective manifest of
  the pulled state under this root, else the bundled one under the pinned root),
  `post_event(...)`, `amend_event(...)`, `retract_event(...)` returning signed
  events, and `cmd_curator(a)` for the CLI.
- `cli.py`: register the `curator` subparser and dispatch to
  `curator.cmd_curator` (one registration block, so B4/A6 rebases stay clean).
- Role check happens twice: the builder signs only when the key is a curator in
  the manifest (so `--dry-run` cannot produce a relay-bot `posted_by` lie either),
  and `relay.send` checks again before connecting.
- Event shape per directive c:87syjz: a root has no e tag; a reply carries only
  the root-marked e tag (`relay` field ""). created_at is the current time.

## Alternatives considered

- Send through the VM's `buzz-send` like the poster: rejected; that signs with
  jibot's key, and a curator post must carry the curator's own signature.
- A pure-stdlib websocket client: rejected; the plan names the `websockets`
  extra, and a hand-written framing layer is new attack surface.
- Lowering a level inside the patch block: valid for a curator, but the design's
  convention line is what a curator in the Buzz app would type, so the CLI uses
  the same text; raising cannot use it (readers treat the line as lower-only).
- No pull before amend: rejected after review. Patches replace lists whole, so an
  amendment computed on a stale thread can revert an intervening change to
  products, actions or sources. Amend pulls first; the mirror itself lags the relay
  by the exporter's timer, a window accepted while one curator posts (Joi).

## Blast radius and rollback

New files plus a subparser and an optional extra; nothing existing changes
behaviour. No live send happens in this task (E3, jibot-code#gs18, does the live
post with Joi's key). Rollback: revert the commits.

## Assumes

- Buzz answers NIP-42 by sending `AUTH` on connect (the plan's interface says
  AUTH then EVENT). A relay that never sends a challenge is reported as an error
  rather than an unauthenticated send; E3 confirms on the live relay.
- The channel `h` tag value is the channel UUID from spec/channels.json.

## Open questions

None blocking.
