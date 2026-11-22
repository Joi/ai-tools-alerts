# Mirror fixture

A synthetic mirror in the layout `pull` reads: `manifest.json`, `feed.json`,
`critical.json`, and for readers that check the checkpoint `checkpoint-key.json` (the root's certificate for
the checkpoint key) and `checkpoint.json` (a checkpoint listing both events,
signed at the newer event's time and valid for a day).

Every key here is a fixture key minted for this directory
with `nostr.keygen()`; the secret keys were discarded when the files were
written and exist nowhere. None of them is a real poster or the real trust
root, so the real CLI rejects this mirror unless the trust root is
overridden for a test, which also needs `trust_root_override = true` in
`~/.config/aitools-alerts/config.toml`:

    AITOOLS_ALERTS_TRUST_ROOT=d93ff4a861da4d569343be6b35bdb765b566fb4c04fbef25e194600e3e18d3f0 \
      aitools-alerts pull --mirror-url file://$PWD/tests/fixtures/mirror/

- fixture trust root: `d93ff4a861da4d569343be6b35bdb765b566fb4c04fbef25e194600e3e18d3f0`
- fixture curator: `16f3e685aab84be11f5c3b4084dd99b73a0b1e8db81cd1b2fdc75eb5a51e8a69`
- fixture relay-bot: `bd1588bc41bb35c4fad4fbe35e3710739cad447ef317856b48ea01a4737cdd38`
- fixture checkpoint key: `0bebd63fcbec6a0ac8df09a8f3dde651987b1ef7682f62c14c20948f0b83ffaa`

Every event carries its channel's `h` tag (the ids in `spec/channels.json`), as the
relay writes it; the reader drops an event without one. The events are dated
2099-01-01 so they never age out of a test: a reader from v0.1.5 on refuses them
as future-dated under the real clock, and the tests pull them with a fixed clock
(`tests/conftest.py`).

`critical.json` holds one relay-bot critical (Claude Code below 99.0.0);
`feed.json` holds the same event and one curator high (git below 1.0.0).
