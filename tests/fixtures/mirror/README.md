# Mirror fixture

A synthetic mirror in the layout `pull` reads: `manifest.json`, `feed.json`,
`critical.json`. Every key here is a fixture key minted for this directory
with `nostr.keygen()`; the secret keys were discarded when the files were
written and exist nowhere. None of them is a real poster or the real trust
root, so the real CLI rejects this mirror unless the trust root is
overridden for a test, which also needs `trust_root_override = true` in
`~/.config/aitools-alerts/config.toml`:

    AITOOLS_ALERTS_TRUST_ROOT=94d98852088607612f8780d6eca08fba7ff783594c628cfcc1e440f31e3aae9d \
      aitools-alerts pull --mirror-url file://$PWD/tests/fixtures/mirror/

- fixture trust root: `94d98852088607612f8780d6eca08fba7ff783594c628cfcc1e440f31e3aae9d`
- fixture curator: `ad3d8b2fec2741cd72f205fd02a3db948d95f344c8422e9f8c34a2372e101755`
- fixture relay-bot: `af422e5d68d9e92721addaed3bd19160e622959157cd42bcff260affc8c176be`

Every event carries its channel's `h` tag (the ids in `spec/channels.json`), as the
relay writes it; the reader drops an event without one. The events are dated
2099-01-01 so they never age out of a test: a reader from v0.1.5 on refuses them
as future-dated under the real clock, and the tests pull them with a fixed clock
(`tests/conftest.py`).

`critical.json` holds one relay-bot critical (Claude Code below 99.0.0);
`feed.json` holds the same event and one curator high (git below 1.0.0).
