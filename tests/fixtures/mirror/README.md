# Mirror fixture

A synthetic mirror in the layout `pull` reads: `manifest.json`, `feed.json`,
`critical.json`. Every key here is a fixture key minted for this directory
with `nostr.keygen()`; the secret keys were discarded when the files were
written and exist nowhere. None of them is a real poster or the real trust
root, so the real CLI rejects this mirror unless the trust root is
overridden for a test:

    AITOOLS_ALERTS_TRUST_ROOT=089ffb066d0b69300c159a17ccce243b57908f39add1a1f7733db9c102f8aad8 \
      aitools-alerts pull --mirror-url file://$PWD/tests/fixtures/mirror/

- fixture trust root: `089ffb066d0b69300c159a17ccce243b57908f39add1a1f7733db9c102f8aad8`
- fixture curator: `8637bceab7230daff7dccbffb02207554851e639a0d1f1cb03ba5af7cd12e7cf`
- fixture relay-bot: `511d61e8625113488b4e223a849a6bcc8e3d1e25f58a145b5ad54c9595d7e9e2`

`critical.json` holds one relay-bot critical (Claude Code below 99.0.0);
`feed.json` holds the same event and one curator high (git below 1.0.0).
