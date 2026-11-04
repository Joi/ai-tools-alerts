# ai-tools-alerts

Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills.

Two channels on the henkaku ai-tools Buzz relay (`#security-feed` to browse, `#security-critical` to be interrupted), a signed public mirror, and a small CLI your agent can read so it verifies who posted an alert, checks what is installed, and prepares the fix.

## Status

Under construction; nothing here is ready to install yet. The design is `docs/design.md` and the implementation plan `docs/plan.md`. Work is tracked in the kata project `ai-tools-alerts`, one issue per plan task, under the epic jibot-code#gr5b.

Done: the pure-Python Nostr primitives (`aitools_alerts/nostr.py`: BIP-340 signatures, NIP-01 event ids, NIP-19 keys) and the trust root. The trust root's public key is `trust/root.pub`; it signs only the manifest that lists who may post alerts, and the CLI pins it as `TRUST_ROOT_PUBKEY`.

The two channels exist on `buzz.ai-tools.md`; their UUIDs are in `spec/channels.json`, and `ops/vm/README.md` says what this service keeps on the relay VM, including the `buzz-send` wrapper. Buzz cannot restrict who posts in an open channel, so `#security-critical` is open: only keys in the trust manifest are trusted by the CLI, and anyone may reply.

Trust root public key (x-only hex), the same value as `trust/root.pub`:

```
afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4
```

Tests: `scripts/test-gate.sh`.
