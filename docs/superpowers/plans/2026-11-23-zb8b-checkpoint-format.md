# Plan: checkpoint format (certificate, checkpoint, signing script)

Spec: `docs/superpowers/specs/2026-11-23-zb8b-checkpoint-format-design.md`. Kata: ai-tools-alerts#zb8b. Branch `zb8b-checkpoint-format`, landed by pull request. Tests first in each chunk.

## Chunk 1: `aitools_alerts/checkpoint.py`

New file; nothing imports it.

- [ ] `tests/test_checkpoint.py`, with throwaway keys from `nostr.keygen()` and a manifest built as `tests/mirror_helpers.Mirror` builds one:
  - round trip: `build_cert` → `load_cert` → `verify_cert` true → `cert_problem is None`; `build_checkpoint` → `load_checkpoint` → `verify_checkpoint` true → `checkpoint_problem is None`;
  - certificate shape, each refused by `load_cert` with `CheckpointError`: not JSON, a duplicate key, a non-standard constant, an extra event key, kind other than 30078, the manifest's `d` tag, the checkpoint's `d` tag, two tags, `created_at != issued_at`, `expires_at <= issued_at`, a bad date string, `checkpoint_key` not 64 hex or not on the curve, `manifest_id` not 64 hex, `manifest_version` not an integer in range (a bool refused), `v` missing, `v: 2`, `v: true`, over 16 KiB, a path that does not exist;
  - `verify_cert`: false for a certificate signed by a non-root key, for a dataclass whose fields were changed after loading (`dataclasses.replace`), for a tampered content with the old signature; never raises on junk;
  - `cert_problem`: `"other manifest"`, `"dated ahead"` at `issued_at == now + 601` and none at `+600`, `"expired"` at `now == expires_at + 1` and none at `expires_at`;
  - checkpoint shape, each refused: the certificate's `d` tag, `seq` 0, negative, a bool, a float; `valid_until` not an integer; `events` not a list, an id that is not 64 lowercase hex, unsorted, a duplicate, 2,001 ids; over 256 KiB; `v` other than 1;
  - `verify_checkpoint`: false under a certificate naming another key; false for a tampered dataclass;
  - forgery, for BOTH documents, each loaded into a consistent dataclass first so that only the signature check can refuse it: the valid event with its signature alone corrupted; other content with the id recomputed and the old signature; other content under the old id;
  - the checkpoint's type boundary, each an otherwise valid event signed by the checkpoint key: kinds 1, 9 and 30079, no tag, the manifest's and the certificate's `d` tag, a second tag, a three-element `d` tag, an extra event key, a missing event key;
  - `checkpoint_problem`: `"other manifest"`, `"dated ahead"`; `fresh_until` is `valid_until` when under 48 hours and `created_at + 172800` when the signer asked for more;
  - an unknown content key in each document loads and verifies;
  - `cert_order` and `checkpoint_order`: every case of the spec's "Order" section, one assertion each;
  - a manifest event is refused by both loaders, and a certificate and a checkpoint are each refused by `manifest.load` (no document passes for another);
  - `build_checkpoint` refuses an id that is not 64 hex, more than 2,000 ids, `seq < 1`, and sorts and de-duplicates what it is given; `build_cert` refuses `expires_at <= issued_at` and a key that is not on the curve.
- [ ] `aitools_alerts/checkpoint.py` as the spec's module section lists it. Reuse `manifest._json`-style parsing (duplicate keys, constants, recursion, the 4300-digit limit) through one private `_json` that raises `CheckpointError`; reuse `nostr._check_shape`, `nostr._is_hex`, `nostr._lift_x`, `nostr.verify_event`, `nostr.sign_event`; `MAX_AHEAD_S` from `pull` is imported lazily or redefined as the same number with a test that the two are equal (no import cycle: `pull` will import `checkpoint` in piece 3).
- [ ] Verify: `python3 -m pytest -q tests/test_checkpoint.py`.

Acceptance: every listed case is a test; `grep -rn "import checkpoint\|from .checkpoint\|checkpoint import" aitools_alerts mirror` finds nothing outside the new module.

## Chunk 2: `scripts/sign-checkpoint-key.py`

- [ ] `tests/test_checkpoint.py` (script section), loading the script with `importlib` as `tests/test_manifest.py` loads `sign-manifest.py`, with `TRUST_ROOT_PUBKEY` monkeypatched to a throwaway root and `read_root_secret` replaced by a stub returning that root's secret:
  - writes `--out`, mode 0644, a certificate that `load_cert`, `verify_cert` and `cert_problem(now)` accept for `--manifest`; `expires_at - issued_at == days * 86400`; default 120 days; stdout is exactly the event id and a newline;
  - accepts the key as an npub only; refuses hex (a secret key in hex is a valid public key half the time), an nsec, a malformed npub, the trust root and every manifest poster;
  - refuses, before the key is read, a certificate that readers holding the existing `--out` would refuse (clock set back, same second), an unreadable or non-root existing `--out`, and `--out` equal to `--manifest`;
  - refuses a manifest that does not load or does not verify under the root, `--days 0`, `--days 401`, a missing output directory: each a `SystemExit` with a `sign-checkpoint-key:` message, the stub never called (the key is not read before the inputs are checked);
  - refuses when the secret read is not the trust root's (stub returns another key): nothing written;
  - the secret never appears in stdout, stderr or the output file.
- [ ] `scripts/sign-checkpoint-key.py`: argparse; inputs checked first; `read_root_secret` imported from `scripts/sign-manifest.py` by path with `importlib` (one implementation of the root key handling; this script adds no code that touches the secret beyond passing it to `checkpoint.build_cert` and deleting the name); atomic write as `sign-manifest._write`; module docstring with usage.
- [ ] `README.md` ("For the fleet: the poster" section): one paragraph naming the two documents and the script. `CHANGELOG.md`: one entry under Unreleased. `pyproject.toml`: no change (`trust/*.json` is already package data, so a future `trust/checkpoint-key.json` ships).
- [ ] Verify: `scripts/test-gate.sh`.

Acceptance: gate green; the code (module and script) is about 430 lines and its tests about 600. The first draft of this line asked for under 600 changed lines in all, which the refusal matrix of two signed formats cannot meet; the module and its only caller stay one deliverable (recorded as a rebuttal in the run manifest); the v0.1.4 reader test of piece 1 still passes (no file that reader fetches or bundles changes: `trust/` gains nothing in this piece).

## Rollback

Revert the merge commit. Nothing imports the module and no data file changes.
