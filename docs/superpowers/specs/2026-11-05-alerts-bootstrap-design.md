# ai-tools-alerts bootstrap: nostr primitives and trust root (Task A1)

Kata: jibot-code#zq90 (epic jibot-code#gr5b). Parent plan: `docs/plan.md`, Task A1. Parent design: `docs/design.md`.

## Problem

Every later task in the plan signs or verifies Nostr events: the trust manifest (A3) is signed by a root key, the member CLI (A5) verifies BIP-340 signatures on mirrored relay events, the curator (A7) signs posts. The member CLI must have no runtime dependencies, so the signature code is pure Python. The trust root key must exist before the manifest can be signed, and its public half must be pinned in the package.

## Success criteria

1. `scripts/test-gate.sh` runs `python3 -m pytest -q` and exits with its status; it passes.
2. `aitools_alerts.nostr` exposes exactly `keygen`, `sign_event`, `verify_event`, `event_id`, `npub`, `nsec_to_hex` with the signatures in plan Task A1.
3. Tests: BIP-340 vector 0 verifies; sign/verify roundtrip; tampered content fails; a known NIP-01 event id is reproduced; nsec roundtrip. Plus: every row of the official BIP-340 `test-vectors.csv` (0–18: signing where a secret key is given, verification for all, including invalid points, infinity, field/order boundaries and variable-length messages) at the raw `schnorr_sign`/`schnorr_verify` boundary; a tamper test that recomputes the id so rejection comes from the signature check; verify returns False (never raises) on malformed input.
4. `python3 -c "from aitools_alerts import TRUST_ROOT_PUBKEY; print(len(TRUST_ROOT_PUBKEY))"` prints 64 and the value equals `trust/root.pub`; a test asserts the equality.
5. Kura holds `AITOOLS_ALERTS_ROOT_NSEC`; `get_secret AITOOLS_ALERTS_ROOT_NSEC | wc -c` prints 65; the value is never printed, logged or committed; the temp file is wiped.
6. `.kata.toml` binds the repo to project `ai-tools-alerts`; `kata list --project ai-tools-alerts` shows eleven issues A2–A7, B1–B4, C1 with the blocked-by order from the brief; the refs are posted on jibot-code#gr5b.
7. README carries a "Status" section naming the kata project and the plan.
8. `main` on GitHub holds the work (fast-forward merge from the primary checkout).

## Approach

- `nostr.py` follows the BIP-340 reference implementation (affine point add/mul over secp256k1, `lift_x`, tagged hashes, `schnorr_sign` with aux randomness from `secrets.token_bytes(32)`, `schnorr_verify`). Scalar multiplication uses Jacobian coordinates for speed; verification of tens of events must stay well under a second each. Bech32 (not bech32m) encode/decode per BIP-173 for NIP-19 `npub`/`nsec`.
- `event_id` serializes `[0, pubkey, created_at, kind, tags, content]` with `json.dumps(..., separators=(",", ":"), ensure_ascii=False)` and hashes the UTF-8 bytes. NIP-01 escaping (only `\n`, `"`, `\\`, `\r`, `\t`, `\b`, `\f` escaped; other control chars as `\uXXXX`) matches `json.dumps` with `ensure_ascii=False`.
- `verify_event` checks the recomputed id equals `event["id"]`, then the signature over the id bytes with the x-only `pubkey`; any exception or malformed field returns False.
- `sign_event` returns a new dict (input not mutated) with `pubkey`, `id`, `sig` set; `created_at`, `kind`, `tags`, `content` required.
- Trust root: `keygen()` run once on this host (host-c); sec hex written to a 0600 temp file in a 0700 temp dir as the full vault line; an EXIT trap removes the temp dir on every exit and signal. `kura-edit.sh` runs with `EDITOR` set to a one-shot script that, inside kura-edit's vault lock, refuses to append when an `AITOOLS_ALERTS_ROOT_NSEC=` line already exists (so a retry or a concurrent writer cannot create a second value) and otherwise appends the line. Exit 3 (lock held) waits and retries; exit 4 (vault replaced mid-edit) overwrites and unlinks the whole-vault plaintext kura-edit keeps (best effort: on APFS an overwrite does not guarantee the old blocks are gone) and retries once; when the key is already present the run derives `trust/root.pub` from the stored value instead; any other failure stops before anything is published. Verification reads (`get_secret`) run with `SECRETS_CACHE_DIR` inside the temp dir, so no plaintext copy lands in the persistent cache `~/.cache/amplifier/secrets/`; the run then asserts no cache entry exists there. Then `kura-autocommit.sh` commits and pushes the vault. Only the pub hex enters the repo. A leak check reads the secret on stdin and searches the repo's working tree and full history for its hex and nsec forms, printing only `absent` or a path.
- Kata: `kata init --project ai-tools-alerts` in the primary checkout's worktree; the `.kata.toml` and the `.gitignore` line it adds are committed.

## Alternatives considered

- `coincurve`/`secp256k1` bindings: rejected; the CLI has no runtime dependencies (plan Global Constraints).
- Affine-only scalar multiplication exactly as in the BIP reference code: correct but roughly 10x slower in verify; Jacobian internal arithmetic with an affine result is a small, standard change. The reference code's semantics (point at infinity as None, `has_even_y`) are kept at the interface.
- Minting on host-b as the plan step says: the brief dispatches this to host-c and the vault is a git-synced file every Mac decrypts, so minting here and pushing through `kura-autocommit.sh` gives the same result.

## Blast radius / rollback

- Repo: new files only; revert the commits.
- Vault: one appended line. Rollback is `kura-edit.sh` removing that line before any manifest is signed; after A3 signs manifest v1, rotating the root means a new pinned key in a CLI release.
- Secret exposure risk: the sec hex lives only in the temp dir (wiped on every exit, cache included) and the vault. Tests use BIP-340 published vectors only.

## Assumes

- Constant-time arithmetic is out of scope: the root key signs a handful of manifests on a fleet Mac, never on a shared host; the member CLI only verifies.
- Assumes kata init on this host can create the project (fallback per brief: issues in jibot-code with `repo:ai-tools-alerts`).

## Open questions

None blocking.
