# ai-tools-alerts bootstrap Implementation Plan (Task A1)

Spec: `docs/superpowers/specs/2026-11-05-alerts-bootstrap-design.md`. Kata: jibot-code#zq90.

## Chunk 1: package scaffold, nostr primitives, gate

Files:
- Create `pyproject.toml`: setuptools build backend, `name = "aitools-alerts"`, `requires-python = ">=3.11"`, `dependencies = []`, `[project.optional-dependencies] dev = ["pytest"]`, packages `aitools_alerts`.
- Create `aitools_alerts/__init__.py`: `__version__`, `TRUST_ROOT_PUBKEY` (placeholder until chunk 2; chunk 2 sets the real value before commit of chunk 2).
- Create `aitools_alerts/nostr.py`: secp256k1 constants; Jacobian double/add, `_mul(k, P)`; `lift_x`; `tagged_hash`; `_sign(sec32, msg32, aux32)`; `_verify(pub32, msg32, sig64)`; bech32 (`_polymod`, `_hrp_expand`, `_convertbits`, `_bech32_encode`, `_bech32_decode`); public `keygen`, `sign_event`, `verify_event`, `event_id`, `npub`, `nsec_to_hex` (also `nsec(sec_hex)` and `npub_to_hex` helpers needed for the roundtrip test).
- Create `tests/test_nostr.py`:
  - `test_bip340_vector_1`: vector 0 (seckey 3, aux 0, msg 0, published sig) — verify True and deterministic sign with aux 0 reproduces the sig.
  - every row of the official `test-vectors.csv` (fixture `tests/fixtures/bip340-test-vectors.csv`), parametrized: sign where a secret key is given, verify against the expected result. Variable-length messages are supported as in the reference code.
  - `test_sign_then_verify_roundtrip`, `test_tampered_content_fails_verify`, tampered id / sig / pubkey fail.
  - `test_event_id_matches_known_event`: a published kind-1 event with id and sig; id reproduced and `verify_event` True.
  - `test_nsec_roundtrip`, `test_npub_known_value` (NIP-19 example npub ↔ hex), bad checksum rejected.
  - `test_verify_malformed_returns_false` (missing keys, non-hex, wrong lengths).
- Create `scripts/test-gate.sh` (`#!/bin/sh`, `cd` to repo root, `exec python3 -m pytest -q`), chmod 755.

Verify: `python3 -m pytest tests/test_nostr.py -v` fails before implementation, passes after; `scripts/test-gate.sh; echo $?` prints 0 (chunk 1 has no trust-root test yet; that test arrives in chunk 2 with the key).

## Chunk 2: kata binding, trust root, README

Helper paths, always absolute: `KE=/path/to/dotfiles-private/scripts/kura-edit.sh`, `SH=/path/to/dotfiles-private/scripts/lib/secrets.sh`, `AC=/path/to/dotfiles-private/scripts/kura-autocommit.sh`. Every multi-line step is a script file in the session scratchpad run with `bash -euo pipefail`.

1. `kata init --project ai-tools-alerts --agent` in the worktree. Commit `.kata.toml` and the `.gitignore` change. If refused for rights: `PROJECT=jibot-code` for chunk 3, the README names jibot-code with the `repo:ai-tools-alerts` label, verification filters `kata list --project jibot-code --label repo:ai-tools-alerts`, and the close-out carries a `notice:`. Otherwise `PROJECT=ai-tools-alerts`.
2. Mint (`mint.sh`, prints no value at any point):
   - `umask 077; D=$(mktemp -d)`; an EXIT trap (signals routed to it) runs `cleanup`: `set +e`, then for every file under `$D` at any depth (the cache dir included) a best-effort `wipe` (overwrite with zeros via `dd conv=notrunc`, then unlink; `rm -P` is a no-op on macOS), then `rm -rf "${D:?}"` and a warning if `$D` survives. On APFS an overwrite does not guarantee old blocks are gone; the guarantee is that no file remains, under a 0700 dir on a FileVault disk.
   - python (the worktree on `PYTHONPATH`, not `-I`, which ignores it; the read-side helpers run `-I` and insert the worktree path into `sys.path` from argv) calls `keygen()`, writes `AITOOLS_ALERTS_ROOT_NSEC=<sec>\n` to `$D/line` and the pub hex to `$D/pub`; stdout prints nothing.
   - One-shot editor `$D/editor.sh`: if the decrypted file it is handed already has a line `^AITOOLS_ALERTS_ROOT_NSEC=`, touch `$D/present` and exit 0 without changing it (kura-edit then reports "No changes" and exits 0); otherwise append `$D/line` (adding a newline first if the file lacks one) and exit 0. The absence check therefore runs inside kura-edit's lock, so no other writer and no retry can create a second value.
   - `EDITOR=$D/editor.sh $KE`; capture exit code. Before any `get_secret` call (the recovery branch below included) the script exports `SECRETS_CACHE_DIR=$D/cache` and sources `$SH`, so no read can write the persistent cache. 0 with `$D/present` → the key already exists (an earlier run appended it): discard the new `$D/pub`, derive the stored key's public half from `get_secret` on stdin into `$D/pub`; if `trust/root.pub` exists and differs, stop; otherwise write it. 0 without `present` → success. 3 (lock held) → wait 60 s and retry, at most 5 times; never force. 4 (vault replaced mid-edit) → `wipe` the kept plaintext path kura-edit printed on stderr (captured to `$D/err`, its path extracted, never the content), then rerun once from the absence check. Any other code → stop, nothing published.
   - Only after success: copy `$D/pub` to `trust/root.pub`.
   - Verify, with `export SECRETS_CACHE_DIR=$D/cache` so no copy reaches the persistent cache: `source $SH; get_secret AITOOLS_ALERTS_ROOT_NSEC | wc -c` → 65 (also proves one value, not two); `get_secret AITOOLS_ALERTS_ROOT_NSEC | python3 -I derive.py trust/root.pub` derives the pub from stdin and prints only `match` or `MISMATCH`; the leak check below runs here too, under the same cache dir; finally `test ! -e /path/to/secrets-cache/AITOOLS_ALERTS_ROOT_NSEC`.
   - `$AC`; then `git -C /path/to/dotfiles-private log -1 --stat` shows only the vault path, and `git -C /path/to/dotfiles-private status --short` shows nothing for it.
3. Set `TRUST_ROOT_PUBKEY` in `__init__.py` to the pub hex; add `tests/test_trust_root.py`: `TRUST_ROOT_PUBKEY` is 64 lowercase hex and equals `trust/root.pub` stripped.
4. README: replace the "being built" line with `## Status`: the kata project, plan `docs/plan.md`, design `docs/design.md`, root pubkey file `trust/root.pub`.

Verify: gate passes; `python3 -c "from aitools_alerts import TRUST_ROOT_PUBKEY; print(len(TRUST_ROOT_PUBKEY))"` → 64; leak check (rerun after the final commit, again under a temp `SECRETS_CACHE_DIR`) `get_secret AITOOLS_ALERTS_ROOT_NSEC | python3 -I leakcheck.py <repo>` reads the secret from stdin and searches for its hex (both cases) and its nsec bech32 in every file under the working tree (tracked, untracked and ignored; `.git` excluded) and in every object in the store (`rev-list --all --reflog --objects` plus `fsck --unreachable`, read raw through `cat-file --batch`), self-tested first against a throwaway key placed in an ignored file and in deleted history, printing only `absent` or `FOUND in <path|commit>`; it never prints a line's content.

## Chunk 3: kata issues (no repo diff)

For each of A2, A3, A4, A5, A6, A7, B1, B2, B3, B4, C1 (dependency order: A2, B1, A3, A4, A5, A6, A7, B2, B3, B4, C1): `kata create "<task title>" --project $PROJECT --body-file <file>` with body = plan path + task name + Files and Interfaces blocks copied verbatim from `docs/plan.md` (extracted by a script from the headings, not retyped); `--priority 2 --label repo:ai-tools-alerts --label area:security --label discovered-from:zq90 --related jibot-code#gr5b --idempotency-key aitools-alerts-<task>-2026-11-05`; `--blocked-by` (repeatable) as: A3←A2, A4←A2, A5←A3+A4, A6←A5, A7←A5, B2←A2+B1, B3←B2, B4←B3, C1←A3. Record each task → ref in a map file; later creates read blockers from it. The body names the plan "at the landed commit"; the merge sha is added as a comment on each after main lands. Post the ref list on jibot-code#gr5b.

Verify: `kata list --project $PROJECT` shows eleven; a check script runs `kata show <ref> --json` for each and asserts priority 2, the three labels, the gr5b relation, and the exact blocker set from the map (A5 and B2 each two), printing one PASS/FAIL line per issue.

## Ending

Review (medium or as the evaluator floors), fix, `git fetch`, rebase if origin/main moved, push branch, ff-merge to main from `/path/to/repos/ai-tools-alerts`, push main, close-out comment, `kata close`, `/finish-worktree`.

Rollback: revert repo commits; remove vault line via `kura-edit.sh`; `kata close` the eleven issues as wont-do.
