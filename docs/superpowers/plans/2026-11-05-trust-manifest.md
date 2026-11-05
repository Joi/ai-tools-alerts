# Plan: signed trust manifest (Task A3, ai-tools-alerts#0exc)

Spec: docs/superpowers/specs/2026-11-05-trust-manifest-design.md. Standard library only; pytest is the only dev dependency. No test reads Kura: tests mint keys with `nostr.keygen()`.

## Chunk 1 — `aitools_alerts/manifest.py` and its tests (TDD)

Files: create `aitools_alerts/manifest.py`, `tests/test_manifest.py`.

- [ ] 1.1 Write `tests/test_manifest.py` with a helper `make(sec, content, kind=30078, tags=None) -> bytes` that signs with `nostr.sign_event` and returns JSON bytes. Tests:
  - `test_manifest_signed_by_root_verifies` — root keypair signs v1; `verify(load(b), root_pub)` is True.
  - `test_manifest_signed_by_other_key_rejected` — signed by another key (also: by a poster's own key) → `verify(..., root_pub)` False.
  - `test_manifest_version_must_increase` — load v2, then `load(v1, previous=m2)` raises `ManifestError`; same version with different content raises; same bytes again is accepted.
  - `test_role_lookup` — curator, relay-bot, unknown → None, uppercase hex → None.
  - `test_committed_manifest_verifies_against_pinned_root` — `load(trust/manifest.json)`, `verify(m, TRUST_ROOT_PUBKEY)`, version 1, roles of the two v1 keys. (Fails until chunk 2 signs v1.)
  - Hardening (parametrized): wrong kind; missing/wrong/duplicate `d` tag; extra or missing event key; extra content key; version bool/0/negative/str; bad `issued_at`; role outside ROLES; duplicate poster pubkey; empty posters; poster pubkey uppercase / not on curve; name empty / control char / bidi char / 65 chars; duplicate JSON key; NaN; non-UTF-8; oversize (>1 MiB); top-level non-object. Each raises `ManifestError`.
  - `verify` hardening: tampered content (id mismatch) False; tampered sig False; `Manifest` with genuine event but posters altered via `dataclasses.replace` False; bad root_pubkey (uppercase, short, non-str) False, never raises.
  - `load` accepts a `pathlib.Path`, a `str` path and `bytes`.
- [ ] 1.2 Run `python3 -m pytest tests/test_manifest.py -q` — expect ImportError FAIL.
- [ ] 1.3 Implement `manifest.py` per the spec: `ManifestError`, `Poster`, `Manifest`, `parse_content(obj) -> (version, issued_at, posters)`, `load`, `verify`, `role_of`, constants `KIND = 30078`, `D_TAG = "aitools-alerts-manifest"`, `MAX_BYTES = 1 << 20`, `MAX_POSTERS = 64`. Imports: `schema.ROLES`, `nostr` (`verify_event`, `_lift_x`, `_is_hex`). Store `event` as `copy.deepcopy`.
- [ ] 1.4 Run — all pass except the committed-manifest test, which stays failing (not skip-marked) until chunk 2 signs v1; chunk 1 is not committed alone.

Acceptance: every chunk-1 test except the committed-manifest test passes.

## Chunk 2 — `scripts/sign-manifest.py`, v1, commit

Files: create `scripts/sign-manifest.py` (mode 755), `trust/manifest.json`; extend `tests/test_manifest.py`.

- [ ] 2.1 Script tests (import via `importlib.util.spec_from_file_location`):
  - `test_sign_script_reads_secret_with_throwaway_cache` — fake runner records `env["SECRETS_CACHE_DIR"]` (exists during the call, refuses a write during the call, gone after), asserts `AITOOLS_ALERTS_ROOT_NSEC` not in env, argv carries no secret, stdin is DEVNULL; returns a throwaway hex key; result equals it. Variants: `nsec1…` value decoded; non-zero exit → `SystemExit` whose message carries no stderr text; garbage value → error, temp dir still removed.
  - `test_sign_script_refuses_when_helper_wrote_to_cache` — a runner that forces a write into the cache dir → `SystemExit`, dir removed, message carries no key.
  - `test_sign_script_builds_verifiable_event` — `build_event(content, sec)` with a throwaway key, then `load` + `verify(…, that pub)` True; `created_at` equals the independently computed epoch of `issued_at` (1793865600 for 2026-11-05T08:00:00Z), and the loaded manifest's `issued_at` is the original string.
  - `test_sign_script_refuses_non_root_key` — `main` with a fake runner returning a throwaway key exits non-zero and writes nothing to `--out`.
  - `test_sign_script_main_writes_and_prints_id` — monkeypatch `TRUST_ROOT_PUBKEY` in the script module to a throwaway pub; `main([content, "--out", tmp])` writes a file that loads and verifies; stdout is exactly the event id + newline.
- [ ] 2.2 Implement the script: `read_root_secret(runner=subprocess.run)`, `build_event(content, sec_hex)`, `main(argv=None)`. Repo root = `Path(__file__).resolve().parent.parent`; inserts it on `sys.path` so `aitools_alerts` imports without install. Atomic write with `tempfile.NamedTemporaryFile(dir=out.parent, delete=False)` + `os.replace`, chmod 644.
- [ ] 2.3 Run `scripts/test-gate.sh` — all pass except the committed-manifest test.
- [ ] 2.4 Re-read the relay-bot key: `ssh relay-vm.example cat /home/relay/.buzz-keys/agent.pub.hex`; stop if it differs from `d4f04ff6…39c1`.
- [ ] 2.5 Write the v1 content to the scratchpad (`version 1`, `issued_at` now UTC, posters Joi/curator, jibot/relay-bot). Run `python3 scripts/sign-manifest.py <scratch>/content.json`. Expect one 64-hex line.
- [ ] 2.6 Verify: the acceptance one-liner prints `curator`; `scripts/test-gate.sh` passes in full. The script itself refuses if the read-only throwaway cache dir received any entry during the real helper run, so a successful signing is the in-execution evidence that the real helper wrote nothing; also confirm the default cache dir has no `AITOOLS_ALERTS_ROOT_NSEC` entry newer than the run. (No automated test runs the real helper: the repo is public and its gate must not depend on the private secrets library or decrypt the vault.)
- [ ] 2.7 Leak check: `git diff origin/main --cached` / `git diff origin/main` grepped for `nsec1`, the fleet host names, and every 64-hex string, each 64-hex string accounted for (root pub, two poster pubs, event id, the sig is 128 hex, test vectors already on main).
- [ ] 2.8 Commit `feat: signed trust manifest v1` (spec, plan, manifest, code, tests, trust/manifest.json).

Acceptance: brief's acceptance criteria (test gate, one-liner prints `curator`, clean leak check).

## Verification commands

```
scripts/test-gate.sh
python3 -c "from aitools_alerts import TRUST_ROOT_PUBKEY, manifest; m = manifest.load('trust/manifest.json'); assert manifest.verify(m, TRUST_ROOT_PUBKEY); print(manifest.role_of(m, '18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29'))"
```

## Rollback

Revert the commits. A wrong v1 already on main is superseded by signing v2 (A5 enforces monotonic versions), not by rewriting history.
