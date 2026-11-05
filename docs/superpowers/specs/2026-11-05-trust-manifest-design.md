# Signed trust manifest (Task A3, ai-tools-alerts#0exc)

Date: 2026-11-05. Parent: docs/plan.md Task A3; design docs/design.md ("Trust manifest and action vocabulary"). Builds on A1 (`aitools_alerts.nostr`, `TRUST_ROOT_PUBKEY`, `trust/root.pub`) and A2 (`schema.ROLES`).

## Problem

The member CLI (A5), the mirror exporter (C1) and the curator subcommand (A7) all have to answer one question: is this pubkey a trusted poster, and in which role? The answer must come from a file a compromised GitHub account cannot edit undetectably. The design's answer is a manifest signed by a dedicated trust root whose public key is pinned in the package. Nothing yet parses, verifies or produces that manifest, and the one script that touches the root signing key must not leave the key anywhere.

## Success criteria

1. `aitools_alerts/manifest.py` exposes `Manifest`, `Poster`, `load`, `verify`, `role_of`, `ManifestError`.
2. `tests/test_manifest.py` holds the plan's four tests (`test_manifest_signed_by_root_verifies`, `test_manifest_signed_by_other_key_rejected`, `test_manifest_version_must_increase`, `test_role_lookup`), the committed-manifest test, and the hardening tests below. Tests mint throwaway keys with `nostr.keygen`; none reads Kura.
3. `trust/manifest.json` is committed, version 1, signed by the root, and this prints `curator`:
   `python3 -c "from aitools_alerts import TRUST_ROOT_PUBKEY, manifest; m = manifest.load('trust/manifest.json'); assert manifest.verify(m, TRUST_ROOT_PUBKEY); print(manifest.role_of(m, '18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29'))"`
4. `scripts/sign-manifest.py <content.json>` signs with the root key read through `get_secret` in a subprocess with a throwaway `SECRETS_CACHE_DIR`, writes `trust/manifest.json`, prints only the event id.
5. `scripts/test-gate.sh` passes. Standard library only. The diff carries no secret and no fleet host name.

## Approach

### Data model

```python
@dataclass(frozen=True)
class Poster:  pubkey: str; role: str; name: str

@dataclass(frozen=True)
class Manifest:
    event: dict          # the signed Nostr event, as loaded (a private deep copy)
    version: int
    issued_at: str
    posters: tuple[Poster, ...]
```

`ManifestError(ValueError)` is raised for every rejection by `load`.

### `load(src, previous=None) -> Manifest`

`src` is a `str`/`os.PathLike` path, or `bytes`. Steps, any failure raising `ManifestError`:

1. Read at most 1 MiB (a longer file is rejected); decode UTF-8; `json.loads` with duplicate-key rejection and `NaN`/`Infinity` rejected (same idiom as `schema.decode_block`), `RecursionError` contained.
2. Event shape: a JSON object with exactly the keys `id, pubkey, created_at, kind, tags, content, sig`; `kind == 30078`; `tags` is exactly `[["d", "aitools-alerts-manifest"]]` (no other tag; implementation tightened this from "contains"). `pubkey`, `id`, `sig` are lowercase hex of the right length. Signature correctness is NOT checked here; that is `verify`.
3. Content: `json.loads(content)` with the same strict decoding; an object with exactly the keys `version, issued_at, posters`.
   - `version`: an `int` (not `bool`), `1 <= version <= 2**31-1`.
   - `issued_at`: a string `YYYY-MM-DDTHH:MM:SSZ` (UTC, seconds, literal `Z`) that `datetime` accepts.
   - `posters`: a list of 1 to 64 objects with exactly `pubkey, role, name`; `pubkey` 64 lowercase hex and a valid x-only curve point (`nostr._lift_x` is the one primitive used, as `tests/test_trust_root.py` already does); `role` in `schema.ROLES` (imported, not redefined); `name` a string of 1 to 64 printable characters (no control or bidi characters). Duplicate pubkeys are rejected.
4. `previous`: if given, `version < previous.version` raises (rollback); `version == previous.version` with a different event id raises (same version, different content); same id is accepted (re-reading the same manifest).

### `verify(m, root_pubkey) -> bool`

True only if `root_pubkey` is 64 lowercase hex, `m.event["pubkey"] == root_pubkey`, `nostr.verify_event(m.event)` is true, and the content re-parsed from `m.event` equals `m`'s `version`, `issued_at` and `posters` (so a `Manifest` built or altered by hand cannot pass with a genuine event attached). Never raises.

### `role_of(m, pubkey) -> str | None`

The role of the poster whose pubkey equals `pubkey` exactly, else `None`. It does not verify; callers verify first. The module docstring says so, and A5's contract is "load, verify, then role_of".

### `scripts/sign-manifest.py <content.json> [--out PATH]`

1. Read and validate `content.json` with the same content validator `load` uses (exposed as `manifest.parse_content`), so a malformed content never gets signed.
2. Read the root secret: `subprocess.run(["bash", "-c", "source the Kura secrets helper && get_secret AITOOLS_ALERTS_ROOT_NSEC"], env=..., stdin=DEVNULL, capture_output=True, timeout=60)`, where `env` is a copy of `os.environ` with `SECRETS_CACHE_DIR` set to a fresh `tempfile.mkdtemp()` and `AITOOLS_ALERTS_ROOT_NSEC` removed (so `get_secret` cannot fall back to a stale environment value). The temp dir is chmod 0500 before the call: `get_secret` writes every value it reads to `$SECRETS_CACHE_DIR` (`_secrets_cache_value`: a `mktemp` there, then a rename), and in a directory without write permission that `mktemp` fails, which the helper ignores (`|| true`), so the key never reaches disk (review pass 1 BLOCKER: a merely throwaway directory still received a plaintext copy). After the call the script refuses if the directory is not empty, then restores 0700 and removes it in a `finally`. The key's one channel is the subprocess's stdout pipe into this process, which is the transport the brief prescribes. Stderr is never echoed (only "could not read the root key, exit N"). The value is accepted as 64 hex or a bech32 `nsec1…` (via `nostr.nsec_to_hex`).
3. Derive the pubkey (sign an event, read its `pubkey`) and refuse unless it equals `TRUST_ROOT_PUBKEY`.
4. Event: `kind 30078`, `tags [["d","aitools-alerts-manifest"]]`, `created_at` = `issued_at` as epoch seconds, `content` = `json.dumps(content, sort_keys=True, separators=(",", ":"))`. Signed with `nostr.sign_event`.
5. Before reading the key: if `--out` already holds a manifest, it must load, and the new version must be higher than its version (otherwise refuse and write nothing). After signing, re-load the event through `manifest.load(..., previous=<that manifest>)` and `manifest.verify(..., TRUST_ROOT_PUBKEY)`; then write `--out` (default `trust/manifest.json` at the repo root) atomically (temp file in the same dir, `os.replace`), pretty-printed JSON with a trailing newline, mode 644.
6. Print the event id and nothing else. The secret never reaches argv, this process's stdout or stderr, a log or a file; it crosses one pipe from the helper.

Testable pieces (`read_root_secret(runner=subprocess.run)`, `build_event(content, sec_hex)`) are functions; tests import the script with `importlib` and pass a fake runner, never the real helper.

### Manifest v1

Content: version 1, `issued_at` the signing time, posters Joi (`18eafd07…fe29`, curator, "Joi") and jibot (`d4f04ff6…39c1`, relay-bot, "jibot"). The jibot key was re-read from the VM before signing and matched the brief. Only `trust/manifest.json` is committed: the content is recoverable from the event, so the input content file lives in the scratchpad.

## Alternatives considered

- **Module-level "highest version seen" state in `load`.** Rejected (the brief's call): hidden state across calls; A5 keeps the accepted manifest in its state file and passes it in.
- **`load` also verifies the signature against the pinned root.** Rejected: the Interfaces block separates `verify(m, root_pubkey)`, and tests need to load manifests signed by throwaway roots. The ordering risk is handled by documentation and by A5's contract.
- **Calling `get_secret` through a helper other than a bash subprocess.** Rejected: the brief and plan name this exact mechanism, matching A1's mint script.

## Blast radius and rollback

New files only, plus nothing modified outside them. Rollback is a revert of the commits. A bad `trust/manifest.json` is replaced by signing a higher version; until A5 ships, no member reads it.

## Amendments from the code review (pass 1)

- `load` rejects any `ValueError` from the JSON decoder (an integer over Python's 4300-digit limit) as `ManifestError`, and requires the event's `created_at` to equal `issued_at` in epoch seconds.
- `sign-manifest.py` refuses to run as root (a privileged process ignores the 0500 mode) and, before the helper runs, proves the throwaway directory refuses a write; it drops `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `BASH_XTRACEFD`, `PS4` from the helper's environment; it checks the `--out` directory exists before reading the key.
- Rollback protection holds only when the caller passes `previous`. A member with no stored state accepts any root-signed manifest, including an old one; A5 owns that (a freshness bound on `issued_at` or a pinned minimum version), and it is noted on ai-tools-alerts#z4hs.

## Assumes

- The secrets helper caches only under `$SECRETS_CACHE_DIR`, chmods only a directory it creates, and treats a failed cache write as non-fatal (true of `secrets.sh` on 2026-11-05; checked by the code reviewer against the real helper with a throwaway vault). If that changes, the script's pre- and post-checks catch a writable directory or a written entry.

- The vault value of `AITOOLS_ALERTS_ROOT_NSEC` is 64 hex characters (the brief's `wc -c` prints 65); the script also accepts `nsec1…`.
- Signing happens on the Mac that runs this task, not the one plan step 5 names: the vault is one synced file, so any fleet Mac reads the same key (notice-class deviation, decided for jibot-code#zq90 in its comment c:688gdd and restated in the brief).
