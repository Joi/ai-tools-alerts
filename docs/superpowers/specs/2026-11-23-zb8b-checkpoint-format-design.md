# Checkpoint format: the checkpoint key certificate and the signed checkpoint

Kata: ai-tools-alerts#zb8b, piece 2 of ai-tools-alerts#ek5q. Sources: the adversarial review of 2026-11-23, finding H2 (`docs/security/2026-11-23-adversarial-review.md` on branch `mythos-adversarial-review`); the design review's rule 7 and "Tension to settle before building" (comments on ai-tools-alerts#h29n); the notice comment on ek5q of 2026-11-23.

## Problem

Each event is signed; the set of events is not. Whoever controls what the mirror serves can leave out one alert, one retraction, or serve an old manifest, and every signature still verifies. The reader needs a signed statement of which events exist, made on a machine that is not the mirror, and a way to know which key may make that statement.

The released v0.1.4 reader refuses a manifest with an unknown content key or an unknown poster role (`manifest.py` `_keys`, `ROLES`). So neither the checkpoint key nor an expiry can go into the manifest: v0.1.4 would stop pulling.

This piece defines the two new signed documents, their parsers and verifiers, and the script that signs the certificate. It changes no reader behaviour: nothing calls the new module yet (piece 3 does, piece 4 produces checkpoints).

## The two documents

Both are Nostr events of kind 30078 (the manifest's kind: an application-data event), told apart by their `d` tag. Both are published as files beside `manifest.json`; neither is ever sent to the relay.

### The checkpoint key certificate (`checkpoint-key.json`)

Signed by the trust root, by hand, when a manifest is signed (a few times a year). It answers "which key may sign checkpoints, for which manifest, until when".

- `kind` 30078, `tags` exactly `[["d", "aitools-alerts-checkpoint-key"]]`, `pubkey` the trust root.
- `content`: JSON object with
  - `v`: the format version, the integer 1;
  - `manifest_id`: the event id (64 hex) of the manifest this certificate belongs to;
  - `manifest_version`: that manifest's version (for messages; the id is what binds);
  - `checkpoint_key`: an x-only public key, 64 hex;
  - `issued_at`, `expires_at`: `YYYY-MM-DDTHH:MM:SSZ`, `expires_at` after `issued_at`.
- `created_at` equals `issued_at`.
- At most 16 KiB.

A certificate is usable at time `now` for manifest `m` when: its signature verifies under the pinned root; `manifest_id == m.event["id"]`; `issued_at <= now + 600`; `now <= expires_at`. A new manifest therefore needs a new certificate, which is what makes a key rotation one hand action: sign the manifest, sign the certificate for it.

The expiry is the signer's choice. The script's default is 120 days. This replaces the issue's "manifest expiry of weeks": a root signature every few weeks needs a person on a schedule, which the ruling of 2026-11-23 excludes; freshness comes from the checkpoint, and the certificate's expiry bounds how long a stolen checkpoint key outlives its revocation where the second manifest origin is blocked.

### The checkpoint (`checkpoint.json`)

Signed by the certified key on the poster machine, every poster run. It answers "these events exist, as of now".

- `kind` 30078, `tags` exactly `[["d", "aitools-alerts-checkpoint"]]`, `pubkey` the certificate's `checkpoint_key`.
- `content`: JSON object with
  - `v`: the format version, the integer 1;
  - `seq`: integer from 1 to 2^53 - 1, higher in every checkpoint the signer makes with this key;
  - `valid_until`: integer, seconds since the epoch;
  - `manifest_id`, `manifest_version`: the manifest the signer held;
  - `events`: the ids (64 hex) of every event the signer vouches for, sorted, no duplicates, at most 2,000.
- `created_at` is the time it was signed.
- At most 256 KiB (2,000 ids are about 134 KiB).

A checkpoint is usable at time `now` under certificate `c` and manifest `m` when: `c` is usable for `m`; its signature verifies under `c.checkpoint_key`; `manifest_id == m.event["id"]`; `created_at <= now + 600`. It is *fresh* while `now <= min(valid_until, created_at + 172800)`: the reader caps the validity it honours at 48 hours, so a thief who signs one checkpoint valid for ten years gains two days. The signer's default validity is 24 hours.

Ids, not a hash: the mirror is usually ahead of the checkpoint (the exporter runs every 5 minutes, the poster hourly). With ids the reader checks that every listed event is present and applies only listed events; newer events wait for the next checkpoint. A per-thread hash cannot say which replies it covers.

### What the checkpoint certifies, and the mirror's caps

The mirror does not serve everything: the exporter keeps the newest threads within 2,000 events and 4 MiB per channel and drops older ones (`export_mirror.cap`). A checkpoint that listed every event ever posted would name events an honest mirror no longer serves, and a reader could not tell that from an attack. So the checkpoint certifies a bounded window, and the three parties agree on it:

- **Signer (piece 4):** lists whole threads, newest thread first, until the next thread would pass 1,500 events or 3 MiB of serialized events over both channels together. Both bounds are below one channel's caps, so the listed events always fit in the mirror.
- **Exporter (piece 4):** keeps every event the current checkpoint lists before it applies its caps to the rest, and publishes a checkpoint only when every event it lists is in the same export. Between an export that cannot yet serve a new checkpoint and the next, it keeps serving the previous checkpoint and the events that one lists.
- **Reader (piece 3):** the alert set is the checkpoint's window. It applies only listed events, refuses the pull when a listed event is in neither the fetched files nor its store, and shows nothing from events no usable checkpoint lists. A thread that has left the window (about 1,500 events back; the reader's own retention is 400 days) is no longer shown, which is what a new reader of the capped mirror sees today. A correction to an old thread is a new event, so it brings its whole thread back into the window.

This piece fixes the format ceiling (2,000 ids, above the signer's 1,500) and states the contract; the test in which an export crosses a cap between two checkpoints belongs to piece 4, where the exporter and signer change, and is named in its issue.

### Order: no going back

The reader keeps the last checkpoint and certificate it accepted (piece 3 stores them). This piece defines the comparison, so the rule is one function with tests, not reader folklore:

- `cert_order(new, old)`: a certificate replaces the stored one when it is the same event, or its `issued_at` is later. An earlier `issued_at`, or the same `issued_at` with a different event id, is refused (`"older certificate"`, `"conflicting certificate"`).
- `checkpoint_order(new, old)`: `seq` is scoped to the checkpoint key. With the same key: the same event id is a retransmission and is fine; a lower `seq` is refused (`"older checkpoint"`); the same `seq` with a different id is refused and reported (`"conflicting checkpoint"`: two different statements under one number mean a stolen key or a split view); a higher `seq` must not be dated before the stored one (`"older checkpoint"`). With a different key (a new certificate named a new key): accepted only if `created_at` is not before the stored checkpoint's; `seq` starts again.

A signer that loses its count cannot go back under the same key: it needs a new key and a certificate naming it (piece 4 states this in the poster's recovery steps). A thief who signs the highest possible `seq` ends that key's use the same way; the remedy is the same new certificate.

A manifest change does not reset anything: the certificate for the new manifest is newer by `issued_at`, and the checkpoint key it names continues its own `seq` if it is the same key.

### Format version and unknown keys

Each document carries `v: 1`. A parser that meets another `v` refuses the document with the reason `"unsupported format"`, which the reader reports as "upgrade aitools-alerts": a later format that adds a restriction (the design review's `ruleset`, `min_cli`) raises `v`, and this reader then fails closed instead of ignoring the restriction. Within `v: 1`, content keys the parser does not know are ignored: they can only be descriptive, because anything a reader must enforce needs a new `v`. The manifest's strictness about every key is why this piece needs two new files at all.

Event-level strictness stays: exactly the seven NIP-01 keys, the exact `d` tag, the right kind.

## The module: `aitools_alerts/checkpoint.py`

```
CERT_D_TAG, CHECKPOINT_D_TAG, KIND, MAX_CERT_BYTES, MAX_CHECKPOINT_BYTES, MAX_EVENT_IDS,
MAX_AHEAD_S (pull's), MAX_VALID_S = 172800, DEFAULT_VALID_S = 86400

class CheckpointError(ValueError)

@dataclass(frozen=True) class Cert:       event, manifest_id, manifest_version, checkpoint_key, issued_at:int, expires_at:int
@dataclass(frozen=True) class Checkpoint: event, seq, created_at, valid_until, manifest_id, manifest_version, events: frozenset

load_cert(src: bytes | path) -> Cert            # shape only, raises CheckpointError
verify_cert(cert, root_pubkey) -> bool          # never raises
cert_problem(cert, manifest, now) -> str | None # "other manifest" | "dated ahead" | "expired" | None

load_checkpoint(src) -> Checkpoint
verify_checkpoint(cp, cert) -> bool
checkpoint_problem(cp, manifest, now) -> str | None  # "other manifest" | "dated ahead" | None
fresh_until(cp) -> int                                # min(valid_until, created_at + MAX_VALID_S)
cert_order(new, old) -> str | None                    # see "Order"
checkpoint_order(new, old) -> str | None

build_cert(root_sec, manifest, checkpoint_key, issued_at:int, expires_at:int) -> dict   # the signed event
build_checkpoint(sec, manifest, seq, event_ids, now:int, valid_s=DEFAULT_VALID_S) -> dict
```

`load_*` follow `manifest.load`: bytes or a path, size cap, UTF-8, duplicate keys and non-standard constants refused, then the shape. `verify_*` re-parse the event and compare with the dataclass, as `manifest.verify` does, so a tampered dataclass never verifies.

## The signing script: `scripts/sign-checkpoint-key.py`

```
scripts/sign-checkpoint-key.py <checkpoint public key, as an npub>
    [--manifest trust/manifest.json] [--days 120] [--out trust/checkpoint-key.json]
```

The key is taken as an npub only: a 64-hex secret key is a valid public key about half the time, so a hex argument could put a secret pasted by mistake into a public file, and an npub cannot be a secret. The script refuses the trust root and every poster of the manifest as the checkpoint key, an `--out` that is the manifest, and a certificate that readers holding the one already at `--out` would refuse (issued at or before it: `cert_order`). All of that is checked before the root key is read.

It loads and verifies the manifest under the pinned root, refuses `--days` outside 1..400, reads the root key exactly as `scripts/sign-manifest.py` does (it imports that script's `read_root_secret`, so there is one implementation of the key handling: the helper, the read-only cache directory, the refusal to run as root), signs, checks the result with `load_cert`, `verify_cert` and `cert_problem`, writes it atomically, and prints only the event id. It refuses a key that is not the trust root.

Generating the checkpoint key itself belongs to the poster (piece 4).

## Success criteria

- Round trip with throwaway keys: `build_cert` then `load_cert`, `verify_cert`, `cert_problem is None`; the same for the checkpoint.
- A certificate signed by a key that is not the root, with a wrong `d` tag or kind, with `created_at` different from `issued_at`, with `expires_at` not after `issued_at`, or over the size cap: refused by `load_cert` or `verify_cert`.
- A certificate for another manifest id: `cert_problem == "other manifest"`; issued more than 600 s ahead: `"dated ahead"`; past `expires_at`: `"expired"`.
- A checkpoint signed by a key other than the certificate's, with an unsorted or duplicated id list, a non-hex id, `seq` below 1 or not an integer, more than 2,000 ids, or over the size cap: refused.
- A checkpoint for another manifest, or dated more than 600 s ahead: named by `checkpoint_problem`. `fresh_until` honours at most 48 hours.
- An unknown content key in either document is accepted and ignored; `v` other than 1, or missing, is refused as `unsupported format`.
- `checkpoint_order`: retransmission accepted; lower `seq`, same `seq` with another id, and a higher `seq` dated earlier refused, each with its reason; a new key accepted only when not dated before the stored checkpoint. `cert_order`: same event accepted, later accepted, earlier and same-time-different-id refused.
- The script, with a stub in place of the secrets helper: writes a certificate that verifies; refuses a non-root key, a bad public key, a manifest that does not verify, and `--days 0`; never prints the key.
- No existing module imports `checkpoint`; `scripts/test-gate.sh` passes; the v0.1.4 reader is unaffected (no file it reads changes).

## Alternatives considered

- **Name the checkpoint key in the manifest (a new role or content key).** Rejected: v0.1.4 refuses the manifest.
- **Sign checkpoints with the relay-bot key.** Rejected: that key is on the relay VM (`ops/vm/buzz-send`), which is the machine the checkpoint must not trust.
- **A manifest expiry of weeks, root re-signing on a schedule.** Rejected: see the certificate's expiry above.
- **A per-thread state hash (design review rule 7 as written).** Rejected: see "Ids, not a hash".
- **Strict content keys.** Rejected: see "Format version and unknown keys".
- **List every event ever posted.** Rejected: see "What the checkpoint certifies".

## Blast radius and rollback

A new module, a new script and tests. Nothing imports the module, so reverting the commit restores the previous behaviour exactly.

## Assumes

- The trust root signs the certificate where it signs the manifest today, with the same helper. The script adds no second way to read the root key.

## Open questions

None for this piece. Which machine holds the checkpoint key is the poster's (piece 4) and the rollout issue's.
