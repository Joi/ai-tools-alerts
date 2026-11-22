#!/usr/bin/env python3
"""Sign the checkpoint key certificate with the trust root key.

    scripts/sign-checkpoint-key.py <checkpoint public key: 64 hex or npub>
        [--manifest trust/manifest.json] [--days 120] [--out trust/checkpoint-key.json]

The certificate names the one key that may sign feed checkpoints
(aitools_alerts/checkpoint.py). It is bound to the manifest at --manifest by
that manifest's event id, so every new manifest needs a new certificate: sign
the manifest, then run this. It expires --days after now (1 to 400).

The root secret is read by scripts/sign-manifest.py's read_root_secret, the
one implementation of that handling: see that script for the helper, its
environment variables and what keeps the key off disk. Every input is checked
before the key is read. The script refuses a key that is not TRUST_ROOT_PUBKEY
and prints only the certificate's event id.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from aitools_alerts import TRUST_ROOT_PUBKEY, checkpoint, manifest, nostr  # noqa: E402

_spec = importlib.util.spec_from_file_location("sign_manifest", Path(__file__).with_name("sign-manifest.py"))
_sign_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sign_manifest)
read_root_secret = _sign_manifest.read_root_secret

DEFAULT_MANIFEST = REPO / "trust" / "manifest.json"
DEFAULT_OUT = REPO / "trust" / "checkpoint-key.json"
MAX_DAYS = 400


def _die(msg: str) -> None:
    raise SystemExit(f"sign-checkpoint-key: {msg}")


def _public_key(text: str) -> str:
    """The checkpoint public key as 64 hex, from hex or an npub. The value is never echoed:
    a secret key pasted by mistake must not reach a terminal or a log."""
    if text.startswith("npub1"):
        try:
            return nostr.npub_to_hex(text)
        except ValueError:
            _die("the checkpoint key is not a valid npub")
    if nostr._is_hex(text, 32) and nostr._lift_x(int(text, 16)) is not None:
        return text
    _die("the checkpoint key must be a public key: 64 lowercase hex characters or an npub")


def _days(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_DAYS:
        raise argparse.ArgumentTypeError(f"must be a whole number of days from 1 to {MAX_DAYS}")
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sign the checkpoint key certificate with the root key.")
    ap.add_argument("checkpoint_key", help="the checkpoint public key: 64 hex or an npub")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--days", type=_days, default=120, help="days until the certificate expires (default 120)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    key = _public_key(args.checkpoint_key)
    try:
        m = manifest.load(args.manifest)
    except manifest.ManifestError as e:
        _die(f"manifest {args.manifest} is unusable: {e}")
    if not manifest.verify(m, TRUST_ROOT_PUBKEY):
        _die(f"manifest {args.manifest} is not signed by the trust root")
    if not args.out.parent.is_dir():
        _die(f"output directory {args.out.parent} does not exist")
    now = int(time.time())

    sec = read_root_secret()
    try:
        ev = checkpoint.build_cert(sec, m, key, now, now + args.days * 86400)
    except checkpoint.CheckpointError as e:
        _die(str(e))
    finally:
        del sec
    if ev["pubkey"] != TRUST_ROOT_PUBKEY:
        _die("the key read is not the trust root (its public key differs from TRUST_ROOT_PUBKEY)")

    data = (json.dumps(ev, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        cert = checkpoint.load_cert(data)
    except checkpoint.CheckpointError as e:
        _die(f"signed certificate does not load: {e}")
    if not checkpoint.verify_cert(cert, TRUST_ROOT_PUBKEY) or checkpoint.cert_problem(cert, m, now) is not None:
        _die("signed certificate does not verify for this manifest")
    _sign_manifest._write(args.out, data)
    print(ev["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
