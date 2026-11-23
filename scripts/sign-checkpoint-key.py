#!/usr/bin/env python3
"""Sign the checkpoint key certificate with the trust root key.

    scripts/sign-checkpoint-key.py <checkpoint public key, as an npub>
        [--manifest trust/manifest.json] [--days 120] [--out trust/checkpoint-key.json]
        [--min-cli N.N.N]

The certificate names the one key that may sign feed checkpoints
(aitools_alerts/checkpoint.py). It is bound to the manifest at --manifest by
that manifest's event id, so every new manifest needs a new certificate: sign
the manifest, then run this. It expires --days after now (1 to 400).

--min-cli names the oldest aitools-alerts release that can read the feed. A CLI
older than it prints one "upgrade" line on every command; nothing is refused.
It lives here and not in the manifest because released readers refuse a
manifest with a key they do not know and ignore one in this certificate
(spec/wire.md). Readers at 0.1.7 and earlier never print the line. Pass it
again on every later certificate, or the floor is gone.

The key is taken as an npub only. A 64-hex secret key is a valid public key
about half the time, so a hex argument could put a secret, pasted by mistake,
into a public file; an npub cannot be a secret. The script also refuses the
trust root and every poster in the manifest as the checkpoint key (the
checkpoint must come from a key the relay machine does not hold), an --out
that is the manifest, and a certificate that readers holding the one already
at --out would refuse (cert_order): each before the root key is read.

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
    """The checkpoint public key as 64 hex, from an npub. The value is never echoed:
    a secret key pasted by mistake must not reach a terminal or a log."""
    if not text.startswith("npub1"):
        _die("the checkpoint key must be a public key written as an npub (npub1...)")
    try:
        return nostr.npub_to_hex(text)
    except ValueError:
        _die("the checkpoint key is not a valid npub")


def _days(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_DAYS:
        raise argparse.ArgumentTypeError(f"must be a whole number of days from 1 to {MAX_DAYS}")
    return n


def _min_cli(text: str) -> str:
    if not checkpoint._MIN_CLI.fullmatch(text):
        raise argparse.ArgumentTypeError("must be a release version written N.N.N")
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sign the checkpoint key certificate with the root key.")
    ap.add_argument("checkpoint_key", help="the checkpoint public key, as an npub")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--days", type=_days, default=120, help="days until the certificate expires (default 120)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--min-cli", type=_min_cli, default=None,
                    help="the oldest CLI release that can read the feed (N.N.N); older ones print an upgrade line")
    args = ap.parse_args(argv)

    key = _public_key(args.checkpoint_key)
    try:
        m = manifest.load(args.manifest)
    except manifest.ManifestError as e:
        _die(f"manifest {args.manifest} is unusable: {e}")
    if not manifest.verify(m, TRUST_ROOT_PUBKEY):
        _die(f"manifest {args.manifest} is not signed by the trust root")
    if key == TRUST_ROOT_PUBKEY or manifest.role_of(m, key) is not None:
        _die("the checkpoint key must be its own key: not the trust root, not a poster in the manifest")
    if not args.out.parent.is_dir():
        _die(f"output directory {args.out.parent} does not exist")
    if args.out.resolve() == args.manifest.resolve():
        _die("--out is the manifest; the certificate is a separate file")
    now = int(time.time())
    previous = None
    if args.out.exists():
        try:
            previous = checkpoint.load_cert(args.out)
        except checkpoint.CheckpointError as e:
            _die(f"existing {args.out} is unreadable ({e}); move it aside to replace it")
        if not checkpoint.verify_cert(previous, TRUST_ROOT_PUBKEY):
            _die(f"existing {args.out} is not signed by the trust root; move it aside to replace it")
        if previous.issued_at >= now:  # readers that hold it would refuse the new one (cert_order)
            _die(f"existing {args.out} is issued at or after this machine's clock; check the clock")

    sec = read_root_secret()
    try:
        ev = checkpoint.build_cert(sec, m, key, now, now + args.days * 86400, args.min_cli)
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
    if (not checkpoint.verify_cert(cert, TRUST_ROOT_PUBKEY) or checkpoint.cert_problem(cert, m, now) is not None
            or checkpoint.cert_order(cert, previous) is not None):
        _die("signed certificate does not verify for this manifest, or would not replace the existing one")
    _sign_manifest._write(args.out, data)
    print(ev["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
