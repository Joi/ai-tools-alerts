#!/usr/bin/env python3
"""Sign a trust manifest with the trust root key.

    scripts/sign-manifest.py <content.json> [--out trust/manifest.json]

<content.json> is the manifest content: {"version", "issued_at", "posters"}.
The root secret is read with get_secret AITOOLS_ALERTS_ROOT_NSEC from the
fleet's secrets helper, in a bash subprocess whose SECRETS_CACHE_DIR is a fresh
temporary directory with no write permission, so the helper's cache write
fails and the key never touches disk; the directory is checked empty and
removed. The key travels only over the subprocess's stdout pipe into this
process: never in argv, never printed, logged or written to a file. The script refuses a key whose public key is not TRUST_ROOT_PUBKEY, and
a version not higher than the manifest already at --out. It prints only the
event id.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from aitools_alerts import TRUST_ROOT_PUBKEY, manifest, nostr  # noqa: E402

SECRET_NAME = "AITOOLS_ALERTS_ROOT_NSEC"
HELPER = "source ~/dotfiles-private/scripts/lib/secrets.sh && get_secret " + SECRET_NAME
DEFAULT_OUT = REPO / "trust" / "manifest.json"


def _die(msg: str) -> None:
    raise SystemExit(f"sign-manifest: {msg}")


def read_root_secret(runner=subprocess.run) -> str:
    """Return the root secret key as 64 lowercase hex."""
    # The helper caches every value it reads in SECRETS_CACHE_DIR. Pointing it
    # at a fresh directory with no write permission makes each cache write fail
    # (the helper ignores that failure), so the key is never written to disk;
    # the directory is checked empty afterwards and removed.
    cache = tempfile.mkdtemp(prefix="sign-manifest-")
    os.chmod(cache, 0o500)
    try:
        env = {k: v for k, v in os.environ.items() if k != SECRET_NAME}
        env["SECRETS_CACHE_DIR"] = cache
        try:
            res = runner(["bash", "-c", HELPER], env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            _die("reading the root key timed out")
        except OSError:
            _die("could not run bash to read the root key")
        if os.listdir(cache):
            _die("the secrets helper wrote into its cache directory; it has been removed")
        if res.returncode != 0:
            _die(f"could not read the root key (get_secret exit {res.returncode})")
        try:
            lines = res.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError:
            lines = []
        if len(lines) != 1:
            _die("the root key value is not a single line")
        value = lines[0].strip()
        if value.startswith("nsec1"):
            try:
                return nostr.nsec_to_hex(value)
            except ValueError:
                _die("the root key value is not a valid nsec")
        if nostr._is_hex(value, 32) and 1 <= int(value, 16) < nostr.N:
            return value
        _die("the root key value is neither 64 hex characters nor an nsec")
    finally:
        os.chmod(cache, 0o700)
        shutil.rmtree(cache, ignore_errors=True)


def build_event(content: dict, sec_hex: str) -> dict:
    """Sign the manifest event for already-validated content."""
    issued = datetime.strptime(content["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return nostr.sign_event(sec_hex, {
        "created_at": int(issued.timestamp()),
        "kind": manifest.KIND,
        "tags": [["d", manifest.D_TAG]],
        "content": json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    })


def _write(out: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".manifest-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv=None, runner=subprocess.run) -> int:
    ap = argparse.ArgumentParser(description="Sign the trust manifest with the root key.")
    ap.add_argument("content", type=Path)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    try:
        raw = manifest._json(args.content.read_text(encoding="utf-8"))
        manifest.parse_content(raw)
    except (OSError, UnicodeDecodeError) as e:
        _die(f"cannot read {args.content}: {e}")
    except manifest.ManifestError as e:
        _die(f"invalid content: {e}")
    content = {"version": raw["version"], "issued_at": raw["issued_at"], "posters": raw["posters"]}

    previous = None
    if args.out.exists():
        try:
            previous = manifest.load(args.out)
        except manifest.ManifestError as e:
            _die(f"existing {args.out} is unreadable ({e}); move it aside to replace it")
        if content["version"] <= previous.version:
            _die(f"version {content['version']} is not higher than the existing version {previous.version}")

    sec = read_root_secret(runner=runner)
    ev = build_event(content, sec)
    del sec
    if ev["pubkey"] != TRUST_ROOT_PUBKEY:
        _die("the key read is not the trust root (its public key differs from TRUST_ROOT_PUBKEY)")

    data = (json.dumps(ev, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        m = manifest.load(data, previous=previous)
    except manifest.ManifestError as e:
        _die(f"signed manifest does not load: {e}")
    if not manifest.verify(m, TRUST_ROOT_PUBKEY):
        _die("signed manifest does not verify against TRUST_ROOT_PUBKEY")
    _write(args.out, data)
    print(ev["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
