#!/usr/bin/env python3
"""scan-for-poster-keys: fail when a trust-manifest poster's secret key is on this machine.

Usage: scan-for-poster-keys.py --manifest <trust/manifest.json> <root> [<root> ...]

Walks every regular file under each root (symlinks are not followed), and every
member of every tar or gzip archive found there, recursing into archives inside
archives. Every string shaped like a Nostr secret key (``nsec1`` bech32, or 64 hex
at a token boundary) is a candidate; its public key is derived in memory and
compared with the manifest's posters. Nothing but paths and counts is printed:
never a candidate, never a key.

Exit 0: no poster key found and every path was read. Exit 1: a poster key was
found, or a file or archive could not be read (an unread path is not a pass).
Exit 2: bad arguments or manifest.

The derivation is aitools_alerts.nostr's, imported from the repository this file
sits in (ops/vm/ -> repository root), so copy the repository, not this file alone.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import io
import json
import lzma
import os
import re
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from aitools_alerts import nostr  # noqa: E402

MAX_DEPTH = 6  # archives inside archives; an archive deeper than this is UNREAD (a failure)
MAX_BLOB = 512 * 1024 * 1024  # a file or member larger than this is UNREAD (a failure), never skipped
# bech32 is single-case: all lowercase or all uppercase (nostr.nsec_to_hex accepts both).
_CANDIDATE = re.compile(rb"nsec1[02-9ac-hj-np-z]{58}|NSEC1[02-9AC-HJ-NP-Z]{58}"
                        rb"|(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
# Compressed or container formats the scan cannot open: present means UNREAD.
_UNSUPPORTED = ((b"\x28\xb5\x2f\xfd", "zstd"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!", "rar"))
_SAFE = re.compile(r"[^\x20-\x7e]")


def poster_pubkeys(manifest_path: Path) -> set[str]:
    ev = json.loads(manifest_path.read_text(encoding="utf-8"))
    posters = json.loads(ev["content"])["posters"]
    keys = {p["pubkey"] for p in posters}
    if not keys or not all(isinstance(k, str) and re.fullmatch(r"[0-9a-f]{64}", k) for k in keys):
        raise ValueError("manifest names no poster keys")
    return keys


class Scan:
    def __init__(self, targets: set[str]):
        self.targets = targets
        self.seen: dict[bytes, bool] = {}  # candidate -> is a poster key (derived once)
        self.files = self.members = 0
        self.hits: list[str] = []
        self.unread: list[str] = []

    def _is_poster(self, cand: bytes) -> bool:
        if cand not in self.seen:
            try:
                s = cand.decode("ascii").lower()
                hexkey = nostr.nsec_to_hex(s) if s.startswith("nsec1") else s
                pub = nostr.pubkey_gen(bytes.fromhex(hexkey)).hex()
                self.seen[cand] = pub in self.targets
            except (ValueError, TypeError, ZeroDivisionError):
                self.seen[cand] = False  # not a valid secret (checksum, out of range)
        return self.seen[cand]

    def data(self, label: str, blob: bytes, depth: int) -> None:
        label = _SAFE.sub("?", label)  # member names come from the archive: print no control bytes
        if any(self._is_poster(m.group(0)) for m in _CANDIDATE.finditer(blob)):
            self.hits.append(label)
        for magic, name in _UNSUPPORTED:
            if blob.startswith(magic):
                self.unread.append(f"{label} ({name}: cannot open)")
                return
        packed = (blob[:2] == b"\x1f\x8b" or blob[:3] == b"BZh" or blob[:6] == b"\xfd7zXZ\x00"
                  or blob[:4] == b"PK\x03\x04" or (len(blob) >= 512 and blob[257:262] == b"ustar"))
        if packed and depth >= MAX_DEPTH:
            self.unread.append(f"{label} (nested deeper than {MAX_DEPTH})")
            return
        for magic, name, fn in ((b"\x1f\x8b", "gzip", gzip.decompress), (b"BZh", "bzip2", bz2.decompress),
                                (b"\xfd7zXZ\x00", "xz", lzma.decompress)):
            if blob.startswith(magic):
                try:
                    inner = fn(blob)
                except (OSError, EOFError, ValueError, lzma.LZMAError):
                    self.unread.append(f"{label} ({name})")
                    return
                if len(inner) > MAX_BLOB:
                    self.unread.append(f"{label} ({name}: larger than {MAX_BLOB} bytes unpacked)")
                    return
                self.data(f"{label}!{name}", inner, depth + 1)
                return
        if blob[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    for zi in zf.infolist():
                        if zi.is_dir():
                            continue
                        self.members += 1
                        if zi.file_size > MAX_BLOB:
                            self.unread.append(_SAFE.sub("?", f"{label}!{zi.filename} (too large)"))
                            continue
                        self.data(f"{label}!{zi.filename}", zf.read(zi), depth + 1)
            except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as e:
                self.unread.append(f"{label} (zip: {type(e).__name__})")
            return
        if len(blob) >= 512 and blob[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
                    for m in tf:
                        if not m.isfile():
                            continue
                        self.members += 1
                        if m.size > MAX_BLOB:
                            self.unread.append(_SAFE.sub("?", f"{label}!{m.name} (too large)"))
                            continue
                        f = tf.extractfile(m)
                        if f is None:
                            self.unread.append(f"{label}!{m.name}")
                            continue
                        self.data(f"{label}!{m.name}", f.read(), depth + 1)
            except (tarfile.TarError, OSError, EOFError) as e:
                self.unread.append(f"{label} (tar: {type(e).__name__})")

    def path(self, p: str) -> None:
        self.files += 1
        try:
            if os.path.getsize(p) > MAX_BLOB:
                self.unread.append(f"{p} (larger than {MAX_BLOB} bytes)")
                return
            with open(p, "rb") as fh:
                blob = fh.read()
        except OSError:
            self.unread.append(p)
            return
        self.data(p, blob, 0)

    def root(self, root: str) -> None:
        if os.path.isfile(root) and not os.path.islink(root):
            self.path(root)
            return
        if not os.path.isdir(root):
            self.unread.append(root + " (missing)")
            return

        def onerror(e):
            self.unread.append(f"{getattr(e, 'filename', root)} (walk)")
        for d, dirs, files in os.walk(root, onerror=onerror):
            dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(d, x))]
            for name in files:
                p = os.path.join(d, name)
                if os.path.isfile(p) and not os.path.islink(p):
                    self.path(p)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("roots", nargs="+")
    a = ap.parse_args(argv)
    try:
        targets = poster_pubkeys(a.manifest)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"scan-for-poster-keys: manifest unusable: {type(e).__name__}", file=sys.stderr)
        return 2
    s = Scan(targets)
    for r in a.roots:
        s.root(r)
    for h in s.hits:
        print(f"POSTER KEY: {h}")
    for u in s.unread:
        print(f"UNREAD: {u}")
    print(f"scanned files={s.files} archive_members={s.members} candidates={len(s.seen)} "
          f"poster_keys={len(s.hits)} unread={len(s.unread)}")
    return 1 if s.hits or s.unread else 0


if __name__ == "__main__":
    sys.exit(main())
