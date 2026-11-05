"""The trust manifest: which pubkeys may post, and in which role.

The manifest is a Nostr event of kind 30078 with the single tag
``["d", "aitools-alerts-manifest"]``, signed by the trust root. Its content is
JSON ``{"version", "issued_at", "posters": [{"pubkey", "role", "name"}]}``,
plus an optional ``"retracted"``: advisory ids every reader treats as
retracted, whoever posted or retracted them (a revoked curator's retractions
are dropped with its key, so the ones that must stand are listed here). A
manifest without the key has ``retracted == ()``.

Use it in this order: ``load`` (parse and validate the shape, and refuse a
version lower than the one already accepted), then ``verify`` against the
pinned ``TRUST_ROOT_PUBKEY``, and only then ``role_of``. ``load`` does not
check the signature, so a loaded but unverified manifest proves nothing.
"""

from __future__ import annotations

import copy
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone

from . import nostr
from .schema import _IDENT, ROLES

__all__ = ["KIND", "D_TAG", "MAX_BYTES", "MAX_POSTERS", "ManifestError",
           "MAX_RETRACTED", "Poster", "Manifest", "parse_content", "load", "verify", "role_of"]

KIND = 30078
D_TAG = "aitools-alerts-manifest"
MAX_BYTES = 1 << 20
MAX_POSTERS = 64
MAX_NAME = 64
MAX_VERSION = 2**31 - 1
MAX_RETRACTED = 1024
_EVENT_KEYS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
_CONTENT_KEYS = frozenset({"version", "issued_at", "posters"})
_OPTIONAL_CONTENT_KEYS = frozenset({"retracted"})
_POSTER_KEYS = frozenset({"pubkey", "role", "name"})
_ISSUED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class ManifestError(ValueError):
    """The manifest is malformed, or its version is not acceptable."""


@dataclass(frozen=True)
class Poster:
    pubkey: str
    role: str
    name: str


@dataclass(frozen=True)
class Manifest:
    event: dict
    version: int
    issued_at: str
    posters: tuple[Poster, ...]
    retracted: tuple[str, ...] = ()


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ManifestError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name):
    raise ManifestError(f"non-standard JSON constant {name}")


def _json(text: str):
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates,
                          parse_constant=_reject_constant)
    except json.JSONDecodeError as e:
        raise ManifestError(f"not JSON: {e.msg}") from None
    except ManifestError:
        raise
    except ValueError:
        # e.g. an integer literal over Python's 4300-digit conversion limit
        raise ManifestError("not JSON: a value cannot be decoded") from None
    except RecursionError:
        raise ManifestError("JSON nested too deeply") from None


def _keys(obj, keys: frozenset, what: str, optional: frozenset = frozenset()) -> dict:
    if not isinstance(obj, dict):
        raise ManifestError(f"{what} must be an object")
    if not keys <= set(obj) <= keys | optional:
        extra = f" (optional: {sorted(optional)})" if optional else ""
        raise ManifestError(f"{what} must have exactly the keys {sorted(keys)}{extra}")
    return obj


def _name_ok(name) -> bool:
    if not isinstance(name, str) or not 1 <= len(name) <= MAX_NAME:
        return False
    if name != name.strip():
        return False
    # no control, format (bidi, zero-width), surrogate, private or unassigned
    # characters, and no line or paragraph separators
    return not any(unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp")
                   for c in name)


def _parse_retracted(ids) -> tuple[str, ...]:
    if not isinstance(ids, list) or len(ids) > MAX_RETRACTED:
        raise ManifestError(f"retracted must be a list of at most {MAX_RETRACTED} advisory ids")
    for i, a in enumerate(ids):
        if not isinstance(a, str) or not _IDENT.fullmatch(a):
            raise ManifestError(f"retracted[{i}] must be an advisory id")
    if len({a.casefold() for a in ids}) != len(ids):
        raise ManifestError("retracted lists an id twice (ids compare case-folded)")
    return tuple(ids)


def parse_content(obj) -> tuple[int, str, tuple[Poster, ...], tuple[str, ...]]:
    """Validate decoded manifest content; return (version, issued_at, posters,
    retracted)."""
    c = _keys(obj, _CONTENT_KEYS, "content", _OPTIONAL_CONTENT_KEYS)
    version = c["version"]
    if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= MAX_VERSION:
        raise ManifestError(f"version must be an integer in 1..{MAX_VERSION}")
    issued_at = c["issued_at"]
    if not isinstance(issued_at, str) or not _ISSUED_AT.fullmatch(issued_at):
        raise ManifestError("issued_at must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ManifestError("issued_at is not a real date and time") from None
    posters = c["posters"]
    if not isinstance(posters, list) or not 1 <= len(posters) <= MAX_POSTERS:
        raise ManifestError(f"posters must be a list of 1..{MAX_POSTERS} entries")
    out, seen = [], set()
    for i, p in enumerate(posters):
        p = _keys(p, _POSTER_KEYS, f"posters[{i}]")
        pub, role, name = p["pubkey"], p["role"], p["name"]
        if not nostr._is_hex(pub, 32) or nostr._lift_x(int(pub, 16)) is None:
            raise ManifestError(f"posters[{i}].pubkey must be a 64-hex x-only public key")
        if pub in seen:
            raise ManifestError(f"posters[{i}].pubkey is listed twice")
        if not isinstance(role, str) or role not in ROLES:
            raise ManifestError(f"posters[{i}].role must be one of {sorted(ROLES)}")
        if not _name_ok(name):
            raise ManifestError(f"posters[{i}].name must be 1..{MAX_NAME} printable characters")
        seen.add(pub)
        out.append(Poster(pubkey=pub, role=role, name=name))
    return version, issued_at, tuple(out), _parse_retracted(c.get("retracted", []))


def _parse_event(ev) -> tuple[int, str, tuple[Poster, ...], tuple[str, ...]]:
    ev = _keys(ev, _EVENT_KEYS, "event")
    try:
        nostr._check_shape(ev)
    except ValueError as e:
        raise ManifestError(f"event: {e}") from None
    if not nostr._is_hex(ev["id"], 32) or not nostr._is_hex(ev["sig"], 64):
        raise ManifestError("event id and sig must be lowercase hex")
    if ev["kind"] != KIND:
        raise ManifestError(f"event kind must be {KIND}")
    if ev["tags"] != [["d", D_TAG]]:
        raise ManifestError(f'event tags must be exactly [["d", "{D_TAG}"]]')
    version, issued_at, posters, retracted = parse_content(_json(ev["content"]))
    issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if ev["created_at"] != int(issued.timestamp()):
        raise ManifestError("event created_at must equal content issued_at")
    return version, issued_at, posters, retracted


def _read(src) -> bytes:
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        try:
            with open(src, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise ManifestError(f"cannot read manifest: {e.strerror}") from None
    else:
        raise ManifestError("manifest source must be a path or bytes")
    if len(data) > MAX_BYTES:
        raise ManifestError(f"manifest larger than {MAX_BYTES} bytes")
    return data


def load(src, previous: Manifest | None = None) -> Manifest:
    """Parse and validate a manifest from a path or bytes. Does NOT verify the
    signature (see ``verify``). With ``previous`` (the last accepted manifest),
    a lower version, or the same version with a different event, is refused."""
    if previous is not None and not isinstance(previous, Manifest):
        raise ManifestError("previous must be a Manifest or None")
    data = _read(src)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ManifestError("manifest is not UTF-8") from None
    ev = _json(text)
    version, issued_at, posters, retracted = _parse_event(ev)
    if previous is not None:
        if version < previous.version:
            raise ManifestError(f"manifest version {version} is older than accepted version {previous.version}")
        if version == previous.version and ev["id"] != previous.event.get("id"):
            raise ManifestError(f"manifest version {version} differs from the accepted manifest of the same version")
    return Manifest(event=copy.deepcopy(ev), version=version, issued_at=issued_at, posters=posters,
                    retracted=retracted)


def verify(m: Manifest, root_pubkey: str) -> bool:
    """True only if the manifest's event is signed by ``root_pubkey`` (the
    event's own pubkey IS the root), its id and signature are valid, and its
    content is exactly what ``m`` says. Never raises."""
    try:
        if not isinstance(m, Manifest) or not nostr._is_hex(root_pubkey, 32):
            return False
        ev = m.event
        if not isinstance(ev, dict) or ev.get("pubkey") != root_pubkey:
            return False
        if _parse_event(ev) != (m.version, m.issued_at, m.posters, m.retracted):
            return False
        return nostr.verify_event(ev)
    except (ManifestError, ValueError, TypeError, KeyError, RecursionError):
        return False


def role_of(m: Manifest, pubkey: str) -> str | None:
    """The role of ``pubkey`` in ``m`` (exact match), or None. Verify ``m`` first."""
    for p in m.posters:
        if p.pubkey == pubkey:
            return p.role
    return None
